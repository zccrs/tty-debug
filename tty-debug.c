// Copyright (C) 2025 UnionTech Software Technology Co., Ltd.
// SPDX-License-Identifier: Apache-2.0 OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <linux/vt.h>
#include <dirent.h>
#include <sys/signalfd.h>
#include <sys/wait.h>

#define MAX_NAME_LEN 512
#define MAX_PATH_LEN 256
#define MAX_PROCESSES 1024
#define MAX_SUSPECTS 10
#define SYSFS_TTY0_ACTIVE "/sys/class/tty/tty0/active"
#define SYSFS_CONSOLE_ACTIVE "/sys/class/tty/console/active"
#define VT_MODE_CHECK_INTERVAL 2  // Check VT mode every 2 seconds
#define PROCESS_CHECK_INTERVAL 3  // Check processes every 3 seconds

static volatile int running = 1;

// VT Control Mode Configuration
typedef struct {
    int enabled;              // Whether VT control mode is enabled
    int target_tty;          // Target TTY to control (-1 = current TTY)
    int silent_allow;        // Silent mode - automatically allow switches
    int interactive_prompt;  // Show interactive prompts for VT switches
} vt_control_config_t;

static vt_control_config_t vt_control_config = {0};
static struct vt_mode original_vt_mode = {0};
static int vt_control_fd = -1;
static int in_vt_control_mode = 0;

// Function declarations for VT control
void vt_control_signal_handler(int sig);
int setup_vt_control_mode(int tty_number);
void cleanup_vt_control_mode(void);
int ask_user_permission(int target_vt);
void print_usage(const char *program_name);

// Get detailed information about VT control process
typedef struct {
    pid_t pid;
    char command[MAX_NAME_LEN];
    char user_name[MAX_NAME_LEN];
    uid_t uid;
    int is_session_leader;
    int has_tty_access;
    int control_score;
} vt_control_info_t;

typedef struct {
    int tty_number;
    char user_name[MAX_NAME_LEN];
    uid_t uid;
    pid_t session_leader;
    char command[MAX_NAME_LEN];
    int vt_mode;
    int release_signal;
    int acquire_signal;
    vt_control_info_t vt_control;
} tty_info_t;

typedef struct {
    pid_t pid;
    char command[MAX_NAME_LEN];
    char user_name[MAX_NAME_LEN];
    uid_t uid;
    unsigned long long last_signal_time;
    unsigned long long last_syscall_time;
    unsigned long long last_activity_time;
    int monitoring;
} process_info_t;

typedef struct {
    pid_t pid;
    char command[MAX_NAME_LEN];
    char user_name[MAX_NAME_LEN];
    unsigned long long activity_score;
    time_t detection_time;
} suspect_process_t;

static process_info_t monitored_processes[MAX_PROCESSES];
static int num_monitored_processes = 0;
static int current_release_signal = -1;
static int current_acquire_signal = -1;

// Function declarations
void get_process_command(pid_t pid, char *command, size_t max_len);
void get_user_info(pid_t pid, char *username, size_t max_len, uid_t *uid);

// Get process command line from /proc/pid/cmdline
void get_process_command(pid_t pid, char *command, size_t max_len) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);

    FILE *file = fopen(path, "rb");
    if (!file) {
        strncpy(command, "unknown", max_len - 1);
        command[max_len - 1] = '\0';
        return;
    }

    char buffer[2048];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
    fclose(file);

    if (bytes_read == 0) {
        strncpy(command, "unknown", max_len - 1);
        command[max_len - 1] = '\0';
        return;
    }

    buffer[bytes_read] = '\0';

    // Convert null bytes to spaces (except the last one)
    for (size_t i = 0; i < bytes_read - 1; i++) {
        if (buffer[i] == '\0') {
            buffer[i] = ' ';
        }
    }

    // Remove trailing spaces
    while (bytes_read > 0 && (buffer[bytes_read - 1] == ' ' || buffer[bytes_read - 1] == '\0')) {
        bytes_read--;
    }
    buffer[bytes_read] = '\0';

    strncpy(command, buffer, max_len - 1);
    command[max_len - 1] = '\0';
}

// Get user information for a process
void get_user_info(pid_t pid, char *username, size_t max_len, uid_t *uid) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *file = fopen(path, "r");
    if (!file) {
        strncpy(username, "unknown", max_len - 1);
        username[max_len - 1] = '\0';
        *uid = (uid_t)-1;
        return;
    }

    char line[256];
    *uid = (uid_t)-1;

    while (fgets(line, sizeof(line), file)) {
        if (strncmp(line, "Uid:", 4) == 0) {
            if (sscanf(line, "Uid:\t%d", uid) == 1) {
                break;
            }
        }
    }
    fclose(file);

    if (*uid == (uid_t)-1) {
        strncpy(username, "unknown", max_len - 1);
        username[max_len - 1] = '\0';
        return;
    }

    struct passwd *pwd = getpwuid(*uid);
    if (pwd) {
        strncpy(username, pwd->pw_name, max_len - 1);
        username[max_len - 1] = '\0';
    } else {
        snprintf(username, max_len, "uid_%d", *uid);
    }
}

// Signal handler for graceful shutdown (monitoring mode)
void monitoring_signal_handler(int sig) {
    if (in_vt_control_mode) {
        // In VT control mode, use the VT control signal handler
        vt_control_signal_handler(sig);
    } else {
        // In monitoring mode, just shutdown gracefully
        printf("\nReceived signal %d, shutting down...\n", sig);
        running = 0;
    }
}

// Get current time as formatted string
void get_current_time(char *time_str, size_t size) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Get process activity statistics from /proc/pid/stat
int get_process_activity_stats(pid_t pid, unsigned long long *signal_time,
                              unsigned long long *syscall_time, unsigned long long *activity_time) {
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);

    FILE *file = fopen(path, "r");
    if (!file) {
        return -1;
    }

    char line[2048];
    if (!fgets(line, sizeof(line), file)) {
        fclose(file);
        return -1;
    }
    fclose(file);

    // Parse stat file - we need multiple fields:
    // Field 37: signal, Field 14: utime, Field 15: stime
    char *tokens[50];
    char *token = strtok(line, " ");
    int field_count = 0;

    while (token && field_count < 50) {
        tokens[field_count++] = token;
        token = strtok(NULL, " ");
    }

    if (field_count >= 37) {
        *signal_time = strtoull(tokens[36], NULL, 10);  // signals field
        if (field_count >= 15) {
            unsigned long long utime = strtoull(tokens[13], NULL, 10);
            unsigned long long stime = strtoull(tokens[14], NULL, 10);
            *syscall_time = stime;  // system time
            *activity_time = utime + stime;  // total CPU time
        }
        return 0;
    }

    return -1;
}

// Get process signal statistics from /proc/pid/stat
int get_process_signal_stats(pid_t pid, unsigned long long *signal_time) {
    unsigned long long syscall_time, activity_time;
    return get_process_activity_stats(pid, signal_time, &syscall_time, &activity_time);
}

// Check if process received a signal
int check_process_signal_change(process_info_t *proc) {
    unsigned long long current_signal_time, current_syscall_time, current_activity_time;
    if (get_process_activity_stats(proc->pid, &current_signal_time,
                                  &current_syscall_time, &current_activity_time) == 0) {
        int changed = 0;
        if (current_signal_time != proc->last_signal_time) {
            proc->last_signal_time = current_signal_time;
            changed = 1;
        }
        if (current_syscall_time != proc->last_syscall_time) {
            proc->last_syscall_time = current_syscall_time;
            changed = 1;
        }
        if (current_activity_time != proc->last_activity_time) {
            proc->last_activity_time = current_activity_time;
            changed = 1;
        }
        return changed;
    }
    return 0;
}

// Calculate activity score for a process (higher = more suspicious)
unsigned long long calculate_activity_score(process_info_t *proc) {
    unsigned long long current_signal_time, current_syscall_time, current_activity_time;
    if (get_process_activity_stats(proc->pid, &current_signal_time,
                                  &current_syscall_time, &current_activity_time) == 0) {

        unsigned long long signal_delta = current_signal_time - proc->last_signal_time;
        unsigned long long syscall_delta = current_syscall_time - proc->last_syscall_time;
        unsigned long long activity_delta = current_activity_time - proc->last_activity_time;

        // Weight: syscalls are most important, then activity, then signals
        return (syscall_delta * 10) + (activity_delta * 5) + (signal_delta * 2);
    }
    return 0;
}

// Check if process has TTY device access
int check_tty_device_access(pid_t pid, int tty_number) {
    char path[MAX_PATH_LEN];
    char fd_path[MAX_PATH_LEN];
    char link_target[MAX_PATH_LEN];
    char tty_device[64];
    DIR *fd_dir;
    struct dirent *entry;

    snprintf(tty_device, sizeof(tty_device), "/dev/tty%d", tty_number);
    snprintf(path, sizeof(path), "/proc/%d/fd", pid);

    fd_dir = opendir(path);
    if (!fd_dir) {
        return 0;
    }

    while ((entry = readdir(fd_dir)) != NULL) {
        if (entry->d_type != DT_LNK) continue;

        snprintf(fd_path, sizeof(fd_path), "%s/%s", path, entry->d_name);
        ssize_t link_len = readlink(fd_path, link_target, sizeof(link_target) - 1);

        if (link_len > 0) {
            link_target[link_len] = '\0';
            if (strcmp(link_target, tty_device) == 0) {
                closedir(fd_dir);
                return 1;  // Process has TTY device open
            }
        }
    }

    closedir(fd_dir);
    return 0;
}

// Find suspect processes that might have changed VT mode
int find_vt_mode_suspects(int tty_number, suspect_process_t *suspects, int max_suspects) {
    int suspect_count = 0;
    time_t current_time = time(NULL);

    printf("Analyzing processes for VT mode change suspects...\n");

    // Check monitored processes first
    for (int i = 0; i < num_monitored_processes && suspect_count < max_suspects; i++) {
        if (!monitored_processes[i].monitoring) continue;

        unsigned long long score = calculate_activity_score(&monitored_processes[i]);
        if (score > 0) {
            suspects[suspect_count].pid = monitored_processes[i].pid;
            strncpy(suspects[suspect_count].command, monitored_processes[i].command, MAX_NAME_LEN - 1);
            strncpy(suspects[suspect_count].user_name, monitored_processes[i].user_name, MAX_NAME_LEN - 1);
            suspects[suspect_count].activity_score = score;
            suspects[suspect_count].detection_time = current_time;
            suspect_count++;
        }
    }

    // Check other processes that have TTY access
    DIR *proc_dir = opendir("/proc");
    if (proc_dir) {
        struct dirent *entry;

        while ((entry = readdir(proc_dir)) != NULL && suspect_count < max_suspects) {
            if (entry->d_type != DT_DIR) continue;

            char *endptr;
            long pid = strtol(entry->d_name, &endptr, 10);
            if (*endptr != '\0' || pid <= 0) continue;

            // Skip if already monitored
            int already_monitored = 0;
            for (int i = 0; i < num_monitored_processes; i++) {
                if (monitored_processes[i].pid == pid) {
                    already_monitored = 1;
                    break;
                }
            }
            if (already_monitored) continue;

            // Check if process has TTY access
            if (check_tty_device_access(pid, tty_number)) {
                suspects[suspect_count].pid = pid;
                get_process_command(pid, suspects[suspect_count].command, MAX_NAME_LEN);

                uid_t uid;
                get_user_info(pid, suspects[suspect_count].user_name, MAX_NAME_LEN, &uid);

                suspects[suspect_count].activity_score = 100;  // Base score for TTY access
                suspects[suspect_count].detection_time = current_time;
                suspect_count++;
            }
        }

        closedir(proc_dir);
    }

    return suspect_count;
}

// Print VT mode change suspects
void print_vt_mode_suspects(suspect_process_t *suspects, int suspect_count) {
    if (suspect_count == 0) {
        printf("  No obvious suspects found.\n");
        return;
    }

    printf("  Possible VT mode change suspects (ranked by activity):\n");

    // Sort suspects by activity score (bubble sort for simplicity)
    for (int i = 0; i < suspect_count - 1; i++) {
        for (int j = 0; j < suspect_count - i - 1; j++) {
            if (suspects[j].activity_score < suspects[j + 1].activity_score) {
                suspect_process_t temp = suspects[j];
                suspects[j] = suspects[j + 1];
                suspects[j + 1] = temp;
            }
        }
    }

    for (int i = 0; i < suspect_count; i++) {
        printf("    %d. PID %d: %s (User: %s, Score: %llu)\n",
               i + 1, suspects[i].pid, suspects[i].command,
               suspects[i].user_name, suspects[i].activity_score);
    }
}

// Get the currently active TTY number from sysfs
int get_active_tty_from_sysfs(void) {
    FILE *file = fopen(SYSFS_TTY0_ACTIVE, "r");
    if (!file) {
        perror("Failed to open " SYSFS_TTY0_ACTIVE);
        return -1;
    }

    char buffer[32];
    if (!fgets(buffer, sizeof(buffer), file)) {
        perror("Failed to read from " SYSFS_TTY0_ACTIVE);
        fclose(file);
        return -1;
    }
    fclose(file);

    // Parse "ttyN" format
    int tty_num;
    if (sscanf(buffer, "tty%d", &tty_num) == 1) {
        return tty_num;
    }

    fprintf(stderr, "Failed to parse TTY number from: %s", buffer);
    return -1;
}

// Get VT mode information for a TTY
int get_tty_mode(int tty_number) {
    char tty_path[MAX_PATH_LEN];
    snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);

    int fd = open(tty_path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    struct vt_mode vt_mode;
    int result = ioctl(fd, VT_GETMODE, &vt_mode);
    close(fd);

    if (result == -1) {
        return -1;
    }

    return vt_mode.mode;
}

// Convert VT mode to readable string
const char* get_vt_mode_string(int mode) {
    switch (mode) {
        case VT_AUTO: return "VT_AUTO (0)";
        case VT_PROCESS: return "VT_PROCESS (1)";
        case VT_ACKACQ: return "VT_ACKACQ (2)";
        default: return "UNKNOWN";
    }
}

// Get VT mode details including signals
void get_vt_mode_details(int tty_number, int *mode, int *release_sig, int *acquire_sig) {
    char tty_path[MAX_PATH_LEN];
    snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);

    int fd = open(tty_path, O_RDONLY);
    if (fd == -1) {
        *mode = -1;
        *release_sig = -1;
        *acquire_sig = -1;
        return;
    }

    struct vt_mode vt_mode;
    int result = ioctl(fd, VT_GETMODE, &vt_mode);
    close(fd);

    if (result == -1) {
        *mode = -1;
        *release_sig = -1;
        *acquire_sig = -1;
        return;
    }

    *mode = vt_mode.mode;
    *release_sig = vt_mode.relsig;
    *acquire_sig = vt_mode.acqsig;
}

// Find all processes in the same session as the TTY
int find_tty_session_processes(int tty_number, process_info_t *processes, int max_processes) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return -1;
    }

    struct dirent *entry;
    int process_count = 0;

    while ((entry = readdir(proc_dir)) != NULL && process_count < max_processes) {
        if (entry->d_type != DT_DIR) continue;

        // Check if directory name is a number (PID)
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        // Check process TTY
        char stat_path[MAX_PATH_LEN];
        snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);

        FILE *stat_file = fopen(stat_path, "r");
        if (!stat_file) continue;

        char stat_line[1024];
        if (fgets(stat_line, sizeof(stat_line), stat_file)) {
            // Parse TTY from stat file (7th field after comm field)
            char *token = strtok(stat_line, " ");
            for (int i = 0; i < 6 && token; i++) {
                token = strtok(NULL, " ");
            }

            if (token) {
                int proc_tty = atoi(token);
                int major = (proc_tty >> 8) & 0xff;
                int minor = proc_tty & 0xff;

                // TTY major number is 4, minor number matches our TTY
                if (major == 4 && minor == tty_number) {
                    processes[process_count].pid = pid;
                    processes[process_count].monitoring = 1;

                    // Get process info
                    get_user_info(pid, processes[process_count].user_name,
                                sizeof(processes[process_count].user_name),
                                &processes[process_count].uid);
                    get_process_command(pid, processes[process_count].command,
                                      sizeof(processes[process_count].command));

                    // Initialize activity monitoring
                    get_process_activity_stats(pid, &processes[process_count].last_signal_time,
                                             &processes[process_count].last_syscall_time,
                                             &processes[process_count].last_activity_time);

                    process_count++;
                }
            }
        }
        fclose(stat_file);
    }

    closedir(proc_dir);
    return process_count;
}

// Find session leader process for a TTY
pid_t find_session_leader(int tty_number) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return -1;
    }

    struct dirent *entry;
    pid_t session_leader = -1;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        // Check if directory name is a number (PID)
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        // Check process TTY
        char stat_path[MAX_PATH_LEN];
        snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);

        FILE *stat_file = fopen(stat_path, "r");
        if (!stat_file) continue;

        char stat_line[1024];
        if (fgets(stat_line, sizeof(stat_line), stat_file)) {
            // Parse TTY from stat file (7th field after comm field)
            char *token = strtok(stat_line, " ");
            for (int i = 0; i < 6 && token; i++) {
                token = strtok(NULL, " ");
            }

            if (token) {
                int proc_tty = atoi(token);
                int major = (proc_tty >> 8) & 0xff;
                int minor = proc_tty & 0xff;

                // TTY major number is 4, minor number matches our TTY
                if (major == 4 && minor == tty_number) {
                    // Check if this is a session leader
                    char sid_path[MAX_PATH_LEN];
                    snprintf(sid_path, sizeof(sid_path), "/proc/%ld/sessionid", pid);

                    FILE *sid_file = fopen(sid_path, "r");
                    if (sid_file) {
                        pid_t sid;
                        if (fscanf(sid_file, "%d", &sid) == 1 && sid == pid) {
                            session_leader = pid;
                            fclose(sid_file);
                            break;
                        }
                        fclose(sid_file);
                    }
                }
            }
        }
        fclose(stat_file);
    }

    closedir(proc_dir);
    return session_leader;
}

// Find VT control process (the process that has VT_PROCESS mode set and receives VT signals)
// This is different from session leader - it's the process that actually controls VT switching
pid_t find_vt_control_process(int tty_number) {
    // First check if VT is in process control mode
    int vt_mode, release_sig, acquire_sig;
    get_vt_mode_details(tty_number, &vt_mode, &release_sig, &acquire_sig);

    if (vt_mode != VT_PROCESS) {
        // VT is not in process control mode, no control process
        return -1;
    }

    // Now find the process that is likely receiving the VT signals
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        return -1;
    }

    struct dirent *entry;
    pid_t control_process = -1;
    int best_score = 0;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        // Check if directory name is a number (PID)
        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        // Check process TTY - must be associated with our target VT
        char stat_path[MAX_PATH_LEN];
        snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);

        FILE *stat_file = fopen(stat_path, "r");
        if (!stat_file) continue;

        char stat_line[1024];
        if (!fgets(stat_line, sizeof(stat_line), stat_file)) {
            fclose(stat_file);
            continue;
        }
        fclose(stat_file);

        // Parse TTY from stat file (7th field after comm field)
        char *token = strtok(stat_line, " ");
        for (int i = 0; i < 6 && token; i++) {
            token = strtok(NULL, " ");
        }

        if (!token) continue;

        int proc_tty = atoi(token);
        int major = (proc_tty >> 8) & 0xff;
        int minor = proc_tty & 0xff;

        // TTY major number is 4, minor number matches our TTY
        if (major != 4 || minor != tty_number) continue;

        // This process is associated with our VT, now score it based on:
        // 1. Has TTY device file open
        // 2. Is session leader
        // 3. Has signal handlers installed (harder to detect)
        int score = 0;

        // Check if process has TTY device access
        if (check_tty_device_access(pid, tty_number)) {
            score += 50;
        }

        // Check if this is a session leader or process group leader
        char sid_path[MAX_PATH_LEN];
        snprintf(sid_path, sizeof(sid_path), "/proc/%ld/stat", pid);
        FILE *stat_check = fopen(sid_path, "r");
        if (stat_check) {
            char line[1024];
            if (fgets(line, sizeof(line), stat_check)) {
                // Parse fields: pid, comm, state, ppid, pgrp, session, tty_nr, tpgid
                char *tokens[8];
                char *tok = strtok(line, " ");
                for (int i = 0; i < 8 && tok; i++) {
                    tokens[i] = tok;
                    tok = strtok(NULL, " ");
                }

                if (tok) {
                    pid_t pgrp = atoi(tokens[4]);
                    pid_t session = atoi(tokens[5]);

                    if (session == pid) {
                        score += 30; // Session leader
                    }
                    if (pgrp == pid) {
                        score += 20; // Process group leader
                    }
                }
            }
            fclose(stat_check);
        }

        // Check if process can access the control TTY (has appropriate permissions)
        char tty_path[MAX_PATH_LEN];
        snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);
        if (access(tty_path, R_OK | W_OK) == 0) {
            score += 10;
        }

        // Higher score wins
        if (score > best_score) {
            best_score = score;
            control_process = pid;
        }
    }

    closedir(proc_dir);
    return (best_score > 0) ? control_process : -1;
}

int get_vt_control_info(int tty_number, vt_control_info_t *info) {
    memset(info, 0, sizeof(vt_control_info_t));

    info->pid = find_vt_control_process(tty_number);
    if (info->pid == -1) {
        return -1;
    }

    // Get process information
    get_process_command(info->pid, info->command, sizeof(info->command));
    get_user_info(info->pid, info->user_name, sizeof(info->user_name), &info->uid);

    // Get additional details
    info->has_tty_access = check_tty_device_access(info->pid, tty_number);

    // Check if session leader
    char stat_path[MAX_PATH_LEN];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", info->pid);
    FILE *stat_file = fopen(stat_path, "r");
    if (stat_file) {
        char stat_line[1024];
        if (fgets(stat_line, sizeof(stat_line), stat_file)) {
            char *tokens[8];
            char *tok = strtok(stat_line, " ");
            for (int i = 0; i < 8 && tok; i++) {
                tokens[i] = tok;
                tok = strtok(NULL, " ");
            }

            if (tok) {
                pid_t session = atoi(tokens[5]);
                info->is_session_leader = (session == info->pid) ? 1 : 0;
            }
        }
        fclose(stat_file);
    }

    return 0;
}

// Print VT control process information
void print_vt_control_info(const vt_control_info_t *info, int tty_number) {
    if (info->pid == -1) {
        printf("VT Control Process: None found (VT may not be in VT_PROCESS mode)\n");
        return;
    }

    printf("=== VT %d Control Process ===\n", tty_number);
    printf("Control PID: %d\n", info->pid);
    printf("Command: %s\n", info->command);
    printf("User: %s (UID: %d)\n", info->user_name, info->uid);
    printf("Session Leader: %s\n", info->is_session_leader ? "Yes" : "No");
    printf("Has TTY Access: %s\n", info->has_tty_access ? "Yes" : "No");
    printf("Note: This process likely receives VT release/acquire signals\n");
    printf("\n");
}

// Print usage information
void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\n");
    printf("TTY Debug Tool - Monitor TTY changes, VT modes, and optionally control VT switching\n");
    printf("\n");
    printf("Options:\n");
    printf("  -h, --help              Show this help message\n");
    printf("  -t, --tty=N            Monitor specific TTY number (default: current TTY)\n");
    printf("  -c, --control          Enable VT control mode (become VT control process)\n");
    printf("  -s, --silent           Silent mode - automatically allow all VT switches\n");
    printf("                         (only used with --control)\n");
    printf("  -i, --interactive      Interactive mode - ask user permission for VT switches\n");
    printf("                         (default when --control is used, conflicts with --silent)\n");
    printf("\n");
    printf("Modes:\n");
    printf("  Default (monitoring):   Monitor TTY changes and VT mode changes\n");
    printf("  Control mode (-c):      Become the VT control process and handle VT switching\n");
    printf("  Silent control (-c -s): Allow all VT switches automatically\n");
    printf("  Interactive (-c -i):    Ask user permission for each VT switch (default)\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                     # Monitor current TTY\n", program_name);
    printf("  %s -t 2               # Monitor TTY 2\n", program_name);
    printf("  %s -c                 # Control current TTY with interactive prompts\n", program_name);
    printf("  %s -c -s              # Control current TTY, allow all switches\n", program_name);
    printf("  %s -c -t 3            # Control TTY 3 with interactive prompts\n", program_name);
    printf("  %s -c -s -t 1         # Control TTY 1, allow all switches\n", program_name);
    printf("\n");
    printf("Note: VT control mode requires running on a virtual terminal (tty1, tty2, etc.)\n");
}

// Get current TTY number
int get_current_tty_number(void) {
    char *tty_name = ttyname(STDIN_FILENO);
    if (!tty_name) {
        return -1;
    }

    // Parse TTY name like "/dev/tty2" -> 2
    if (strncmp(tty_name, "/dev/tty", 8) == 0) {
        char *tty_num_str = tty_name + 8;
        char *endptr;
        long tty_num = strtol(tty_num_str, &endptr, 10);
        if (*endptr == '\0' && tty_num > 0 && tty_num <= 63) {
            return (int)tty_num;
        }
    }

    return -1;
}

// Ask user permission for VT switch
int ask_user_permission(int target_vt) {
    char response[10];
    char time_str[64];
    get_current_time(time_str, sizeof(time_str));

    printf("\n[%s] VT SWITCH REQUEST:\n", time_str);
    printf("System wants to switch to VT %d\n", target_vt);
    printf("Allow this switch? [y/N/a/d]: ");
    printf("  y = Yes, allow this switch\n");
    printf("  N = No, deny this switch (default)\n");
    printf("  a = Always allow (switch to silent mode)\n");
    printf("  d = Deny and disable control mode\n");
    printf("Choice: ");
    fflush(stdout);

    if (fgets(response, sizeof(response), stdin) == NULL) {
        printf("Failed to read input, denying switch\n");
        return 0;
    }

    // Remove newline
    response[strcspn(response, "\n")] = '\0';

    switch (response[0]) {
        case 'y':
        case 'Y':
            printf("Allowing VT switch to %d\n", target_vt);
            return 1;

        case 'a':
        case 'A':
            printf("Switching to silent mode - will allow all future switches\n");
            vt_control_config.silent_allow = 1;
            vt_control_config.interactive_prompt = 0;
            return 1;

        case 'd':
        case 'D':
            printf("Disabling VT control mode and allowing switch\n");
            cleanup_vt_control_mode();
            return 1;

        case 'n':
        case 'N':
        case '\0':  // Empty input
        default:
            printf("Denying VT switch to %d\n", target_vt);
            return 0;
    }
}

// VT control signal handler
void vt_control_signal_handler(int sig) {
    char time_str[64];
    get_current_time(time_str, sizeof(time_str));

    if (sig == SIGUSR1) {  // VT release signal
        printf("\n[%s] VT Release signal received (SIGUSR1)\n", time_str);

        // Get current VT to determine target
        int current_vt = get_active_tty_from_sysfs();
        if (current_vt == -1) {
            current_vt = vt_control_config.target_tty;
        }

        printf("Request to release VT %d for switching\n", current_vt);

        int allow_switch = 1;

        if (vt_control_config.silent_allow) {
            printf("Silent mode: Automatically allowing VT switch\n");
        } else if (vt_control_config.interactive_prompt) {
            // We can't safely do interactive prompts in signal handler
            // So we'll just allow it and log
            printf("Interactive mode: Allowing switch (interactive prompts not safe in signal handler)\n");
            printf("Note: Use SIGUSR2 handler for better interactive experience\n");
        }

        if (allow_switch) {
            printf("Acknowledging VT release\n");
            if (vt_control_fd != -1) {
                ioctl(vt_control_fd, VT_RELDISP, 1);  // Allow release
            }
        } else {
            printf("Denying VT release\n");
            if (vt_control_fd != -1) {
                ioctl(vt_control_fd, VT_RELDISP, 0);  // Deny release
            }
        }

    } else if (sig == SIGUSR2) {  // VT acquire signal
        printf("\n[%s] VT Acquire signal received (SIGUSR2)\n", time_str);
        printf("VT has been switched back to us\n");
        printf("Acknowledging VT acquisition\n");

        if (vt_control_fd != -1) {
            ioctl(vt_control_fd, VT_RELDISP, VT_ACKACQ);  // Acknowledge acquire
        }

    } else if (sig == SIGINT || sig == SIGTERM) {
        printf("\n[%s] Received termination signal %d\n", time_str, sig);
        running = 0;
    }
}

// Setup VT control mode
int setup_vt_control_mode(int tty_number) {
    char tty_path[MAX_PATH_LEN];
    snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);

    printf("Setting up VT control mode for TTY %d\n", tty_number);

    // Open TTY device
    vt_control_fd = open(tty_path, O_RDWR | O_NOCTTY);
    if (vt_control_fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", tty_path, strerror(errno));
        return -1;
    }

    // Get current VT mode
    if (ioctl(vt_control_fd, VT_GETMODE, &original_vt_mode) == -1) {
        fprintf(stderr, "Failed to get current VT mode: %s\n", strerror(errno));
        close(vt_control_fd);
        vt_control_fd = -1;
        return -1;
    }

    printf("Original VT mode: %s\n", get_vt_mode_string(original_vt_mode.mode));

    // Set up signal handlers
    signal(SIGUSR1, vt_control_signal_handler);
    signal(SIGUSR2, vt_control_signal_handler);

    // Set VT_PROCESS mode
    struct vt_mode new_mode = {
        .mode = VT_PROCESS,
        .waitv = 0,
        .relsig = SIGUSR1,
        .acqsig = SIGUSR2,
        .frsig = 0
    };

    if (ioctl(vt_control_fd, VT_SETMODE, &new_mode) == -1) {
        fprintf(stderr, "Failed to set VT_PROCESS mode: %s\n", strerror(errno));
        close(vt_control_fd);
        vt_control_fd = -1;
        return -1;
    }

    in_vt_control_mode = 1;
    printf("VT control mode enabled successfully!\n");
    printf("This process (PID %d) is now the VT control process for TTY %d\n",
           getpid(), tty_number);
    printf("VT signals: Release=%d, Acquire=%d\n", SIGUSR1, SIGUSR2);

    if (vt_control_config.silent_allow) {
        printf("Running in SILENT mode - all VT switches will be allowed automatically\n");
    } else {
        printf("Running in INTERACTIVE mode - VT switches will be logged\n");
        printf("Note: Interactive prompts in signal handlers are limited\n");
    }

    return 0;
}

// Cleanup VT control mode
void cleanup_vt_control_mode(void) {
    if (!in_vt_control_mode || vt_control_fd == -1) {
        return;
    }

    printf("\nCleaning up VT control mode...\n");

    // Restore original VT mode
    if (ioctl(vt_control_fd, VT_SETMODE, &original_vt_mode) == -1) {
        fprintf(stderr, "Warning: Failed to restore original VT mode: %s\n", strerror(errno));
    } else {
        printf("Original VT mode restored: %s\n", get_vt_mode_string(original_vt_mode.mode));
    }

    // Restore default signal handlers
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);

    close(vt_control_fd);
    vt_control_fd = -1;
    in_vt_control_mode = 0;

    printf("VT control mode cleanup completed\n");
}

// Collect information about a TTY
void collect_tty_info(int tty_number, tty_info_t *info) {
    memset(info, 0, sizeof(tty_info_t));
    info->tty_number = tty_number;
    info->session_leader = -1;
    info->uid = (uid_t)-1;

    // Get VT mode details
    get_vt_mode_details(tty_number, &info->vt_mode, &info->release_signal, &info->acquire_signal);

    // Find session leader
    info->session_leader = find_session_leader(tty_number);

    if (info->session_leader != -1) {
        // Get user information
        get_user_info(info->session_leader, info->user_name, sizeof(info->user_name), &info->uid);

        // Get command information
        get_process_command(info->session_leader, info->command, sizeof(info->command));
    } else {
        strncpy(info->user_name, "none", sizeof(info->user_name) - 1);
        strncpy(info->command, "none", sizeof(info->command) - 1);
    }

    // Get VT control process information
    get_vt_control_info(tty_number, &info->vt_control);
}

// Print TTY information
void print_tty_info(const tty_info_t *info) {
    printf("=== TTY %d Information ===\n", info->tty_number);

    if (info->vt_mode != -1) {
        printf("VT Mode: %s\n", get_vt_mode_string(info->vt_mode));
        if (info->vt_mode == VT_PROCESS) {
            printf("Release Signal: %d\n", info->release_signal);
            printf("Acquire Signal: %d\n", info->acquire_signal);
        }
    } else {
        printf("VT Mode: Unable to get mode\n");
    }

    if (info->session_leader != -1) {
        printf("Session Leader PID: %d\n", info->session_leader);
        printf("User: %s (UID: %d)\n", info->user_name, info->uid);
        printf("Command: %s\n", info->command);
    } else {
        printf("Session Leader: None found\n");
        printf("User: %s\n", info->user_name);
        printf("Command: %s\n", info->command);
    }

    // Print VT control process information
    if (info->vt_mode == VT_PROCESS && info->vt_control.pid != -1) {
        printf("\n--- VT Control Process ---\n");
        printf("Control PID: %d\n", info->vt_control.pid);
        printf("Control Command: %s\n", info->vt_control.command);
        printf("Control User: %s (UID: %d)\n", info->vt_control.user_name, info->vt_control.uid);
        printf("Is Session Leader: %s\n", info->vt_control.is_session_leader ? "Yes" : "No");
        printf("Has TTY Access: %s\n", info->vt_control.has_tty_access ? "Yes" : "No");
        printf("Note: This process likely receives VT signals (%d, %d)\n",
               info->release_signal, info->acquire_signal);
    } else if (info->vt_mode == VT_PROCESS) {
        printf("\n--- VT Control Process ---\n");
        printf("Control Process: None found (unexpected for VT_PROCESS mode)\n");
    }

    printf("\n");
}

// Print monitored processes
void print_monitored_processes(void) {
    printf("=== Monitored Session Processes ===\n");
    printf("Total processes: %d\n", num_monitored_processes);
    for (int i = 0; i < num_monitored_processes; i++) {
        printf("  PID %d: %s (User: %s)\n",
               monitored_processes[i].pid,
               monitored_processes[i].command,
               monitored_processes[i].user_name);
    }
    printf("\n");
}

// Update monitored processes for current TTY
void update_monitored_processes(int tty_number) {
    num_monitored_processes = find_tty_session_processes(tty_number, monitored_processes, MAX_PROCESSES);
    if (num_monitored_processes > 0) {
        printf("Now monitoring %d processes on TTY %d for VT signals (%d, %d)\n",
               num_monitored_processes, tty_number,
               current_release_signal, current_acquire_signal);
        print_monitored_processes();
    }
}

// Check for signal activity in monitored processes
void check_signal_activity(void) {
    char time_str[64];

    for (int i = 0; i < num_monitored_processes; i++) {
        if (!monitored_processes[i].monitoring) continue;

        // Check if process still exists
        if (kill(monitored_processes[i].pid, 0) == -1) {
            monitored_processes[i].monitoring = 0;
            continue;
        }

        // Check for signal changes
        if (check_process_signal_change(&monitored_processes[i])) {
            get_current_time(time_str, sizeof(time_str));
            printf("[%s] Signal activity detected in process:\n", time_str);
            printf("  PID: %d\n", monitored_processes[i].pid);
            printf("  Command: %s\n", monitored_processes[i].command);
            printf("  User: %s\n", monitored_processes[i].user_name);
            printf("  Possible VT signals: Release(%d) or Acquire(%d)\n",
                   current_release_signal, current_acquire_signal);
            printf("  ---\n");
        }
    }
}

// Compare two tty_info_t structures for VT mode changes
int compare_vt_mode_info(const tty_info_t *old_info, const tty_info_t *new_info) {
    if (old_info->tty_number != new_info->tty_number) {
        return 1; // Different TTY, always report
    }

    if (old_info->vt_mode != new_info->vt_mode ||
        old_info->release_signal != new_info->release_signal ||
        old_info->acquire_signal != new_info->acquire_signal) {
        return 1; // VT mode changed
    }

    return 0; // No change
}

// Print VT mode change information with suspect analysis
void print_vt_mode_change(const tty_info_t *old_info, const tty_info_t *new_info) {
    char time_str[64];
    get_current_time(time_str, sizeof(time_str));

    printf("[%s] VT Mode Change Detected on TTY %d:\n", time_str, new_info->tty_number);

    if (old_info->vt_mode != new_info->vt_mode) {
        printf("  Mode: %s -> %s\n",
               get_vt_mode_string(old_info->vt_mode),
               get_vt_mode_string(new_info->vt_mode));
    }

    if (old_info->release_signal != new_info->release_signal) {
        printf("  Release Signal: %d -> %d\n",
               old_info->release_signal, new_info->release_signal);
    }

    if (old_info->acquire_signal != new_info->acquire_signal) {
        printf("  Acquire Signal: %d -> %d\n",
               old_info->acquire_signal, new_info->acquire_signal);
    }

    // Find and display suspects
    suspect_process_t suspects[MAX_SUSPECTS];
    int suspect_count = find_vt_mode_suspects(new_info->tty_number, suspects, MAX_SUSPECTS);
    print_vt_mode_suspects(suspects, suspect_count);

    printf("  ---\n");
}

int main(int argc, char *argv[]) {
    printf("TTY Debug Tool - Enhanced Version with VT Control Process Detection\n");
    printf("===================================================================\n\n");

    // Parse command line arguments
    int show_help = 0;

    // Initialize config with defaults
    vt_control_config.target_tty = -1;  // Will be set to current TTY
    vt_control_config.enabled = 0;
    vt_control_config.silent_allow = 0;
    vt_control_config.interactive_prompt = 1;  // Default for control mode

    // Simple argument parsing (getopt would be better but keeping dependencies minimal)
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            show_help = 1;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--control") == 0) {
            vt_control_config.enabled = 1;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--silent") == 0) {
            vt_control_config.silent_allow = 1;
            vt_control_config.interactive_prompt = 0;
        } else if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interactive") == 0) {
            vt_control_config.interactive_prompt = 1;
            vt_control_config.silent_allow = 0;
        } else if (strncmp(argv[i], "-t", 2) == 0 || strncmp(argv[i], "--tty", 5) == 0) {
            char *tty_str = NULL;
            if (strncmp(argv[i], "-t", 2) == 0) {
                if (strlen(argv[i]) > 2) {
                    tty_str = argv[i] + 2;  // -t2
                } else if (i + 1 < argc) {
                    tty_str = argv[++i];    // -t 2
                }
            } else if (strncmp(argv[i], "--tty=", 6) == 0) {
                tty_str = argv[i] + 6;      // --tty=2
            } else if (i + 1 < argc) {
                tty_str = argv[++i];        // --tty 2
            }

            if (tty_str) {
                char *endptr;
                long tty_num = strtol(tty_str, &endptr, 10);
                if (*endptr == '\0' && tty_num > 0 && tty_num <= 63) {
                    vt_control_config.target_tty = (int)tty_num;
                } else {
                    fprintf(stderr, "Error: Invalid TTY number '%s'. Must be 1-63.\n", tty_str);
                    return 1;
                }
            } else {
                fprintf(stderr, "Error: TTY number required for %s option\n", argv[i]);
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            fprintf(stderr, "Use --help for usage information.\n");
            return 1;
        }
    }

    if (show_help) {
        print_usage(argv[0]);
        return 0;
    }

    // Validate arguments
    if (vt_control_config.silent_allow && vt_control_config.interactive_prompt) {
        fprintf(stderr, "Error: --silent and --interactive options are mutually exclusive\n");
        return 1;
    }

    if (vt_control_config.silent_allow && !vt_control_config.enabled) {
        fprintf(stderr, "Error: --silent can only be used with --control\n");
        return 1;
    }

    // Determine target TTY
    if (vt_control_config.target_tty == -1) {
        vt_control_config.target_tty = get_current_tty_number();
        if (vt_control_config.target_tty == -1) {
            if (vt_control_config.enabled) {
                fprintf(stderr, "Error: Could not determine current TTY and no TTY specified.\n");
                fprintf(stderr, "VT control mode requires running on a virtual terminal (tty1, tty2, etc.)\n");
                fprintf(stderr, "Use -t option to specify target TTY.\n");
                return 1;
            } else {
                // For monitoring mode, try to get from sysfs
                vt_control_config.target_tty = get_active_tty_from_sysfs();
                if (vt_control_config.target_tty == -1) {
                    fprintf(stderr, "Error: Could not determine target TTY\n");
                    return 1;
                }
            }
        }
    }

    printf("Target TTY: %d\n", vt_control_config.target_tty);

    if (vt_control_config.enabled) {
        printf("Mode: VT Control\n");
        if (vt_control_config.silent_allow) {
            printf("VT Switch Policy: Silent (allow all)\n");
        } else {
            printf("VT Switch Policy: Interactive (log all)\n");
        }
        printf("\n");

        // Setup VT control mode
        if (setup_vt_control_mode(vt_control_config.target_tty) == -1) {
            return 1;
        }
    } else {
        printf("Mode: Monitoring\n\n");
    }

    // Setup signal handlers
    signal(SIGINT, monitoring_signal_handler);
    signal(SIGTERM, monitoring_signal_handler);

    // Check if sysfs files exist
    if (access(SYSFS_TTY0_ACTIVE, R_OK) != 0) {
        fprintf(stderr, "Error: Cannot access %s\n", SYSFS_TTY0_ACTIVE);
        fprintf(stderr, "This system may not support sysfs TTY monitoring.\n");
        return 1;
    }

    // Get initial TTY state
    int current_tty;
    if (vt_control_config.enabled) {
        // In control mode, use the target TTY
        current_tty = vt_control_config.target_tty;
    } else {
        // In monitoring mode, get active TTY
        current_tty = get_active_tty_from_sysfs();
        if (current_tty == -1) {
            fprintf(stderr, "Failed to get initial TTY state\n");
            return 1;
        }
    }

    printf("Monitoring TTY: %d\n", current_tty);

    // Collect and display initial TTY information
    tty_info_t info, previous_info;
    collect_tty_info(current_tty, &info);
    print_tty_info(&info);

    // Save initial state for comparison
    previous_info = info;

    // Update current VT signals
    current_release_signal = info.release_signal;
    current_acquire_signal = info.acquire_signal;

    // Initialize process monitoring
    update_monitored_processes(current_tty);

    // Open sysfs file for polling
    int sysfs_fd = open(SYSFS_TTY0_ACTIVE, O_RDONLY);
    if (sysfs_fd == -1) {
        perror("Failed to open sysfs file for polling");
        return 1;
    }

    printf("Monitoring TTY changes, VT mode changes, and VT signal activity...\n");
    printf("Will attempt to identify processes that change VT mode.\n");
    printf("VT mode will be checked every %d seconds.\n", VT_MODE_CHECK_INTERVAL);
    printf("Process signals will be checked every %d seconds.\n", PROCESS_CHECK_INTERVAL);
    printf("Press Ctrl+C to stop.\n\n");

    // Setup poll structure
    struct pollfd pfd;
    pfd.fd = sysfs_fd;
    pfd.events = POLLPRI | POLLERR;  // POLLPRI for sysfs notify events

    // Initial read to clear any pending data
    char buffer[32];
    lseek(sysfs_fd, 0, SEEK_SET);
    read(sysfs_fd, buffer, sizeof(buffer));

    time_t last_vt_check = time(NULL);
    time_t last_process_check = time(NULL);

    while (running) {
        // Wait for changes with shorter timeout to enable signal monitoring
        int ret = poll(&pfd, 1, 500);  // 0.5 second timeout

        if (ret == -1) {
            if (errno == EINTR) {
                continue;  // Interrupted by signal
            }
            perror("poll failed");
            break;
        }

        // Check for TTY switch events
        if (ret > 0 && (pfd.revents & (POLLPRI | POLLERR))) {
            // TTY change detected, get new active TTY
            int new_tty = get_active_tty_from_sysfs();
            if (new_tty != -1 && new_tty != current_tty) {
                current_tty = new_tty;

                printf("[%ld] TTY switched to: %d\n", (long)time(NULL), current_tty);
                collect_tty_info(current_tty, &info);
                print_tty_info(&info);

                // Update VT signals
                current_release_signal = info.release_signal;
                current_acquire_signal = info.acquire_signal;

                // Update monitored processes for new TTY
                update_monitored_processes(current_tty);

                // Update previous info for new TTY
                previous_info = info;
            }

            // Reset file position for next poll
            lseek(sysfs_fd, 0, SEEK_SET);
            read(sysfs_fd, buffer, sizeof(buffer));
        }

        time_t current_time = time(NULL);

        // Periodically check VT mode changes on current TTY
        if (current_time - last_vt_check >= VT_MODE_CHECK_INTERVAL) {
            last_vt_check = current_time;

            // Collect current TTY info
            tty_info_t current_info;
            collect_tty_info(current_tty, &current_info);

            // Check if VT mode has changed
            if (compare_vt_mode_info(&previous_info, &current_info)) {
                if (previous_info.tty_number == current_info.tty_number) {
                    // Same TTY, VT mode changed - analyze suspects
                    print_vt_mode_change(&previous_info, &current_info);

                    // Update VT signals
                    current_release_signal = current_info.release_signal;
                    current_acquire_signal = current_info.acquire_signal;

                    // Update monitored processes
                    update_monitored_processes(current_tty);
                }
                // Update previous info
                previous_info = current_info;
            }
        }

        // Check for signal activity in monitored processes
        if (current_time - last_process_check >= PROCESS_CHECK_INTERVAL) {
            last_process_check = current_time;
            check_signal_activity();
        }
    }

    close(sysfs_fd);

    // Cleanup VT control mode if enabled
    if (vt_control_config.enabled) {
        cleanup_vt_control_mode();
    }

    printf("TTY monitoring stopped.\n");
    return 0;
}

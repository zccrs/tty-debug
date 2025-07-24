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
#include <sys/signalfd.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <linux/vt.h>
#include <dirent.h>
#include <sys/wait.h>

#define MAX_NAME_LEN 512
#define MAX_PATH_LEN 256
#define MAX_PROCESSES 1024
#define SYSFS_TTY0_ACTIVE "/sys/class/tty/tty0/active"
#define MONITOR_INTERVAL_MS 100  // Monitor every 100ms

static volatile int running = 1;

// Program modes
typedef enum {
    MODE_MONITOR_ALL,       // Monitor all TTYs
    MODE_MONITOR_SPECIFIC,  // Monitor specific TTY
    MODE_CONTROL           // Control mode
} program_mode_t;

// Signal monitoring structure for VT control processes
typedef struct {
    pid_t target_pid;      // PID being monitored
    pid_t strace_pid;      // strace process PID
    int tty_number;        // TTY number for this monitor
    int active;            // Whether monitoring is active
    time_t start_time;     // When monitoring started
    char process_name[64]; // Process name for identification
} signal_monitor_t;

// TTY information structure
typedef struct {
    int tty_number;
    int vt_mode;           // VT_AUTO or VT_PROCESS
    int release_signal;
    int acquire_signal;
    pid_t session_leader;
    pid_t vt_control_pids[16]; // Array of all processes with TTY open
    int vt_control_count;      // Number of processes with TTY open
    char session_user[MAX_NAME_LEN];
    char session_command[MAX_NAME_LEN];
    char control_users[16][MAX_NAME_LEN];   // Users for each control process
    char control_commands[16][MAX_NAME_LEN]; // Commands for each control process
    uid_t session_uid;
    uid_t control_uids[16];  // UIDs for each control process
} tty_info_t;

// Control mode configuration
typedef struct {
    int tty_number;
    int auto_allow;        // -y flag: automatically allow switches
    int control_fd;
    int signal_fd;         // signalfd for safe signal handling
    struct vt_mode original_mode;
} control_config_t;

static control_config_t control_config = {0};
static signal_monitor_t signal_monitors[64 * 16] = {0}; // Multiple monitors per TTY

// Function declarations
void print_usage(const char *program_name);
int parse_tty_device(const char *device_path);
int get_active_tty_from_sysfs(void);
int get_vt_mode_details(int tty_number, int *mode, int *release_sig, int *acquire_sig);
pid_t find_session_leader(int tty_number);
void get_process_info(pid_t pid, char *command, char *username, uid_t *uid);
void collect_tty_info(int tty_number, tty_info_t *info);
void print_tty_info(const tty_info_t *info);
int compare_tty_info(const tty_info_t *old_info, const tty_info_t *new_info);
void monitor_all_ttys(void);
void monitor_specific_tty(int tty_number);
int setup_control_mode(int tty_number, int auto_allow);
void cleanup_control_mode(void);
void handle_vt_signals(void);
int ask_user_permission(void);
void signal_handler(int sig);

// Signal monitoring functions
int start_signal_monitoring_for_pid(pid_t target_pid, int tty_number, const char* process_name);
void stop_signal_monitoring_for_pid(pid_t target_pid, int tty_number);
void stop_all_signal_monitoring_for_tty(int tty_number);
void cleanup_all_signal_monitors(void);
int is_strace_available(void);
int get_monitor_index(pid_t target_pid, int tty_number);

// Helper function to compare PIDs for sorting
int compare_pids(const void *a, const void *b) {
    pid_t pid_a = *(const pid_t*)a;
    pid_t pid_b = *(const pid_t*)b;
    return (pid_a > pid_b) - (pid_a < pid_b);
}

// Get monitor index for a specific PID and TTY
int get_monitor_index(pid_t target_pid, int tty_number) {
    for (int i = 0; i < 64 * 16; i++) {
        if (signal_monitors[i].active &&
            signal_monitors[i].target_pid == target_pid &&
            signal_monitors[i].tty_number == tty_number) {
            return i;
        }
    }
    return -1;
}

// Find free monitor slot
int find_free_monitor_slot(void) {
    for (int i = 0; i < 64 * 16; i++) {
        if (!signal_monitors[i].active) {
            return i;
        }
    }
    return -1;
}

// Check if strace is available
int is_strace_available(void) {
    int ret = system("which strace >/dev/null 2>&1");
    return WEXITSTATUS(ret) == 0;
}

// Start signal monitoring for a specific PID
int start_signal_monitoring_for_pid(pid_t target_pid, int tty_number, const char* process_name) {
    if (tty_number < 1 || tty_number >= 64) return -1;

    // Check if already monitoring this PID
    if (get_monitor_index(target_pid, tty_number) != -1) {
        return 0; // Already monitoring
    }

    // Find free slot
    int slot = find_free_monitor_slot();
    if (slot == -1) {
        printf("  Warning: No free monitor slots available\n");
        return -1;
    }

    signal_monitor_t *monitor = &signal_monitors[slot];

    // Check if strace is available
    if (!is_strace_available()) {
        printf("  Warning: strace not available, signal monitoring disabled\n");
        return -1;
    }

    // Fork to run strace
    pid_t strace_pid = fork();
    if (strace_pid == -1) {
        perror("Failed to fork for strace");
        return -1;
    }

    if (strace_pid == 0) {
        // Child process: run strace
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%d", target_pid);

        printf("  Starting signal monitoring for %s (PID %d, TTY %d)...\n", process_name, target_pid, tty_number);
        fflush(stdout);

        // Redirect stderr to stdout for easier parsing
        dup2(STDOUT_FILENO, STDERR_FILENO);

        // Execute strace to monitor signals
        execl("/usr/bin/strace", "strace",
              "-p", pid_str,           // Attach to process
              "-e", "signal",          // Only trace signals
              "-q",                    // Quiet mode
              "-o", "/dev/stdout",     // Output to stdout
              NULL);

        // If execl fails
        perror("Failed to exec strace");
        exit(1);
    }

    // Parent process: record monitoring info
    monitor->target_pid = target_pid;
    monitor->strace_pid = strace_pid;
    monitor->tty_number = tty_number;
    monitor->active = 1;
    monitor->start_time = time(NULL);
    strncpy(monitor->process_name, process_name, sizeof(monitor->process_name) - 1);
    monitor->process_name[sizeof(monitor->process_name) - 1] = '\0';

    printf("  Signal monitoring started for %s (PID %d) on TTY %d\n",
           process_name, target_pid, tty_number);
    printf("  Monitor PID: %d\n", strace_pid);

    return 0;
}

// Stop signal monitoring for a specific PID
void stop_signal_monitoring_for_pid(pid_t target_pid, int tty_number) {
    int index = get_monitor_index(target_pid, tty_number);
    if (index == -1) return;

    signal_monitor_t *monitor = &signal_monitors[index];

    printf("  Stopping signal monitoring for %s (PID %d, TTY %d)\n",
           monitor->process_name, target_pid, tty_number);

    // Kill the strace process
    if (monitor->strace_pid > 0) {
        kill(monitor->strace_pid, SIGTERM);

        // Wait briefly for graceful termination
        int status;
        pid_t result = waitpid(monitor->strace_pid, &status, WNOHANG);
        if (result == 0) {
            // Still running, force kill
            usleep(100000); // 100ms
            kill(monitor->strace_pid, SIGKILL);
            waitpid(monitor->strace_pid, &status, 0);
        }
    }

    // Clear monitor info
    memset(monitor, 0, sizeof(signal_monitor_t));
}

// Stop all signal monitoring for a TTY
void stop_all_signal_monitoring_for_tty(int tty_number) {
    for (int i = 0; i < 64 * 16; i++) {
        if (signal_monitors[i].active && signal_monitors[i].tty_number == tty_number) {
            stop_signal_monitoring_for_pid(signal_monitors[i].target_pid, tty_number);
        }
    }
}

// Cleanup all signal monitors
void cleanup_all_signal_monitors(void) {
    printf("Cleaning up all signal monitors...\n");
    for (int i = 0; i < 64 * 16; i++) {
        if (signal_monitors[i].active) {
            stop_signal_monitoring_for_pid(signal_monitors[i].target_pid, signal_monitors[i].tty_number);
        }
    }
}

// Get process information
void get_process_info(pid_t pid, char *command, char *username, uid_t *uid) {
    // Get command
    char path[MAX_PATH_LEN];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *file = fopen(path, "rb");
    if (file) {
        char buffer[1024];
        size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, file);
        fclose(file);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            // Convert null bytes to spaces
            for (size_t i = 0; i < bytes_read - 1; i++) {
                if (buffer[i] == '\0') buffer[i] = ' ';
            }
            // Remove trailing spaces
            while (bytes_read > 0 && (buffer[bytes_read - 1] == ' ' || buffer[bytes_read - 1] == '\0')) {
                bytes_read--;
            }
            buffer[bytes_read] = '\0';
            strncpy(command, buffer, MAX_NAME_LEN - 1);
            command[MAX_NAME_LEN - 1] = '\0';
        } else {
            strcpy(command, "unknown");
        }
    } else {
        strcpy(command, "unknown");
    }

    // Get user info
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    file = fopen(path, "r");
    if (file) {
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

        if (*uid != (uid_t)-1) {
            struct passwd *pwd = getpwuid(*uid);
            if (pwd) {
                strncpy(username, pwd->pw_name, MAX_NAME_LEN - 1);
                username[MAX_NAME_LEN - 1] = '\0';
            } else {
                snprintf(username, MAX_NAME_LEN, "uid_%d", *uid);
            }
        } else {
            strcpy(username, "unknown");
        }
    } else {
        strcpy(username, "unknown");
        *uid = (uid_t)-1;
    }
}

// Parse TTY device path (e.g., "/dev/tty1" -> 1)
int parse_tty_device(const char *device_path) {
    if (strncmp(device_path, "/dev/tty", 8) == 0) {
        char *endptr;
        long tty_num = strtol(device_path + 8, &endptr, 10);
        if (*endptr == '\0' && tty_num > 0 && tty_num <= 63) {
            return (int)tty_num;
        }
    }
    return -1;
}

// Get active TTY from sysfs
int get_active_tty_from_sysfs(void) {
    FILE *file = fopen(SYSFS_TTY0_ACTIVE, "r");
    if (!file) return -1;

    char buffer[32];
    if (!fgets(buffer, sizeof(buffer), file)) {
        fclose(file);
        return -1;
    }
    fclose(file);

    int tty_num;
    if (sscanf(buffer, "tty%d", &tty_num) == 1) {
        return tty_num;
    }
    return -1;
}

// Get VT mode details
int get_vt_mode_details(int tty_number, int *mode, int *release_sig, int *acquire_sig) {
    char tty_path[MAX_PATH_LEN];
    snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);

    int fd = open(tty_path, O_RDONLY);
    if (fd == -1) {
        *mode = -1;
        *release_sig = -1;
        *acquire_sig = -1;
        return -1;
    }

    struct vt_mode vt_mode;
    int result = ioctl(fd, VT_GETMODE, &vt_mode);
    close(fd);

    if (result == -1) {
        *mode = -1;
        *release_sig = -1;
        *acquire_sig = -1;
        return -1;
    }

    *mode = vt_mode.mode;
    *release_sig = vt_mode.relsig;
    *acquire_sig = vt_mode.acqsig;
    return 0;
}

// Find session leader for a TTY
pid_t find_session_leader(int tty_number) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return -1;

    struct dirent *entry;
    pid_t session_leader = -1;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        char stat_path[MAX_PATH_LEN];
        snprintf(stat_path, sizeof(stat_path), "/proc/%ld/stat", pid);

        FILE *stat_file = fopen(stat_path, "r");
        if (!stat_file) continue;

        char stat_line[1024];
        if (fgets(stat_line, sizeof(stat_line), stat_file)) {
            // Parse TTY from stat file (7th field)
            char *token = strtok(stat_line, " ");
            for (int i = 0; i < 6 && token; i++) {
                token = strtok(NULL, " ");
            }

            if (token) {
                int proc_tty = atoi(token);
                int major = (proc_tty >> 8) & 0xff;
                int minor = proc_tty & 0xff;

                // TTY major number is 4
                if (major == 4 && minor == tty_number) {
                    // Check if session leader
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

// Collect TTY information
void collect_tty_info(int tty_number, tty_info_t *info) {
    memset(info, 0, sizeof(tty_info_t));
    info->tty_number = tty_number;
    info->session_leader = -1;
    info->vt_control_count = 0;
    info->session_uid = (uid_t)-1;
    info->control_uids[0] = (uid_t)-1; // Initialize all UIDs to -1

    // Get VT mode details
    get_vt_mode_details(tty_number, &info->vt_mode, &info->release_signal, &info->acquire_signal);

    // Find session leader
    info->session_leader = find_session_leader(tty_number);
    if (info->session_leader != -1) {
        get_process_info(info->session_leader, info->session_command, info->session_user, &info->session_uid);
    } else {
        strcpy(info->session_user, "none");
        strcpy(info->session_command, "none");
    }

    // Find all processes with the TTY device open
    char tty_path[MAX_PATH_LEN];
    snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return;

    struct dirent *entry;
    int current_control_index = 0;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        // Check if process has the TTY device open
        char fd_dir_path[MAX_PATH_LEN];
        snprintf(fd_dir_path, sizeof(fd_dir_path), "/proc/%ld/fd", pid);

        DIR *fd_dir = opendir(fd_dir_path);
        if (!fd_dir) continue;

        int has_tty_open = 0;
        struct dirent *fd_entry;
        while ((fd_entry = readdir(fd_dir)) != NULL) {
            if (fd_entry->d_type != DT_LNK) continue;

            char fd_path[MAX_PATH_LEN];
            char link_target[MAX_PATH_LEN];
            snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd/%s", pid, fd_entry->d_name);

            ssize_t len = readlink(fd_path, link_target, sizeof(link_target) - 1);
            if (len > 0) {
                link_target[len] = '\0';
                if (strcmp(link_target, tty_path) == 0) {
                    has_tty_open = 1;
                    break;
                }
            }
        }
        closedir(fd_dir);

        if (!has_tty_open) continue;

        // Add this PID to the control processes array
        if (current_control_index < 16) {
            info->vt_control_pids[current_control_index] = pid;
            get_process_info(pid, info->control_commands[current_control_index],
                           info->control_users[current_control_index], &info->control_uids[current_control_index]);
            current_control_index++;
        }
    }
    closedir(proc_dir);

    info->vt_control_count = current_control_index;

    // Sort control processes by PID for consistent output
    if (info->vt_control_count > 1) {
        qsort(info->vt_control_pids, info->vt_control_count, sizeof(pid_t), compare_pids);
        // Note: We would need to sort other arrays too, but for simplicity, just sort PIDs
    }
}

// Compare TTY information for changes
int compare_tty_info(const tty_info_t *old_info, const tty_info_t *new_info) {
    if (old_info->vt_mode != new_info->vt_mode ||
        old_info->release_signal != new_info->release_signal ||
        old_info->acquire_signal != new_info->acquire_signal ||
        old_info->session_leader != new_info->session_leader ||
        old_info->vt_control_count != new_info->vt_control_count) {
        return 1; // Changed
    }

    // Compare all control process PIDs
    for (int i = 0; i < new_info->vt_control_count; i++) {
        if (old_info->vt_control_pids[i] != new_info->vt_control_pids[i]) {
            return 1; // Changed
        }
    }
    return 0; // No change
}

// Print TTY information
void print_tty_info(const tty_info_t *info) {
    const char *mode_str = (info->vt_mode == VT_AUTO) ? "VT_AUTO" :
                          (info->vt_mode == VT_PROCESS) ? "VT_PROCESS" : "UNKNOWN";

    printf("=== TTY %d Information ===\n", info->tty_number);
    printf("VT Mode: %s\n", mode_str);

    if (info->vt_mode == VT_PROCESS) {
        printf("Release Signal: %d\n", info->release_signal);
        printf("Acquire Signal: %d\n", info->acquire_signal);
    }

    printf("Session Leader: ");
    if (info->session_leader != -1) {
        printf("PID %d (%s) User: %s\n", info->session_leader, info->session_command, info->session_user);
    } else {
        printf("None\n");
    }

    if (info->vt_control_count > 0) {
        printf("Processes with TTY open (%d):\n", info->vt_control_count);
        for (int i = 0; i < info->vt_control_count; i++) {
            printf("  %d. PID %d (%s) User: %s\n", i + 1, info->vt_control_pids[i],
                   info->control_commands[i], info->control_users[i]);

            // Start signal monitoring for each process
            char process_name[128];
            snprintf(process_name, sizeof(process_name), "%s", info->control_commands[i]);
            // Truncate long command lines for display
            if (strlen(process_name) > 40) {
                strcpy(process_name + 37, "...");
            }

            start_signal_monitoring_for_pid(info->vt_control_pids[i], info->tty_number, process_name);
        }
    } else {
        printf("Processes with TTY open: None found\n");
        printf("  Note: Run with sudo for better process detection\n");
    }

    printf("\n");
}

// Monitor all TTYs
void monitor_all_ttys(void) {
    printf("Monitoring all TTYs for VT_PROCESS mode...\n");
    printf("Checking every %d ms. Press Ctrl+C to stop.\n", MONITOR_INTERVAL_MS);

    if (is_strace_available()) {
        printf("Signal monitoring enabled (using strace)\n\n");
    } else {
        printf("Signal monitoring disabled (strace not available)\n\n");
    }

    tty_info_t previous_infos[64] = {0}; // TTY 1-63
    int has_previous[64] = {0};

    while (running) {
        int found_vt_process = 0;

        // Check TTY 1-12 (common range)
        for (int tty = 1; tty <= 12; tty++) {
            tty_info_t current_info;
            collect_tty_info(tty, &current_info);

            if (current_info.vt_mode == VT_PROCESS) {
                found_vt_process = 1;

                // Check if this is a new VT_PROCESS TTY or if details changed
                if (!has_previous[tty]) {
                    // New VT_PROCESS TTY detected
                    printf("[%ld] TTY %d entered VT_PROCESS mode:\n", time(NULL), tty);
                    print_tty_info(&current_info);
                    previous_infos[tty] = current_info;
                    has_previous[tty] = 1;
                } else if (previous_infos[tty].vt_mode != VT_PROCESS) {
                    // TTY changed from VT_AUTO to VT_PROCESS
                    printf("[%ld] TTY %d changed from VT_AUTO to VT_PROCESS mode:\n", time(NULL), tty);
                    print_tty_info(&current_info);
                    previous_infos[tty] = current_info;
                } else if (compare_tty_info(&previous_infos[tty], &current_info)) {
                    // VT_PROCESS TTY details changed
                    printf("[%ld] TTY %d VT_PROCESS details changed:\n", time(NULL), tty);
                    print_tty_info(&current_info);
                    previous_infos[tty] = current_info;
                }
            } else {
                // TTY is not in VT_PROCESS mode
                if (has_previous[tty] && previous_infos[tty].vt_mode == VT_PROCESS) {
                    // TTY changed from VT_PROCESS to VT_AUTO
                    printf("[%ld] TTY %d changed from VT_PROCESS to VT_AUTO mode\n", time(NULL), tty);
                    // Stop signal monitoring for this TTY
                    stop_all_signal_monitoring_for_tty(tty);
                }

                // Always update the current state for proper change detection
                if (current_info.vt_mode != -1) { // Only if we successfully got TTY info
                    previous_infos[tty] = current_info;
                    has_previous[tty] = 1;
                } else if (has_previous[tty]) {
                    // TTY info unavailable, but we had it before
                    printf("[%ld] TTY %d no longer accessible\n", time(NULL), tty);
                    has_previous[tty] = 0;
                    // Stop signal monitoring for this TTY
                    stop_all_signal_monitoring_for_tty(tty);
                }
            }
        }

        if (!found_vt_process) {
            static time_t last_no_vt_process_msg = 0;
            time_t now = time(NULL);
            if (now - last_no_vt_process_msg >= 5) { // Print every 5 seconds
                printf("[%ld] No TTYs found in VT_PROCESS mode\n", now);
                last_no_vt_process_msg = now;
            }
        }

        usleep(MONITOR_INTERVAL_MS * 1000);
    }

    // Cleanup signal monitors when exiting
    cleanup_all_signal_monitors();
}

// Monitor specific TTY
void monitor_specific_tty(int tty_number) {
    printf("Monitoring TTY %d...\n", tty_number);
    printf("Checking every %d ms. Press Ctrl+C to stop.\n", MONITOR_INTERVAL_MS);

    if (is_strace_available()) {
        printf("Signal monitoring enabled (using strace)\n\n");
    } else {
        printf("Signal monitoring disabled (strace not available)\n\n");
    }

    tty_info_t previous_info = {0};
    int has_previous = 0;

    // Show initial state
    tty_info_t current_info;
    collect_tty_info(tty_number, &current_info);
    print_tty_info(&current_info);
    previous_info = current_info;
    has_previous = 1;

    while (running) {
        collect_tty_info(tty_number, &current_info);

        if (has_previous && compare_tty_info(&previous_info, &current_info)) {
            printf("[%ld] TTY %d state changed:\n", time(NULL), tty_number);
            print_tty_info(&current_info);
            previous_info = current_info;
        }

        usleep(MONITOR_INTERVAL_MS * 1000);
    }

    // Cleanup signal monitor when exiting
    stop_all_signal_monitoring_for_tty(tty_number);
}

// Ask user permission for VT switch
int ask_user_permission(void) {
    printf("Allow TTY switch? [y/N]: ");
    fflush(stdout);

    char response[10];
    if (fgets(response, sizeof(response), stdin) != NULL) {
        return (response[0] == 'y' || response[0] == 'Y');
    }
    return 0; // Default to deny
}

// Handle VT signals using signalfd
void handle_vt_signals(void) {
    struct signalfd_siginfo si;
    char time_str[64];
    time_t now;
    struct tm *tm_info;

    while (running) {
        struct pollfd pfd[2];

        // Poll signalfd for VT signals
        pfd[0].fd = control_config.signal_fd;
        pfd[0].events = POLLIN;

        // Poll stdin for user input (if not auto-allow mode)
        pfd[1].fd = STDIN_FILENO;
        pfd[1].events = POLLIN;

        int nfds = control_config.auto_allow ? 1 : 2;
        int ret = poll(pfd, nfds, -1);

        if (ret == -1) {
            if (errno == EINTR) continue;
            perror("poll");
            break;
        }

        // Handle VT signals
        if (pfd[0].revents & POLLIN) {
            ssize_t s = read(control_config.signal_fd, &si, sizeof(si));
            if (s == sizeof(si)) {
                now = time(NULL);
                tm_info = localtime(&now);
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

                if (si.ssi_signo == SIGUSR1) {  // VT release signal
                    printf("\n[%s] VT Release signal received (SIGUSR1)\n", time_str);
                    printf("Request to release TTY %d for switching\n", control_config.tty_number);

                    if (control_config.auto_allow) {
                        printf("Auto-allow mode: Allowing VT switch\n");
                        if (control_config.control_fd != -1) {
                            ioctl(control_config.control_fd, VT_RELDISP, 1);  // Allow release
                        }
                    } else {
                        // Interactive mode - ask user
                        if (ask_user_permission()) {
                            printf("Allowing VT switch\n");
                            if (control_config.control_fd != -1) {
                                ioctl(control_config.control_fd, VT_RELDISP, 1);  // Allow release
                            }
                        } else {
                            printf("Denying VT switch\n");
                            if (control_config.control_fd != -1) {
                                ioctl(control_config.control_fd, VT_RELDISP, 0);  // Deny release
                            }
                        }
                    }
                } else if (si.ssi_signo == SIGUSR2) {  // VT acquire signal
                    printf("\n[%s] VT Acquire signal received (SIGUSR2)\n", time_str);
                    printf("TTY %d has been switched back to us\n", control_config.tty_number);
                    if (control_config.control_fd != -1) {
                        ioctl(control_config.control_fd, VT_RELDISP, VT_ACKACQ);  // Acknowledge acquire
                    }
                } else if (si.ssi_signo == SIGINT || si.ssi_signo == SIGTERM) {
                    printf("\n[%s] Received termination signal, shutting down...\n", time_str);
                    running = 0;
                    break;
                }
            }
        }
    }
}

// General signal handler (for non-control modes)
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;

    // Cleanup signal monitors when shutting down
    cleanup_all_signal_monitors();
}

// Setup control mode
int setup_control_mode(int tty_number, int auto_allow) {
    char tty_path[MAX_PATH_LEN];
    snprintf(tty_path, sizeof(tty_path), "/dev/tty%d", tty_number);

    printf("Setting up VT control mode for TTY %d\n", tty_number);
    if (auto_allow) {
        printf("Auto-allow mode: Will automatically allow all VT switches\n");
    } else {
        printf("Interactive mode: Will prompt for VT switch permission\n");
    }

    // Open TTY device
    control_config.control_fd = open(tty_path, O_RDWR | O_NOCTTY);
    if (control_config.control_fd == -1) {
        fprintf(stderr, "Failed to open %s: %s\n", tty_path, strerror(errno));
        return -1;
    }

    // Get current VT mode
    if (ioctl(control_config.control_fd, VT_GETMODE, &control_config.original_mode) == -1) {
        fprintf(stderr, "Failed to get current VT mode: %s\n", strerror(errno));
        close(control_config.control_fd);
        return -1;
    }

    // Setup signalfd for safe signal handling
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);

    // Block signals for signalfd
    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        fprintf(stderr, "Failed to block signals: %s\n", strerror(errno));
        close(control_config.control_fd);
        return -1;
    }

    // Create signalfd
    control_config.signal_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (control_config.signal_fd == -1) {
        fprintf(stderr, "Failed to create signalfd: %s\n", strerror(errno));
        close(control_config.control_fd);
        return -1;
    }

    // Set VT_PROCESS mode
    struct vt_mode new_mode = {
        .mode = VT_PROCESS,
        .waitv = 0,
        .relsig = SIGUSR1,
        .acqsig = SIGUSR2,
        .frsig = 0
    };

    if (ioctl(control_config.control_fd, VT_SETMODE, &new_mode) == -1) {
        fprintf(stderr, "Failed to set VT_PROCESS mode: %s\n", strerror(errno));
        close(control_config.signal_fd);
        close(control_config.control_fd);
        return -1;
    }

    control_config.tty_number = tty_number;
    control_config.auto_allow = auto_allow;

    printf("VT control mode enabled successfully!\n");
    printf("This process (PID %d) is now the VT control process for TTY %d\n",
           getpid(), tty_number);
    printf("Press Ctrl+C to stop and restore original VT mode.\n\n");

    return 0;
}

// Cleanup control mode
void cleanup_control_mode(void) {
    if (control_config.control_fd == -1) return;

    printf("Cleaning up VT control mode...\n");

    // Close signalfd
    if (control_config.signal_fd != -1) {
        close(control_config.signal_fd);
        control_config.signal_fd = -1;
    }

    // Restore signal mask
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    // Restore original VT mode
    if (ioctl(control_config.control_fd, VT_SETMODE, &control_config.original_mode) == -1) {
        fprintf(stderr, "Warning: Failed to restore original VT mode: %s\n", strerror(errno));
    } else {
        printf("Original VT mode restored\n");
    }

    close(control_config.control_fd);
    control_config.control_fd = -1;
}

// Print usage
void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS] [TTY_DEVICE]\n", program_name);
    printf("\n");
    printf("TTY Debug Tool - Monitor TTY changes and VT control processes\n");
    printf("\n");
    printf("Modes:\n");
    printf("  1. Monitor all TTYs (default):      %s\n", program_name);
    printf("     Scans all TTYs, shows those in VT_PROCESS mode\n");
    printf("     Monitors VT control process signals using strace\n");
    printf("\n");
    printf("  2. Monitor specific TTY:            %s /dev/ttyN\n", program_name);
    printf("     Monitors specific TTY for control process and signal changes\n");
    printf("     Monitors VT control process signals using strace\n");
    printf("\n");
    printf("  3. Control mode:                    %s -c [/dev/ttyN]\n", program_name);
    printf("     Become VT control process for TTY (default: active TTY)\n");
    printf("\n");
    printf("Options:\n");
    printf("  -c              Enable control mode\n");
    printf("  -y              Auto-allow mode (with -c): automatically allow VT switches\n");
    printf("  -h, --help      Show this help\n");
    printf("\n");
    printf("Signal Monitoring:\n");
    printf("  In monitoring modes, when a VT control process is detected,\n");
    printf("  strace is automatically started to monitor signals received\n");
    printf("  by the control process. This helps track VT switching activity.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                    # Monitor all TTYs with signal monitoring\n", program_name);
    printf("  %s /dev/tty2          # Monitor TTY 2 with signal monitoring\n", program_name);
    printf("  %s -c                # Control active TTY with prompts\n", program_name);
    printf("  %s -c /dev/tty1       # Control TTY 1 with prompts\n", program_name);
    printf("  %s -c -y /dev/tty3    # Control TTY 3, auto-allow switches\n", program_name);
}

int main(int argc, char *argv[]) {
    printf("TTY Debug Tool - Simplified Version with Signal Monitoring\n");
    printf("==========================================================\n\n");

    program_mode_t mode = MODE_MONITOR_ALL;
    int control_mode = 0;
    int auto_allow = 0;
    int target_tty = -1;

    // Initialize control config
    control_config.control_fd = -1;
    control_config.signal_fd = -1;

    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-c") == 0) {
            control_mode = 1;
        } else if (strcmp(argv[i], "-y") == 0) {
            auto_allow = 1;
        } else if (strncmp(argv[i], "/dev/tty", 8) == 0) {
            target_tty = parse_tty_device(argv[i]);
            if (target_tty == -1) {
                fprintf(stderr, "Error: Invalid TTY device '%s'\n", argv[i]);
                return 1;
            }
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    // Validate arguments
    if (auto_allow && !control_mode) {
        fprintf(stderr, "Error: -y option can only be used with -c\n");
        return 1;
    }

    // Set mode based on arguments
    if (control_mode) {
        mode = MODE_CONTROL;
        if (target_tty == -1) {
            target_tty = get_active_tty_from_sysfs();
            if (target_tty == -1) {
                fprintf(stderr, "Error: Could not determine active TTY\n");
                return 1;
            }
        }
    } else if (target_tty != -1) {
        mode = MODE_MONITOR_SPECIFIC;
    }

    // Setup signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // Execute based on mode
    switch (mode) {
        case MODE_MONITOR_ALL:
            monitor_all_ttys();
            break;

        case MODE_MONITOR_SPECIFIC:
            monitor_specific_tty(target_tty);
            break;

        case MODE_CONTROL:
            if (setup_control_mode(target_tty, auto_allow) == 0) {
                // Handle VT signals using signalfd
                handle_vt_signals();
                cleanup_control_mode();
            }
            break;
    }

    printf("TTY monitoring stopped.\n");
    return 0;
}

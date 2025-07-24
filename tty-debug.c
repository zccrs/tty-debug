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

// TTY information structure
typedef struct {
    int tty_number;
    int vt_mode;           // VT_AUTO or VT_PROCESS
    int release_signal;
    int acquire_signal;
    pid_t session_leader;
    pid_t vt_control_pid;
    char session_user[MAX_NAME_LEN];
    char session_command[MAX_NAME_LEN];
    char control_user[MAX_NAME_LEN];
    char control_command[MAX_NAME_LEN];
    uid_t session_uid;
    uid_t control_uid;
} tty_info_t;

// Control mode configuration
typedef struct {
    int tty_number;
    int auto_allow;        // -y flag: automatically allow switches
    int control_fd;
    struct vt_mode original_mode;
} control_config_t;

static control_config_t control_config = {0};

// Function declarations
void print_usage(const char *program_name);
int parse_tty_device(const char *device_path);
int get_active_tty_from_sysfs(void);
int get_vt_mode_details(int tty_number, int *mode, int *release_sig, int *acquire_sig);
pid_t find_session_leader(int tty_number);
pid_t find_vt_control_process(int tty_number);
void get_process_info(pid_t pid, char *command, char *username, uid_t *uid);
void collect_tty_info(int tty_number, tty_info_t *info);
void print_tty_info(const tty_info_t *info);
int compare_tty_info(const tty_info_t *old_info, const tty_info_t *new_info);
void monitor_all_ttys(void);
void monitor_specific_tty(int tty_number);
int setup_control_mode(int tty_number, int auto_allow);
void cleanup_control_mode(void);
void control_signal_handler(int sig);
void signal_handler(int sig);

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

// Find VT control process
pid_t find_vt_control_process(int tty_number) {
    int vt_mode, release_sig, acquire_sig;
    if (get_vt_mode_details(tty_number, &vt_mode, &release_sig, &acquire_sig) != 0) {
        return -1;
    }

    if (vt_mode != VT_PROCESS) {
        return -1; // Not in process control mode
    }

    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) return -1;

    struct dirent *entry;
    pid_t best_candidate = -1;
    int best_score = 0;

    while ((entry = readdir(proc_dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || pid <= 0) continue;

        // Check if process is associated with our TTY
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

        // Parse TTY from stat file
        char *token = strtok(stat_line, " ");
        for (int i = 0; i < 6 && token; i++) {
            token = strtok(NULL, " ");
        }

        if (!token) continue;

        int proc_tty = atoi(token);
        int major = (proc_tty >> 8) & 0xff;
        int minor = proc_tty & 0xff;

        if (major != 4 || minor != tty_number) continue;

        // Score this process as potential VT control process
        int score = 10; // Base score for TTY association

        // Check if session leader (higher score)
        char *session_token = strtok(NULL, " ");
        if (session_token && atoi(session_token) == pid) {
            score += 30;
        }

        // Check if process group leader
        char *pgrp_token = strtok(NULL, " ");
        if (pgrp_token && atoi(pgrp_token) == pid) {
            score += 20;
        }

        if (score > best_score) {
            best_score = score;
            best_candidate = pid;
        }
    }

    closedir(proc_dir);
    return (best_score > 0) ? best_candidate : -1;
}

// Collect TTY information
void collect_tty_info(int tty_number, tty_info_t *info) {
    memset(info, 0, sizeof(tty_info_t));
    info->tty_number = tty_number;
    info->session_leader = -1;
    info->vt_control_pid = -1;
    info->session_uid = (uid_t)-1;
    info->control_uid = (uid_t)-1;

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

    // Find VT control process
    info->vt_control_pid = find_vt_control_process(tty_number);
    if (info->vt_control_pid != -1) {
        get_process_info(info->vt_control_pid, info->control_command, info->control_user, &info->control_uid);
    } else {
        strcpy(info->control_user, "none");
        strcpy(info->control_command, "none");
    }
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

    if (info->vt_mode == VT_PROCESS) {
        printf("VT Control Process: ");
        if (info->vt_control_pid != -1) {
            printf("PID %d (%s) User: %s\n", info->vt_control_pid, info->control_command, info->control_user);
        } else {
            printf("None found\n");
        }
    }

    printf("\n");
}

// Compare TTY information for changes
int compare_tty_info(const tty_info_t *old_info, const tty_info_t *new_info) {
    if (old_info->vt_mode != new_info->vt_mode ||
        old_info->release_signal != new_info->release_signal ||
        old_info->acquire_signal != new_info->acquire_signal ||
        old_info->session_leader != new_info->session_leader ||
        old_info->vt_control_pid != new_info->vt_control_pid) {
        return 1; // Changed
    }
    return 0; // No change
}

// Monitor all TTYs
void monitor_all_ttys(void) {
    printf("Monitoring all TTYs for VT_PROCESS mode...\n");
    printf("Checking every %d ms. Press Ctrl+C to stop.\n\n", MONITOR_INTERVAL_MS);

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

                if (!has_previous[tty] || compare_tty_info(&previous_infos[tty], &current_info)) {
                    printf("[%ld] TTY %d in VT_PROCESS mode:\n", time(NULL), tty);
                    print_tty_info(&current_info);
                    previous_infos[tty] = current_info;
                    has_previous[tty] = 1;
                }
            } else if (has_previous[tty] && previous_infos[tty].vt_mode == VT_PROCESS) {
                printf("[%ld] TTY %d no longer in VT_PROCESS mode\n", time(NULL), tty);
                has_previous[tty] = 0;
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
}

// Monitor specific TTY
void monitor_specific_tty(int tty_number) {
    printf("Monitoring TTY %d...\n", tty_number);
    printf("Checking every %d ms. Press Ctrl+C to stop.\n\n", MONITOR_INTERVAL_MS);

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
}

// Control mode signal handler
void control_signal_handler(int sig) {
    char time_str[64];
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);

    if (sig == SIGUSR1) {  // VT release signal
        printf("\n[%s] VT Release signal received (SIGUSR1)\n", time_str);
        printf("Request to release TTY %d for switching\n", control_config.tty_number);

        if (control_config.auto_allow) {
            printf("Auto-allow mode: Allowing VT switch\n");
            if (control_config.control_fd != -1) {
                ioctl(control_config.control_fd, VT_RELDISP, 1);  // Allow release
            }
        } else {
            printf("Allow TTY switch? [y/N]: ");
            fflush(stdout);

            char response[10];
            if (fgets(response, sizeof(response), stdin) != NULL &&
                (response[0] == 'y' || response[0] == 'Y')) {
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
    } else if (sig == SIGUSR2) {  // VT acquire signal
        printf("\n[%s] VT Acquire signal received (SIGUSR2)\n", time_str);
        printf("TTY %d has been switched back to us\n", control_config.tty_number);
        if (control_config.control_fd != -1) {
            ioctl(control_config.control_fd, VT_RELDISP, VT_ACKACQ);  // Acknowledge acquire
        }
    }
}

// General signal handler
void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down...\n", sig);
    running = 0;
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

    // Set up signal handlers
    signal(SIGUSR1, control_signal_handler);
    signal(SIGUSR2, control_signal_handler);

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

    // Restore original VT mode
    if (ioctl(control_config.control_fd, VT_SETMODE, &control_config.original_mode) == -1) {
        fprintf(stderr, "Warning: Failed to restore original VT mode: %s\n", strerror(errno));
    } else {
        printf("Original VT mode restored\n");
    }

    // Restore default signal handlers
    signal(SIGUSR1, SIG_DFL);
    signal(SIGUSR2, SIG_DFL);

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
    printf("\n");
    printf("  2. Monitor specific TTY:            %s /dev/ttyN\n", program_name);
    printf("     Monitors specific TTY for control process and signal changes\n");
    printf("\n");
    printf("  3. Control mode:                    %s -c [/dev/ttyN]\n", program_name);
    printf("     Become VT control process for TTY (default: active TTY)\n");
    printf("\n");
    printf("Options:\n");
    printf("  -c              Enable control mode\n");
    printf("  -y              Auto-allow mode (with -c): automatically allow VT switches\n");
    printf("  -h, --help      Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s                    # Monitor all TTYs\n", program_name);
    printf("  %s /dev/tty2          # Monitor TTY 2\n", program_name);
    printf("  %s -c                # Control active TTY with prompts\n", program_name);
    printf("  %s -c /dev/tty1       # Control TTY 1 with prompts\n", program_name);
    printf("  %s -c -y /dev/tty3    # Control TTY 3, auto-allow switches\n", program_name);
}

int main(int argc, char *argv[]) {
    printf("TTY Debug Tool - Simplified Version\n");
    printf("===================================\n\n");

    program_mode_t mode = MODE_MONITOR_ALL;
    int control_mode = 0;
    int auto_allow = 0;
    int target_tty = -1;

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
                // Wait for signals in control mode
                while (running) {
                    pause(); // Wait for signals
                }
                cleanup_control_mode();
            }
            break;
    }

    printf("TTY monitoring stopped.\n");
    return 0;
}

# TTY Debug Tool

A simplified tool for monitoring TTY virtual terminal changes and VT-related processes, with comprehensive signal monitoring for all processes that have TTY devices open.

## Features

### 1. Monitor All TTYs (Default Mode)
When run without parameters, the tool scans all TTYs (1-12) and displays information about any TTY that is in `VT_PROCESS` mode:

```bash
./tty-debug
```

This mode:
- Scans TTY 1-12 every 100ms
- Shows session leader and all processes that have the TTY device open
- **Automatically starts signal monitoring** for ALL detected processes using `strace`
- Reports when TTYs enter or leave VT_PROCESS mode
- Prints a status message every 5 seconds if no VT_PROCESS TTYs are found

### 2. Monitor Specific TTY
Monitor a specific TTY device for control process and signal changes:

```bash
./tty-debug /dev/tty2
```

This mode:
- Shows initial TTY state (VT mode, session leader, all processes with TTY open)
- **Automatically starts signal monitoring** for ALL processes with TTY open using `strace`
- Monitors for changes every 100ms
- Reports any changes in VT mode, control processes, or session leader
- Works with both VT_AUTO and VT_PROCESS mode TTYs

### 3. Control Mode
Become the VT control process for a TTY and handle VT switching requests:

```bash
# Control active TTY with interactive prompts
./tty-debug -c

# Control specific TTY with interactive prompts
./tty-debug -c /dev/tty1

# Control TTY with automatic allow (no prompts)
./tty-debug -c -y /dev/tty3
```

Control mode features:
- Sets the target TTY to `VT_PROCESS` mode
- Becomes the VT control process for that TTY
- Receives VT release/acquire signals (SIGUSR1/SIGUSR2)
- Interactive mode: Prompts user for permission on VT switch requests
- Auto-allow mode (`-y`): Automatically allows all VT switches
- Restores original VT mode on exit

## Comprehensive Signal Monitoring

### Multi-Process Monitoring
Instead of trying to identify a single "VT control process", the tool monitors **all processes** that have the TTY device open:

- **systemd-logind**: The actual VT controller that manages VT switching
- **Display managers**: GDM, LightDM, SDDM processes
- **Session processes**: User session managers and applications
- **Other processes**: Any process that opens the TTY device

### Automatic Signal Tracking
For each detected process, the tool automatically:

1. **Starts individual `strace` processes** to monitor signals
2. **Tracks VT signals** like SIGUSR1 (release) and SIGUSR2 (acquire)
3. **Shows real-time signal activity** from all monitored processes
4. **Manages strace processes** automatically (start/stop/cleanup per process)

### Signal Monitoring Output
```bash
Processes with TTY open (2):
  1. PID 638 (/usr/lib/systemd/systemd-logind) User: root
  Signal monitoring started for /usr/lib/systemd/systemd-logind (PID 638) on TTY 2
  Monitor PID: 847856
  2. PID 816747 (/usr/lib/gdm-wayland-session /usr/bin/gnome-session) User: zccrs
  Signal monitoring started for /usr/lib/gdm-wayland-session /usr/bin... (PID 816747) on TTY 2
  Monitor PID: 847860
```

### Requirements
- `strace` must be installed and available in PATH
- Appropriate permissions to attach to target processes
- If `strace` is not available, monitoring continues without signal tracking

## Command Line Options

```
Usage: tty-debug [OPTIONS] [TTY_DEVICE]

Options:
  -c              Enable control mode
  -y              Auto-allow mode (with -c): automatically allow VT switches
  -h, --help      Show this help

TTY_DEVICE:
  /dev/ttyN       Specify TTY device (e.g., /dev/tty1, /dev/tty2)
                  For control mode: TTY to control (default: active TTY)
                  For monitor mode: TTY to monitor specifically

Signal Monitoring:
  In monitoring modes, strace is automatically started for ALL processes
  that have the TTY device open. This provides comprehensive visibility
  into VT-related signal activity across the entire system.
```

## Output Information

For each monitored TTY, the tool displays:

- **TTY Number**: The virtual terminal number
- **VT Mode**: Current mode (VT_AUTO or VT_PROCESS)
- **Release/Acquire Signals**: Signal numbers used for VT switching (VT_PROCESS mode only)
- **Session Leader**: Process ID, command, and user of the session leader
- **All Processes with TTY Open**: Complete list with PIDs, commands, and users
- **Signal Monitoring Status**: Individual strace monitor for each process

## Process Detection and Privileges

The tool detects all processes that have the TTY device file open by examining `/proc/PID/fd/` directories:

### Detection Method
1. **Scan all processes** in `/proc/`
2. **Check file descriptors** in `/proc/PID/fd/` for TTY device links
3. **Verify TTY device path** using `readlink()` on each file descriptor
4. **Collect process information** for all matching processes

### Privilege-Based Results

- **With root privileges (`sudo`)**:
  - Detects ALL processes with TTY open (systemd-logind, display managers, user processes)
  - Provides complete visibility into VT ecosystem
  - Example: 2+ processes detected for active TTY

- **With user privileges**:
  - Detects only user-accessible processes
  - May miss systemd-logind and other system processes
  - Example: 1 process detected (user's display manager session)

**Example Detection Results:**
```bash
# Normal user
Processes with TTY open (1):
  1. PID 816747 (/usr/lib/gdm-wayland-session /usr/bin/gnome-session) User: zccrs

# With sudo
Processes with TTY open (2):
  1. PID 638 (/usr/lib/systemd/systemd-logind) User: root
  2. PID 816747 (/usr/lib/gdm-wayland-session /usr/bin/gnome-session) User: zccrs
```

**Recommendation**: Run with `sudo` for complete process visibility and comprehensive signal monitoring.

## Use Cases

1. **System Monitoring**: Track all processes involved in VT management
2. **Desktop Environment Debugging**: Monitor VT-related processes and their interactions
3. **Comprehensive Signal Analysis**: See signal activity from all VT-related processes
4. **VT Switch Control**: Implement custom VT switching policies
5. **System Administration**: Understand complete TTY ecosystem
6. **Security Analysis**: Monitor which processes have access to TTY devices

## Example Output

```bash
TTY Debug Tool - Simplified Version with Signal Monitoring
==========================================================

Monitoring TTY 2...
Checking every 100 ms. Press Ctrl+C to stop.
Signal monitoring enabled (using strace)

=== TTY 2 Information ===
VT Mode: VT_PROCESS
Release Signal: 34
Acquire Signal: 35
Session Leader: None
Processes with TTY open (2):
  1. PID 638 (/usr/lib/systemd/systemd-logind) User: root
  Signal monitoring started for /usr/lib/systemd/systemd-logind (PID 638) on TTY 2
  Monitor PID: 847856
  2. PID 816747 (/usr/lib/gdm-wayland-session /usr/bin/gnome-session) User: zccrs
  Signal monitoring started for /usr/lib/gdm-wayland-session /usr/bin... (PID 816747) on TTY 2
  Monitor PID: 847860
```

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Requirements

- Linux system with virtual terminal support
- Access to `/proc` filesystem
- Access to `/sys/class/tty/tty0/active` for active TTY detection
- Appropriate permissions to access TTY devices for control mode
- **`strace`** for signal monitoring (optional but recommended)
- **Root privileges recommended** for complete process detection

## Technical Details

- Monitoring interval: 100ms
- Supported TTY range: 1-63 (scans 1-12 in monitor-all mode)
- VT signals: SIGUSR1 (release), SIGUSR2 (acquire)
- Process detection: File descriptor analysis via `/proc/PID/fd/`
- Signal monitoring: Individual `strace -e signal` per detected process
- Graceful shutdown: Automatic cleanup of all strace processes with SIGTERM/SIGKILL

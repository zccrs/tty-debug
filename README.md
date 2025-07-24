# TTY Debug Tool

A simplified tool for monitoring TTY virtual terminal changes and VT control processes, with automatic signal monitoring capabilities.

## Features

### 1. Monitor All TTYs (Default Mode)
When run without parameters, the tool scans all TTYs (1-12) and displays information about any TTY that is in `VT_PROCESS` mode:

```bash
./tty-debug
```

This mode:
- Scans TTY 1-12 every 100ms
- Shows session leader and VT control process information for TTYs in VT_PROCESS mode
- **Automatically starts signal monitoring** for detected VT control processes using `strace`
- Reports when TTYs enter or leave VT_PROCESS mode
- Prints a status message every 5 seconds if no VT_PROCESS TTYs are found

### 2. Monitor Specific TTY
Monitor a specific TTY device for control process and signal changes:

```bash
./tty-debug /dev/tty2
```

This mode:
- Shows initial TTY state (VT mode, session leader, VT control process)
- **Automatically starts signal monitoring** for VT control processes using `strace`
- Monitors for changes every 100ms
- Reports any changes in VT mode, control process, or session leader
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

## Signal Monitoring Feature

### Automatic Signal Tracking
When a VT control process is detected in monitoring modes, the tool automatically:

1. **Starts `strace`** to monitor signals received by the VT control process
2. **Tracks VT signals** like SIGUSR1 (release) and SIGUSR2 (acquire)
3. **Shows real-time signal activity** to help debug VT switching behavior
4. **Manages strace processes** automatically (start/stop/cleanup)

### Signal Monitoring Output
```bash
Signal monitoring started for TTY 2 VT control process (PID 1234)
Monitor PID: 5678
Starting signal monitoring for PID 1234 (TTY 2)...
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
  In monitoring modes, when a VT control process is detected,
  strace is automatically started to monitor signals received
  by the control process. This helps track VT switching activity.
```

## Output Information

For each monitored TTY, the tool displays:

- **TTY Number**: The virtual terminal number
- **VT Mode**: Current mode (VT_AUTO or VT_PROCESS)
- **Release/Acquire Signals**: Signal numbers used for VT switching (VT_PROCESS mode only)
- **Session Leader**: Process ID, command, and user of the session leader
- **VT Control Process**: Process ID, command, and user of the VT control process (VT_PROCESS mode only)
- **Signal Monitoring Status**: Whether signal monitoring is active for the control process

## VT Control Process Detection

The tool identifies VT control processes using several criteria:
- Must be associated with the target TTY
- Higher score for session leaders and process group leaders
- Must exist when TTY is in VT_PROCESS mode

## Use Cases

1. **System Monitoring**: Track which TTYs have active VT control processes
2. **Desktop Environment Debugging**: Monitor how desktop environments manage VT switching
3. **Signal Activity Analysis**: See real-time VT signals received by control processes
4. **VT Switch Control**: Implement custom VT switching policies
5. **System Administration**: Understand TTY session management

## Example Output

```bash
TTY Debug Tool - Simplified Version with Signal Monitoring
==========================================================

Monitoring all TTYs for VT_PROCESS mode...
Checking every 100 ms. Press Ctrl+C to stop.
Signal monitoring enabled (using strace)

[1753344980] TTY 2 entered VT_PROCESS mode:
=== TTY 2 Information ===
VT Mode: VT_PROCESS
Release Signal: 34
Acquire Signal: 35
Session Leader: None
VT Control Process: PID 816747 (/usr/lib/gdm-wayland-session /usr/bin/gnome-session) User: zccrs
  Signal monitoring started for TTY 2 VT control process (PID 816747)
  Monitor PID: 831846
  Starting signal monitoring for PID 816747 (TTY 2)...
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

## Technical Details

- Monitoring interval: 100ms
- Supported TTY range: 1-63 (scans 1-12 in monitor-all mode)
- VT signals: SIGUSR1 (release), SIGUSR2 (acquire)
- Signal monitoring: Uses `strace -e signal` to track VT control process signals
- Graceful shutdown on SIGINT/SIGTERM with automatic cleanup of strace processes

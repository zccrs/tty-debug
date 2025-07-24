# TTY Debug Tool

一个用于监控TTY切换、VT模式变化和进程信号活动的C语言工具，同时支持作为VT控制进程来管理VT切换。

## 功能特性

### 1. TTY切换监控
- 实时监控当前活跃的TTY变化
- 使用Linux sysfs (`/sys/class/tty/tty0/active`) 进行高效轮询
- 显示每次TTY切换的详细信息

### 2. VT模式监控
- 监控虚拟终端(VT)模式变化
- 支持检测 VT_AUTO、VT_PROCESS、VT_ACKACQ 模式
- 显示Release和Acquire信号配置
- **新增：VT模式设置者检测** - 能够识别可能修改VT模式的进程
- **新增：VT控制进程检测** - 识别当前接收VT信号的控制进程

### 3. 进程信号监控
- 监控TTY会话中所有进程的信号活动
- 特别关注VT相关的Release和Acquire信号
- 显示进程的详细信息（PID、命令、用户）

### 4. 嫌疑进程分析
- **新功能**：当检测到VT模式变化时，自动分析可能的设置者
- 通过进程活动分析（系统调用、CPU时间、信号统计）计算嫌疑分数
- 检查进程是否有TTY设备访问权限
- 按活动分数排序显示最可能的嫌疑进程

### 5. VT控制模式 (新增)
- **VT控制进程模式**：tty-debug可以作为VT控制进程运行
- **VT切换拦截**：接收并处理VT切换信号（SIGUSR1/SIGUSR2）
- **交互式确认**：可以询问用户是否允许VT切换
- **静默模式**：自动允许所有VT切换并记录日志
- **指定目标TTY**：可以控制特定的TTY而非当前TTY

### 6. VT控制进程变化监控 (新增)
- **实时监控**：检测VT控制进程的实时变化
- **进程切换检测**：当新进程成为VT控制进程时立即检测
- **属性变化监控**：监控控制进程的用户、命令、权限变化
- **进程消失检测**：检测VT控制进程终止或失去控制权
- **安全监控**：用于检测未授权的VT控制进程接管

## 编译

```bash
# 使用GCC编译
gcc -Wall -Wextra -std=c99 -o tty-debug tty-debug.c

# 或使用Clang编译
clang -Wall -Wextra -std=c99 -o tty-debug tty-debug.c
```

## 使用方法

### 命令行选项
```bash
# 显示帮助信息
./tty-debug --help

# 监控模式（默认）
./tty-debug              # 监控当前TTY
./tty-debug -t 0         # 监控当前活跃TTY（从sysfs获取）
./tty-debug -t 2         # 监控指定TTY 2

# VT控制模式
./tty-debug -c           # 成为当前TTY的VT控制进程
./tty-debug -c -s        # 静默模式，自动允许所有VT切换
./tty-debug -c -t 0      # 控制当前活跃TTY（从sysfs获取）
./tty-debug -c -t 3      # 控制指定TTY 3
./tty-debug -c -s -t 1   # 静默模式控制TTY 1
```

#### TTY参数说明
- **无参数**：自动检测当前运行程序的TTY
- **`-t 0`**：使用`/sys/class/tty/tty0/active`中的活跃TTY
- **`-t N`**：指定具体的TTY号码（1-63）

### 基本使用
```bash
# 监控模式 - 观察TTY和VT变化
./tty-debug

# 程序将显示：
# 1. 当前活跃的TTY信息
# 2. VT模式配置（模式、信号）
# 3. 会话领导进程信息
# 4. VT控制进程信息
# 5. 监控的进程列表
```

### VT控制模式使用
```bash
# 成为VT控制进程，静默允许所有切换
./tty-debug -c -s

# 成为VT控制进程，记录所有VT信号活动
./tty-debug -c

# 控制特定的TTY
./tty-debug -c -t 2 -s
```

### 监控内容
程序会持续监控以下内容：
- **TTY切换**：实时检测TTY切换事件
- **VT模式变化**：每2秒检查一次VT模式变化
- **进程信号活动**：每3秒检查一次进程信号统计
- **嫌疑进程分析**：VT模式变化时自动分析可能的设置者

### 示例输出
```
TTY Debug Tool - Enhanced Version with VT Mode Setter Detection
==============================================================

Initial active TTY: 2
=== TTY 2 Information ===
VT Mode: VT_PROCESS (1)
Release Signal: 34
Acquire Signal: 35
Session Leader PID: 1446
User: zccrs (UID: 1000)
Command: /usr/lib/gdm-wayland-session /usr/bin/gnome-session

--- VT Control Process ---
Control PID: 1446
Control Command: /usr/lib/gdm-wayland-session /usr/bin/gnome-session
Control User: zccrs (UID: 1000)
Is Session Leader: Yes
Has TTY Access: Yes
Note: This process likely receives VT signals (34, 35)

Now monitoring 2 processes on TTY 2 for VT signals (34, 35)
=== Monitored Session Processes ===
Total processes: 2
  PID 1446: /usr/lib/gdm-wayland-session /usr/bin/gnome-session (User: zccrs)
  PID 1452: /usr/lib/gnome-session-binary (User: zccrs)

Monitoring TTY changes, VT mode changes, and VT signal activity...
Will attempt to identify processes that change VT mode.
VT mode will be checked every 2 seconds.
Process signals will be checked every 3 seconds.
Press Ctrl+C to stop.

[2025-01-08 14:25:30] VT Mode Change Detected on TTY 2:
  Mode: VT_PROCESS (1) -> VT_AUTO (0)
Analyzing processes for VT mode change suspects...
  Possible VT mode change suspects (ranked by activity):
    1. PID 1446: /usr/lib/gdm-wayland-session /usr/bin/gnome-session (User: zccrs, Score: 150)
    2. PID 1452: /usr/lib/gnome-session-binary (User: zccrs, Score: 75)
  ---
```

## 测试

### 自动测试脚本
项目包含一个测试脚本来演示VT模式变化检测功能：

```bash
# 需要root权限运行测试（因为需要修改VT模式）
sudo ./test_vt_mode_change.sh
```

测试脚本会：
1. 显示当前VT模式
2. 启动tty-debug监控
3. 执行多次VT模式变化
4. 演示嫌疑进程检测功能

### 手动测试
如果你想手动测试VT模式变化检测：

```bash
# 终端1：运行监控工具
./tty-debug

# 终端2：修改VT模式（需要root权限）
sudo bash -c 'echo 0 > /sys/class/tty/tty2/mode'  # 设置为VT_AUTO
sudo bash -c 'echo 1 > /sys/class/tty/tty2/mode'  # 设置为VT_PROCESS
```

### 测试VT控制进程检测
项目包含测试程序来验证VT控制进程检测：

```bash
# 编译测试程序
clang -Wall -Wextra -std=c99 -o test_vt_control test_vt_control.c

# 终端1：运行VT控制进程测试
./test_vt_control

# 终端2：运行tty-debug观察VT控制进程
./tty-debug
```

### 测试新的VT控制功能
```bash
# 运行VT控制模式测试
./test_vt_control_mode.sh
```

该脚本将演示：
1. tty-debug的VT控制模式
2. VT信号拦截和处理
3. 静默模式vs交互模式
4. 指定TTY控制

### 测试VT控制进程变化监控
```bash
# 运行VT控制进程变化监控测试
./test_vt_control_process_monitoring.sh
```

该脚本将演示：
1. VT控制进程的实时变化检测
2. 新进程成为VT控制进程的检测
3. VT控制进程属性变化监控
4. VT控制进程消失的检测

### 测试活跃TTY监控功能
```bash
# 运行活跃TTY监控测试（-t 0参数）
./test_tty_zero_parameter.sh
```

该脚本将演示：
1. 使用`-t 0`自动监控活跃TTY
2. 与手动指定TTY的区别
3. 动态TTY监控的用例
4. sysfs TTY信息的获取

### 完整功能演示
运行完整的演示脚本：

```bash
# 给脚本执行权限
chmod +x test_vt_control_detection.sh

# 运行演示（需要在VT终端中运行，如tty1, tty2等）
./test_vt_control_detection.sh
```

该脚本将：
1. 显示当前TTY的初始状态
2. 启动VT控制进程测试程序
3. 使用tty-debug检测并显示VT控制进程
4. 分析会话领导进程vs VT控制进程的区别
5. 清理并恢复原始状态

## 新增功能：VT控制进程检测

### 什么是VT控制进程？
VT控制进程是指：
- 设置了`VT_PROCESS`模式的进程
- 接收VT释放信号(`relsig`)和获取信号(`acqsig`)的进程
- 负责响应VT切换请求并管理VT状态的进程

这与**会话领导进程**不同：
- **会话领导进程**：创建会话的进程，通常是shell或显示管理器
- **VT控制进程**：实际控制VT切换行为的进程，可能是会话中的某个子进程

### 检测算法
程序通过以下步骤识别VT控制进程：
1. **验证VT模式**：确认VT处于`VT_PROCESS`模式
2. **进程关联性**：查找与目标VT关联的所有进程
3. **权限评分**：基于以下因素计算分数：
   - TTY设备文件访问权限 (+50分)
   - 会话领导者身份 (+30分)
   - 进程组领导者身份 (+20分)
   - VT设备读写权限 (+10分)
4. **最佳匹配**：选择得分最高的进程作为VT控制进程

### 使用场景
- **调试VT切换问题**：识别哪个进程负责处理VT信号
- **权限诊断**：确认进程是否有适当的VT控制权限
- **信号跟踪**：了解VT信号的接收者
- **系统分析**：区分会话管理和VT控制的职责
- **VT访问控制**：在安全环境中控制VT切换权限
- **VT切换监控**：记录和分析VT切换行为
- **测试VT功能**：为VT相关开发提供测试工具
- **安全审计**：检测未授权的VT控制进程变化
- **进程生命周期监控**：跟踪VT控制进程的创建、变化和终止

## 技术实现

### VT模式设置者检测算法
1. **活动分析**：监控进程的系统调用时间、CPU时间和信号统计
2. **权限检查**：验证进程是否有TTY设备的访问权限
3. **分数计算**：根据进程活动变化计算嫌疑分数
   - 系统调用变化 × 10
   - CPU时间变化 × 5
   - 信号统计变化 × 2
4. **排序展示**：按分数降序显示最可能的嫌疑进程

### 监控机制
- **sysfs轮询**：使用Linux sysfs接口高效监控TTY切换
- **定期检查**：定时检查VT模式和进程信号状态
- **进程追踪**：维护TTY会话中所有进程的状态信息

## 系统要求

- Linux操作系统
- 支持sysfs文件系统
- 读取 `/sys/class/tty/` 目录的权限
- 读取 `/proc/` 目录的权限
- 修改VT模式需要root权限（仅测试时需要）

## 注意事项

1. **权限**：程序需要读取系统信息，但不需要root权限运行
2. **性能**：使用高效的轮询机制，CPU占用很低
3. **准确性**：嫌疑进程检测基于活动分析，可能存在误报
4. **兼容性**：在不同Linux发行版上测试通过

## 故障排除

### 常见问题
1. **无法访问sysfs**：确保 `/sys/class/tty/tty0/active` 文件可读
2. **编译错误**：确保安装了GCC或Clang编译器
3. **权限不足**：某些系统可能需要特殊权限访问TTY信息

### 调试模式
程序提供详细的输出信息，包括：
- 时间戳
- 进程详细信息
- VT模式变化详情
- 嫌疑进程分析结果

## 许可证

本项目使用以下许可证：
- Apache-2.0 OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only

## 更新日志

### v2.0 - VT模式设置者检测
- 新增VT模式变化的嫌疑进程检测功能
- 改进进程活动监控算法
- 添加TTY设备访问权限检查
- 优化进程信号统计分析
- 增强输出格式和时间戳显示

### v1.0 - 基础功能
- TTY切换监控
- VT模式监控
- 进程信号活动监控
- 基础的进程信息显示

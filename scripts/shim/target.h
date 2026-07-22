// target.h — 阶段2 触发点参数，RE 定位后填。0/空表示未配置。
// 运行时也可用 C:\windows\temp\tdx_shim_target.txt 覆盖（第一行 hwnd 或 class，第二行 cmd_id）。
#ifndef TARGET_H
#define TARGET_H

// 持仓窗口 HWND（每次启动会变，优先用下面的 class）。
#define TARGET_HWND 0

// 持仓窗口类名（RE 用 Spy++/winedbg 定位，跨启动稳定）。空则用 HWND。
#define TARGET_CLASS ""

// 刷新按钮的 WM_COMMAND 命令 ID（RE 定位）。
#define TARGET_CMD 0

#endif

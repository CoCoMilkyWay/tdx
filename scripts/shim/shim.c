// shim.dll — 注入到 TdxW.exe，建立控制通道（TCP 127.0.0.1:17703）。
// 阶段1（当前）：注入成功证明 + ping/pong。
// 阶段2（TODO）：收到 "refresh" 时触发客户端内部"刷新持仓"函数（触发点待 RE 填入 target.h）。
// 编译：见 build.sh（i686-w64-mingw32-gcc，32 位匹配 TdxW）。

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#define CTRL_PORT 17703
#include "target.h"

// 阶段2：触发客户端内部刷新持仓。触发点由 RE 定位后填入 target.h。
// 当前全部 0/空 → 返回未配置，不实际触发。
static const char *trigger_refresh(void) {
    if (!TARGET_HWND && !TARGET_CLASS[0]) {
        return "refresh not configured (RE pending)\n";
    }
    HWND hwnd = TARGET_HWND;
    if (!hwnd && TARGET_CLASS[0]) hwnd = FindWindowA(TARGET_CLASS, NULL);
    if (!hwnd) return "refresh: target window not found\n";
    PostMessageW(hwnd, WM_COMMAND, (WPARAM)TARGET_CMD, 0);
    return "refresh sent\n";
}

static int handle(SOCKET c) {
    char buf[64] = {0};
    int n = recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return 1;
    if (!strncmp(buf, "ping", 4)) {
        char r[128];
        snprintf(r, sizeof(r), "pong tdxw pid=%lu\n", GetCurrentProcessId());
        send(c, r, strlen(r), 0);
    } else if (!strncmp(buf, "refresh", 7)) {
        const char *r = trigger_refresh();
        send(c, r, strlen(r), 0);
    } else {
        send(c, "unknown\n", 8, 0);
    }
    return 0;
}

static DWORD WINAPI listener(LPVOID arg) {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;
    SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) return 2;
    BOOL on = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(CTRL_PORT);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(srv);
        return 3;
    }
    if (listen(srv, 4) == SOCKET_ERROR) {
        closesocket(srv);
        return 4;
    }
    for (;;) {
        SOCKET c = accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) break;
        handle(c);
        closesocket(c);
    }
    closesocket(srv);
    return 0;
}

// DllMain 不做重活（loader lock 下不能 WSAStartup），只起监听线程。
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        HANDLE t = CreateThread(NULL, 0, listener, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}

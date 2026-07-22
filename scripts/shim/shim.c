// shim.dll — 注入到 TdxW.exe，建立控制通道（TCP 127.0.0.1:17703）。
// 阶段1（当前）：注入证明 + ping/pong + 消息 spy（捕获刷新持仓的 WM_COMMAND）。
// 阶段2（TODO）：用 spy 抓到的 (hwnd, cmd_id) 经 PostMessage 触发客户端内部刷新持仓。
// 编译：见 positions.py（i686-w64-mingw32-gcc 或 clang --target=i686-w64-windows-gnu）。

#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CTRL_PORT 17703
#include "target.h"

static HMODULE g_hMod = NULL;
static CRITICAL_SECTION g_cs;
static int g_cs_inited = 0;

// ---------- 消息 spy：捕获 WM_COMMAND ----------
#define SPY_CAP 256
struct spy_evt { HWND hwnd; WPARAM wp; LPARAM lp; };
static struct spy_evt g_spy[SPY_CAP];
static int g_spy_head = 0, g_spy_count = 0;
static HHOOK g_hooks[128];
static int g_nhooks = 0;

static LRESULT CALLBACK spy_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION) {
        CWPSTRUCT *c = (CWPSTRUCT *)lp;
        if (c->message == WM_COMMAND) {
            EnterCriticalSection(&g_cs);
            g_spy[g_spy_head].hwnd = c->hwnd;
            g_spy[g_spy_head].wp = c->wParam;
            g_spy[g_spy_head].lp = c->lParam;
            g_spy_head = (g_spy_head + 1) % SPY_CAP;
            if (g_spy_count < SPY_CAP) g_spy_count++;
            LeaveCriticalSection(&g_cs);
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

// WH_GETMESSAGE：捕获 PostMessage 投递的 WM_COMMAND（lp 是 MSG*）。
static LRESULT CALLBACK spy_getmsg_proc(int code, WPARAM wp, LPARAM lp) {
    if (code == HC_ACTION && wp == PM_REMOVE) {
        MSG *m = (MSG *)lp;
        if (m->message == WM_COMMAND) {
            EnterCriticalSection(&g_cs);
            g_spy[g_spy_head].hwnd = m->hwnd;
            g_spy[g_spy_head].wp = m->wParam;
            g_spy[g_spy_head].lp = m->lParam;
            g_spy_head = (g_spy_head + 1) % SPY_CAP;
            if (g_spy_count < SPY_CAP) g_spy_count++;
            LeaveCriticalSection(&g_cs);
        }
    }
    return CallNextHookEx(NULL, code, wp, lp);
}

static int spy_on(void) {
    DWORD mypid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != mypid) continue;
            if (g_nhooks >= 126) break;
            HHOOK h1 = SetWindowsHookExA(WH_CALLWNDPROC, spy_proc, g_hMod, te.th32ThreadID);
            if (h1) g_hooks[g_nhooks++] = h1;
            if (g_nhooks >= 127) break;
            HHOOK h2 = SetWindowsHookExA(WH_GETMESSAGE, spy_getmsg_proc, g_hMod, te.th32ThreadID);
            if (h2) g_hooks[g_nhooks++] = h2;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return g_nhooks;
}

static void spy_off(void) {
    int i;
    for (i = 0; i < g_nhooks; i++) UnhookWindowsHookEx(g_hooks[i]);
    g_nhooks = 0;
}

static void spy_clear(void) {
    EnterCriticalSection(&g_cs);
    g_spy_head = g_spy_count = 0;
    LeaveCriticalSection(&g_cs);
}

static void spy_dump(SOCKET c) {
    int i, n, start;
    char line[160];
    EnterCriticalSection(&g_cs);
    n = g_spy_count;
    start = (g_spy_count < SPY_CAP) ? 0 : g_spy_head;
    for (i = 0; i < n; i++) {
        int idx = (start + i) % SPY_CAP;
        int len = snprintf(line, sizeof(line),
            "WM_COMMAND hwnd=0x%08x wparam=0x%08x lparam=0x%08x\n",
            (unsigned)(DWORD_PTR)g_spy[idx].hwnd,
            (unsigned)(DWORD_PTR)g_spy[idx].wp,
            (unsigned)(DWORD_PTR)g_spy[idx].lp);
        send(c, line, len, 0);
    }
    LeaveCriticalSection(&g_cs);
    send(c, "end\n", 4, 0);
}

// ---------- 阶段2：触发客户端内部刷新持仓 ----------
// 用 spy 抓到的 (hwnd, wparam, lparam) 完整复现 WM_COMMAND：PostMessage。
// 运行时配置 C:\windows\temp\tdx_shim_target.txt 三行：hwnd（0x... 或 class=类名）、wparam、lparam。
// 没配置则回放最近一次 spy 抓到的 WM_COMMAND（同一会话内 hwnd 仍有效，免去手写配置）。
// 都没有 → 提示先跑 spy。
static char g_refbuf[256];
static const char *trigger_refresh(void) {
    HWND hwnd = TARGET_HWND;
    WPARAM wp = (WPARAM)TARGET_CMD;
    LPARAM lp = 0;
    int from_cfg = 0;
    FILE *f = fopen("C:\\windows\\temp\\tdx_shim_target.txt", "r");
    if (f) {
        char l1[128] = {0}, l2[64] = {0}, l3[64] = {0};
        if (fgets(l1, sizeof(l1), f)) {
            fgets(l2, sizeof(l2), f);
            fgets(l3, sizeof(l3), f);
        }
        fclose(f);
        char *p1 = l1, *p2 = l2, *p3 = l3;
        while (*p1 == ' ' || *p1 == '\t' || *p1 == '\r' || *p1 == '\n') p1++;
        while (*p2 == ' ' || *p2 == '\t' || *p2 == '\r' || *p2 == '\n') p2++;
        while (*p3 == ' ' || *p3 == '\t' || *p3 == '\r' || *p3 == '\n') p3++;
        if (p1[0]) {
            if (!strncmp(p1, "class=", 6)) hwnd = FindWindowA(p1 + 6, NULL);
            else hwnd = (HWND)(DWORD_PTR)strtoul(p1, NULL, 0);
            from_cfg = 1;
        }
        if (p2[0]) { wp = (WPARAM)strtoul(p2, NULL, 0); from_cfg = 1; }
        if (p3[0]) lp = (LPARAM)strtoul(p3, NULL, 0);
    }
    if (!from_cfg) {
        // 回放最近一次 spy 抓到的 WM_COMMAND
        EnterCriticalSection(&g_cs);
        if (g_spy_count > 0) {
            int idx = (g_spy_head - 1 + SPY_CAP) % SPY_CAP;
            hwnd = g_spy[idx].hwnd;
            wp = g_spy[idx].wp;
            lp = g_spy[idx].lp;
        }
        LeaveCriticalSection(&g_cs);
    }
    if (!hwnd && TARGET_CLASS[0]) hwnd = FindWindowA(TARGET_CLASS, NULL);
    if (!hwnd) { strncpy(g_refbuf, "refresh: no target (run spy first, or write td_shim_target.txt)\n", sizeof(g_refbuf)-1); return g_refbuf; }
    if (!wp)   { strncpy(g_refbuf, "refresh: no wparam (run spy first)\n", sizeof(g_refbuf)-1); return g_refbuf; }
    PostMessageW(hwnd, WM_COMMAND, wp, lp);
    snprintf(g_refbuf, sizeof(g_refbuf),
             "refresh sent hwnd=0x%08x wparam=0x%08x lparam=0x%08x\n",
             (unsigned)(DWORD_PTR)hwnd, (unsigned)(DWORD_PTR)wp, (unsigned)(DWORD_PTR)lp);
    return g_refbuf;
}

// ---------- 控制通道 ----------
static int handle(SOCKET c) {
    char buf[128] = {0};
    int n = recv(c, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return 1;
    if (!strncmp(buf, "ping", 4)) {
        char r[128];
        snprintf(r, sizeof(r), "pong tdxw pid=%lu\n", GetCurrentProcessId());
        send(c, r, strlen(r), 0);
    } else if (!strncmp(buf, "spy on", 6)) {
        int nh = spy_on();
        char r[64];
        snprintf(r, sizeof(r), "spy on hooks=%d\n", nh);
        send(c, r, strlen(r), 0);
    } else if (!strncmp(buf, "spy off", 7)) {
        spy_off();
        send(c, "spy off\n", 8, 0);
    } else if (!strncmp(buf, "spy clear", 9)) {
        spy_clear();
        send(c, "spy cleared\n", 12, 0);
    } else if (!strncmp(buf, "spy dump", 8)) {
        spy_dump(c);
    } else if (!strncmp(buf, "refresh", 7)) {
        const char *r = trigger_refresh();
        send(c, r, strlen(r), 0);
    } else {
        send(c, "unknown\n", 8, 0);
    }
    return 0;
}

// 控制端口从 C:\windows\temp\tdx_shim_port.txt 读（Python 注入前写入），缺失则用 CTRL_PORT 默认。
static int read_ctrl_port(void) {
    FILE *f = fopen("C:\\windows\\temp\\tdx_shim_port.txt", "r");
    if (!f) return CTRL_PORT;
    char buf[32] = {0};
    int p = CTRL_PORT;
    if (fgets(buf, sizeof(buf), f)) {
        int v = atoi(buf);
        if (v > 0 && v < 65536) p = v;
    }
    fclose(f);
    return p;
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
    addr.sin_port = htons(read_ctrl_port());
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
        g_hMod = hMod;
        if (!g_cs_inited) { InitializeCriticalSection(&g_cs); g_cs_inited = 1; }
        DisableThreadLibraryCalls(hMod);
        HANDLE t = CreateThread(NULL, 0, listener, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}

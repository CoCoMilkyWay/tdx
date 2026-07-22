// shim.dll — 通用 Win32 消息桥，注入到目标 Wine 进程（如 TdxW.exe）。
// 控制通道：TCP 127.0.0.1，端口由 C:\windows\temp\tdx_shim_port.txt
// 指定（Python 注入前写入）。 协议：行命令，\n 结尾。命令：
//   ping
//   spy on [msg=<id>|all]   默认 msg=0x111(WM_COMMAND)；all=抓所有消息（吵）
//   spy off / spy clear / spy dump
//   post <target> <msg> <wparam> <lparam>   PostMessageW；target=0x.. 或
//   class=<类名> send <target> <msg> <wparam> <lparam> SendMessageW（同步，返回
//   result） enum [hwnd]            列本进程顶层窗口（或 hwnd
//   的子窗口）：hwnd/class/title find class=<cls> [title=<ttl>]
//   FindWindowExA，回 hwnd=0x.. 或 hwnd=0x0 help
// 编译：见 shimctl.py（i686-w64-mingw32-gcc 或 clang
// --target=i686-w64-windows-gnu）。

#include <winsock2.h>

#include <windows.h>

#include <tlhelp32.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_PORT 17703
#define SPY_CAP 512
#define FILTER_ALL 0xFFFFFFFFu

static HMODULE g_hMod = NULL;
static CRITICAL_SECTION g_cs;
static int g_cs_inited = 0;

// ---------- 消息 spy ----------
struct spy_evt {
  DWORD msg;
  HWND hwnd;
  WPARAM wp;
  LPARAM lp;
};
static struct spy_evt g_spy[SPY_CAP];
static int g_spy_head = 0, g_spy_count = 0;
static DWORD g_filter = WM_COMMAND; // 默认只抓 WM_COMMAND
static HHOOK g_hooks[256];
static int g_nhooks = 0;

static void spy_record(DWORD msg, HWND hwnd, WPARAM wp, LPARAM lp) {
  if (g_filter != FILTER_ALL && msg != g_filter)
    return;
  EnterCriticalSection(&g_cs);
  g_spy[g_spy_head].msg = msg;
  g_spy[g_spy_head].hwnd = hwnd;
  g_spy[g_spy_head].wp = wp;
  g_spy[g_spy_head].lp = lp;
  g_spy_head = (g_spy_head + 1) % SPY_CAP;
  if (g_spy_count < SPY_CAP)
    g_spy_count++;
  LeaveCriticalSection(&g_cs);
}

static LRESULT CALLBACK spy_cwp(int code, WPARAM wp, LPARAM lp) {
  if (code == HC_ACTION) {
    CWPSTRUCT *c = (CWPSTRUCT *)lp;
    spy_record(c->message, c->hwnd, c->wParam, c->lParam);
  }
  return CallNextHookEx(NULL, code, wp, lp);
}

static LRESULT CALLBACK spy_gm(int code, WPARAM wp, LPARAM lp) {
  if (code == HC_ACTION && wp == PM_REMOVE) {
    MSG *m = (MSG *)lp;
    spy_record(m->message, m->hwnd, m->wParam, m->lParam);
  }
  return CallNextHookEx(NULL, code, wp, lp);
}

static int spy_on(void) {
  DWORD mypid = GetCurrentProcessId();
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE)
    return 0;
  THREADENTRY32 te;
  te.dwSize = sizeof(te);
  if (Thread32First(snap, &te)) {
    do {
      if (te.th32OwnerProcessID != mypid)
        continue;
      if (g_nhooks >= 254)
        break;
      HHOOK h1 =
          SetWindowsHookExA(WH_CALLWNDPROC, spy_cwp, g_hMod, te.th32ThreadID);
      if (h1)
        g_hooks[g_nhooks++] = h1;
      if (g_nhooks >= 255)
        break;
      HHOOK h2 =
          SetWindowsHookExA(WH_GETMESSAGE, spy_gm, g_hMod, te.th32ThreadID);
      if (h2)
        g_hooks[g_nhooks++] = h2;
    } while (Thread32Next(snap, &te));
  }
  CloseHandle(snap);
  return g_nhooks;
}

static void spy_off(void) {
  int i;
  for (i = 0; i < g_nhooks; i++)
    UnhookWindowsHookEx(g_hooks[i]);
  g_nhooks = 0;
}

// ---------- 窗口解析 / 枚举 ----------
static HWND resolve_target(const char *s) {
  if (!strncmp(s, "class=", 6))
    return FindWindowA(s + 6, NULL);
  return (HWND)(DWORD_PTR)strtoul(s, NULL, 0);
}

struct enum_ctx {
  char *buf;
  size_t cap, len;
};

static void append(struct enum_ctx *e, const char *fmt, ...) {
  char tmp[512];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n <= 0)
    return;
  if (e->len + (size_t)n + 1 > e->cap) {
    size_t ncap = (e->len + n + 1) * 2;
    char *nb = (char *)realloc(e->buf, ncap);
    if (!nb)
      return;
    e->buf = nb;
    e->cap = ncap;
  }
  memcpy(e->buf + e->len, tmp, n);
  e->len += n;
  e->buf[e->len] = 0;
}

static BOOL CALLBACK enum_top_proc(HWND hwnd, LPARAM lp) {
  struct enum_ctx *e = (struct enum_ctx *)lp;
  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid != GetCurrentProcessId())
    return TRUE;
  char cls[256] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  append(e, "hwnd=0x%08x class=\"%s\" title=\"%s\"\n",
         (unsigned)(DWORD_PTR)hwnd, cls, ttl);
  return TRUE;
}

static BOOL CALLBACK enum_child_proc(HWND hwnd, LPARAM lp) {
  struct enum_ctx *e = (struct enum_ctx *)lp;
  char cls[256] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  append(e, "hwnd=0x%08x class=\"%s\" title=\"%s\"\n",
         (unsigned)(DWORD_PTR)hwnd, cls, ttl);
  return TRUE;
}

// ---------- 命令处理 ----------
static int send_str(SOCKET c, const char *s) {
  return send(c, s, strlen(s), 0);
}

static void cmd_spy_dump(SOCKET c) {
  int i, n, start;
  char line[256];
  EnterCriticalSection(&g_cs);
  n = g_spy_count;
  start = (g_spy_count < SPY_CAP) ? 0 : g_spy_head;
  for (i = 0; i < n; i++) {
    int idx = (start + i) % SPY_CAP;
    char cls[256] = {0};
    GetClassNameA(g_spy[idx].hwnd, cls, sizeof(cls));
    int len = snprintf(
        line, sizeof(line),
        "msg=0x%08x hwnd=0x%08x class=\"%s\" wparam=0x%08x lparam=0x%08x\n",
        (unsigned)g_spy[idx].msg, (unsigned)(DWORD_PTR)g_spy[idx].hwnd, cls,
        (unsigned)(DWORD_PTR)g_spy[idx].wp, (unsigned)(DWORD_PTR)g_spy[idx].lp);
    send(c, line, len, 0);
  }
  LeaveCriticalSection(&g_cs);
  send_str(c, "end\n");
}

static void cmd_post(SOCKET c, char *args) {
  char a1[128] = {0}, a2[64] = {0}, a3[64] = {0}, a4[64] = {0};
  sscanf(args, "%127s %63s %63s %63s", a1, a2, a3, a4);
  HWND hwnd = resolve_target(a1);
  DWORD msg = strtoul(a2, NULL, 0);
  WPARAM wp = (WPARAM)strtoul(a3, NULL, 0);
  LPARAM lp = (LPARAM)strtoul(a4, NULL, 0);
  if (!hwnd) {
    send_str(c, "post: target not found\n");
    return;
  }
  if (!msg) {
    send_str(c, "post: msg=0?\n");
    return;
  }
  PostMessageW(hwnd, msg, wp, lp);
  char r[160];
  snprintf(r, sizeof(r), "posted hwnd=0x%08x msg=0x%08x wp=0x%08x lp=0x%08x\n",
           (unsigned)(DWORD_PTR)hwnd, (unsigned)msg, (unsigned)(DWORD_PTR)wp,
           (unsigned)(DWORD_PTR)lp);
  send_str(c, r);
}

static void cmd_send(SOCKET c, char *args) {
  char a1[128] = {0}, a2[64] = {0}, a3[64] = {0}, a4[64] = {0};
  sscanf(args, "%127s %63s %63s %63s", a1, a2, a3, a4);
  HWND hwnd = resolve_target(a1);
  DWORD msg = strtoul(a2, NULL, 0);
  WPARAM wp = (WPARAM)strtoul(a3, NULL, 0);
  LPARAM lp = (LPARAM)strtoul(a4, NULL, 0);
  if (!hwnd) {
    send_str(c, "send: target not found\n");
    return;
  }
  if (!msg) {
    send_str(c, "send: msg=0?\n");
    return;
  }
  LRESULT res = SendMessageW(hwnd, msg, wp, lp);
  char r[160];
  snprintf(r, sizeof(r), "sent hwnd=0x%08x msg=0x%08x result=0x%08x\n",
           (unsigned)(DWORD_PTR)hwnd, (unsigned)msg, (unsigned)(DWORD_PTR)res);
  send_str(c, r);
}

static void cmd_enum(SOCKET c, char *args) {
  struct enum_ctx e = {0, 0, 0};
  append(&e, "begin\n");
  if (args[0]) {
    HWND parent = resolve_target(args);
    if (parent)
      EnumChildWindows(parent, enum_child_proc, (LPARAM)&e);
    else
      append(&e, "enum: parent not found\n");
  } else {
    EnumWindows(enum_top_proc, (LPARAM)&e);
  }
  append(&e, "end\n");
  if (e.buf) {
    send(c, e.buf, e.len, 0);
    free(e.buf);
  }
}

static void cmd_find(SOCKET c, char *args) {
  char cls[128] = {0}, ttl[128] = {0};
  char *p = args;
  if (!strncmp(p, "class=", 6)) {
    p += 6;
    size_t i = 0;
    while (*p && *p != ' ' && i < sizeof(cls) - 1)
      cls[i++] = *p++;
    cls[i] = 0;
    while (*p == ' ')
      p++;
    if (!strncmp(p, "title=", 6)) {
      p += 6;
      size_t i = 0;
      while (*p && i < sizeof(ttl) - 1)
        ttl[i++] = *p++;
      ttl[i] = 0;
    }
  }
  HWND h = FindWindowExA(NULL, NULL, cls[0] ? cls : NULL, ttl[0] ? ttl : NULL);
  char r[64];
  snprintf(r, sizeof(r), "hwnd=0x%08x\n", (unsigned)(DWORD_PTR)h);
  send_str(c, r);
}

static int handle(SOCKET c) {
  char buf[512] = {0};
  int n = recv(c, buf, sizeof(buf) - 1, 0);
  if (n <= 0)
    return 1;
  char *sp = strchr(buf, ' ');
  char *cmd = buf;
  char *args = "";
  if (sp) {
    *sp = 0;
    args = sp + 1;
  }
  char *nl = strchr(args, '\n');
  if (nl)
    *nl = 0;
  nl = strchr(cmd, '\n');
  if (nl)
    *nl = 0;

  if (!strcmp(cmd, "ping")) {
    char r[64];
    snprintf(r, sizeof(r), "pong pid=%lu\n", GetCurrentProcessId());
    send_str(c, r);
  } else if (!strcmp(cmd, "spy")) {
    if (!strncmp(args, "on", 2)) {
      g_filter = WM_COMMAND;
      const char *m = strstr(args, "msg=");
      if (m)
        g_filter = strtoul(m + 4, NULL, 0);
      else if (strstr(args, "all"))
        g_filter = FILTER_ALL;
      int nh = spy_on();
      char r[80];
      snprintf(r, sizeof(r), "spy on hooks=%d filter=0x%08x\n", nh,
               (unsigned)g_filter);
      send_str(c, r);
    } else if (!strncmp(args, "off", 3)) {
      spy_off();
      send_str(c, "spy off\n");
    } else if (!strncmp(args, "clear", 5)) {
      EnterCriticalSection(&g_cs);
      g_spy_head = g_spy_count = 0;
      LeaveCriticalSection(&g_cs);
      send_str(c, "spy cleared\n");
    } else if (!strncmp(args, "dump", 4)) {
      cmd_spy_dump(c);
    } else
      send_str(c, "spy: expected on/off/clear/dump\n");
  } else if (!strcmp(cmd, "post")) {
    cmd_post(c, args);
  } else if (!strcmp(cmd, "send")) {
    cmd_send(c, args);
  } else if (!strcmp(cmd, "enum")) {
    cmd_enum(c, args);
  } else if (!strcmp(cmd, "find")) {
    cmd_find(c, args);
  } else if (!strcmp(cmd, "help")) {
    send_str(c, "cmds: ping; spy on [msg=ID|all]/off/clear/dump; post <target> "
                "<msg> <wp> <lp>; send <target> <msg> <wp> <lp>; enum [hwnd]; "
                "find class=<cls> [title=<ttl>]\n");
  } else {
    send_str(c, "unknown cmd (try help)\n");
  }
  return 0;
}

static int read_port(void) {
  FILE *f = fopen("C:\\windows\\temp\\tdx_shim_port.txt", "r");
  if (!f)
    return DEFAULT_PORT;
  char b[32] = {0};
  int p = DEFAULT_PORT;
  if (fgets(b, sizeof(b), f)) {
    int v = atoi(b);
    if (v > 0 && v < 65536)
      p = v;
  }
  fclose(f);
  return p;
}

static DWORD WINAPI listener(LPVOID arg) {
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    return 1;
  SOCKET srv = socket(AF_INET, SOCK_STREAM, 0);
  if (srv == INVALID_SOCKET)
    return 2;
  BOOL on = 1;
  setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(read_port());
  if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR) {
    closesocket(srv);
    return 3;
  }
  if (listen(srv, 8) == SOCKET_ERROR) {
    closesocket(srv);
    return 4;
  }
  for (;;) {
    SOCKET c = accept(srv, NULL, NULL);
    if (c == INVALID_SOCKET)
      break;
    handle(c);
    closesocket(c);
  }
  closesocket(srv);
  return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_hMod = hMod;
    if (!g_cs_inited) {
      InitializeCriticalSection(&g_cs);
      g_cs_inited = 1;
    }
    DisableThreadLibraryCalls(hMod);
    HANDLE t = CreateThread(NULL, 0, listener, NULL, 0, NULL);
    if (t)
      CloseHandle(t);
  }
  return TRUE;
}

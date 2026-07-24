// shim.dll — 通用 Win32 消息桥，注入到目标 Wine 进程（如 TdxW.exe）。
// 控制通道：TCP 127.0.0.1，端口由 C:\windows\temp\tdx_shim_port.txt
// 指定（Python 注入前写入）。 协议：行命令，\n 结尾。命令：
//   ping
//   spy on [msg=<id>|all]   默认 msg=0x111(WM_COMMAND)；all=抓所有消息（吵）
//   spy off / spy clear / spy dump
//   post <target> <msg> <wparam> <lparam>   PostMessageW；target=0x.. 或
//   class=<类名> send <target> <msg> <wparam> <lparam> SendMessageW（同步，返回
//   result） postcmd <msg> <wparam> <lparam>
//   自动找本进程主框架（最大可见无 owner 顶层窗口）再 PostMessageW，命令路由免
//   hwnd enum [hwnd]            列本进程顶层窗口（或 hwnd
//   的子窗口）：hwnd/class/title find class=<cls> [title=<ttl>]
//   FindWindowExA，回 hwnd=0x.. 或 hwnd=0x0 postvia <root_cls> <anchor_cls>
//   <anchor_title> <target_cls> <msg> <wp> <lp>   锚定 root 下 class+title
//   匹配的子窗口，向上找第一个 class==target_cls 的祖先，PostMessageW 到那里 help
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

// ---------- postcmd：post 到本进程主框架（命令路由，免 hwnd）----------
struct main_ctx {
  HWND best;
  long area;
};

static BOOL CALLBACK find_main_proc(HWND hwnd, LPARAM lp) {
  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid != GetCurrentProcessId())
    return TRUE;
  if (!IsWindowVisible(hwnd))
    return TRUE;
  if (GetWindow(hwnd, GW_OWNER) != NULL) // 跳过被拥有的弹窗/对话框
    return TRUE;
  RECT r;
  if (!GetWindowRect(hwnd, &r))
    return TRUE;
  long area = (r.right - r.left) * (r.bottom - r.top);
  struct main_ctx *c = (struct main_ctx *)lp;
  if (area > c->area) {
    c->area = area;
    c->best = hwnd;
  }
  return TRUE;
}

static void cmd_postcmd(SOCKET c, char *args) {
  char a1[64] = {0}, a2[64] = {0}, a3[64] = {0};
  sscanf(args, "%63s %63s %63s", a1, a2, a3);
  DWORD msg = strtoul(a1, NULL, 0);
  WPARAM wp = (WPARAM)strtoul(a2, NULL, 0);
  LPARAM lp = (LPARAM)strtoul(a3, NULL, 0);
  if (!msg) {
    send_str(c, "postcmd: msg=0?\n");
    return;
  }
  struct main_ctx mc = {NULL, 0};
  EnumWindows(find_main_proc, (LPARAM)&mc);
  if (!mc.best) {
    send_str(c, "postcmd: no main window\n");
    return;
  }
  PostMessageW(mc.best, msg, wp, lp);
  char r[160];
  snprintf(r, sizeof(r), "posted main=0x%08x msg=0x%08x wp=0x%08x lp=0x%08x\n",
           (unsigned)(DWORD_PTR)mc.best, (unsigned)msg, (unsigned)(DWORD_PTR)wp,
           (unsigned)(DWORD_PTR)lp);
  send_str(c, r);
}

// ---------- postvia：锚定子窗口再上溯到 root 的直接子窗口，post 到那里
// ---------- 用途：插件面板（如 AddinFlatJy
// 持仓面板）不在主框架命令路由链里，必须 post 到 面板本身；面板 hwnd
// 运行时变，但面板里工具栏的 class+title 稳定，可作锚点，上溯到
// root（主框架）的直接子窗口即面板本身。
struct via_ctx {
  const char *cls;
  const char *ttl;
  HWND found;
};

static BOOL CALLBACK find_anchor_proc(HWND hwnd, LPARAM lp) {
  struct via_ctx *v = (struct via_ctx *)lp;
  if (v->found)
    return TRUE;
  char cls[256] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  if (!strcmp(cls, v->cls) && !strcmp(ttl, v->ttl))
    v->found = hwnd;
  return TRUE;
}

// 走到目标窗口：FindWindow(root_cls) → 锚点(anchor_cls/anchor_title) → 向上找第一个
// class==target_cls 的祖先。postvia/find_lv 共用。
static HWND walk_to_target(const char *root_cls, const char *anchor_cls,
                           const char *anchor_title, const char *target_cls) {
  HWND root = FindWindowA(root_cls[0] ? root_cls : NULL, NULL);
  if (!root)
    return NULL;
  struct via_ctx v = {anchor_cls, anchor_title, NULL};
  EnumChildWindows(root, find_anchor_proc, (LPARAM)&v);
  if (!v.found)
    return NULL;
  HWND t = v.found;
  for (;;) {
    char cls[256] = {0};
    GetClassNameA(t, cls, sizeof(cls));
    if (!strcmp(cls, target_cls))
      return t;
    HWND p = GetParent(t);
    if (!p)
      return NULL;
    t = p;
  }
}

static void cmd_postvia(SOCKET c, char *args) {
  char root_cls[128] = {0}, a_cls[128] = {0}, a_ttl[128] = {0}, tgt_cls[128] = {0};
  char a5[64] = {0}, a6[64] = {0}, a7[64] = {0};
  // a_ttl 可能含空格——用 %n 拿到 tgt_cls 起始位置
  int off = 0;
  if (sscanf(args, "%127s %127s %127s %n", root_cls, a_cls, a_ttl, &off) < 3) {
    send_str(c, "postvia: need root_cls anchor_cls anchor_title target_cls msg "
                "wp lp\n");
    return;
  }
  if (off <= 0 || off >= (int)strlen(args)) {
    send_str(c, "postvia: need target_cls msg wp lp\n");
    return;
  }
  sscanf(args + off, "%127s %63s %63s %63s", tgt_cls, a5, a6, a7);
  DWORD msg = strtoul(a5, NULL, 0);
  WPARAM wp = (WPARAM)strtoul(a6, NULL, 0);
  LPARAM lp = (LPARAM)strtoul(a7, NULL, 0);
  if (!msg) {
    send_str(c, "postvia: msg=0?\n");
    return;
  }
  HWND target = walk_to_target(root_cls, a_cls, a_ttl, tgt_cls);
  if (!target) {
    send_str(c, "postvia: target not found\n");
    return;
  }
  PostMessageW(target, msg, wp, lp);
  char r[160];
  snprintf(r, sizeof(r),
           "posted via target=0x%08x msg=0x%08x wp=0x%08x lp=0x%08x\n",
           (unsigned)(DWORD_PTR)target, (unsigned)msg, (unsigned)(DWORD_PTR)wp,
           (unsigned)(DWORD_PTR)lp);
  send_str(c, r);
}

// ---------- anchorinfo：给定 hwnd，回根框架类 + 第一个工具栏锚点 class/title
// ----------
struct tb_ctx {
  char cls[256];
  char ttl[256];
  int found;
};

static BOOL CALLBACK find_toolbar_proc(HWND hwnd, LPARAM lp) {
  struct tb_ctx *t = (struct tb_ctx *)lp;
  if (t->found)
    return TRUE;
  char cls[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  // 大小写不敏感含 "toolbar"
  char low[256];
  int i;
  for (i = 0; cls[i] && i < (int)sizeof(low) - 1; i++)
    low[i] = (char)(cls[i] >= 'A' && cls[i] <= 'Z' ? cls[i] + 32 : cls[i]);
  low[i] = 0;
  if (strstr(low, "toolbar") || strstr(low, "toolbar32")) {
    t->found = 1;
    strncpy(t->cls, cls, sizeof(t->cls) - 1);
    GetWindowTextA(hwnd, t->ttl, sizeof(t->ttl));
  }
  return TRUE;
}

static void cmd_anchorinfo(SOCKET c, char *args) {
  HWND h = resolve_target(args);
  if (!h) {
    send_str(c, "anchorinfo: hwnd not found\n");
    return;
  }
  // 上溯到顶层
  HWND top = h;
  for (;;) {
    HWND p = GetParent(top);
    if (!p)
      break;
    top = p;
  }
  char root_cls[256] = {0};
  GetClassNameA(top, root_cls, sizeof(root_cls));
  // 找第一个工具栏后代
  struct tb_ctx t;
  memset(&t, 0, sizeof(t));
  EnumChildWindows(h, find_toolbar_proc, (LPARAM)&t);
  char r[600];
  snprintf(r, sizeof(r), "root_class=%s anchor_class=%s anchor_title=%s\n",
           root_cls, t.found ? t.cls : "", t.found ? t.ttl : "");
  send_str(c, r);
}

// ---------- dlgs：列出本进程可见对话框（#32770）及其按钮 ----------
struct dlg_btn_ctx {
  SOCKET c;
};

static BOOL CALLBACK dlg_btn_proc(HWND hwnd, LPARAM lp) {
  SOCKET c = (SOCKET)lp;
  char cls[256] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  // 取控件 ID（对话框内子窗口的 ID）
  LONG_PTR id = GetWindowLongPtrW(hwnd, GWLP_ID);
  char line[512];
  snprintf(line, sizeof(line), "    btn id=%ld class=\"%s\" title=\"%s\"\n",
           (long)id, cls, ttl);
  send(c, line, strlen(line), 0);
  return TRUE;
}

static BOOL CALLBACK dlg_proc(HWND hwnd, LPARAM lp) {
  SOCKET c = (SOCKET)lp;
  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid != GetCurrentProcessId())
    return TRUE;
  if (!IsWindowVisible(hwnd))
    return TRUE;
  char cls[256] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  if (strcmp(cls, "#32770"))
    return TRUE; // 只看标准对话框
  char head[400];
  snprintf(head, sizeof(head), "dlg hwnd=0x%08x title=\"%s\"\n",
           (unsigned)(DWORD_PTR)hwnd, ttl);
  send(c, head, strlen(head), 0);
  EnumChildWindows(hwnd, dlg_btn_proc, (LPARAM)c);
  return TRUE;
}

static void cmd_dlgs(SOCKET c) {
  EnumWindows(dlg_proc, (LPARAM)c);
  send_str(c, "end\n");
}

// ---------- lv_find：在 SysListView32 里找任意列等于 text 的行号 ----------
#define LVWM_FIRST 0x1000
#define LVM_GETITEMCOUNT (LVWM_FIRST + 0)
#define LVM_GETITEMRECT (LVWM_FIRST + 14)
#define LVM_SETITEMSTATE (LVWM_FIRST + 43)
#define LVM_GETITEMTEXTA (LVWM_FIRST + 45)
#define LVIR_BOUNDS 0
#define LVIS_SELECTED 0x0002
#define LVIS_FOCUSED 0x0001
#define SMTO_ABORTIFHUNG 0x0002

// 跨线程 SendMessage 可能死锁（目标线程不泵消息），用超时版避免 shim 卡死
static LRESULT lv_send(HWND list, UINT msg, WPARAM wp, LPARAM lp) {
  DWORD_PTR res = 0;
  if (!SendMessageTimeoutA(list, msg, wp, lp, SMTO_ABORTIFHUNG, 2000, &res))
    return 0;
  return (LRESULT)res;
}

typedef struct {
  UINT mask;
  int iItem;
  int iSubItem;
  UINT state;
  UINT stateMask;
  char *pszText;
  int cchTextMax;
} LVITEMA_TEXT;

static void cmd_lv_find(SOCKET c, char *args) {
  char a1[64] = {0};
  // text 取剩余（委托号是数字，但通用起见取剩余）
  int off = 0;
  if (sscanf(args, "%63s %n", a1, &off) < 1 || off <= 0 || off >= (int)strlen(args)) {
    send_str(c, "lv_find: need <list_hwnd> <text>\n");
    return;
  }
  char text[128] = {0};
  strncpy(text, args + off, sizeof(text) - 1);
  char *nl = strchr(text, '\n');
  if (nl)
    *nl = 0;
  HWND list = (HWND)(DWORD_PTR)strtoul(a1, NULL, 0);
  if (!IsWindow(list)) {
    send_str(c, "lv_find: bad list hwnd\n");
    return;
  }
  int count = (int)lv_send(list, LVM_GETITEMCOUNT, 0, 0);
  int found = -1;
  int row, col;
  for (row = 0; row < count && found < 0; row++) {
    for (col = 0; col < 16; col++) {
      char buf[256] = {0};
      LVITEMA_TEXT it;
      memset(&it, 0, sizeof(it));
      it.mask = 0x0001; // LVIF_TEXT
      it.iItem = row;
      it.iSubItem = col;
      it.pszText = buf;
      it.cchTextMax = sizeof(buf);
      int n = (int)lv_send(list, LVM_GETITEMTEXTA, (WPARAM)row, (LPARAM)&it);
      if (n > 0 && !strcmp(buf, text)) {
        found = row;
        break;
      }
      if (n == 0 && col > 0)
        break; // 该行无更多列
    }
  }
  char r[96];
  snprintf(r, sizeof(r), "row=%d count=%d\n", found, count);
  send_str(c, r);
}

// ---------- find_lv：走到目标面板，找 class==child_cls 的后代（如 SysListView32）----------
struct child_ctx {
  const char *cls;
  HWND found;
};

static BOOL CALLBACK find_child_proc(HWND hwnd, LPARAM lp) {
  struct child_ctx *c = (struct child_ctx *)lp;
  if (c->found)
    return TRUE;
  if (!IsWindowVisible(hwnd))
    return TRUE; // 跳过隐藏的（其线程可能被阻塞，SendMessage 会卡死）
  char cls[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  if (!strcmp(cls, c->cls))
    c->found = hwnd;
  return TRUE;
}

static void cmd_find_lv(SOCKET c, char *args) {
  char root_cls[128] = {0}, a_cls[128] = {0}, a_ttl[128] = {0}, tgt_cls[128] = {0};
  char child_cls[128] = {0};
  int off = 0;
  if (sscanf(args, "%127s %127s %127s %n", root_cls, a_cls, a_ttl, &off) < 3) {
    send_str(c, "find_lv: need root_cls anchor_cls anchor_title target_cls child_cls\n");
    return;
  }
  if (off <= 0 || sscanf(args + off, "%127s %127s", tgt_cls, child_cls) < 2) {
    send_str(c, "find_lv: need target_cls child_cls\n");
    return;
  }
  HWND target = walk_to_target(root_cls, a_cls, a_ttl, tgt_cls);
  if (!target) {
    send_str(c, "find_lv: target not found\n");
    return;
  }
  struct child_ctx cc = {child_cls, NULL};
  EnumChildWindows(target, find_child_proc, (LPARAM)&cc);
  char r[96];
  snprintf(r, sizeof(r), "lv hwnd=0x%08x\n", (unsigned)(DWORD_PTR)cc.found);
  send_str(c, r);
}

// ---------- lv_dblclick：选中并双击 SysListView32 的第 row 行 ----------
typedef struct {
  UINT mask;
  int iItem;
  int iSubItem;
  UINT state;
  UINT stateMask;
} LVITEMA2;

static void cmd_lv_dblclick(SOCKET c, char *args) {
  char a1[64] = {0}, a2[64] = {0};
  if (sscanf(args, "%63s %63s", a1, a2) < 2) {
    send_str(c, "lv_dblclick: need <list_hwnd> <row>\n");
    return;
  }
  HWND list = (HWND)(DWORD_PTR)strtoul(a1, NULL, 0);
  int row = (int)strtol(a2, NULL, 0);
  if (!IsWindow(list)) {
    send_str(c, "lv_dblclick: bad list hwnd\n");
    return;
  }
  int count = (int)lv_send(list, LVM_GETITEMCOUNT, 0, 0);
  if (row < 0 || row >= count) {
    char r[96];
    snprintf(r, sizeof(r), "lv_dblclick: row %d out of range (count=%d)\n", row, count);
    send_str(c, r);
    return;
  }
  // 选中该行
  LVITEMA2 it;
  memset(&it, 0, sizeof(it));
  it.mask = 0x0008; // LVIF_STATE
  it.iItem = row;
  it.iSubItem = 0;
  it.state = LVIS_SELECTED | LVIS_FOCUSED;
  it.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
  lv_send(list, LVM_SETITEMSTATE, (WPARAM)row, (LPARAM)&it);
  // 取行矩形中心
  RECT rc;
  rc.left = LVIR_BOUNDS;
  lv_send(list, LVM_GETITEMRECT, (WPARAM)row, (LPARAM)&rc);
  int x = (rc.left + rc.right) / 2;
  int y = (rc.top + rc.bottom) / 2;
  LPARAM lp = MAKELPARAM(x, y);
  PostMessageW(list, WM_LBUTTONDOWN, MK_LBUTTON, lp);
  PostMessageW(list, WM_LBUTTONUP, 0, lp);
  PostMessageW(list, WM_LBUTTONDBLCLK, MK_LBUTTON, lp);
  PostMessageW(list, WM_LBUTTONUP, 0, lp);
  char r[128];
  snprintf(r, sizeof(r), "dblclick list=0x%08x row=%d @(%d,%d)\n",
           (unsigned)(DWORD_PTR)list, row, x, y);
  send_str(c, r);
}

// ---------- click_dlg_btn：找 title==dlg_title 的可见 #32770 对话框，点 title==btn_text 的按钮 ----------
struct cdb_ctx {
  const char *btn;
  HWND found;
};

static BOOL CALLBACK cdb_btn_proc(HWND hwnd, LPARAM lp) {
  struct cdb_ctx *c = (struct cdb_ctx *)lp;
  if (c->found)
    return TRUE;
  char cls[64] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  if (!strcmp(cls, "Button") && !strcmp(ttl, c->btn))
    c->found = hwnd;
  return TRUE;
}

struct cdb_dlg_ctx {
  const char *dlg;
  const char *btn;
  HWND btn_hwnd;
};

static BOOL CALLBACK cdb_dlg_proc(HWND hwnd, LPARAM lp) {
  struct cdb_dlg_ctx *d = (struct cdb_dlg_ctx *)lp;
  if (d->btn_hwnd)
    return TRUE;
  DWORD pid = 0;
  GetWindowThreadProcessId(hwnd, &pid);
  if (pid != GetCurrentProcessId() || !IsWindowVisible(hwnd))
    return TRUE;
  char cls[64] = {0}, ttl[256] = {0};
  GetClassNameA(hwnd, cls, sizeof(cls));
  GetWindowTextA(hwnd, ttl, sizeof(ttl));
  if (strcmp(cls, "#32770") || strcmp(ttl, d->dlg))
    return TRUE;
  struct cdb_ctx bc = {d->btn, NULL};
  EnumChildWindows(hwnd, cdb_btn_proc, (LPARAM)&bc);
  if (bc.found)
    d->btn_hwnd = bc.found;
  return TRUE;
}

static void cmd_click_dlg_btn(SOCKET c, char *args) {
  char dlg_ttl[128] = {0}, btn_ttl[128] = {0};
  // dlg_ttl 可能含空格——用 %n 拿 btn 起始
  int off = 0;
  if (sscanf(args, "%127s %n", dlg_ttl, &off) < 1) {
    send_str(c, "click_dlg_btn: need <dlg_title> <btn_text>\n");
    return;
  }
  if (off <= 0 || off >= (int)strlen(args)) {
    send_str(c, "click_dlg_btn: need btn_text\n");
    return;
  }
  // btn_ttl 取剩余（可能含空格）
  strncpy(btn_ttl, args + off, sizeof(btn_ttl) - 1);
  // 去尾换行
  char *nl = strchr(btn_ttl, '\n');
  if (nl)
    *nl = 0;
  struct cdb_dlg_ctx d = {dlg_ttl, btn_ttl, NULL};
  EnumWindows(cdb_dlg_proc, (LPARAM)&d);
  if (!d.btn_hwnd) {
    send_str(c, "click_dlg_btn: dialog/button not found\n");
    return;
  }
  PostMessageW(d.btn_hwnd, BM_CLICK, 0, 0);
  char r[128];
  snprintf(r, sizeof(r), "clicked btn=0x%08x\n", (unsigned)(DWORD_PTR)d.btn_hwnd);
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
  } else if (!strcmp(cmd, "postcmd")) {
    cmd_postcmd(c, args);
  } else if (!strcmp(cmd, "postvia")) {
    cmd_postvia(c, args);
  } else if (!strcmp(cmd, "anchorinfo")) {
    cmd_anchorinfo(c, args);
  } else if (!strcmp(cmd, "dlgs")) {
    cmd_dlgs(c);
  } else if (!strcmp(cmd, "find_lv")) {
    cmd_find_lv(c, args);
  } else if (!strcmp(cmd, "lv_find")) {
    cmd_lv_find(c, args);
  } else if (!strcmp(cmd, "lv_dblclick")) {
    cmd_lv_dblclick(c, args);
  } else if (!strcmp(cmd, "click_dlg_btn")) {
    cmd_click_dlg_btn(c, args);
  } else if (!strcmp(cmd, "enum")) {
    cmd_enum(c, args);
  } else if (!strcmp(cmd, "find")) {
    cmd_find(c, args);
  } else if (!strcmp(cmd, "help")) {
    send_str(c,
             "cmds: ping; spy on [msg=ID|all]/off/clear/dump; post <target> "
             "<msg> <wp> <lp>; send <target> <msg> <wp> <lp>; postcmd <msg> "
             "<wp> <lp>; postvia <root_cls> <anchor_cls> <anchor_title> "
             "<target_cls> <msg> <wp> <lp>; anchorinfo <hwnd>; dlgs; find_lv "
             "<root_cls> <anc_cls> <anc_ttl> <tgt_cls> <child_cls>; lv_find "
             "<list_hwnd> <text>; lv_dblclick <list_hwnd> <row>; click_dlg_btn "
             "<dlg_title> <btn_text>; enum [hwnd]; find class=<cls> [title=<ttl>]\n");
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

#!/usr/bin/env python3
# common — 动作共享层：编译注入 shim + capture 抓命令 + 按锚点触发目标窗口。
# 无任何具体业务。操作脚本（api/*.py）顶部定义触发常量，调用 trigger() 即可走全套。
#
# 为什么不只存 CMD_ID：插件面板（如持仓/交易面板）不在主框架命令路由链里，WM_COMMAND
# 必须投递到面板本身；面板 hwnd 运行时变，但面板内工具栏的 class+title 稳定，作锚点，
# 上溯到主框架的直接子窗口即面板。root_cls/anchor_cls/anchor_title/CMD_ID 全是编译进
# 二进制的稳定量，capture 一次终身用，重启/换机（同客户端）不用重新 sync。
#
# CLI：
#   python3 scripts/common.py capture   # spy 抓 WM_COMMAND + 自动发现锚点常量，打印供操作脚本填
#   python3 scripts/common.py ping      # 确认 shim 在线
#   python3 scripts/common.py ensure    # 编译+注入
#   python3 scripts/common.py scan <pat> [ctx]  # 扫 tdxw 内存找 pat，打印 GBK 上下文（开发用，认表格式）
#
# 库 API：
#   import common
#   common.ensure()
#   common.find_tdxw_pid(); common.read_maps(pid)
#   common.trigger(ROOT_CLS, ANCHOR_CLS, ANCHOR_TITLE, TARGET_CLS, CMD_ID)
#   common.trigger(ROOT_CLS, ANCHOR_CLS, ANCHOR_TITLE, TARGET_CLS, CMD_ID, wp=.., lp=..)

import importlib.util
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(name):
    """按路径加载兄弟模块，避免顶层 import 被 formatter 上提（破坏 sys.path 顺序）。"""
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(HERE, f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


shimctl = _load("shimctl")

WM_COMMAND = 0x111


def ensure():
    return shimctl.ensure()


# ---------- 进程/内存原语（非业务，供 api/*.py 复用）----------

def find_tdxw_pid():
    out = subprocess.check_output(["ps", "-eo", "pid,comm,args"], text=True)
    for line in out.splitlines():
        if "tdxw.exe" in line.lower() and "grep" not in line:
            return line.split()[0]
    return None


def read_maps(pid):
    maps = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            p = line.split()
            a, b = p[0].split("-")
            perms = p[1]
            path = p[5] if len(p) > 5 else ""
            if "r" not in perms:
                continue
            if path.startswith("[vvar") or path.startswith("[vdso") or path == "[vsyscall]":
                continue
            maps.append((int(a, 16), int(b, 16), path))
    return maps


def scan_mem(pattern, ctx=256, max_hits=20):
    """扫 tdxw 内存找 pattern（bytes），打印每处 GBK 上下文。开发用：认明文表格式。"""
    pid = find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    pat = pattern.encode() if isinstance(pattern, str) else pattern
    mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    hits = 0
    for (s, e, path) in read_maps(pid):
        if e - s > 400 * 1024 * 1024:
            continue
        try:
            mem.seek(s)
            data = mem.read(e - s)
        except OSError:
            continue
        i = 0
        while True:
            j = data.find(pat, i)
            if j == -1:
                break
            a = max(0, j - ctx)
            b = min(len(data), j + len(pat) + ctx)
            seg = data[a:b]
            print(f"--- hit @ 0x{s + j:x} (map {path}) ---")
            print(seg.decode("gbk", errors="replace"))
            hits += 1
            if hits >= max_hits:
                mem.close()
                return
            i = j + 1
    mem.close()
    if not hits:
        print(f"(没找到 {pat!r})")


def trigger(root_cls, anchor_cls, anchor_title, target_cls, cmd_id, wp=0, lp=0):
    """PostMessage(WM_COMMAND, cmd_id, lp) 到目标窗口。
    从 root 下锚点（anchor_cls/anchor_title）向上找第一个 class==target_cls 的祖先，
    post 到那里。target_cls 由 capture 从 spy 抓到的命令接收窗口类给出（插件面板多为
    AfxWnd100，主框架路由动作填 TdxW_MainFrame_Class）。cmd_id 填 wparam 低位，wp 高位，lp 默认 0。"""
    s = shimctl.ensure()
    wparam = (cmd_id & 0xFFFF) | ((wp & 0xFFFF) << 16)
    return s.postvia(root_cls, anchor_cls, anchor_title, target_cls, WM_COMMAND, wparam, lp)


def cancel(order_id, root_cls, anchor_cls, anchor_title, target_cls,
           dlg_title, btn_text, child_cls="SysListView32", wait=0.6):
    """双击委托行撤单：找到面板里的列表视图 → 按委托号搜出真实行号 → 双击该行 →
    点确认对话框的按钮。委托号在列表视图里直接搜，不依赖内存表行序，避免撤错单。"""
    s = shimctl.ensure()
    r = s.find_lv(root_cls, anchor_cls, anchor_title, target_cls, child_cls) or ""
    m = re.search(r"lv hwnd=(0x[0-9a-f]+)", r)
    assert m, f"找不到列表视图（{child_cls}）: {r.strip()}"
    lv = m.group(1)
    r = s.lv_find(lv, str(order_id)) or ""
    m = re.search(r"row=(-?\d+)", r)
    assert m, f"列表视图里找不到委托号 {order_id}: {r.strip()}"
    row = int(m.group(1))
    assert row >= 0, f"委托号 {order_id} 不在列表视图里（row={row}）"
    print(f"[*] 双击行 {row}（委托号 {order_id}）:", s.lv_dblclick(lv, row).strip())
    time.sleep(wait)  # 等确认对话框弹出
    r = s.click_dlg_btn(dlg_title, btn_text) or ""
    print(f"[*] 点确认按钮「{btn_text}」:", r.strip())
    assert "clicked" in r, f"确认按钮没点到: {r.strip()}"
    return r


def capture():
    """spy 抓 WM_COMMAND；每抓一条就用 anchorinfo 发现锚点常量，结束时打印供操作脚本填。"""
    s = shimctl.ensure()
    s.spy_clear()
    print(s.spy_on().strip())
    print("[*] 去客户端点一次目标动作... (Ctrl+C 停)")
    seen = []
    try:
        while True:
            r = s.spy_dump()
            if r:
                for line in r.splitlines():
                    if not line or line == "end":
                        continue
                    if line not in seen:
                        seen.append(line)
                        print("  " + line)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n" + (s.spy_off() or "").strip())
    assert seen, "没抓到任何消息"
    print("\n[*] 把以下常量填到操作脚本顶部：")
    for line in seen:
        wm = re.search(r"msg=(0x[0-9a-f]+)", line)
        hm = re.search(r"hwnd=(0x[0-9a-f]+)", line)
        wpm = re.search(r"wparam=(0x[0-9a-f]+)", line)
        lpm = re.search(r"lparam=(0x[0-9a-f]+)", line)
        cm = re.search(r'class="([^"]*)"', line)
        if not (wm and hm and wpm and cm):
            continue
        if int(wm.group(1), 0) != WM_COMMAND:
            print(f"    # 非 WM_COMMAND（{wm.group(1)}），跳过")
            continue
        info = s.anchorinfo(hm.group(1)) or ""
        rc = re.search(r"root_class=(\S+)", info)
        ac = re.search(r"anchor_class=(\S+)", info)
        at = re.search(r"anchor_title=(.*)", info)
        cmd_id = int(wpm.group(1), 0) & 0xFFFF
        lpv = lpm.group(1) if lpm else "0x0"
        if rc and ac and at:
            print(f"    ROOT_CLS     = {rc.group(1)}")
            print(f"    ANCHOR_CLS   = {ac.group(1)}")
            print(f"    ANCHOR_TITLE = {at.group(1)}")
            print(f"    TARGET_CLS   = {cm.group(1)}")
            print(f"    CMD_ID       = 0x{cmd_id:04x}   # lparam={lpv}"
                  + ("  (lparam=0 命令路由，可跨重启)" if lpv == "0x00000000" else ""))
        else:
            print(f"    # hwnd={hm.group(1)} 没找到工具栏锚点（info: {info.strip()})")


def main():
    args = sys.argv[1:]
    sub = args[0] if args else "ping"
    if sub == "capture":
        capture()
    elif sub == "ping":
        print(shimctl.Shim().ping() or "(无应答)")
    elif sub == "ensure":
        shimctl.ensure()
    elif sub == "scan":
        assert len(args) >= 2, "用法: scan <pat> [ctx]"
        scan_mem(args[1], int(args[2]) if len(args) > 2 else 256)
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# shimctl — 通用 Win32 消息桥控制器（Linux 侧）。
# 负责编译/注入 shim 到 Wine 目标进程，并通过 TCP 控制通道发命令：
#   spy 抓任意窗口消息、post/send 回放任意消息、enum/find 按 class/title 解析窗口。
# 业务无关：不假设"持仓"或任何具体动作。动作由调用方按 (target, msg, wparam, lparam) 给出。
#
# 环境无关：WINEPREFIX 取环境变量或默认 ~/.wine；路径一律 __file__ 相对；编译器用
# gcc-mingw-w64-i686（自动探测，缺则 sudo apt 装）；注入用 C:\windows\temp 路径，不依赖 Z: 盘映射。
#
# 库用法：
#   from shimctl import Shim, ensure
#   ensure()                      # 编译+注入(若未在线)
#   s = Shim()
#   s.spy_on(); ...; s.spy_dump() # 抓消息
#   s.post("0x503ca", 0x111, 0x2721, 0)   # 回放
#   s.postcmd(0x111, 0x2721, 0)           # 回放命令到本进程主框架（免 target）
#   s.enum(); s.find("TdxW_Main")
#
# CLI：
#   python3 scripts/shimctl.py ensure
#   python3 scripts/shimctl.py ping
#   python3 scripts/shimctl.py spy [msg=ID|all]      # 持续 dump 直到 Ctrl+C
#   python3 scripts/shimctl.py post <target> <msg> <wp> <lp>
#   python3 scripts/shimctl.py send <target> <msg> <wp> <lp>
#   python3 scripts/shimctl.py postcmd <msg> <wp> <lp>
#   python3 scripts/shimctl.py enum [target]
#   python3 scripts/shimctl.py find class=<cls> [title=<ttl>]
# target = 0x........ 或 class=<类名>

import os
import sys
import subprocess
import socket
import hashlib
import shutil
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM_DIR = os.path.join(HERE, "shim")
INJECT_EXE = os.path.join(SHIM_DIR, "inject.exe")
BUILD_FILE = os.path.join(SHIM_DIR, ".build")
WINEPREFIX = os.environ.get("WINEPREFIX") or os.path.expanduser("~/.wine")
WINE_TEMP = os.path.join(WINEPREFIX, "drive_c", "windows", "temp")
PORT_FILE = os.path.join(WINE_TEMP, "tdx_shim_port.txt")
TARGET_PROC = os.environ.get("SHIM_TARGET_PROC", "tdxw.exe")

GCC = "i686-w64-mingw32-gcc"


# ---------- 编译 ----------

def _have(cmd):
    return shutil.which(cmd) is not None


def gcc_usable():
    return _have(GCC)


def _apt_install(pkgs):
    print(f"[*] sudo apt 安装 {' '.join(pkgs)}（会提示输密码；只此一步需要 root）")
    subprocess.run(["sudo", "apt-get", "install", "-y", *pkgs], check=True)


def ensure_compiler():
    if gcc_usable():
        return
    _apt_install(["gcc-mingw-w64-i686"])
    assert gcc_usable(), "安装后仍无可用交叉编译器"


def _gcc_base():
    return [GCC]


def _src_hash():
    h = hashlib.sha1()
    for n in ("shim.c", "inject.c"):
        with open(os.path.join(SHIM_DIR, n), "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:8]


def _write_build(dll_name, port):
    with open(BUILD_FILE, "w") as f:
        f.write(f"{dll_name}\n{port}\n")


def build_info():
    if not os.path.exists(BUILD_FILE):
        return None, None
    lines = open(BUILD_FILE).read().splitlines()
    if len(lines) < 2:
        return None, None
    return lines[0].strip() or None, int(lines[1])


def ctrl_port():
    _, port = build_info()
    return port or 17703


def _try_compile(base):
    H = _src_hash()
    dll_name = f"shim_{H}.dll"
    dll_path = os.path.join(SHIM_DIR, dll_name)
    port = 20000 + int(H, 16) % 10000
    if os.path.exists(dll_path):
        _write_build(dll_name, port)
        print(f"[*] {dll_name} 已构建，跳过编译（端口 {port}）")
        return
    ensure_compiler()
    print(f"[*] 编译 {dll_name} / inject.exe（端口 {port}）")
    subprocess.run(base + ["-shared", "-o", dll_path, "shim.c", "-lws2_32", "-luser32", "-lkernel32"],
                   cwd=SHIM_DIR, check=True)
    subprocess.run(base + ["-o", INJECT_EXE, "inject.c",
                   "-lkernel32"], cwd=SHIM_DIR, check=True)
    assert os.path.exists(dll_path) and os.path.exists(INJECT_EXE), "编译后产物仍缺失"
    _write_build(dll_name, port)


def build():
    if not gcc_usable():
        ensure_compiler()
    print("[*] 用 gcc")
    _try_compile(_gcc_base())


# ---------- 注入 ----------

def _write_port_file():
    os.makedirs(WINE_TEMP, exist_ok=True)
    with open(PORT_FILE, "w") as f:
        f.write(str(ctrl_port()))


def _copy_dll_to_wine():
    """把 shim DLL 拷进 wine 的 C:\\windows\\temp，返回 Windows 路径（不依赖 Z: 盘）。"""
    dll_name, _ = build_info()
    assert dll_name, "shim 未构建（先 build）"
    src = os.path.join(SHIM_DIR, dll_name)
    os.makedirs(WINE_TEMP, exist_ok=True)
    dst = os.path.join(WINE_TEMP, dll_name)
    shutil.copyfile(src, dst)
    return f"C:\\windows\\temp\\{dll_name}"


def inject():
    dll_win = _copy_dll_to_wine()
    _write_port_file()
    print(f"[*] 注入 {dll_win}（pid 由 inject.exe 自找 {TARGET_PROC}）")
    r = subprocess.run(["wine", INJECT_EXE, dll_win,
                       TARGET_PROC], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit(f"注入失败 rc={r.returncode}")


# ---------- Shim 控制通道 ----------

class Shim:
    def __init__(self, port=None):
        self.port = port or ctrl_port()

    def _cmd(self, line, timeout=3):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect(("127.0.0.1", self.port))
            s.sendall(line.encode("gbk") + b"\n")
            chunks = []
            while True:
                try:
                    d = s.recv(4096)
                except socket.timeout:
                    break
                if not d:
                    break
                chunks.append(d)
                if b"end\n" in b"".join(chunks):
                    break
            return b"".join(chunks).decode("gbk", errors="replace")
        except OSError:
            return None
        finally:
            s.close()

    def ping(self):
        r = self._cmd("ping")
        return r.strip() if r else None

    def spy_on(self, filt=None):
        # filt: None=默认WM_COMMAND, "all", 或 "msg=0x..."
        arg = "on" if filt is None else f"on {filt}"
        return self._cmd(f"spy {arg}")

    def spy_off(self):
        return self._cmd("spy off")

    def spy_clear(self):
        return self._cmd("spy clear")

    def spy_dump(self):
        return self._cmd("spy dump")

    def post(self, target, msg, wp, lp):
        return self._cmd(f"post {target} {msg} {wp} {lp}")

    def send(self, target, msg, wp, lp):
        return self._cmd(f"send {target} {msg} {wp} {lp}")

    def postcmd(self, msg, wp, lp):
        return self._cmd(f"postcmd {msg} {wp} {lp}")

    def postvia(self, root_cls, anchor_cls, anchor_title, target_cls, msg, wp, lp):
        return self._cmd(f"postvia {root_cls} {anchor_cls} {anchor_title} {target_cls} {msg} {wp} {lp}")

    def anchorinfo(self, hwnd):
        return self._cmd(f"anchorinfo {hwnd}")

    def dlgs(self):
        return self._cmd("dlgs")

    def find_lv(self, root_cls, anchor_cls, anchor_title, target_cls, child_cls):
        return self._cmd(f"find_lv {root_cls} {anchor_cls} {anchor_title} {target_cls} {child_cls}")

    def lv_find(self, list_hwnd, text):
        return self._cmd(f"lv_find {list_hwnd} {text}")

    def lv_dblclick(self, list_hwnd, row):
        return self._cmd(f"lv_dblclick {list_hwnd} {row}")

    def click_dlg_btn(self, dlg_title, btn_text):
        return self._cmd(f"click_dlg_btn {dlg_title} {btn_text}")

    def enum(self, target=""):
        return self._cmd(f"enum {target}")

    def find(self, cls, title=None):
        arg = f"class={cls}" + (f" title={title}" if title else "")
        return self._cmd(f"find {arg}")


def ensure():
    """编译+注入直到 shim 在线。已在线则跳过。"""
    build()
    s = Shim()
    if s.ping():
        print(f"[+] shim 在线: {s.ping()}")
        return s
    inject()
    pong = s.ping()
    assert pong, f"shim 注入后 ping 无应答（端口 {s.port}）"
    print(f"[+] shim 在线: {pong}")
    return s


# ---------- CLI ----------

def _parse_int(x):
    return int(x, 0)


def main():
    args = sys.argv[1:]
    sub = args[0] if args else "ensure"
    if sub == "build":
        build()
        return
    if sub == "ensure":
        ensure()
        return
    if sub == "ping":
        print(Shim().ping() or "(无应答)")
        return
    if sub == "inject":
        inject()
        return
    if sub == "spy":
        filt = args[1] if len(args) > 1 else None
        s = ensure()
        print(s.spy_clear().strip())
        print(s.spy_on(filt).strip())
        print("[*] spy 已开，操作客户端 UI 抓消息... (Ctrl+C 停)")
        seen = set()
        try:
            while True:
                r = s.spy_dump()
                if r:
                    for line in r.splitlines():
                        if not line or line == "end":
                            continue
                        if line not in seen:
                            seen.add(line)
                            print("  " + line)
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n" + (s.spy_off() or "").strip())
    elif sub == "post":
        s = ensure()
        target, msg, wp, lp = args[1], _parse_int(
            args[2]), _parse_int(args[3]), _parse_int(args[4])
        print(s.post(target, msg, wp, lp).strip())
    elif sub == "send":
        s = ensure()
        target, msg, wp, lp = args[1], _parse_int(
            args[2]), _parse_int(args[3]), _parse_int(args[4])
        print(s.send(target, msg, wp, lp).strip())
    elif sub == "postcmd":
        s = ensure()
        msg, wp, lp = _parse_int(args[1]), _parse_int(
            args[2]), _parse_int(args[3])
        print(s.postcmd(msg, wp, lp).strip())
    elif sub == "postvia":
        s = ensure()
        root_cls, anchor_cls, anchor_title, target_cls = args[1], args[2], args[3], args[4]
        msg, wp, lp = _parse_int(args[5]), _parse_int(
            args[6]), _parse_int(args[7])
        print(s.postvia(root_cls, anchor_cls, anchor_title, target_cls, msg, wp, lp).strip())
    elif sub == "anchorinfo":
        s = ensure()
        print(s.anchorinfo(args[1]).strip())
    elif sub == "dlgs":
        s = ensure()
        print(s.dlgs(), end="")
    elif sub == "find_lv":
        s = ensure()
        assert len(args) >= 6, "need root_cls anchor_cls anchor_title target_cls child_cls"
        print(s.find_lv(*args[1:6]).strip())
    elif sub == "lv_find":
        s = ensure()
        assert len(args) >= 3, "need <list_hwnd> <text>"
        print(s.lv_find(args[1], args[2]).strip())
    elif sub == "lv_dblclick":
        s = ensure()
        assert len(args) >= 3, "need <list_hwnd> <row>"
        print(s.lv_dblclick(args[1], args[2]).strip())
    elif sub == "click_dlg_btn":
        s = ensure()
        assert len(args) >= 3, "need <dlg_title> <btn_text>"
        print(s.click_dlg_btn(args[1], args[2]).strip())
    elif sub == "enum":
        s = ensure()
        target = args[1] if len(args) > 1 else ""
        print(s.enum(target), end="")
    elif sub == "find":
        s = ensure()
        cls = title = None
        for a in args[1:]:
            if a.startswith("class="):
                cls = a.split("=", 1)[1]
            elif a.startswith("title="):
                title = a.split("=", 1)[1]
        print(s.find(cls, title).strip())
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()

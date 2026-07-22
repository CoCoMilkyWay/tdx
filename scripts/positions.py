#!/usr/bin/env python3
# 一键：编译 shim → 注入到 TdxW.exe → 控制通道 → 消息 spy / 主动 refresh → 读持仓 → 展示。
# 一条命令走完：python3 scripts/positions.py
# 缺交叉编译运行时时只对 apt 那步走 sudo（会提示输密码）；其余按当前用户跑。
# 注意：不要整脚本 sudo——wine 会切到 root 的 WINEPREFIX，看不到你正在跑的 tdxw。
#
# 子命令：
#   python3 scripts/positions.py            # poll：编译+注入+ping+被动读持仓+表格
#   python3 scripts/positions.py spy        # 抓「刷新持仓」的 WM_COMMAND（去 UI 点一次刷新）
#   python3 scripts/positions.py refresh    # 主动触发客户端刷新持仓，再读新鲜内存展示
#   python3 scripts/positions.py --no-inject  # poll 但跳过编译注入（shim 已在）
#
# 阶段2 配置：spy 抓到 (hwnd, wparam, lparam) 后写入
#   C:\windows\temp\tdx_shim_target.txt（即 ~/.wine/drive_c/windows/temp/tdx_shim_target.txt）
#   第一行 hwnd（0x...）或 class=类名，第二行 wparam（0x...），第三行 lparam（0x...）。
#   之后 `positions.py refresh` 即主动刷新。
#
# 前提：客户端已登录交易。poll/refresh 读内存还需持仓窗口至少打开过一次。

import sys, os, re, subprocess, json, socket

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM_DIR = os.path.join(HERE, "shim")
INJECT_EXE = os.path.join(SHIM_DIR, "inject.exe")
BUILD_FILE = os.path.join(SHIM_DIR, ".build")
WINE_TEMP = os.path.expanduser("~/.wine/drive_c/windows/temp")
SHIM_PORT_FILE = os.path.join(WINE_TEMP, "tdx_shim_port.txt")
GCC = "i686-w64-mingw32-gcc"


# ---------- 构建信息 ----------
# shim 改动后用源码哈希做唯一 DLL 名 + 端口，这样再注入是全新加载（DllMain 重跑），
# 不用重启客户端就能换上新 shim。旧 shim 仍留在进程里监听旧端口，无害。
import hashlib


def _src_hash():
    h = hashlib.sha1()
    for n in ("shim.c", "inject.c", "target.h"):
        with open(os.path.join(SHIM_DIR, n), "rb") as f:
            h.update(f.read())
    return h.hexdigest()[:8]


def _write_build(dll_name, port):
    with open(BUILD_FILE, "w") as f:
        f.write(f"{dll_name}\n{port}\n")


def _build_info():
    """返回 (dll_name, port)。没构建过返回 (None, None)。"""
    if not os.path.exists(BUILD_FILE):
        return None, None
    lines = open(BUILD_FILE).read().splitlines()
    if len(lines) < 2:
        return None, None
    return lines[0].strip() or None, int(lines[1])


def _ctrl_port():
    _, port = _build_info()
    return port or 17703


# ---------- 编译 ----------

def ensure_compiler():
    r = subprocess.run(["which", GCC], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return
    print(f"[*] 未找到 {GCC}，sudo apt 安装 gcc-mingw-w64-i686（会提示输密码）")
    # 只这一步需要 root；编译/注入/读内存都不需要 sudo，且整脚本用 sudo 跑会切到 root 的
    # WINEPREFIX，看不到 chuyin prefix 里正在跑的 tdxw，所以不能整脚本 sudo。
    subprocess.run(["sudo", "apt-get", "install", "-y", "gcc-mingw-w64-i686"], check=True)
    r2 = subprocess.run(["which", GCC], capture_output=True, text=True)
    assert r2.returncode == 0 and r2.stdout.strip(), f"{GCC} 安装后仍不可用"


def compile_shim():
    """编译 shim_<hash>.dll + inject.exe（32 位匹配 TdxW）。源码没变则跳过。"""
    H = _src_hash()
    dll_name = f"shim_{H}.dll"
    dll_path = os.path.join(SHIM_DIR, dll_name)
    port = 20000 + int(H, 16) % 10000
    if os.path.exists(dll_path):
        _write_build(dll_name, port)
        print(f"[*] {dll_name} 已构建，跳过编译（控制端口 {port}）")
        return
    ensure_compiler()
    print(f"[*] 编译 {dll_name} / inject.exe（控制端口 {port}）")
    subprocess.run([GCC, "-shared", "-o", dll_path, "shim.c",
                    "-lws2_32", "-luser32", "-lkernel32"],
                   cwd=SHIM_DIR, check=True)
    subprocess.run([GCC, "-o", INJECT_EXE, "inject.c", "-lkernel32"],
                   cwd=SHIM_DIR, check=True)
    assert os.path.exists(dll_path) and os.path.exists(INJECT_EXE), "编译后产物仍缺失"
    _write_build(dll_name, port)


# ---------- shim 注入 ----------

def to_windows_path(p):
    # Wine 默认 Z: 映射到 /，所以 /home/... → Z:\home\...
    return "Z:" + p.replace("/", "\\")


def inject_shim():
    dll_name, port = _build_info()
    assert dll_name, "shim 未构建（先 compile_shim）"
    dll_path = os.path.join(SHIM_DIR, dll_name)
    assert os.path.exists(dll_path) and os.path.exists(INJECT_EXE), "shim 产物缺失（编译失败？）"
    dll_win = to_windows_path(dll_path)
    print(f"[*] 注入 {dll_win}")
    r = subprocess.run(["wine", INJECT_EXE, dll_win], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit(f"注入失败 rc={r.returncode}")


def send_cmd(cmd, timeout=2):
    """连控制通道发一行命令，返回应答文本。连不上返回 None。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", _ctrl_port()))
        s.sendall(cmd.encode() + b"\n")
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
        return b"".join(chunks).decode(errors="replace")
    except OSError:
        return None
    finally:
        s.close()


def ping_shim(timeout=2):
    r = send_cmd("ping", timeout)
    return r.strip() if r else None


def ensure_shim():
    """确保当前源码版本对应的 shim 已注入且在线。先编译（写 .build 定端口），再 ping，不通才注入。"""
    compile_shim()
    pong = ping_shim()
    if pong:
        print(f"[+] shim 在线: {pong}")
        return
    _write_port_file()
    inject_shim()
    pong = ping_shim()
    assert pong, f"shim 注入后 ping 无应答（端口 {_ctrl_port()}）"
    print(f"[+] shim 在线: {pong}")


def _write_port_file():
    """注入前把控制端口写进 wine 侧文件，shim 启动时读它决定监听端口。"""
    os.makedirs(WINE_TEMP, exist_ok=True)
    with open(SHIM_PORT_FILE, "w") as f:
        f.write(str(_ctrl_port()))


# ---------- 持仓读取（被动：扫 TdxW 内存里解密后的明文表）----------

HEADER = b"0||28||P00"


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


def find_best_block(pid):
    mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    best = None  # (row_count, block_bytes)
    for (s, e, path) in read_maps(pid):
        if e - s > 400 * 1024 * 1024:
            continue
        try:
            mem.seek(s)
            data = mem.read(e - s)
        except OSError:
            continue
        h = 0
        while True:
            ho = data.find(HEADER, h)
            if ho == -1:
                break
            j = data.find(b"\r\n", ho)
            if j == -1:
                break
            j += 2
            rows = 0
            end = j
            while j < len(data):
                nl = data.find(b"\r\n", j)
                if nl == -1:
                    break
                line = data[j:nl]
                if re.match(rb"\d{6}\|", line) and line.count(b"|") >= 5:
                    rows += 1
                    end = nl + 2
                    j = nl + 2
                else:
                    break
            if rows > 0:
                block = data[ho:end]
                if best is None or rows > best[0]:
                    best = (rows, block)
            h = ho + 1
    mem.close()
    return best[1] if best else None


def parse(block):
    text = block.decode("gbk", errors="replace")
    positions = []
    for ln in text.split("\r\n"):
        if not re.match(r"\d{6}\|", ln):
            continue
        f = ln.split("|")
        nf = len(f)
        if nf < 15:
            continue
        if nf >= 22:
            i_cost, i_price, i_mv, i_pnl, i_pnlp, i_mkt, i_sh = 8, 9, 10, 11, 12, 14, 19
        else:
            i_cost, i_price, i_mv, i_pnl, i_pnlp, i_mkt, i_sh = 7, 8, 9, 10, 11, 13, 15

        def num(x):
            try:
                return float(x)
            except ValueError:
                return None

        def get(i):
            return num(f[i]) if i < nf else None

        positions.append({
            "code": f[0],
            "name": f[1],
            "balance": num(f[3]),
            "available": num(f[4]),
            "cost": get(i_cost),
            "price": get(i_price),
            "market_value": get(i_mv),
            "pnl": get(i_pnl),
            "pnl_pct": get(i_pnlp),
            "market_flag": int(f[i_mkt]) if i_mkt < nf and f[i_mkt].isdigit() else None,
            "shareholder": f[i_sh] if i_sh < nf else "",
        })
    return positions


# ---------- 展示 ----------

def disp_w(s):
    w = 0
    for ch in str(s):
        w += 2 if ord(ch) > 0x2E80 else 1
    return w


def rpad(s, w):
    s = str(s)
    return s + " " * max(0, w - disp_w(s))


def print_table(positions):
    cols = ["Code", "Name", "余额", "可用", "成本", "现价", "市值", "浮盈", "盈亏%"]
    widths = [7, 8, 10, 10, 8, 8, 12, 12, 8]
    print(" ".join(rpad(c, widths[i]) for i, c in enumerate(cols)))
    print("-" * sum(widths + [len(widths)]))
    for p in positions:
        print(" ".join([
            rpad(p["code"], widths[0]),
            rpad(p["name"], widths[1]),
            rpad(p["balance"], widths[2]),
            rpad(p["available"], widths[3]),
            rpad(p["cost"], widths[4]),
            rpad(p["price"], widths[5]),
            rpad(p["market_value"], widths[6]),
            rpad(p["pnl"], widths[7]),
            rpad(p["pnl_pct"], widths[8]),
        ]))


# ---------- 子命令：spy / refresh / poll ----------

def cmd_spy():
    """消息 spy：hook 客户端 UI 线程，捕获点「刷新持仓」时的 WM_COMMAND。
    用法：python3 scripts/positions.py spy
    然后在客户端点一次刷新持仓，本脚本打印捕获的 hwnd/cmd_id；Ctrl+C 停。"""
    import time
    ensure_shim()
    r = send_cmd("spy clear")
    r = send_cmd("spy on")
    print(f"[*] {r.strip()}")
    print("[*] 现在去客户端点一次「刷新持仓」... (Ctrl+C 停止 spy)")
    seen = set()
    try:
        while True:
            r = send_cmd("spy dump", timeout=3)
            if r:
                for line in r.splitlines():
                    if not line or line == "end":
                        continue
                    if line not in seen:
                        seen.add(line)
                        print("  " + line)
            time.sleep(1)
    except KeyboardInterrupt:
        send_cmd("spy off")
        print("\n[*] spy off")
        if seen:
            print("[*] 把你要的那条 WM_COMMAND 的三行填进")
            print("    C:\\windows\\temp\\tdx_shim_target.txt（即 ~/.wine/drive_c/windows/temp/tdx_shim_target.txt）")
            print("    第一行 hwnd（0x...）或 class=类名，第二行 wparam（0x...），第三行 lparam（0x...）")
            print("    之后 `python3 scripts/positions.py refresh` 即可主动触发刷新。")


def cmd_refresh():
    """主动触发客户端刷新持仓，然后读新鲜内存展示。"""
    ensure_shim()
    r = send_cmd("refresh")
    print(f"[*] {r.strip()}")
    if "no target" in r or "no wparam" in r:
        print("先跑 `python3 scripts/positions.py spy` 并在客户端点一次刷新持仓，再 refresh", file=sys.stderr)
        sys.exit(1)
    import time
    time.sleep(0.8)  # 等客户端完成查询、明文落堆
    _poll_and_print()


def _poll_and_print():
    pid = find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    block = find_best_block(pid)
    if not block:
        print("内存里没持仓表，先在客户端点一次持仓查询", file=sys.stderr)
        sys.exit(1)
    positions = parse(block)
    if not positions:
        print("持仓为空", file=sys.stderr)
        sys.exit(1)
    print(f"\n=== 持仓 {len(positions)} 只 ===")
    print_table(positions)


# ---------- 主流程 ----------

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sub = args[0] if args else "poll"

    if sub == "spy":
        cmd_spy()
        return
    if sub == "refresh":
        cmd_refresh()
        return
    # 默认 poll：编译 + 注入 + ping + 被动读持仓 + 表格
    if "--no-inject" not in sys.argv:
        ensure_shim()
    else:
        print("[*] 跳过注入（--no-inject）")
    _poll_and_print()


if __name__ == "__main__":
    main()

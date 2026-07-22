#!/usr/bin/env python3
# 一键：编译 shim → 注入到 TdxW.exe → 验证控制通道 → 读持仓 → 展示。
# 一条命令走完：sudo python3 scripts/positions.py
# 缺交叉编译器会自动 apt 装 gcc-mingw-w64-i686（所以需要 root/sudo）。
#
# 当前（阶段1）：编译 + 注入 + ping/pong 证明 + 被动读内存持仓。
# TODO（阶段2）：shim 的 refresh 命令触发客户端内部刷新持仓（触发点待 RE 填 target.h），
#               届时本脚本发 "refresh" 再读新鲜内存，不再依赖 UI 先点一次。
#
# 前提：客户端已登录交易。被动读还需 UI 点过一次持仓查询；阶段2 完成后免去此步。
# 需要可读 /proc/<pid>/mem：建议 sudo 跑。
#
# 用法：
#   sudo python3 scripts/positions.py            # 编译 + 注入 + ping + 读持仓 + 表格
#   sudo python3 scripts/positions.py --no-inject  # 跳过编译注入，只读持仓（shim 已在）

import sys, os, re, subprocess, json, socket

HERE = os.path.dirname(os.path.abspath(__file__))
SHIM_DIR = os.path.join(HERE, "shim")
SHIM_DLL = os.path.join(SHIM_DIR, "shim.dll")
INJECT_EXE = os.path.join(SHIM_DIR, "inject.exe")
CTRL_PORT = 17703
GCC = "i686-w64-mingw32-gcc"


# ---------- 编译 ----------

def ensure_compiler():
    r = subprocess.run(["which", GCC], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return
    print(f"[*] 未找到 {GCC}，apt 安装 gcc-mingw-w64-i686（需要 root/sudo）")
    subprocess.run(["apt-get", "install", "-y", "gcc-mingw-w64-i686"], check=True)


def _newest(*paths):
    return max(os.path.getmtime(p) for p in paths)


def compile_shim():
    """编译 shim.dll + inject.exe（32 位匹配 TdxW）。已是最新则跳过。"""
    srcs = [os.path.join(SHIM_DIR, "shim.c"),
            os.path.join(SHIM_DIR, "inject.c"),
            os.path.join(SHIM_DIR, "target.h")]
    if os.path.exists(SHIM_DLL) and os.path.exists(INJECT_EXE) \
            and os.path.getmtime(SHIM_DLL) >= _newest(*srcs) \
            and os.path.getmtime(INJECT_EXE) >= _newest(*srcs):
        print("[*] shim.dll/inject.exe 已是最新，跳过编译")
        return
    ensure_compiler()
    print("[*] 编译 shim.dll / inject.exe")
    subprocess.run([GCC, "-shared", "-o", SHIM_DLL, "shim.c",
                    "-lws2_32", "-luser32", "-lkernel32"],
                   cwd=SHIM_DIR, check=True)
    subprocess.run([GCC, "-o", INJECT_EXE, "inject.c", "-lkernel32"],
                   cwd=SHIM_DIR, check=True)
    assert os.path.exists(SHIM_DLL) and os.path.exists(INJECT_EXE), "编译后产物仍缺失"


# ---------- shim 注入 ----------

def to_windows_path(p):
    # Wine 默认 Z: 映射到 /，所以 /home/... → Z:\home\...
    return "Z:" + p.replace("/", "\\")


def inject_shim():
    assert os.path.exists(INJECT_EXE) and os.path.exists(SHIM_DLL), "shim 产物缺失（编译失败？）"
    dll_win = to_windows_path(SHIM_DLL)
    print(f"[*] 注入 {dll_win}")
    r = subprocess.run(["wine", INJECT_EXE, dll_win], capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        sys.stderr.write(r.stderr)
        raise SystemExit(f"注入失败 rc={r.returncode}")


def ping_shim(timeout=2):
    """连控制通道发 ping，返回应答字符串。连不上返回 None。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", CTRL_PORT))
        s.sendall(b"ping\n")
        data = s.recv(256).decode(errors="replace").strip()
        return data
    except OSError:
        return None
    finally:
        s.close()


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


# ---------- 主流程 ----------

def main():
    do_inject = "--no-inject" not in sys.argv

    if do_inject:
        compile_shim()
        inject_shim()
        pong = ping_shim()
        assert pong, "shim 注入后 ping 无应答（检查 wine 输出 / 端口 17703）"
        print(f"[+] shim 在线: {pong}")
    else:
        print("[*] 跳过注入（--no-inject）")

    # TODO 阶段2：这里发 "refresh" 触发客户端刷新持仓，再读新鲜内存。
    #   s = socket.create_connection(("127.0.0.1", CTRL_PORT)); s.sendall(b"refresh\n"); print(s.recv(256).decode())

    pid = find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    block = find_best_block(pid)
    if not block:
        print("内存里没持仓表，先在客户端点一次持仓查询（阶段2 完成后可免去）", file=sys.stderr)
        sys.exit(1)
    positions = parse(block)
    if not positions:
        print("持仓为空", file=sys.stderr)
        sys.exit(1)
    print(f"\n=== 持仓 {len(positions)} 只 ===")
    print_table(positions)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
# positions — 持仓工具：读 TdxW.exe 内存里的持仓明文表 + 展示，并可主动触发客户端刷新持仓。
# 控制逻辑（注入/spy/post）全部委托给通用 shimctl；本文件只管"持仓"这一业务。
#
# 子命令：
#   python3 scripts/positions.py             # poll：读内存持仓 + 表格（被动，需客户端点过一次查询）
#   python3 scripts/positions.py refresh     # 主动触发客户端刷新持仓，再读新鲜内存 + 表格
#   python3 scripts/positions.py capture     # spy 抓「刷新持仓」的 WM_COMMAND 存进 .refresh
#   python3 scripts/positions.py --no-shim   # poll 但不注入 shim（纯被动读）
#
# 刷新动作配置 scripts/.refresh 四行：target（0x.. 或 class=类名）、msg、wparam、lparam。
# capture 会自动写它（优先用 class，跨重启稳定）。换电脑/重启客户端后重跑一次 capture 即可。
#
# 前提：客户端已登录交易，持仓窗口至少打开过一次。

from shimctl import Shim
import shimctl
import os
import sys
import re
import subprocess
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

REFRESH_CFG = os.path.join(HERE, ".refresh")
HEADER = b"0||28||P00"


# ---------- 持仓读取（扫 TdxW 内存里解密后的明文表）----------

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
            "code": f[0], "name": f[1],
            "balance": num(f[3]), "available": num(f[4]),
            "cost": get(i_cost), "price": get(i_price),
            "market_value": get(i_mv), "pnl": get(i_pnl), "pnl_pct": get(i_pnlp),
            "market_flag": int(f[i_mkt]) if i_mkt < nf and f[i_mkt].isdigit() else None,
            "shareholder": f[i_sh] if i_sh < nf else "",
        })
    return positions


# ---------- 展示 ----------

def disp_w(s):
    return sum(2 if ord(c) > 0x2E80 else 1 for c in str(s))


def rpad(s, w):
    s = str(s)
    return s + " " * max(0, w - disp_w(s))


def print_table(positions):
    cols = ["Code", "Name", "余额", "可用", "成本", "现价", "市值", "浮盈", "盈亏%"]
    widths = [7, 8, 10, 10, 8, 8, 12, 12, 8]
    print(" ".join(rpad(c, widths[i]) for i, c in enumerate(cols)))
    print("-" * (sum(widths) + len(widths)))
    for p in positions:
        print(" ".join([
            rpad(p["code"], widths[0]), rpad(p["name"], widths[1]),
            rpad(p["balance"], widths[2]), rpad(p["available"], widths[3]),
            rpad(p["cost"], widths[4]), rpad(p["price"], widths[5]),
            rpad(p["market_value"], widths[6]), rpad(p["pnl"], widths[7]),
            rpad(p["pnl_pct"], widths[8]),
        ]))


def poll_and_print():
    pid = find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    block = find_best_block(pid)
    if not block:
        print("内存里没持仓表，先在客户端点一次持仓查询", file=sys.stderr)
        sys.exit(1)
    positions = parse(block)
    assert positions, "持仓为空"
    print(f"\n=== 持仓 {len(positions)} 只 ===")
    print_table(positions)


# ---------- 刷新动作（用通用 shimctl 的 post）----------

def load_refresh_cfg():
    if not os.path.exists(REFRESH_CFG):
        return None
    lines = open(REFRESH_CFG).read().splitlines()
    if len(lines) < 4:
        return None
    return lines  # [target, msg, wparam, lparam]


def save_refresh_cfg(target, msg, wp, lp):
    with open(REFRESH_CFG, "w") as f:
        f.write(f"{target}\n{msg}\n{wp}\n{lp}\n")


def cmd_refresh():
    cfg = load_refresh_cfg()
    assert cfg, f"没有刷新配置，先跑 `python3 scripts/positions.py capture`"
    target, msg, wp, lp = cfg
    s = shimctl.ensure()
    r = s.post(target, int(msg, 0), int(wp, 0), int(lp, 0))
    print(f"[*] {r.strip()}")
    if "not found" in (r or "") or "msg=0?" in (r or ""):
        print("post 失败，重跑 capture 抓一次", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.8)  # 等客户端完成查询、明文落堆
    poll_and_print()


def cmd_capture():
    """spy 抓刷新持仓的 WM_COMMAND，写进 .refresh（优先用 class，跨重启稳定）。"""
    s = shimctl.ensure()
    s.spy_clear()
    print(s.spy_on().strip())
    print("[*] 现在去客户端点一次「刷新持仓」... (Ctrl+C 停)")
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
    last = seen[-1]
    # 解析 msg=.. hwnd=.. class=".." wparam=.. lparam=..
    # target 用 hwnd（本会话正确）。class= 对子窗口不可靠（FindWindow 只匹配顶层），故不采用。
    # 重启客户端/换机后 hwnd 会变，重跑一次 capture（点一下刷新）即可。
    msg = re.search(r"msg=(0x[0-9a-f]+)", last).group(1)
    wp = re.search(r"wparam=(0x[0-9a-f]+)", last).group(1)
    lp = re.search(r"lparam=(0x[0-9a-f]+)", last).group(1)
    hwnd = re.search(r"hwnd=(0x[0-9a-f]+)", last).group(1)
    save_refresh_cfg(hwnd, msg, wp, lp)
    print(f"[*] 已存 {REFRESH_CFG}: target={hwnd} msg={msg} wp={wp} lp={lp}")
    print("[*] 现在可跑 `python3 scripts/positions.py refresh` 主动刷新")
    print("[*] 重启客户端/换机后 hwnd 失效，重跑一次 capture 即可")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    sub = args[0] if args else "poll"
    use_shim = "--no-shim" not in sys.argv

    if sub == "capture":
        cmd_capture()
        return
    if sub == "refresh":
        cmd_refresh()
        return
    # poll：被动读。默认不注入 shim（纯读内存不需要）；--shim 才注入。
    if use_shim and "--shim" in sys.argv:
        shimctl.ensure()
    poll_and_print()


if __name__ == "__main__":
    main()

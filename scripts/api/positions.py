#!/usr/bin/env python3
# positions — 持仓：触发客户端刷新持仓 + 读内存明文表 + 表格展示。
# 跑一下就走全套：trigger 刷新 → 等客户端落堆 → 读内存 → 打印。
#
# 触发常量来自 capture：`python3 scripts/common.py capture` 后在客户端点一次「刷新持仓」。
# 全是编译进二进制的稳定量，重启/换机（同客户端）不变，capture 一次终身用。

import importlib.util
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.dirname(HERE)


def _load(name, base):
    """按路径加载兄弟模块，避免顶层 import 被 formatter 上提（破坏 sys.path 顺序）。"""
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(base, f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


common = _load("common", SCRIPTS)

ROOT_CLS = "TdxW_MainFrame_Class"   # 主框架类
ANCHOR_CLS = "MHPToolBar"            # 持仓面板内工具栏类
ANCHOR_TITLE = "MainViewBar"         # 工具栏标题（程序化名，稳定）
TARGET_CLS = "AfxWnd100"             # 命令接收窗口类（从锚点向上找第一个此类的祖先）
CMD_ID = 0x2721                     # 刷新持仓（lparam=0 命令路由，可跨重启）

HEADER = b"0||28||P00"


# ---------- 持仓读取（扫 TdxW 内存里解密后的明文表）----------

def find_best_block(pid):
    mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    best = None  # (row_count, block_bytes)
    for (s, e, path) in common.read_maps(pid):
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
    pid = common.find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    block = find_best_block(pid)
    if not block:
        print("内存里没持仓表，先在客户端点一次持仓查询", file=sys.stderr)
        sys.exit(1)
    positions = parse(block)
    assert positions, "持仓为空"
    print(f"\n=== 持仓 {len(positions)} 只 ===")
    print_table(positions)


def main():
    r = common.trigger(ROOT_CLS, ANCHOR_CLS, ANCHOR_TITLE, TARGET_CLS, CMD_ID).strip()
    print("[*] trigger 刷新持仓:", r)
    if "not found" in r or "msg=0?" in r:
        print("post 失败，重跑 `python3 scripts/common.py capture` 抓一次", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.8)  # 等客户端完成查询、明文落堆
    poll_and_print()


if __name__ == "__main__":
    main()

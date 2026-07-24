#!/usr/bin/env python3
# orders — 当日委托：触发客户端查询委托 + 读内存明文委托表 + 表格展示。
# 跑一下就走全套：trigger 查询 → 等客户端落堆 → 读内存 → 打印。
#
# 触发常量来自 capture：`python3 scripts/common.py capture` 后在客户端点一次「当日委托」查询。
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
ANCHOR_CLS = "MHPToolBar"            # 委托面板内工具栏类
ANCHOR_TITLE = "MainViewBar"         # 工具栏标题（程序化名，稳定）
TARGET_CLS = "AfxWnd100"             # 命令接收窗口类
CMD_ID = 0x271a                     # 当日委托查询（lparam=0 命令路由，可跨重启）

# 委托表行：时间|代码|名称|名称|...|买卖|类型|状态|价格|数量|委托号|已成价|已成量|...
ROW = re.compile(rb"\d{2}:\d{2}:\d{2}\|\d{6}\|")
# 表头：0||<count>||P（持仓表头是 0||28||P00，委托表头是 0||2||P|，公共前缀 0||<n>||P）
HEADER = re.compile(rb"0\|\|\d+\|\|P")

# 撤单确认对话框（dlgs 命令查到的）：title=提示，确定按钮 id=7015
DLG_TITLE = "提示"
DLG_BTN = "确定"


# ---------- 委托读取（扫 TdxW 内存里解密后的明文表）----------

def find_orders_block(pid):
    """找委托明文表：定位表头 0||<n>||P，取其后连续的时间行。
    内存里有多份快照（撤单后旧的还在），取最后一份（地址最高 = 最新分配的缓冲）。"""
    mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    best = None  # (row_count, addr, block_bytes)
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
            ho = HEADER.search(data, h)
            if ho is None:
                break
            # 跳到表头行尾
            j = data.find(b"\n", ho.end())
            if j == -1:
                break
            j += 1
            rows = 0
            end = j
            while j < len(data):
                nl = data.find(b"\n", j)
                if nl == -1:
                    break
                line = data[j:nl]
                if line.endswith(b"\r"):
                    line = line[:-1]
                if ROW.match(line):
                    rows += 1
                    end = nl + 1
                    j = nl + 1
                else:
                    break
            if rows > 0:
                block = data[ho.start():end]
                addr = s + ho.start()
                # 取最后一份（地址最高）
                if best is None or addr > best[1]:
                    best = (rows, addr, block)
            h = ho.end()
    mem.close()
    if best:
        print(f"[*] 委托表 @ 0x{best[1]:x}，{best[0]} 行", file=sys.stderr)
        return best[2]
    return None


def parse(block):
    text = block.decode("gbk", errors="replace")
    orders = []
    for ln in text.split("\n"):
        ln = ln.rstrip("\r")
        if not ROW.match(ln.encode()):
            continue
        f = ln.split("|")
        if len(f) < 13:
            continue

        def num(x):
            try:
                return float(x)
            except ValueError:
                return None

        orders.append({
            "time": f[0], "code": f[1], "name": f[2],
            "dir": f[5], "status": f[7],
            "price": num(f[8]), "qty": num(f[9]),
            "id": f[10], "filled": num(f[12]),
            "shareholder": f[15] if len(f) > 15 else "",
        })
    return orders


# ---------- 展示 ----------

def disp_w(s):
    return sum(2 if ord(c) > 0x2E80 else 1 for c in str(s))


def rpad(s, w):
    s = str(s)
    return s + " " * max(0, w - disp_w(s))


def print_table(orders):
    cols = ["时间", "委托号", "代码", "名称", "买卖", "价格", "数量", "已成", "状态", "股东代码"]
    widths = [10, 12, 8, 8, 5, 8, 9, 9, 5, 12]
    print(" ".join(rpad(c, widths[i]) for i, c in enumerate(cols)))
    print("-" * (sum(widths) + len(widths)))
    for o in orders:
        print(" ".join([
            rpad(o["time"], widths[0]), rpad(o["id"], widths[1]),
            rpad(o["code"], widths[2]), rpad(o["name"], widths[3]),
            rpad(o["dir"], widths[4]), rpad(o["price"], widths[5]),
            rpad(o["qty"], widths[6]), rpad(o["filled"], widths[7]),
            rpad(o["status"], widths[8]), rpad(o["shareholder"], widths[9]),
        ]))


def poll_and_print():
    pid = common.find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    block = find_orders_block(pid)
    if not block:
        print("内存里没委托表，先在客户端点一次当日委托查询", file=sys.stderr)
        sys.exit(1)
    orders = parse(block)
    assert orders, "委托为空"
    print(f"\n=== 当日委托 {len(orders)} 条 ===")
    print_table(orders)


def main():
    r = common.trigger(ROOT_CLS, ANCHOR_CLS, ANCHOR_TITLE, TARGET_CLS, CMD_ID).strip()
    print("[*] trigger 当日委托:", r)
    if "not found" in r or "msg=0?" in r:
        print("post 失败，重跑 `python3 scripts/common.py capture` 抓一次", file=sys.stderr)
        sys.exit(1)
    time.sleep(0.8)  # 等客户端完成查询、明文落堆
    poll_and_print()
    # 撤单
    order_id = input("\n输入要撤的委托号（回车跳过）: ").strip()
    if not order_id:
        return
    common.cancel(order_id, ROOT_CLS, ANCHOR_CLS, ANCHOR_TITLE, TARGET_CLS,
                  DLG_TITLE, DLG_BTN)
    print("[*] 撤单已发出，重新查询确认...")
    time.sleep(0.8)
    common.trigger(ROOT_CLS, ANCHOR_CLS, ANCHOR_TITLE, TARGET_CLS, CMD_ID)
    time.sleep(0.8)
    poll_and_print()


if __name__ == "__main__":
    main()

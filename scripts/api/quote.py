#!/usr/bin/env python3
# quote — 持仓盘口滑点表：触发刷新持仓 → 读内存明文表 → 批量取 5档 → 相对 micro price 算滑点。
# 6 档名义金额：1W买/1W卖/5W买/5W卖/10W买/10W卖。
# 5档吃不满的，按已成交部分算滑点并加 ">" 表示实际更差。
# 依赖：pip install pytdx；客户端需登录交易。
#
# 触发常量来自 capture：`python3 scripts/common.py capture` 后在客户端点一次「刷新持仓」。
# 全是编译进二进制的稳定量，重启/换机（同客户端）不变，capture 一次终身用。

from pytdx.hq import TdxHq_API
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

HOSTS = [("115.238.90.165", 7709), ("124.71.187.122", 7709),
         ("114.141.177.121", 7709), ("182.131.3.227", 7709)]

NOTIONALS = [(10000, "1W买", True), (10000, "1W卖", False),
             (50000, "5W买", True), (50000, "5W卖", False),
             (100000, "10W买", True), (100000, "10W卖", False)]

# 现价 ±1% / ±2% 的价格档位
PCT_LEVELS = [("+2%", 1.02), ("+1%", 1.01), ("-1%", 0.99), ("-2%", 0.98)]

# 名字着色分组（按代码 match）
GREEN_CODES = {
    "600697",  # 欧亚集团
    "301006",  # 迈拓股份
    "300535",  # 达威股份
    "605567",  # 春雪食品
    "603214",  # 爱婴室
    "600561",  # 江西长运
    "300645",  # 正元智慧
    "301037",  # 保立佳
}
RED_CODES = set()  # 红名单：先空着，后面加


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
    # 持仓表字段（管道符 | 分隔，行尾 \r\n）：
    #   0 代码  1 名称  2 名称2  3 股票余额  4 可用余额  5 冻结1  6 冻结2
    #   7 可用2  8 成本价  9 现价  10 市值  11 浮盈  12 盈亏%
    #   13 ?    14 沪深标志(1=沪,0=深)  15 同  16 税率
    #   17 ?%   18 空  19 股东代码  20 附加  21 空  22 空
    # 两种布局：旧 23 列（nf>=22）/ 新 18 列精简视图（重新登录后常见），列序不同，见下方 i_* 分支。
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
            "frozen1": num(f[5]),
            "frozen2": num(f[6]),
            "cost": get(i_cost),
            "price": get(i_price),
            "market_value": get(i_mv),
            "pnl": get(i_pnl),
            "pnl_pct": get(i_pnlp),
            "market_flag": int(f[i_mkt]) if i_mkt < nf and f[i_mkt].isdigit() else None,
            "shareholder": f[i_sh] if i_sh < nf else "",
        })
    return positions


# ---------- 盘口滑点 ----------

def micro_price(q):
    b, bv = q.get("bid1"), q.get("bid_vol1")
    a, av = q.get("ask1"), q.get("ask_vol1")
    if not b or not a or not bv or not av:
        return None
    return (b * av + a * bv) / (bv + av)


def fill(levels, notional, is_buy):
    """levels: [(price, vol_lots)]。返回 (avg_price, filled_full)。"""
    spent, shares = 0.0, 0.0
    for price, vol_lots in levels:
        if not price or price <= 0 or not vol_lots:
            continue
        avail = vol_lots * 100  # 手 → 股
        remaining = notional - spent
        if remaining <= 1e-6:
            break
        affordable = remaining / price
        take = min(avail, affordable)
        spent += take * price
        shares += take
        if spent >= notional - 1e-6:
            break
    filled = spent >= notional - 1e-6
    return (spent / shares if shares > 0 else None), filled


def slip_pct(q, notional, is_buy):
    micro = micro_price(q)
    if not micro:
        return None, "N/A"
    levels = ([(q.get(f"ask{i}"), q.get(f"ask_vol{i}")) for i in range(1, 6)] if is_buy
              else [(q.get(f"bid{i}"), q.get(f"bid_vol{i}")) for i in range(1, 6)])
    avg, filled = fill(levels, notional, is_buy)
    if avg is None:
        return None, "N/A"
    pct = (avg - micro) / micro * 10000
    sign = "+" if pct >= 0 else ""
    return pct, f"{'' if filled else '>'}{sign}{pct:.1f}p"


def base_price(q):
    """现价；缺失或盘前为 0 时退到买卖中间价、再退到昨收。"""
    p = q.get("price")
    if p and p > 0:
        return p
    b, a = q.get("bid1"), q.get("ask1")
    if b and a and b > 0 and a > 0:
        return (b + a) / 2
    lc = q.get("last_close")
    if lc and lc > 0:
        return lc
    return None


def price_levels(q):
    """现价 ±1%/±2% 的价格，返回 [(label, disp), ...]。"""
    base = base_price(q)
    if not base:
        return [(lbl, "N/A") for lbl, _ in PCT_LEVELS]
    return [(lbl, f"{base * f:.2f}") for lbl, f in PCT_LEVELS]


def fetch_quotes(api, req, chunk=20):
    """分块取 5 档报价。申购等无盘口代码会让 pytdx 整批返回 0 条（一个毒代码污染整批），
    故分块；某块返回条数对不上时逐个查，隔离掉返回 0 的毒代码（它们在表里自然显示「无行情」）。"""
    qmap = {}
    for i in range(0, len(req), chunk):
        batch = req[i:i + chunk]
        r = api.get_security_quotes(batch) or []
        if len(r) == len(batch):
            for x in r:
                qmap[(x["market"], x["code"])] = x
            continue
        for one in batch:
            for x in (api.get_security_quotes([one]) or []):
                qmap[(x["market"], x["code"])] = x
    return qmap


# ---------- 展示 ----------

def disp_w(s):
    w = 0
    for ch in str(s):
        w += 2 if ord(ch) > 0x2E80 else 1
    return w


def rpad(s, w):
    s = str(s)
    return " " * max(0, w - disp_w(s)) + s


COLORS = {"31": "\033[31m", "33": "\033[33m", "32": "\033[32m"}
RESET = "\033[0m"


def colorize(s, code):
    return f"{COLORS[code]}{s}{RESET}" if code else s


def thr_code(x):
    return "" if x is None else ("32" if abs(x) < 10 else ("33" if abs(x) < 20 else "31"))


def print_table(positions, qmap):
    # 持仓百分比（按市值）
    total_mv = sum(p["market_value"] or 0 for p in positions) or 1

    # 收集每行滑点
    rows = []
    for pos in positions:
        q = qmap.get((pos["market_flag"], pos["code"]))
        pct = (pos["market_value"] or 0) / total_mv * 100
        if not q:
            rows.append((pos, None, pct, [(lbl, "N/A")
                        for lbl, _ in PCT_LEVELS]))
            continue
        rows.append((pos, [slip_pct(q, n, buy)
                    for n, _, buy in NOTIONALS], pct, price_levels(q)))

    # 每列按滑点绝对值固定阈值着色：<10 绿，10-20 黄，>20 红；并算市值加权 aggregate
    n_cols = len(NOTIONALS)
    agg = [None] * n_cols
    for ci in range(n_cols):
        num = den = 0.0
        for i in range(len(rows)):
            if not rows[i][1]:
                continue
            v = rows[i][1][ci][0]
            mv = rows[i][0]["market_value"] or 0
            if v is None or mv <= 0:
                continue
            num += v * mv
            den += mv
        agg[ci] = num / den if den > 0 else None
        for i in range(len(rows)):
            if not rows[i][1]:
                continue
            v, disp = rows[i][1][ci]
            code = "" if v is None else thr_code(v)
            rows[i][1][ci] = (v, disp, code)

    # 表头（按 aggregate 滑点染色）
    cols = ["Code", "Name"] + [n for _, n, _ in NOTIONALS] + \
        [lbl for lbl, _ in PCT_LEVELS] + ["占比"]
    widths = [7, 8, 8, 8, 8, 8, 9, 9, 7, 7, 7, 7, 7]
    n_slip = len(NOTIONALS)
    n_lvl = len(PCT_LEVELS)
    hdr_cells = [rpad(cols[0], widths[0]), rpad(cols[1], widths[1])]
    for ci in range(n_slip):
        hdr_cells.append(
            colorize(rpad(cols[2 + ci], widths[2 + ci]), thr_code(agg[ci])))
    for li in range(n_lvl):
        hdr_cells.append(rpad(cols[2 + n_slip + li], widths[2 + n_slip + li]))
    hdr_cells.append(rpad(cols[-1], widths[-1]))
    hdr = " ".join(hdr_cells)
    print(hdr)
    print("-" * disp_w(hdr))
    for pos, slips, pct, levels in rows:
        nc = "32" if pos["code"] in GREEN_CODES else (
            "31" if pos["code"] in RED_CODES else "")
        name_cell = colorize(rpad(pos["name"], widths[1]), nc)
        if slips is None:
            print(" ".join([rpad(pos["code"], widths[0]), name_cell,
                            rpad("无行情", sum(widths[2:-1])), rpad(f"{pct:.1f}%", widths[-1])]))
            continue
        cells = [rpad(pos["code"], widths[0]), name_cell]
        for ci, (v, disp, code) in enumerate(slips):
            w = widths[2 + ci]
            if v is None:
                cells.append(rpad(disp, w))
            else:
                cells.append(colorize(rpad(disp, w), code))
        for li, (lbl, disp) in enumerate(levels):
            w = widths[2 + n_slip + li]
            cells.append(rpad(disp, w))
        cells.append(rpad(f"{pct:.1f}%", widths[-1]))
        print(" ".join(cells))


def poll_and_print():
    pid = common.find_tdxw_pid()
    assert pid, "找不到 tdxw.exe 进程"
    block = find_best_block(pid)
    if not block:
        print("内存里没持仓表，先在客户端点一次持仓查询", file=sys.stderr)
        sys.exit(1)
    positions = parse(block)
    assert positions, "持仓为空"
    positions.sort(key=lambda p: p["code"])

    api = TdxHq_API()
    conn = None
    for h, p in HOSTS:
        try:
            if api.connect(h, p):
                conn = (h, p)
                break
        except Exception:
            continue
    assert conn, "连不上 7709"
    req = [(pos["market_flag"], pos["code"]) for pos in positions]
    qmap = fetch_quotes(api, req)
    api.disconnect()

    print(f"\n=== 持仓 {len(positions)} 只 ===")
    print_table(positions, qmap)


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

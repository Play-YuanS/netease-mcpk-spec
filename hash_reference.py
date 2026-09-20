# -*- coding: utf-8 -*-
"""MCPK 路径哈希参考实现 (f1 / f2)

逆向自网易《我的世界》中国版客户端二进制中的两个内部函数:
  - f1: 零终止字符串版
  - f2: (指针, 显式长度) 版
两者算法相同: 输入按 4 字节小端分词 (末尾不足补零, 仍做一轮),
经 128 位状态的双轮混合与终结化, 输出 32 位键。

在 MCPK 表区中的用途:
  - 文件条目名字键: key(j) = (entry[j].X << 24) | entry[j-1].W   (vanilla 层)
  - netease 层: 键直接存于条目 b+1..b+4
  - 组区目录键 / count 族 / 锚点体系同样基于该哈希

验证方式: 对包内已知路径计算 f1(basename), 与表中键比对 (全量样本 0 失配)。

纯 Python 实现, 无第三方依赖。仅输入需哈希的路径字符串, 不接触任何游戏数据。
"""


M  = 0xFFFFFFFF
MA = 0xBDEB77DE   # and-mask 1
O1 = 0x02040801   # or-bits 1
MB = 0x7D7EBBDE   # and-mask 2
O2 = 0x00804021   # or-bits 2
KX = 0x267B0B11
C1 = 0x9BE74448
C2 = 0x66F42C48

H1_INIT = 0x37A8470E
H2_INIT = 0x7758B42B
H3_INIT = 0xF4FA8928


def _rol(x, n):
    x &= M
    return ((x << n) | (x >> (32 - n))) & M


def _fold_hi(p):
    # 64 位结果折叠方式一: r = (hi!=0) + lo + hi; out = (r>>32) + (r&M)
    lo = p & M
    hi = p >> 32
    r = (1 if hi else 0) + lo + hi
    return ((r >> 32) + (r & M)) & M


def _fold_lo(p):
    # 64 位结果折叠方式二: t = lo + 2*hi; out = t + 2*(t>>32)
    lo = p & M
    hi = p >> 32
    t = lo + 2 * hi
    return (t + 2 * (t >> 32)) & M


def _dbl_round(h1, h2, key):
    a = (key ^ KX) & M
    m1 = ((((a + h2) & M) & MA) | O1) & M
    m2 = ((((a + h1) & M) & MB) | O2) & M
    p1 = m1 * h1
    p2 = m2 * h2
    return _fold_hi(p1), _fold_lo(p2)


def _hash_words(words):
    h1 = H1_INIT
    h2 = H2_INIT
    h3 = H3_INIT
    for w in words:              # 每个 word 含末尾 1..4 字节补零的短字
        h1 = (h1 ^ w) & M
        h2 = (h2 ^ w) & M
        h3 = _rol(h3, 1)
        h1, h2 = _dbl_round(h1, h2, h3)
    # 终结化
    h1 = (h1 ^ C1) & M
    h2 = (h2 ^ C1) & M
    c = _rol(h3, 1)
    h1, h2 = _dbl_round(h1, h2, c)
    c2 = _rol(c, 1)              # 即 rol(h3, 2)
    v1 = (h1 ^ C2) & M
    v2 = (h2 ^ C2) & M
    x, y = _dbl_round(v1, v2, c2)
    return (y ^ x) & M


def f2(data: bytes) -> int:
    """显式长度版: 输入任意字节串"""
    words = []
    i = 0
    n = len(data)
    while i < n:
        chunk = data[i:i + 4]
        words.append(int.from_bytes(chunk.ljust(4, b"\x00"), "little"))
        i += 4
    return _hash_words(words)


def f1(data: bytes) -> int:
    """零终止字符串版: 传入不含结尾 NUL 的字符串字节"""
    return f2(data)


def path_key(path: str) -> int:
    """便捷入口: 对路径取 basename 后哈希 (表区文件条目键的口径)"""
    return f1(path.rsplit("/", 1)[-1].encode("utf-8"))


if __name__ == "__main__":
    # 自检: 输出确定性哈希值, 供复现比对
    for s in ("textures/blocks", "hud_screen.json"):
        print(f"f1({s!r:24}) = {f1(s.encode()):08X}  "
              f"path_key = {path_key(s):08X}")

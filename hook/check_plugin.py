#!/usr/bin/env python3
"""插件版 dylib 出厂自检。

CI 里编完就跑这一条：python3 hook/check_plugin.py RelyWipe.dylib
本地也能跑（不需要 iOS SDK）。

查四件事：
  1. 8 个 rely_transport_* 同名符号**不能**导出（插件模式全改名成 rbplug_*，
     否则会和 framework 的符号撞名，dlsym(RTLD_DEFAULT) 会拿到我们的壳）
  2. 必须有 rbplug_* 那批符号（说明改名生效，不是编了个空壳）
  3. 关键字符串在（clang 会把部分中文编成 UTF-16，所以两种编码都查）
  4. 不能残留 tipa 版的启动串（rb-shim v85 ...）
"""
import sys

BARE = [
    "rely_transport_new",
    "rely_transport_request",
    "rely_transport_send_fire_and_forget",
    "rely_transport_free",
    "rely_transport_free_buffer",
    "rely_transport_is_connected",
    "rely_transport_force_reconnect",
    "rely_transport_set_network_available",
]
RENAMED = [
    "rbplug_transport_new",
    "rbplug_transport_request",
    "rbplug_transport_fire",
    "rbplug_transport_free",
    "rbplug_transport_freebuf",
    "rbplug_transport_isconn",
    "rbplug_transport_force",
    "rbplug_transport_setnet",
]
MUST_HAVE = [
    "rb-plugin v1",            # 版本串
    "插件自停用",               # tipa 版共存检测
    "立即抹数据重来",            # 面板按钮
    "rely_transport_orig",     # 共存检测里比对的备份文件名
]
MUST_NOT = [
    "rb-shim v85 精简版",
    "rb-shim v85 已停用",
]


def has(data: bytes, s: str) -> bool:
    return (s.encode("utf-8") in data) or (s.encode("utf-16-le") in data)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    data = open(path, "rb").read()
    bad = []

    # 符号表：Mach-O 的符号是 \x00 + 名字 + \x00 的形式，直接找字节即可
    for s in BARE:
        if b"\x00" + s.encode() + b"\x00" in data:
            bad.append("不该导出裸符号 " + s)
    for s in RENAMED:
        if not has(data, s):
            bad.append("缺改名后的符号 " + s)
    for s in MUST_HAVE:
        if not has(data, s):
            bad.append("缺字符串 " + s)
    for s in MUST_NOT:
        if has(data, s):
            bad.append("残留 tipa 版字符串 " + s)

    if bad:
        print("自检失败：")
        for b in bad:
            print("  -", b)
        return 1

    print("自检通过：%s（%d 字节）" % (path, len(data)))
    print("  裸符号 0 个 / rbplug_* %d 个 / 关键串 %d 条 / 无 tipa 残留"
          % (len(RENAMED), len(MUST_HAVE)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

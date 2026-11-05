# vivo 厂商防线对照与加固建议

本文从公开 PoC 的静态审计里，整理 vivo 在 GKI 5.10 / 6.1 / 6.6 内核族上实际部署的防线、被击穿的环节、以及对应的加固方向。结论按"防线 → 被击穿方式 → 加固建议"展开。

## vr.ko（vivo 反 root 内核模块）

**防线**：`vr.ko` 是 vivo 加载的内核模块，对进程打 tag，阻止已知 root 载体（`su`、`ksud`、`magisk` 等）的常规启动。公开 PoC 里多次出现"绕 vr.ko"这一步。

**被击穿方式**：在 exploit 落地前，先对 `vr.ko` 的 tag 数据结构做清理（`vr.ko` tag cleanup），让后续的 `ksud` / `su` 启动不被拦截。Romk-a 在 X100 Ultra 上的 README 详述了这条路径。

**加固建议**：`vr.ko` 的 tag 数据不应放在容易被内核读写原语定位的固定偏移；改为随机化存放 + 每次启动重布局，或引入独立的内核签名通道校验（如与 hardware-backed keystore 联动），让"改 tag"这一步必须先突破硬件边界。

## vermagic / 模块签名

**防线**：vivo 对内核模块加载有 vermagic 检查，阻止任意 `.ko` 注入。

**被击穿方式**：公开 PoC 普遍**不加载新模块**，而是用 UAF / 物理读写直接改 `cred` / SELinux，再挂已有的 `ksud`（KernelSU 的用户态守护）。模块签名防线没有被正面绕过，而是被"绕道"了。

**加固建议**：这条防线本身是有效的，问题在于后续的 `ksud` 挂载路径：`ksud` 的 late-load 只依赖用户态 seccomp/SELinux，不依赖模块签名。加固方向是让 `ksud` / `su` 的启动也必须经过内核签名或硬件信任链校验，而不是仅靠用户态检查。

## kptr_restrict / KASLR

**防线**：`kptr_restrict` + KASLR，阻止用户态直接拿到内核符号地址。

**被击穿方式**：公开 PoC 普遍通过 BPF 读原语或 `/proc` 泄露，恢复 KASLR slide（`slide=0x1f93600000` 之类的日志出现在 zenyxx-xd 的 cve64560 记录里）。`init_signals+0x10 ↔ init_task+0x6d8` 这类符号对在多个仓库中反复出现，说明 vivo 对核心符号的 KASLR 保护没有做到位。

**加固建议**：收紧 `kptr_restrict=2`；对 `init_task` / `init_signals` 等核心符号启用 per-boot 随机化而非仅 per-boot 段基址；禁止 `/proc` / BPF 路径对未授权进程暴露内核地址。

## SELinux

**防线**：vivo 默认 Enforcing，`untrusted_app` 域的 SELinux policy 较紧。

**被击穿方式**：所有五个家族的公开实现都需要"翻转 SELinux permissive"这一步，通过内核读写改 SELinux state。

**加固建议**：SELinux 状态的翻转本身依赖内核写原语，SELinux 不是独立的防线；真正的防线是把 `cred` / SELinux state 的存放地址放进只读页或加 CRC / 硬件签名校验，让"改 cred"这一步必须先突破完整性检查。

## seccomp

**防线**：vivo 对 `untrusted_app` 域启用较紧的 seccomp filter，阻止 `ptrace` / 驱动 fd 交接。

**被击穿方式**：exploit 落地后，公开 PoC 普遍需要"清 seccomp=0"这一步，才能让 `ksud` 挂载。zhubaohe123 的 post-root 模块专门处理"app seccomp 142 握手与驱动 fd 交接"问题。

**加固建议**：seccomp filter 本身是有效的；问题是内核写原语可以清掉它。加固方向同上——`cred` / `seccomp` 状态的完整性校验，或把 filter 状态放到只读页。

## GKI 内核版本

**现状**：公开 PoC 覆盖 GKI 5.10（MT6896）、6.1（T4 / Z9 Turbo）、6.6（S60 / Neo11 / Z10 Turbo Pro）。多个仓库同时维护多内核版本的 profile / offset（Romk-a 6.6/6.12/6.1/5.15 路由、hmascs 的 135 个 prebuilt payload），说明 vivo / iQOO 的 GKI 版本跨度大、每版本都要单独适配。

**加固建议**：GKI 版本多本身不是漏洞，但说明"逐版本 offset 对齐"是当前公开 PoC 的主要工程成本。对厂商而言，与其在每个版本上单独补防线，不如把 `vr.ko` / 信任链 / cred 完整性校验做成内核版本无关的通用机制。

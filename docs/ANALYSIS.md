# 24 项逐一判定

审计时间 2026-11-05，静态只读。`commit` 为克隆时默认分支 `HEAD` 短 SHA；空仓无 `HEAD`。所有"已验证/成功"均引用仓库自述，未独立真机复现。

## 总表

| # | 仓库 | commit | 判定 | 触发代码/载荷 | 优先级 |
|---|---|---|---|---|---|
| 1 | 233laoliu/mt6985-CVE-2026-43499 | 695e3c7 | 偏移/复现研究包 | 无（依赖上游 CyberMeowfia） | P1 |
| 2 | linux-tools/vivo_iqoo_neo_9_root_research_on_CVE-2025-21479 | 00bba0b | 二进制封装 | 有（无源码） | P1 |
| 3 | xiaohj233/ghostlock-x200-root | 1194725 | 完整源码 | 有 | P0 |
| 4 | Qingizi7/cve-2025-21479_iqooneo8 | b634799 | 完整源码 | 有 | P0 |
| 5 | xx2901318208/ghostlock-cve-2026-64560 | - | 空仓 | 无 | P3 |
| 6 | sgswzglwlx/vivo-root-build | 9ba8b36 | 源码门控 | 有（preflight 前停止） | P2 |
| 7 | zenyxx-xd/RootMyVivo-Exploit | 201ffc0 | 实验源码 | 有（未确认 root） | P1 |
| 8 | hmascs/KSuRoot | aa475cb | 载荷目录 + App | 有（载荷 + 构建源） | P0 |
| 9 | L-1124/RootMyVivo-Exploit | - | 空仓 | 无 | P3 |
| 10 | YUE546/IQOO-neo7-ghostlock-43499 | 59b7cba | 完整源码 | 有 | P0 |
| 11 | L-1124/RootMyVivo-rs | - | 空仓 | 无 | P3 |
| 12 | ankitrawatgit/DirtyFrag-Android-Root-Jailbreak | 7049e00 | 源码适配 | 有（DirtyFrag 通用链） | P1 |
| 13 | zhubaohe123/ghostlock-kit-v2 | 761d290 | 后置框架 | 无核心触发（依赖外部一键包） | P1 |
| 14 | stolas33/vivo-dirtyfrag-root | - | 空仓 | 无 | P3 |
| 15 | Escosis/V2463A-LPE | 67a072c | 包装器 + prebuilt | 有（无源码） | P1 |
| 16 | AuroraMythweaver/iqoo-neo9-ghostlock-pc | 64e000f | 包装器 + prebuilt | 有（无源码） | P1 |
| 17 | zenyxx-xd/RootMyVivo | a3c6681 | App + DirtyFrag 源 | 有（GhostLock payload 远程） | P0 |
| 18 | Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root | 02eaa75 | 完整源码 | 有 | P0 |
| 19 | janewas/cve-2026-98260-vivo-gki-research | 0796d94 | 研究笔记 | 无 | P2 |
| 20 | Syerain/cve-2026-43499-mt6896-pd2238 | 2970a36 | 完整源码 | 有 | P1 |
| 21 | Syerain/cve-2026-43499-vivo-mt6896 | 2970a36 | 重复 | 同 #20 | P3 |
| 22 | molanp/CVE-2026-98260-vivo-s60-poc | 636a586 | 完整源码 | 有 | P0 |
| 23 | AmarnathCJD/CVE-2026-98260-IQOO-13 | - | 空仓 | 无 | P3 |
| 24 | simayang01/CVE-2026-98260-vivo-x-fold6-poc | - | 空仓 | 无 | P3 |

## P0：完整触发源码 / 成熟载荷

- `xiaohj233`：`exploit/src/{main.c,root.c,pipe.c,slide.c,su_daemon.c}` 实现 futex-PI requeue → pipe_buffer 任意读写 → cred/SELinux。README 明确 X200（PD2415）"已实测验证"。
- `YUE546`：`exploit/src/sysctl.c` + `slide.c`，README 记录"真机全链路验证通过：exploit → KSU → Enforcing 下第三方 app 冷启动与网络正常"，单轮成功率 50%+。
- `Romk-a`：`src/core/**` + `app/**` 的通用 route/profile 引擎；README 详述 W1/W2 写入、`vr.ko` tag 清理、zygote 重启、BPF 读原语等，X100 Ultra（PD2366）达到 `su -c` root。
- `Qingizi7`：`source/cheese.c` 基于 KGSL ioctl 的任意物理内存读写，关闭 SELinux、patch `capset` 提权，README 给出完整链。
- `molanp`：`timer-t28-kernel15.c` posix-cpu-timer UAF，README 列出 timer UAF、fake cred、SELinux permissive、full caps、seccomp=0、ksud late-load rc=0 全部通过，遗留 KSU manager seccomp 未闭环。
- `hmascs/KSuRoot`：281 星，`载荷构建/targets/*/root.c` 为上游源码复刻，`app/jniLibs` 含 135 个预编译载荷；README 自述"没有任何真机验证"（构建端），但作为 payload 目录价值最高。
- `zenyxx-xd/RootMyVivo`：92 星，App 侧 `DirtyFragRunner.kt` + `dfexp.c` 为 DirtyFrag 通用链，GhostLock payload 从 `RootMyVivo-Payloads` 远程拉取；README 标注 Neo 11（PD2520）作者实测。

## P1：有代码但未闭环 / 二进制 / 包装器

- `linux-tools`：`exploit/` 与 `kernel-module/`、`KSUOneTap.apk` 全为二进制，无源码；是 KGSL CVE-2025-21479 的现成封装，逆向价值高但无法源码审计。
- `zenyxx-xd/RootMyVivo-Exploit`：`afunix`（CVE-2026-53361 移植）停在 race 抢占 10% 阶段，`cve64560` 达到 `STAGE0_GATE_PASS` 但 `STAGE8` root 未确认。方法学与日志有价值，武器化未完成。
- `ankitrawatgit`：DirtyFrag（CVE-2026-43284）独立 fork/设备移植，`exp.c` 为 ESP/page-cache 写原语，README 标注 iQOO Z9 5G 测试；核心链继承上游。
- `zhubaohe123`：`src/kmod/ghostlock.c` 是 root 后的任意 4 字节内核写模块，`ksushimd`/`ksud-exec` 解决 app seccomp 142 握手与驱动 fd 交接；触发本体在 Releases 一键包中，仓库源码不含。
- `Escosis`：`PreloadPusher.kt` + 内置 `libadb.so` + 33 个 prebuilt payload，锁屏自动提权编排；无 exploit 源码，且 30 个 payload 与 KSuRoot 逐字节相同。
- `AuroraMythweaver`：Go 编排 + 内嵌 `ghostlock` 二进制与 71 份内核 profile，面向 iQOO Neo9（PD2338）的"开机窗口"自动化；无 exploit 源码。
- `233laoliu`：MT6985（PD2241）的偏移/符号表/target.h 研究包，README 说明尚未打通 KernelSnitch，核心触发依赖上游。

## P2：研究笔记

- `sgswzglwlx`：`rmv-engine/src` 保留完整触发源码但 `TARGET_DESTRUCTIVE_WRITE_ENABLED=0`，README 明确"在 target_preflight() 之前停止"，phys-map/linked-base/vr.ko 未证明，只能做几何与环境只读检查。
- `janewas`：29 个文件全部为文档与 offset，`CVE-2026-98260` 到 vivo/iQOO GKI 6.6.127 的移植研究，无 exploit 代码。

## P3：空仓 / 完全重复

- 空仓：`xx2901318208`、`L-1124/RootMyVivo-Exploit`、`L-1124/RootMyVivo-rs`、`stolas33`、`AmarnathCJD`、`simayang01`。
- 重复：`Syerain/cve-2026-43499-vivo-mt6896` 与 `Syerain/cve-2026-43499-mt6896-pd2238` 提交与树完全相同，保留前者（名称含 vivo 与机型）。

# vivo / iQOO 内核提权研究索引

本仓把散落在公开 PoC 仓里的 vivo / iQOO 内核提权实现，收敛成三样东西：**漏洞根因与受影响面**、**厂商防线对照**、**检测与加固建议**。数据源是公开仓库的静态审计，结论只到"根因 / 原语类型 / 修复方向"，不含利用步骤、偏移或载荷。

## 为什么值得看

GhostLock（futex-PI requeue UAF）、KGSL 物理读写、posix-timer UAF、DirtyFrag（xfrm-ESP）、AF_UNIX gc race —— 五条路线覆盖了 vivo / iQOO 当前 GKI 5.10 / 6.1 / 6.6 内核族的主要提权入口。每个家族攻击的是不同的边界：GhostLock 打 futex 子系统的引用计数，KGSL 打 GPU 驱动的 ioctl 校验，posix-timer 打定时器对象的生命周期，DirtyFrag 打 xfrm / page-cache，AF_UNIX 打垃圾回收的竞争窗口。把它们放在同一个索引里，才能看清 vivo 的防线（`vr.ko`、vermagic、`kptr_restrict`、SELinux、seccomp）分别在哪些环节被击穿、哪些环节仍然有效。

## 五个家族对照

| 家族 | CVE | 根因位置 | 原语类型 | 厂商防线被击穿的环节 |
|---|---|---|---|---|
| GhostLock / IonStack | CVE-2026-43499 | futex-PI requeue 引用计数 | 内核任意读写 → cred/SELinux | `vr.ko` tag 清理、kptr_restrict |
| KGSL | CVE-2025-21479 | Adreno GPU 驱动 ioctl 校验 | 物理内存任意读写 | SELinux permissive、capset |
| posix-timer | CVE-2026-98260 | posix-cpu-timer 生命周期 | UAF → fake cred | seccomp=0、KSU late-load |
| DirtyFrag | CVE-2026-43284 | xfrm-ESP / page-cache | 写原语 → cred | SELinux permissive |
| AF_UNIX | CVE-2026-53361 | unix_gc 竞争窗口 | race → 内核读写 | （未闭环，停在 race 阶段） |

逐条根因、受影响内核路径与修复方向见 [docs/ROOT_CAUSE.md](docs/ROOT_CAUSE.md)；厂商防线与加固建议见 [docs/DEFENSE.md](docs/DEFENSE.md)；防御侧检测点见 [docs/DETECTION.md](docs/DETECTION.md)。

## 机型 × CVE

机器可读总表见 [data/models.csv](data/models.csv) 与 [data/cves.csv](data/cves.csv)，字段定义见 [data/schema.md](data/schema.md)。下表覆盖全部机型：✅ = 仓库或社区自述已真机验证；❌ = 未确认（源码可用 / 仅有载荷 / 门控未闭环 / 已修补 / 空仓）。2026-11-05 全网检索补充。

| 机型 | 代号 | CVE / 家族 | 验证来源 | 是否 Root |
|---|---|---|---|---|
| vivo X200 | PD2415 | CVE-2026-43499 GhostLock | xiaohj233 | ✅ |
| vivo X200s | PD2415 (推断) | CVE-2026-43499 GhostLock | — | ❌ |
| vivo X100 Ultra | PD2366 | CVE-2026-43499 GhostLock | Romk-a | ✅ |
| vivo S60 | PD2571 | CVE-2026-98260 posix-timer | molanp | ✅ |
| vivo X Fold6 | — | CVE-2026-98260 posix-timer | simayang01 | ❌ |
| vivo Pad5 Pro | PA2573 | CVE-2026-43499 GhostLock | hmascs | ❌ |
| vivo T4 | I2407 | CVE-2026-43499 GhostLock | sgswzglwlx | ❌ |
| vivo X200 Pro | PD2405 | CVE-2026-43499 GhostLock / CVE-2026-43284 DirtyFrag | YuKongA/ghostlock-app | ❌ |
| vivo X200 Ultra | PD2454 | CVE-2026-43499 GhostLock | JoinChang/ghostlock-oneplus | ❌ |
| vivo Y03t | V2344 | CVE-2026-43499 GhostLock | zenyxx-xd | ❌ |
| iQOO Neo9 | PD2338 | CVE-2025-21479 KGSL / CVE-2026-43499 GhostLock | linux-tools | ✅ |
| iQOO Neo8 | PD2301 | CVE-2025-21479 KGSL | Qingizi7 | ❌ |
| iQOO Neo7 | PD2231 | CVE-2026-43499 GhostLock | YUE546 | ✅ |
| iQOO Neo7 (V2238A) | PD2238 | CVE-2026-43499 GhostLock | Syerain | ❌ |
| iQOO Neo9S Pro | PD2339 | CVE-2026-43499 GhostLock | Romk-a | ✅ |
| iQOO Neo10 Pro+ | V2463A | CVE-2026-43499 GhostLock | Escosis | ❌ |
| iQOO Neo10 Pro | PD2463 | CVE-2026-98260 posix-timer | molanp | ❌ |
| iQOO Neo11 | PD2520 | CVE-2026-43284 DirtyFrag / CVE-2026-64560 fanout | zenyxx-xd | ✅ |
| iQOO 13 | — | CVE-2026-43499 / CVE-2026-98260 | AmarnathCJD | ✅ |
| iQOO Z9 5G | — | CVE-2026-43284 DirtyFrag | ankitrawatgit | ✅ |
| iQOO Z9 | PD2361 | CVE-2026-43499 GhostLock | YuKongA/ghostlock-app | ❌ |
| iQOO Z9 Turbo | PD2352 | CVE-2026-43499 GhostLock | sgswzglwlx | ❌ |
| iQOO Z10 Turbo Pro | PD2453 | CVE-2026-98260 posix-timer | janewas | ❌ |
| iQOO 11 | — | CVE-2025-21479 KGSL | — | ❌ |
| iQOO 11S | — | CVE-2025-21479 KGSL | — | ❌ |
| iQOO 11 Pro | PD2254 | CVE-2025-21479 KGSL | xianwan1314 | ❌ |

## 目录

- [docs/ROUTES.md](docs/ROUTES.md) — CVE-2026-98260 深挖：posix-cpu-timer UAF → uid-0 → KSU late-load 逐阶段复盘
- [docs/ROOT_CAUSE.md](docs/ROOT_CAUSE.md) — 五个家族的根因、受影响路径与修复方向
- [docs/DEFENSE.md](docs/DEFENSE.md) — vivo 厂商防线对照与加固建议
- [docs/DETECTION.md](docs/DETECTION.md) — 防御侧检测点与 IOC
- [docs/ANALYSIS.md](docs/ANALYSIS.md) — 24 个公开仓的静态审计结论
- [docs/DEEP_DIVE_ORDER.md](docs/DEEP_DIVE_ORDER.md) — 建议的深挖顺序与产出物
- [docs/PAYLOAD_PROVENANCE.md](docs/PAYLOAD_PROVENANCE.md) — 预编译载荷哈希复用关系
- [docs/COLLECTION_POLICY.md](docs/COLLECTION_POLICY.md) — 收录 / 去重 / 维护规则
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — 数据流与维护流程
- [data/inventory.csv](data/inventory.csv) — 机器可读清单
- [data/models.csv](data/models.csv) — 机型维度事实源
- [data/cves.csv](data/cves.csv) — CVE 维度事实源
- [data/schema.md](data/schema.md) — 三份 CSV 的字段与取值约定
- [tools/detect/detect_root_98260.c](tools/detect/detect_root_98260.c) — 防御侧检测工具（只读，非利用）

## 合规

全部为静态分析，未编译、未运行任何利用代码。本仓只做漏洞研究与防御分析，不提供可执行的利用工具。涉及内核提权，仅用于对自有或已授权设备的安全研究；请遵守本地法律与厂商授权边界。

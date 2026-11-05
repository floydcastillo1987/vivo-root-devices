# vivo / iQOO 提权项目集合仓

从公开频道 [GithubRedTeam](https://t.me/GithubRedTeam) 中关于 vivo 的帖子出发，整理并静态审计了 24 个 GitHub 仓库。本仓是"可检索、可复现、可继承"的集合入口，而不是漏洞工具本身。

## 一句话结论

- 24 条频道条目 → 18 个非空仓库、6 个空仓。
- 15 条含真实触发代码或预编译载荷，去重后 14 个独立实现/语料。
- 没有 GitHub 官方 fork（`fork=false`），但存在源码级拷贝与 payload 复用。
- `Syerain` 两个仓库是同一提交（`2970a36`）的完全重复，只保留一个。

## 核心价值：值得深挖的 P0

| 仓库 | 家族 | 为什么值得看 |
|---|---|---|
| [xiaohj233/ghostlock-x200-root](https://github.com/xiaohj233/ghostlock-x200-root) | GhostLock/IonStack | 完整 C 源码 + prebuilt + 模块，X200 已实测，链路最干净 |
| [YUE546/IQOO-neo7-ghostlock-43499](https://github.com/YUE546/IQOO-neo7-ghostlock-43499) | GhostLock | 真机全链路验证（exploit → KSU → Enforcing），vivo 厂商怪癖记录最细 |
| [Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root](https://github.com/Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root) | GhostLock | 通用化 route/profile 引擎 + `vr.ko` 反 root 绕过研究 |
| [Syerain/cve-2026-43499-mt6896-pd2238](https://github.com/Syerain/cve-2026-43499-mt6896-pd2238) | GhostLock | MT6896/5.10 定制链路，QEMU 复现方法学完整 |
| [Qingizi7/cve-2025-21479_iqooneo8](https://github.com/Qingizi7/cve-2025-21479_iqooneo8) | KGSL 物理读写 | 不同于 GhostLock 的第二条提权路线，含源码 |
| [molanp/CVE-2026-98260-vivo-s60-poc](https://github.com/molanp/CVE-2026-98260-vivo-s60-poc) | posix-timer UAF | 新漏洞家族 + KSU late-load，已验证提权 |
| [hmascs/KSuRoot](https://github.com/hmascs/KSuRoot) | GhostLock 载荷目录 | 星数最高、载荷/机型目录最全，多项目复用其 payload |

## 机型 × CVE 索引（单一事实源）

机器可读总表见 [data/models.csv](data/models.csv) 与 [data/cves.csv](data/cves.csv)，字段定义见 [data/schema.md](data/schema.md)。下表只列“仓库自述已真机验证”的机型，其余（源码 / 载荷 / 目标 / 空仓）请查 CSV 的 `status` 列。

| 机型 | 代号 | CVE / 家族 | 验证来源 |
|---|---|---|---|
| vivo X200 | PD2415 | CVE-2026-43499 GhostLock | xiaohj233 |
| vivo X100 Ultra | PD2366 | CVE-2026-43499 GhostLock | Romk-a |
| iQOO Neo7 | PD2231 | CVE-2026-43499 GhostLock | YUE546 |
| vivo S60 | PD2571 | CVE-2026-98260 posix-timer | molanp |
| iQOO Neo11 | PD2520 | CVE-2026-43284 DirtyFrag | zenyxx-xd |
| iQOO Z9 5G | — | CVE-2026-43284 DirtyFrag | ankitrawatgit |

> 上表均为“作者自述验证”，未独立真机复现。未列入上表的机型（Pad5 Pro、T4、Neo8 / Neo9 / Neo9S Pro、Neo10 Pro(+)、Z9 Turbo、Z10 Turbo Pro、X200s、X Fold6、iQOO 13 等）处于源码可用 / 仅有载荷 / 门控未闭环 / 空仓状态，详见 `data/models.csv`。

## 目录结构

- [docs/ANALYSIS.md](docs/ANALYSIS.md) — 24 项逐一判定与证据
- [docs/DEEP_DIVE_ORDER.md](docs/DEEP_DIVE_ORDER.md) — 建议的深挖顺序与产出物
- [docs/PAYLOAD_PROVENANCE.md](docs/PAYLOAD_PROVENANCE.md) — 预编译载荷哈希复用关系
- [docs/COLLECTION_POLICY.md](docs/COLLECTION_POLICY.md) — 收录/去重/维护规则
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — 数据流与维护流程
- [data/inventory.csv](data/inventory.csv) — 机器可读清单
- [data/models.csv](data/models.csv) — 机型维度事实源
- [data/cves.csv](data/cves.csv) — CVE 维度事实源
- [data/schema.md](data/schema.md) — 三份 CSV 的字段与取值约定

## 使用与合规

全部为静态分析，未编译、未运行任何利用代码。这些仓库涉及内核提权，仅用于对自有或已授权设备的安全研究；请遵守本地法律与厂商授权边界。

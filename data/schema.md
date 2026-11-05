# 数据层 Schema

本仓的机器可读事实源是 `data/` 下的三份 CSV。文档与 README 中的表格由这三份 CSV 派生，改数据时先改 CSV。

## 三张表的关系

- `inventory.csv`：仓库维度（24 个仓库的原始采集与静态审计结论）。
- `cves.csv`：漏洞维度（CVE → 家族 → 受影响机型 → 项目 → 状态）。
- `models.csv`：机型维度（机型 → 代号 → 品牌 → SoC → 内核 → CVE → 验证状态 → 证据 → 项目）。

`cves.csv` 与 `models.csv` 通过 `cve` 字段关联；两者与 `inventory.csv` 通过 `projects`（仓库 `owner/repo` 名，以 `;` 分隔）关联。

## inventory.csv 字段

| 字段 | 说明 |
|---|---|
| rank | 频道条目序号 |
| repository_url | GitHub 仓库完整 URL |
| telegram_post | 频道原帖 permalink |
| commit | 克隆时默认分支 HEAD 短 SHA（空仓为空） |
| family | 漏洞家族 |
| verdict | 审计判定（full-source / binary-only / empty / ...） |
| trigger_code | 是否含真实触发代码或载荷（yes / no） |
| priority | P0–P3 |
| keep_note | 去重 / 保留说明 |

## cves.csv 字段

| 字段 | 说明 |
|---|---|
| cve | CVE 编号 |
| type | 漏洞类型 / 原语 |
| family | 家族名 |
| affected_models | 受影响机型（`;` 分隔） |
| verified_models | 有作者自述已验证 / 源码可用的机型（`;` 分隔） |
| projects | 关联仓库 `owner/repo`（`;` 分隔） |
| note | 状态与核验说明 |

## models.csv 字段

| 字段 | 说明 |
|---|---|
| model | 商用机型名 |
| codename | 内部代号 / 产品名（PD/PA/I/V 开头等） |
| brand | 品牌（vivo / iQOO） |
| soc | SoC 平台（仅当仓库自述时填写，否则 `—`） |
| kernel | 目标内核版本（仅当仓库自述时填写，否则 `—`） |
| cve | 关联 CVE |
| status | 验证状态（见下） |
| evidence | 证据说明与出处 |
| projects | 关联仓库 `owner/repo`（`;` 分隔） |
| root_ok | 是否 Root（✅ = author-claimed-verified，含仓库 / 社区自述或维护者确认；❌ = 其余状态） |

## status 取值集

| 取值 | 含义 |
|---|---|
| author-claimed-verified | 仓库自述真机验证通过，未独立复现 |
| same-kernel-inferred | 与已验证机型同平台 / 同内核，推断可覆盖 |
| source-available | 有完整源码，但无真机验证记录 |
| payload-available | 有预编译载荷，无源码或无真机验证 |
| binary-only | 只有二进制封装，无可审计源码 |
| unverified-target | 有目标 / 偏移研究，触发未闭环 |
| research-in-progress | 研究笔记 / 武器化未完成 |
| empty-source | 空仓，无可用内容 |
| patched | 厂商已在更新中修补，漏洞不可用 |

## 约定

- CSV 用 UTF-8 编码；单元格内逗号用双引号包裹；多值字段用 `;` 分隔，避免与 CSV 逗号冲突。
- 所有“验证通过 / 能 Root”均引用仓库自述或源码证据，未独立真机复现；独立复现结果会在 `status` 与 `evidence` 单独标注。
- 涉及内核提权，仅用于对自有或已授权设备的安全研究；请遵守本地法律与厂商授权边界。

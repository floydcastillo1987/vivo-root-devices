# 方法论与维护流程

本文说明本仓的数据从“公开频道”到“可检索事实源”的流转方式，以及后续持续维护的做法。所有结论只做静态只读审计，未编译、未运行任何利用代码。

## 数据流

1. `channel` — 从 Telegram 频道 [GithubRedTeam](https://t.me/GithubRedTeam) 检索 `vivo` / `iQOO` 相关帖子，记录原帖 permalink。
2. `repositories` — 去重后得到 24 个仓库 URL，写回 `data/inventory.csv`（仓库维度）。
3. `audit` — 浅克隆 + 静态指纹：commit、文件树、源码 / 二进制占比、预编译载荷 SHA256、跨仓库 payload 复用关系。
4. `cves` — 从仓库 README / 源码 / target 目录提取 CVE 与漏洞家族，写回 `data/cves.csv`。
5. `models` — 从 README / target.h / payload 文件名提取“机型 → 代号 → SoC → 内核 → CVE”，并标注验证状态，写回 `data/models.csv`。

## 单次迭代要做的事

- 新增频道帖子：在 `inventory.csv` 追加一行，先跑静态指纹判断是否空仓 / 重复 / 纯文档。
- 去重：同一 `commit` + 相同文件树视为重复，只在 `inventory.csv` 的 `keep_note` 标记，不在 `cves.csv` / `models.csv` 重复登记。
- 分层：按 `full-source > payload-available / binary-only > unverified-target > research-in-progress > empty-source` 更新优先级。
- 机型状态：只有仓库自述真机验证通过才写 `author-claimed-verified`；同平台推断写 `same-kernel-inferred`；有源码无验证写 `source-available`。绝不把“有源码”写成“能 Root”。

## 单一事实源规则

- `data/*.csv` 是唯一事实源，README / docs 里的表格由 CSV 派生，改数据先改 CSV。
- 多值字段用 `;` 分隔；单元格内逗号用双引号包裹；UTF-8 编码。
- 所有“验证 / 成功”必须引用仓库自述或源码证据，独立真机复现的结果单独在 `evidence` 标注，不混入作者自述。

## 边界与合规

- 不打包第三方二进制进本仓，只保留 URL + 哈希；需要逆向的二进制在本地工作区处理，不入库。
- 涉及内核提权，仅用于对自有或已授权设备的安全研究；请遵守本地法律与厂商授权边界。
- 本仓是“可检索、可复现、可继承”的集合入口，不是漏洞工具本身，也不做漏洞评级或武器化交付。

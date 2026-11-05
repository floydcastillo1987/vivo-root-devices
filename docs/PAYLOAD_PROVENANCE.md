# 预编译载荷谱系

对克隆仓库中 ≥20KB 的 `.so/.ko/.apk/.exe/.bin` 及无扩展名可执行文件计算 SHA256，按"同一哈希出现在多个仓库"聚类。

## 主要复用关系

- `Escosis/V2463A-LPE` 与 `hmascs/KSuRoot`：30 个 payload 逐字节相同。Escosis 的 `assets/**/V*.so` 就是 KSuRoot `jniLibs/libksu_vivo_*.so` 的重命名副本（示例：`V2458A.so` ↔ `libksu_vivo_x200s_6689_a.so`）。
- `Syerain/cve-2026-43499-mt6896-pd2238` 与 `Syerain/cve-2026-43499-vivo-mt6896`：43 个 payload 相同，且提交/树完全一致，属同一仓库双入口。
- `hmascs/KSuRoot` 与 `zenyxx-xd/RootMyVivo-Exploit`：2 个 payload 相同（`preload_64560.so` 与 `libbs.so` 等）。
- 少量跨三方命中（KSuRoot ↔ Syerain）说明上游同源，多为 `boxiaolanya2008/CVE-2026-43499-Neo11Plus` 或 IonStack 派生。

## 谱系推断

- GhostLock/IonStack 系：`xiaohj233`、`YUE546`、`Romk-a`、`Syerain`、`KSuRoot`、`Escosis`、`AuroraMythweaver`、`zhubaohe123`。核心原语一致（futex-PI requeue UAF + pipe_buffer），差异在路由、profile、厂商绕过。
- KGSL 系：`linux-tools`、`Qingizi7`（CVE-2025-21479 物理读写）。
- DirtyFrag 系：`ankitrawatgit`、`zenyxx-xd/RootMyVivo`（CVE-2026-43284，`dfexp.c`）。
- posix-timer 系：`molanp`（CVE-2026-98260）、`janewas`（仅笔记）。

## 使用注意

- 同一哈希不代表同一作者，只说明分发的是同一份二进制；收录时保留来源 URL，不重复打包。
- 二进制未做恶意代码排查，仅在集合内以哈希引用，不提供可执行副本。

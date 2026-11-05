# 深挖顺序与产出

目标是吸收各仓库可复用部分，形成一份"vivo/iQOO 内核提权路线图谱 + 每个 CVE 的差异化细节"。建议按以下顺序，逐层产出可复用的中间物。

1. `xiaohj233/ghostlock-x200-root` — 建立 GhostLock 基线：触发、pipe 任意读写、cred/SELinux、KSU late-load。产出：7 阶段链路图 + 各阶段源码定位。
2. `YUE546/IQOO-neo7-ghostlock-43499` — 补厂商侧差异：`vr.ko`、`vermagic`、`kptr_restrict`、KSU 移交。产出：vivo 内核防护绕过对照表。
3. `Romk-a/CVE-2026-43499-ghostlock-vivo-x100-ultra-root` — 抽象 route/profile 引擎，梳理 6.6/6.12/6.1/5.15 路由差异与 BPF 读原语。产出：多内核族适配矩阵。
4. `Syerain/cve-2026-43499-mt6896-pd2238` — MT6896/5.10 定制链路 + QEMU 复现方法。产出：MediaTek 侧差异 + 仿真验证手册。
5. `Qingizi7/cve-2025-21479_iqooneo8` — 第二条家族（KGSL 物理读写）。产出：与 GhostLock 的路线对比，评估备用提权路径。
6. `molanp/CVE-2026-98260-vivo-s60-poc` — posix-timer UAF + KSU seccomp 问题。产出：新家族原语 + seccomp_filter layout 陷阱。
7. `hmascs/KSuRoot` + `Escosis` — payload 目录与 30 个共享哈希。产出：按机型/内核的 payload 复用图谱。
8. `zhubaohe123/ghostlock-kit-v2` — post-root 的 seccomp 142 / 驱动 fd / manager 卡死。产出：KernelSU 管理器侧修复合集。
9. `linux-tools` — 对 KGSL 二进制做逆向，补齐源码缺失。产出：函数边界与 ROP/gadget 清单。
10. `233laoliu` + `janewas` — offset/笔记作为各步参考附录，不作为主线。

## 最终可交付

- `ROUTES.md`：每条 CVE 的 reachability → primitive → cred/SELinux → KSU 完整链。
- `VIVO_DEFENSE.md`：`vr.ko`、`vermagic`、`kptr_restrict`、`seccomp`、模块签名等厂商防护与绕过汇总。
- `OFFSETS/`：按 `uname -r` 归类的 target.h / profile 索引（只存文本，不存二进制）。
- `inventory.csv`：持续更新状态、commit、payload 哈希。

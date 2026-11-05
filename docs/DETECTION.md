# 防御侧检测点与 IOC

本文从公开 PoC 的静态审计里，整理 vivo / iQOO 内核提权攻击在**防御侧**可观测的痕迹，供 EDR / 厂商安全团队做检测规则。结论按攻击阶段（入口 → 落地 → 后持）排列。

## 入口阶段

| 检测点 | 说明 | 对应家族 |
|---|---|---|
| `futex` 系统调用高频混用 | `FUTEX_CMP_REQUEUE_PI` 与 `FUTEX_LOCK_PI` 在同一进程内高频交叉，正常应用不会这样用 | GhostLock |
| KGSL ioctl 异常寻址 | `kgsl_ioctl` 传入的地址超出进程自身 `ib_desc` / `gpuobj` 范围 | KGSL |
| `posix_cpu_timer` 高频创建/销毁 | 大量 timer 对象反复 create/delete，配合进程退出，正常应用不会这样用 | posix-timer / fanout |
| xfrm 用户态高频 SA/policy 写 | xfrm SA / policy 的高频增删，配合文件写回 | DirtyFrag |
| AF_UNIX socket 高频创建/关闭 | 大量短命 AF_UNIX socket，配合 GC 触发 | AF_UNIX |

## 落地阶段

| 检测点 | 说明 | 对应家族 |
|---|---|---|
| `cred` 结构完整性异常 | `struct cred` 的 uid/gid/caps 字段与系统记录不一致（如 caps 全量置位） | 全部 |
| SELinux 状态异常翻转 | 系统态为 Enforcing，但某个进程的 `cred` 里 SELinux state 已变 permissive | 全部 |
| seccomp filter 被清 | 进程 seccomp filter 计数从 N 变 0，且该进程无正常理由清 filter | posix-timer / GhostLock |
| pipe_buffer 异常指针 | pipe 的 buffer 数组指向非 pipe_page 地址 | GhostLock |
| 内核符号地址出现在用户态日志 | `init_signals` / `init_task` / `random_table` 等符号地址出现在应用进程的日志或内存 | GhostLock / fanout |

## 后持阶段

| 检测点 | 说明 | 对应家族 |
|---|---|---|
| `ksud` / `su` 进程出现 | KernelSU 的 `ksud` 守护进程或 `su` 二进制出现 | 全部 |
| `vr.ko` tag 数据异常 | `vr.ko` 内部 tag 表中已知 root 载体标记被清除 | GhostLock |
| 未知内核模块 / vermagic 异常 | 加载的 `.ko` 的 vermagic 与当前内核不匹配 | （未被正面绕过，但可作为监控点） |
| seccomp=0 且 SELinux permissive | 一个普通 app 进程同时满足"无 seccomp + SELinux permissive + 全量 caps"三条件 | 全部 |

## 备注

- 上表是"防御侧可以做什么"的分析，不是攻击步骤；实际检测规则需要在真机上根据日志 / eBPF / SELinux audit 输出调优。
- "落地阶段"的三个检测点（cred 完整性、SELinux 状态、seccomp 计数）是**跨家族通用**的，优先做这三条收益最大。

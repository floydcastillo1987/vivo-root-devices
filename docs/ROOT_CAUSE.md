# 五个家族的根因、受影响路径与修复方向

本文只讲"为什么能打进来、根子在哪个子系统、该怎么修"。不含利用步骤、偏移或载荷。

## GhostLock / IonStack（CVE-2026-43499）

**根因位置**：Linux kernel `futex` 子系统 `requeue_pi` 路径。`futex_requeue_pi()` 在把 waiter 从 uaddr1 迁移到 uaddr2 时，对 `futex_pi_state` / `rt_mutex` waiter 的引用计数和所有权处理存在竞争窗口：`PI futex` 与 `non-PI futex` 混用、`FUTEX_LOCK_PI` 与 `requeue` 并发时，`pi_state` 对象可能在仍被引用时释放。

**原语类型**：UAF → 内核任意读写。公开实现普遍用 `pipe_buffer` 作为落地对象：把 pipe 的 buffer 数组替换成受控指针，获得对 `struct cred` 的读写，改 uid/gid/caps 并翻转 SELinux state。

**受影响面**：覆盖 vivo / iQOO GKI 5.10 / 6.1 / 6.6 多款机型（X200 / X100 Ultra / Neo 系列 / S 系列 / Pad5 Pro 等），是目前公开 PoC 里覆盖最广的一条。

**修复方向**：`futex_requeue_pi()` 对 `pi_state` 的引用计数与生命周期管理加锁串行化，确保迁移期间 `pi_state` 不会被并发释放；对 `FUTEX_CMP_REQUEUE_PI` 与 `FUTEX_LOCK_PI` 的交叉场景补 race guard。上游 Linux 主线相关 patch 可作为 backport 参考。

## KGSL（CVE-2025-21479）

**根因位置**：Qualcomm Adreno GPU 驱动（`drivers/gpu/msm/kgsl*`）。KGSL 的 ioctl 路径在处理用户态传入的 `ib_desc` / `cmdlist` / `gpuobj` 引用时，缺少对目标物理地址范围的归属校验，导致一个进程可以通过 KGSL ioctl 获得对**其他物理页**的读写能力。

**原语类型**：物理内存任意读写。拿到物理读写后，公开实现的路径是：定位自身 `cred` 所在物理页 → 改写 uid/gid/caps → 翻转 SELinux permissive → `capset` 全量提权。

**受影响面**：主要是 iQOO Neo8 / Neo9（PD2301 / PD2338）等搭载 Adreno GPU 的骁龙平台机型。

**修复方向**：KGSL ioctl 对所有用户态传入的地址做严格的进程归属检查；`ib_desc` / `gpuobj` 分配与释放路径补齐 race guard；对 `USER_MEM` / `MEMOBJECT` 的 `physaddr` 映射做白名单校验。

## posix-timer（CVE-2026-98260）

**根因位置**：Linux kernel `kernel/time/posix-cpu-timers.c`。`posix_cpu_timer` 的定时器对象在 `it_process` 指向的进程退出时没有正确清空反向引用，导致已释放的 `k_itimer` 对象仍可被引用。

**原语类型**：UAF → fake cred。公开实现的路径：堆布局后用受控对象重占 UAF 槽位 → 写入 fake `cred` 地址 → 翻转 SELinux permissive → 打满 caps → 清 seccomp → 挂 KSU 的 `ksud` late-load。

**受影响面**：vivo S60（PD2571）已真机验证；iQOO Neo10 Pro（PD2463）为同内核族推断目标；X Fold6 / iQOO 13 对应的公开仓为空仓，无可用实现。

**修复方向**：`posix_cpu_timer_schedule()` / `posix_cpu_timer_del()` 的对象生命周期加锁，确保 `it_process` 引用与 `k_itimer` 释放互斥；对 `SIGHUP` / `SIGKILL` 时序下的 timer 回收补 race guard。

## posix-timer fanout（CVE-2026-64560）

**根因位置**：与 CVE-2026-98260 同属 posix-cpu-timer 生命周期问题，但攻击面不同：fanout 路线利用多个 timer 实例的引用计数 fanout，把 UAF 变成更大范围的堆重排原语。公开实现的源头是 NebuSec / CyberMeowfia 系列的跨厂商移植，原语描述在不同来源之间存在出入，核验状态为**未确认 root**（公开日志到 STAGE0 / KASLR slide，未达 STAGE8）。

**修复方向**：同 posix-timer 家族，重点在 timer 对象的引用计数串行化与并发回收 race guard。

## DirtyFrag（CVE-2026-43284）

**根因位置**：Linux kernel `net/xfrm` + page-cache 联动路径。xfrm（IPsec/ESP）处理用户态传入的 SA / policy 时，配合 page-cache 写回，可以把内核堆上的内容写回用户态文件，形成写原语。

**原语类型**：内核写原语 → cred。公开实现的路径：xfrm-ESP 构造受控数据 → page-cache 写回 → 重写 `cred`。

**受影响面**：iQOO Z9 5G（ankitrawatgit 实测）、iQOO Neo11（PD2520，zenyxx-xd 实测）、Z10 Turbo Pro（PD2453，为同内核族推断目标）。

**修复方向**：xfrm 用户态接口对所有 `struct xfrm_user*` 输入做长度与归属校验；ESP 处理路径补 race guard，防止与 page-cache 写回的交叉。

## AF_UNIX（CVE-2026-53361）

**根因位置**：Linux kernel `net/unix/af_unix.c` 的垃圾回收路径（`unix_gc()`）。`unix_gc` 对skb / `unix_sock` 对象的引用计数与并发关闭处理存在竞争窗口，可把已释放的 `unix_sock` 对象重新引用。

**原语类型**：race → 内核读写。公开实现（`afunix.cc`）停在 race 抢占阶段（~10% 命中率），未武器化。

**修复方向**：`unix_gc()` 的对象遍历加锁串行化；`unix_release_sock()` 与 GC 的并发时序补 race guard。

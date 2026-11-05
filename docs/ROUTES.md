# CVE-2026-98260 深挖：posix-cpu-timer UAF → uid-0 → KSU late-load

本文复盘 vivo S60（PD2571，内核 `6.1.145-android14-11-maybe-dirty`）上 CVE-2026-98260 的完整链路，逐阶段对应内核函数与防线环节。结论只到"根因 / 原语 / 防线"，不含利用步骤、偏移或载荷。数据源：molanp `CVE-2026-98260-vivo-s60-poc` 的静态审计。

## 一句话结论

这是一个 **posix-cpu-timer 对象（`k_itimer`）的 use-after-free**。未授权进程用 `timer_create(CLOCK_THREAD_CPUTIME_ID)` 大量分配 `posix_timers_cache` 里的 `k_itimer`，再用 `timer_settime` 与定时器触发竞争制造悬垂对象；随后用 `cred_jar` 重占该对象，借一次 8 字节写原语把 `task->cred` 指向受控的 fake cred，清 uid/gid、翻转 SELinux、打满 caps、清 seccomp，最后挂 KernelSU 的 `ksud` late-load。与 GhostLock（CVE-2026-43499，futex-PI requeue）**原语不同、后持相同**——两者最后都落到 KSU，但触发路径是两套独立的内核子系统。

## 阶段链（Stage → 内核函数 → 防线）

| 阶段 | 做什么 | 涉及内核函数/对象 | 触碰的防线环节 |
|---|---|---|---|
| 1. 触发 UAF | `timer_create(CLOCK_THREAD_CPUTIME_ID)` 分配 `k_itimer`，`timer_settime` 制造触发/回收竞争 | `sys_timer_create` → `do_timer_create`（`posix_timers_cache` 的 `kmem_cache_alloc` 返回点）；`sys_timer_settime` → `do_timer_settime` | 无需任何权限，`untrusted_app` 可达；此阶段未越任何边界 |
| 2. 堆布局/重占 | 用 `cred_jar`（`bytes_req=0xb8`，`HWCACHE` 对齐 `size=0xc0`）喷占已释放的 `k_itimer` 槽位 | SLUB `kmem_cache_alloc` / freelist | SLAB freelist 随机化、`CONFIG_SLAB_FREELIST_HARDENED/RANDOM` |
| 3. 写原语 | 借 `rb_erase` 把节点指针写到目标地址（单次 8 字节 store） | `rb_erase` / `__rb_change_child` | KASLR（写点地址需要 slide），但对活对象无完整性校验 |
| 4. fake cred | 把 `task->cred` 指向受控页里的 fake cred | `task_struct.cred`（`OFF_TASK_CRED`）；`struct cred` 各字段（cap_perm/eff/bset、security、user_ns、group_info） | `cred` 无完整性/只读保护 |
| 5. 清零 uid/gid + 打满 caps | 一次零写清 `real_cred` 的 uid/gid，写 `cap_perm/eff/bset=000001ffffffffff` | `struct cred` cap 字段 | DAC（uid=0）、capability（全量）被绕过 |
| 6. SELinux + seccomp | 写 `selinux_state` → Permissive；清 `seccomp_filter` | `selinux_state.enforcing`；`task_struct.seccomp` | SELinux、seccomp 两道防线被原语直接翻转 |
| 7. 后持（KSU late-load） | worker `exec` `ksud`，加载 `android14-6.1_kernelsu.ko` 常驻 | `ksud` / `libksud.so`；`insmod` 加载 LKM | vermagic（`patch_vermagic` 适配）、`vr.ko` |

## 未闭环的一环：seccomp_filter.cache 的 BTF 偏移错位

这是本 CVE 里**最有防御价值**的结论。KernelSU / SukiSU 的 `kernel/infra/seccomp_cache.c` 在编译期手写了 `struct seccomp_filter` 的布局，但在 PD2571 上不成立：

- `refcount_t` 被 KASAN / vivo debug 构建 padding 到 32 字节；
- `action_cache` 因 vivo 开启 32 位 compat seccomp（`allow_compat` bitmap）从 64 字节扩到 128 字节；
- 结果 `cache` 字段真实偏移是 `+0x80`，而 KSU 编译期以为在 `~+0x0c`。

于是 `ksu_seccomp_allow_cache(__NR_reboot)` 的 `set_bit` 写到错误地址，manager 的 `SYS_reboot` 握手被 seccomp BPF 拦截，`driver fd` 获取失败，`OnceLock` 缓存 -1 导致后续全部调用失败。**根因是"编译期 struct 布局"撞上"运行时 BTF 真实布局"。**

正确修法是运行时用 vmlinux BTF 解析结构偏移（SukiSU-Ultra 的 `ksu_btf_field()` 已具备该基础设施），而不是写死布局。这是研究这条链路时，除了"会不会 root"之外真正值得沉淀的工程结论——它说明厂商加固（KASAN padding、compat seccomp）如何**无意中**破坏了 root 框架的自证逻辑。

## 防御侧怎么看这条链

- **入口可达性高**：`timer_create` / `timer_settime` 无权限门槛，`untrusted_app` 即可触达，是这类提权的高危前提。
- **根因在对象生命周期**：`k_itimer` 的释放与定时器触发路径之间缺锁/引用计数保护，是修复唯一要点。
- **cred / SELinux / seccomp 是"被改"而非"被绕过"**：三道防线本身有效，只是内核写原语能直接改它们；真正该补的是 `cred` / `selinux_state` 的完整性或只读保护。
- **后持可观测**：KSU LKM 常驻 `/proc/modules`、`ksud` 进程、`seccomp=0` + `CapEff=全量` + `getenforce=Permissive` 三者同时出现，是强 IOC。

## 与 GhostLock（CVE-2026-43499）的边界对照

| 维度 | CVE-2026-98260 | CVE-2026-43499 |
|---|---|---|
| 触发子系统 | posix-cpu-timer | futex-PI requeue |
| 对象 | `k_itimer` | `futex_pi_state` / `rt_mutex_waiter` |
| 写原语 | `rb_erase` 单次 8 字节 store | `rb_erase` 任意写（pipe_buffer / pselect 覆盖） |
| 内核版本 | 6.1.145（S60） | 6.6.89（X200，b57） |
| 后持 | KSU late-load | KSU / permissive_restore |

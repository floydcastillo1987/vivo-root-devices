// SPDX-License-Identifier: Apache-2.0
/*
 * detect_root_98260.c — 防御侧检测工具（不是利用工具）
 *
 * 用途：在 vivo / iQOO 设备上检查是否出现 CVE-2026-98260（posix-cpu-timer UAF）
 * 提权链落地的痕迹。只读检查，不做任何修改，也不触发漏洞。
 *
 * 检查项（对应 docs/ROUTES.md 的 IOC）：
 *   1. SELinux 是否 Permissive（/sys/fs/selinux/enforce == 0）
 *   2. /proc/modules 是否加载 kernelsu LKM
 *   3. 进程表是否出现 ksud / ksud_run
 *   4. 是否存在"非 root UID + 全量 CapEff"的进程
 *   5. 是否存在"非 init + Seccomp=0"的异常进程
 *
 * 编译（Android NDK 或桌面 gcc 均可）：
 *   aarch64-linux-android24-clang -O2 -static -o detect_root_98260 detect_root_98260.c
 * 运行：
 *   adb push detect_root_98260 /data/local/tmp/ && adb shell /data/local/tmp/detect_root_98260
 *
 * 退出码：0 = 未见异常；1 = 命中至少一个 IOC；2 = 运行错误。
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 41 个 capability 位全部置位（cap 0..40）对应的十六进制。 */
static const char FULL_CAPS[] = "000001ffffffffff";

static int hits = 0;

static void report(int ioc, const char *fmt, const char *a)
{
    hits++;
    printf("[IOC%d] %s%s\n", ioc, fmt, a ? a : "");
}

/* 读一行，去掉末尾换行。返回 -1 表示失败。 */
static int read_one_line(const char *path, char *buf, size_t n)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(buf, (int)n, f)) {
        fclose(f);
        return -1;
    }
    fclose(f);
    size_t len = strlen(buf);
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return 0;
}

/* IOC1: SELinux 是否 Permissive。 */
static void check_selinux(void)
{
    char buf[16];
    if (read_one_line("/sys/fs/selinux/enforce", buf, sizeof(buf)) == 0) {
        if (buf[0] == '0')
            report(1, "SELinux is Permissive (/sys/fs/selinux/enforce=", buf);
    }
}

/* IOC2: /proc/modules 是否出现 kernelsu。 */
static void check_modules(void)
{
    FILE *f = fopen("/proc/modules", "r");
    if (!f)
        return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char name[128] = {0};
        if (sscanf(line, "%127s", name) == 1 && strstr(name, "kernelsu"))
            report(2, "kernelsu module resident in /proc/modules (", name);
    }
    fclose(f);
}

/* 从 /proc/<pid>/status 读取指定字段的值。返回 1 表示命中。 */
static int status_field(const char *pid, const char *key, char *out, size_t n)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/status", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[512];
    int found = 0;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0) {
            const char *p = line + klen;
            while (*p == '\t' || *p == ' ')
                p++;
            size_t i = 0;
            while (p[i] && p[i] != '\n' && p[i] != '\r' && i + 1 < n)
                out[i++] = p[i];
            out[i] = '\0';
            found = 1;
            break;
        }
    }
    fclose(f);
    return found;
}

/* 读 /proc/<pid>/comm。 */
static void read_comm(const char *pid, char *out, size_t n)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/comm", pid);
    if (read_one_line(path, out, n) != 0)
        out[0] = '\0';
}

/* IOC3/4/5: 进程表扫描。 */
static void check_procs(void)
{
    DIR *d = opendir("/proc");
    if (!d)
        return;
    struct dirent *e;
    while ((e = readdir(d))) {
        /* 只处理纯数字的 PID 目录。 */
        int pid = atoi(e->d_name);
        if (pid <= 0)
            continue;
        char comm[64];
        read_comm(e->d_name, comm, sizeof(comm));

        /* IOC3: ksud / ksud_run 进程。 */
        if (strstr(comm, "ksud"))
            report(3, "ksud process present (pid=", e->d_name);

        char uid[64] = {0};
        char seccomp[64] = {0};
        char capeff[64] = {0};
        int have_uid = status_field(e->d_name, "Uid:", uid, sizeof(uid));
        int have_seccomp = status_field(e->d_name, "Seccomp:", seccomp, sizeof(seccomp));
        int have_capeff = status_field(e->d_name, "CapEff:", capeff, sizeof(capeff));

        /* Uid 行第一个字段是 real uid。 */
        char real_uid[32] = {0};
        if (have_uid)
            sscanf(uid, "%31s", real_uid);

        /* IOC4: 非 root uid 但 CapEff 全量。 */
        if (have_capeff && strcmp(capeff, FULL_CAPS) == 0 &&
            have_uid && strcmp(real_uid, "0") != 0)
            report(4, "non-root uid with full caps (pid=", e->d_name);

        /* IOC5: 全量 CapEff 且 seccomp=0 的进程（root shell 且 seccomp 被清）。
         * 仅当两者同时出现才提示，避免对普通 seccomp=0 守护进程误报。 */
        if (have_seccomp && strcmp(seccomp, "0") == 0 &&
            have_capeff && strcmp(capeff, FULL_CAPS) == 0 && pid != 1) {
            char tag[128];
            snprintf(tag, sizeof(tag), "pid=%s comm=%s", e->d_name, comm);
            report(5, "full caps + seccomp=0 process ", tag);
        }
    }
    closedir(d);
}

int main(void)
{
    printf("== CVE-2026-98260 detection scan (read-only) ==\n");
    check_selinux();
    check_modules();
    check_procs();
    if (hits == 0)
        printf("no IOC matched\n");
    else
        printf("%d IOC matched\n", hits);
    return hits == 0 ? 0 : 1;
}

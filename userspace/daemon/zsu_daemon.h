/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - userspace/daemon/zsu_daemon.h
 *
 * Internal interfaces of zerosud. Everything here is single-threaded: the
 * daemon owns exactly one thread and never forks a worker, so none of these
 * functions has to be reentrant and none of the shared state needs a lock.
 *
 * The only concurrency is the ordering the epoll loop imposes, which is why
 * the init functions are explicit about what must already exist before they
 * are called (in particular: broker_init() needs session_su_fd(), and
 * broker_doorbell() needs policy_stage_uid() to have armed the watch).
 */

#ifndef ZSU_DAEMON_H
#define ZSU_DAEMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "zsu_ipc.h"

/* ------------------------------------------------------------------ */
/* util.c                                                              */
/* ------------------------------------------------------------------ */

extern int zsu_verbose;
extern const char *zsu_prog;

void zsu_log(const char *fmt, ...);
void zsu_warn(const char *fmt, ...);
void zsu_die(const char *fmt, ...);

/* explicit_bzero() with a portable fallback; always wipes. */
void zsu_wipe(void *p, size_t n);

int  zsu_mkdir_p(const char *path, mode_t mode);
int  zsu_chmod(const char *path, mode_t mode);
int  zsu_write_all(int fd, const void *buf, size_t n);
int  zsu_read_file(const char *path, void *buf, size_t n);
int  zsu_copy_file(const char *src, const char *dst, mode_t mode);
int  zsu_set_selinux_label(const char *path, const char *ctx);
int  zsu_write_attr(const char *attr, const char *ctx);
int  zsu_read_attr(const char *attr, char *buf, size_t n);

int  zsu_hex_encode(const uint8_t *in, size_t n, char *out);
int  zsu_hex_decode(const char *in, uint8_t *out, size_t n);

/* /proc/<pid>/stat field 22, exactly the token ELEVATE_TASK wants. */
int  zsu_proc_start_time_fd(int pid_dirfd, uint64_t *out);
int  zsu_proc_start_time_path(const char *procdir, uint64_t *out);

/* pidfd helpers; fall back to kill() only if pidfd is unavailable. */
int  zsu_pidfd_kill(pid_t pid, int sig);

void zsu_sha256(const void *data, size_t len, uint8_t out[32]);

/* ------------------------------------------------------------------ */
/* session.c: the kernel ABI                                           */
/* ------------------------------------------------------------------ */

int session_boot(const uint8_t key[ZSU_PATCH_KEY_LEN]);
int session_su_fd(void);
int session_verify_plain(const uint8_t key[ZSU_PATCH_KEY_LEN], bool *ok);
int session_elevate_task(pid_t pid, uint64_t start_time);
int session_open_plain(int *out_fd);
int session_ping(int fd, uint32_t *abi);

/* ------------------------------------------------------------------ */
/* policy.c: packages, grants, staging, inotify                        */
/* ------------------------------------------------------------------ */

int  policy_init_paths(void);
int  policy_inotify_init(void);
int  policy_inotify_fd(void);
int  policy_package_wd(void);

int  policy_refresh_packages(void);
int  policy_pkg_appid(const char *pkg, uint32_t *appid);
int  policy_pkg_uid(const char *pkg, uint32_t user, uid_t *uid);
size_t policy_pkg_count(void);

int  policy_uid_allowed(uid_t uid);
int  policy_allow_uid(uid_t uid);
int  policy_revoke_uid(uid_t uid);
size_t policy_allowed_count(void);
int  policy_foreach_allowed(int (*cb)(uid_t, void *), void *arg);
int  policy_load_grants(void);
int  policy_restage_all(void);

int  policy_stage_uid(uid_t uid);
int  policy_doorbell_uid(int wd, uid_t *uid);
int  policy_arm_doorbell(uid_t uid);
void policy_disarm_doorbell(uid_t uid);
void policy_forget_wd(int wd);

int  policy_upper_path(uid_t uid, char *buf, size_t n);
int  policy_work_path(uid_t uid, char *buf, size_t n);
int  policy_stub_path(uid_t uid, char *buf, size_t n);

/* ------------------------------------------------------------------ */
/* ns_inject.c                                                         */
/* ------------------------------------------------------------------ */

int  ns_inject_init(void);
int  ns_inject(int pid_dirfd, uid_t uid);

/* ------------------------------------------------------------------ */
/* proc_monitor.c                                                      */
/* ------------------------------------------------------------------ */

int  proc_monitor_init(void);
int  proc_monitor_fd(void);
void proc_monitor_drain(void);

/* ------------------------------------------------------------------ */
/* broker.c                                                            */
/* ------------------------------------------------------------------ */

int  broker_init(void);
int  broker_listen_fd(void);
int  broker_accept(void);
int  broker_handle(int cfd);
void broker_close(int cfd);

int  broker_doorbell(uid_t uid);
int  broker_hot_inject(uid_t uid);

/* ------------------------------------------------------------------ */
/* cgroup helpers (util.c)                                             */
/* ------------------------------------------------------------------ */

int  zsu_cgroup_for_each_pid(uid_t uid, int (*cb)(pid_t, void *), void *arg);
int  zsu_cgroup_kill(uid_t uid);

#endif /* ZSU_DAEMON_H */

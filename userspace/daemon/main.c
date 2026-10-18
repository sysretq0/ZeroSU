// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/main.c
 *
 * zerosud entry point and the single-threaded epoll loop. There are no worker
 * threads and no fork(): every subsystem below is driven by one of five
 * event sources, in one address space, so none of them needs a lock and none
 * of them can race another.
 *
 *   1. ctl.sock       zsu_ctl commands (allow / revoke / list / status / shell)
 *   2. inotify        packages.list changes and per-uid doorbell opens
 *   3. logdr          am_proc_bound / am_proc_start spawn events
 *   4. signalfd       SIGINT / SIGTERM / SIGHUP
 *   5. timerfd        logdr reconnect and nothing else
 *
 * The patch slot lives in this translation unit, in .data, so zsu_ctl patch
 * can find it in the file image and the daemon can wipe it at runtime.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * The one and only key slot. It is deliberately writable (.data) and marked
 * used so the linker cannot fold it away: zsu_ctl patch rewrites these 72
 * bytes in the file, and the daemon explicit_bzero()s them once the su
 * session is authenticated.
 */
struct zsu_patch_slot zsu_boot_slot __attribute__((used)) = {
	.magic = { 'Z', 'S', 'U', 'K', 'E', 'Y', '0', '0' },
	.key = { 0 },
};

/*
 * A marker placed next to the key slot is *not* used: the patcher looks for
 * the magic itself, and adding a second copy of any marker would break the
 * "unique slot" guarantee. Keeping this note here is cheaper than a bug.
 */

static int epfd = -1;
static int sig_fd = -1;
static int timer_fd = -1;

enum ep_kind {
	EP_LISTEN = 1,
	EP_INOTIFY,
	EP_LOGDR,
	EP_SIGNAL,
	EP_TIMER,
};

static int ep_add(int fd, enum ep_kind kind)
{
	struct epoll_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.events = EPOLLIN;
	ev.data.u64 = ((uint64_t)kind << 32) | (uint32_t)fd;
	return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) ? -errno : 0;
}

static void ep_del(int fd)
{
	epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

/* ------------------------------------------------------------------ */
/* key slot                                                            */
/* ------------------------------------------------------------------ */

static int load_key(uint8_t key[ZSU_PATCH_KEY_LEN])
{
	int i, nonzero = 0;

	/*
	 * Deliberately no memcmp() against ZSU_PATCH_MAGIC here: referencing it
	 * as a string literal emits a second copy of "ZSUKEY00" into .rodata,
	 * and zsu_ctl requires the slot to be the file's *only* occurrence. The
	 * magic's job is offline (it anchors the patch site); at runtime the
	 * only invalid state is an all-zero key, which the loop below catches.
	 */
	for (i = 0; i < ZSU_PATCH_KEY_LEN; i++)
		nonzero += zsu_boot_slot.key[i] != 0;

	if (!nonzero) {
		zsu_warn("key slot is all zero: run 'zsu_ctl patch <zerosud>'");
		return -ENOKEY;
	}

	memcpy(key, zsu_boot_slot.key, ZSU_PATCH_KEY_LEN);
	return 0;
}

/* ------------------------------------------------------------------ */
/* event handlers                                                      */
/* ------------------------------------------------------------------ */

static void drain_inotify(void)
{
	char buf[4096];
	int ifd = policy_inotify_fd();

	for (;;) {
		ssize_t n = read(ifd, buf, sizeof(buf));
		char *p;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		if (n == 0)
			break;

		for (p = buf; p < buf + n; ) {
			struct inotify_event *ev = (struct inotify_event *)p;

			if (ev->mask & IN_IGNORED) {
				policy_forget_wd(ev->wd);
			} else if (ev->wd == policy_package_wd()) {
				if ((ev->mask & (IN_MOVED_TO | IN_CLOSE_WRITE)) &&
				    ev->len && !strcmp(ev->name, "packages.list"))
					policy_refresh_packages();
			} else {
				uid_t uid;

				/*
				 * Defense in depth: a stale watch must never
				 * elevate a uid whose grant is gone.
				 */
				if (!policy_doorbell_uid(ev->wd, &uid) &&
				    policy_uid_allowed(uid))
					broker_doorbell(uid);
			}
			p += sizeof(*ev) + ev->len;
		}
	}
}

static void drain_clients(void)
{
	for (;;) {
		int cfd = broker_accept();

		if (cfd < 0) {
			if (cfd == -EAGAIN || cfd == -EWOULDBLOCK)
				break;
			break;
		}
		broker_handle(cfd);
		broker_close(cfd);
	}
}

static void on_timer(void)
{
	uint64_t expirations;

	if (read(timer_fd, &expirations, sizeof(expirations)) < 0)
		return;

	/* logdr is the only thing that can die on us; re-subscribe to it. */
	if (proc_monitor_fd() < 0) {
		if (proc_monitor_init() == 0) {
			if (ep_add(proc_monitor_fd(), EP_LOGDR))
				zsu_warn("epoll add logdr");
			else
				zsu_log("reconnected to logdr");
		}
	}
}

static int on_signal(void)
{
	struct signalfd_siginfo si;
	ssize_t n;

	n = read(sig_fd, &si, sizeof(si));
	if (n != (ssize_t)sizeof(si))
		return 0;

	switch (si.ssi_signo) {
	case SIGHUP:
		policy_refresh_packages();
		return 0;
	case SIGINT:
	case SIGTERM:
		zsu_log("signal %u, shutting down", si.ssi_signo);
		return -1;
	default:
		return 0;
	}
}

/* ------------------------------------------------------------------ */
/* setup                                                               */
/* ------------------------------------------------------------------ */

static int setup_signals(void)
{
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGTERM);
	sigaddset(&mask, SIGHUP);
	sigaddset(&mask, SIGPIPE);
	if (sigprocmask(SIG_BLOCK, &mask, NULL))
		return -errno;

	sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	return sig_fd < 0 ? -errno : 0;
}

static int setup_timer(void)
{
	struct itimerspec its;

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	if (timer_fd < 0)
		return -errno;

	memset(&its, 0, sizeof(its));
	its.it_value.tv_sec = 5;
	its.it_interval.tv_sec = 5;
	if (timerfd_settime(timer_fd, 0, &its, NULL))
		return -errno;
	return 0;
}

static int hot_inject_cb(uid_t uid, void *arg)
{
	(void)arg;
	broker_hot_inject(uid);
	return 0;
}

int main(int argc, char **argv)
{
	uint8_t key[ZSU_PATCH_KEY_LEN];
	int rc, opt;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		if (opt == 'v')
			zsu_verbose = 1;
	}

	if (getuid() != 0) {
		fprintf(stderr, "zerosud: must run as root\n");
		return 1;
	}

	if (load_key(key))
		return 1;

	rc = policy_init_paths();
	if (rc)
		zsu_die("paths: %d", rc);

	rc = session_boot(key);
	zsu_wipe(key, sizeof(key));
	zsu_wipe(zsu_boot_slot.key, sizeof(zsu_boot_slot.key));
	if (rc)
		zsu_die("kernel session: %d", rc);

	rc = ns_inject_init();
	if (rc)
		zsu_die("mount namespace setup: %d", rc);

	rc = policy_inotify_init();
	if (rc)
		zsu_die("inotify: %d", rc);

	policy_refresh_packages();
	policy_load_grants();
	policy_restage_all();

	rc = broker_init();
	if (rc)
		zsu_die("control socket: %d", rc);

	/*
	 * A restart must re-enter the mount namespace of every process that is
	 * already running as a granted uid, because the overlay is only mounted
	 * in a namespace once; a grant that was restored from disk gets its
	 * already-running processes re-injected here.
	 */
	policy_foreach_allowed(hot_inject_cb, NULL);

	if (setup_signals() || setup_timer())
		zsu_die("signalfd/timerfd setup failed");

	/* logdr may not be up yet; the timer retries until it is. */
	(void)proc_monitor_init();

	epfd = epoll_create1(EPOLL_CLOEXEC);
	if (epfd < 0)
		zsu_die("epoll_create1: %s", strerror(errno));

	ep_add(broker_listen_fd(), EP_LISTEN);
	ep_add(policy_inotify_fd(), EP_INOTIFY);
	if (proc_monitor_fd() >= 0)
		ep_add(proc_monitor_fd(), EP_LOGDR);
	ep_add(sig_fd, EP_SIGNAL);
	ep_add(timer_fd, EP_TIMER);

	zsu_log("ready: abi %d, %zu packages, %zu grants",
		ZSU_ABI_VERSION, policy_pkg_count(), policy_allowed_count());

	for (;;) {
		struct epoll_event evs[16];
		int n = epoll_wait(epfd, evs, 16, -1);
		int i;

		if (n < 0) {
			if (errno == EINTR)
				continue;
			zsu_die("epoll_wait: %s", strerror(errno));
		}

		for (i = 0; i < n; i++) {
			uint32_t kind = (uint32_t)(evs[i].data.u64 >> 32);
			int fd = (int)(evs[i].data.u64 & 0xffffffff);

			switch (kind) {
			case EP_LISTEN:
				drain_clients();
				if (zsu_stop_requested)
					goto done;
				break;
			case EP_INOTIFY:
				drain_inotify();
				break;
			case EP_LOGDR:
				proc_monitor_drain();
				break;
			case EP_SIGNAL:
				if (on_signal())
					goto done;
				break;
			case EP_TIMER:
				on_timer();
				break;
			default:
				ep_del(fd);
				break;
			}
		}
	}

done:
	close(sig_fd);
	close(timer_fd);
	close(epfd);
	zsu_log("stopped");
	return 0;
}

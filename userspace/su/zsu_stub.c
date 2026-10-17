// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/su/zsu_stub.c
 *
 * The template for /system/bin/su. It is copied into a granted uid's overlay
 * upperdir and becomes the app's `su`. It runs as the *app* on exec and has
 * exactly one job: hand the daemon a proof of presence and wait to be
 * elevated.
 *
 * There is no socket here on purpose. An untrusted app cannot traverse
 * /data/adb/zerosu, so there is nowhere to connect to. Instead the stub
 * parks two anonymous pipes on fixed descriptors and rings a doorbell by
 * opening its own binary, which is what the daemon's inotify watch is on.
 *
 *   fd 3  read end of the request pipe, pre-loaded with "ZSU3"
 *   fd 4  read end of the ack pipe
 *   fd 5  write end of the ack pipe (kept open so the daemon can write fd/5)
 *
 * The daemon reads /proc/<stub-pid>/fd/3, checks the magic, verifies the
 * start-time token, elevates the task through the kernel, and writes a single
 * ZSU_RDV_OK byte to fd/5. Only then does the stub close the pipes and exec
 * /system/bin/sh - which is now uid 0 because the cred was swapped under it.
 *
 * Fixed descriptors rather than passed ones are deliberate: the daemon has to
 * find them by number through /proc, and a random number that the app cannot
 * influence is the simplest way to make that deterministic.
 */


#include "zsu_ipc.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void fail(const char *what)
{
	dprintf(2, "su: %s: %s\n", what, strerror(errno));
	_exit(1);
}

/* dup2() to a fixed target, closing the source if it moved. */
static void move_fd(int from, int to)
{
	if (from == to)
		return;
	if (dup2(from, to) < 0)
		fail("dup2");
	close(from);
}

/*
 * Strip the optional su arguments the stub understands: a login shell flag
 * ("-" / "-l") and an explicit user ("0" / "root"). Everything else is left
 * for /system/bin/sh. argv[0] is replaced with "sh", so the elevated shell
 * sees the name it actually is.
 */
static void build_sh_argv(int argc, char **argv, char **out)
{
	int i, j = 0;

	out[j++] = (char *)"sh";
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-") || !strcmp(argv[i], "-l"))
			continue;
		if (!strcmp(argv[i], "0") || !strcmp(argv[i], "root"))
			continue;
		out[j++] = argv[i];
	}
	out[j] = NULL;
}

int main(int argc, char **argv)
{
	int req[2], ack[2];
	struct pollfd pfd;
	uint8_t ackbyte;
	char **sh_argv;
	int fd, pr;

	if (pipe2(req, O_CLOEXEC) || pipe2(ack, O_CLOEXEC))
		fail("pipe2");

	/* Load the request pipe before any dup2() can land on its write end. */
	if (write(req[1], ZSU_STUB_REQ_MAGIC, ZSU_STUB_REQ_MAGIC_LEN) !=
	    ZSU_STUB_REQ_MAGIC_LEN)
		fail("write request");
	close(req[1]);

	move_fd(req[0], ZSU_STUB_REQ_RD_FD);
	move_fd(ack[0], ZSU_STUB_ACK_RD_FD);
	move_fd(ack[1], ZSU_STUB_ACK_WR_FD);

	/*
	 * The doorbell. A failed open is not immediately fatal: the daemon may
	 * already be blocked on this uid, and the poll below is what decides.
	 */
	fd = open("/system/bin/su", O_RDONLY | O_CLOEXEC);
	if (fd >= 0)
		close(fd);

	pfd.fd = ZSU_STUB_ACK_RD_FD;
	pfd.events = POLLIN;
	pr = poll(&pfd, 1, ZSU_STUB_ACK_TIMEOUT_MS);
	if (pr <= 0)
		fail("no daemon ack");

	if (read(ZSU_STUB_ACK_RD_FD, &ackbyte, 1) != 1)
		fail("ack read");
	if (ackbyte != ZSU_RDV_OK)
		fail("bad ack");

	close(ZSU_STUB_REQ_RD_FD);
	close(ZSU_STUB_ACK_RD_FD);
	close(ZSU_STUB_ACK_WR_FD);

	sh_argv = calloc((size_t)argc + 2, sizeof(char *));
	if (!sh_argv)
		fail("calloc");
	build_sh_argv(argc, argv, sh_argv);

	execv("/system/bin/sh", sh_argv);
	fail("execv /system/bin/sh");
	return 1;
}

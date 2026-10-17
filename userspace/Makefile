# SPDX-License-Identifier: GPL-2.0
#
# ZeroSU - userspace/Makefile
#
# Three binaries, no shared library, no build system:
#
#   zerosud   the single-threaded daemon
#   zsu_stub  the template /system/bin/su (installed, then copied per uid)
#   zsu_ctl   the orchestrator CLI
#
# The kernel UAPI header is *not* copied into this tree: -I adds
# kernel/include so userspace/include/zerosu.h can include uapi/zerosu.h
# verbatim. A second copy would drift and tests/abi_layout.c would not catch
# it, because it asserts against the kernel header.

ROOT := $(CURDIR)
KINC := $(ROOT)/../kernel/include

CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Werror
CPPFLAGS += -D_GNU_SOURCE -I$(ROOT)/include -I$(KINC) -I$(ROOT)/daemon

DAEMON_SRCS := \
	daemon/main.c \
	daemon/session.c \
	daemon/policy.c \
	daemon/proc_monitor.c \
	daemon/ns_inject.c \
	daemon/broker.c \
	daemon/util.c

CTL_SRCS := ctl/zsu_ctl.c daemon/util.c
SU_SRCS  := su/zsu_stub.c

.PHONY: all clean check install

all: zerosud zsu_stub zsu_ctl

zerosud: $(DAEMON_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DAEMON_SRCS) $(LDFLAGS)

zsu_stub: $(SU_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SU_SRCS) $(LDFLAGS)

zsu_ctl: $(CTL_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(CTL_SRCS) $(LDFLAGS)

# Stage exactly the on-device layout. The 0711 on /data/adb/zerosu is what lets
# adb shell (uid 2000, gid shell) traverse to ctl.sock. bin/ is 0755 so the
# shell can execute the CLI, but the daemon and the stub inside it stay 0700.
# /data/adb itself is chmod 0711 at daemon startup (policy_init_paths) rather
# than here, because install(1) cannot set a mode on a directory it did not
# create.
PREFIX ?= /data/adb/zerosu

install: all
	install -d -m 0711 $(DESTDIR)$(PREFIX)
	install -d -m 0755 $(DESTDIR)$(PREFIX)/bin
	install -d -m 0700 $(DESTDIR)$(PREFIX)/uids
	install -m 0700 zerosud $(DESTDIR)$(PREFIX)/bin/zerosud
	install -m 0700 zsu_stub $(DESTDIR)$(PREFIX)/bin/zsu_stub
	install -m 0755 zsu_ctl $(DESTDIR)$(PREFIX)/bin/zsu_ctl

clean:
	rm -f zerosud zsu_stub zsu_ctl

# The full offline check: UAPI ABI, kernel syntax matrix, auth regression
# guard, userspace compile, and the EventLog decoder regression.
check:
	sh $(ROOT)/../tests/syntax-check.sh

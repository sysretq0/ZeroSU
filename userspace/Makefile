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

.PHONY: all clean check

all: zerosud zsu_stub zsu_ctl

zerosud: $(DAEMON_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(DAEMON_SRCS) $(LDFLAGS)

zsu_stub: $(SU_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(SU_SRCS) $(LDFLAGS)

zsu_ctl: $(CTL_SRCS)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(CTL_SRCS) $(LDFLAGS)

clean:
	rm -f zerosud zsu_stub zsu_ctl

# The kernel-side checks (UAPI ABI + stub syntax + auth regression guard).
check:
	sh $(ROOT)/../tests/syntax-check.sh

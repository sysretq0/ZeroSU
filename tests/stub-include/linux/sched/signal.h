/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal <linux/sched/signal.h> for the stub harness.
 *
 * struct sighand_struct itself (with its siglock) is defined in stub.h and
 * included first, so this header only carries the include guard that makes
 * `#include <linux/sched/signal.h>` reachable from kernel sources compiled
 * against the stubs. The real header declares the same struct plus the
 * signal machinery, which seccomp.c does not touch.
 */
#ifndef _STUB_LINUX_SCHED_SIGNAL_H
#define _STUB_LINUX_SCHED_SIGNAL_H

#include "../../stub.h"

#endif /* _STUB_LINUX_SCHED_SIGNAL_H */

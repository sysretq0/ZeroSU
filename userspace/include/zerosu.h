/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - userspace/include/zerosu.h
 *
 * The userspace side of the kernel contract. It does not re-declare anything:
 * the UAPI header is the single source of truth and is pulled in verbatim
 * from kernel/include/uapi/zerosu.h (the build adds -I<root>/kernel/include).
 *
 * Keeping this a one-line include is the point. A second hand-maintained copy
 * of the ABI is a copy that will drift, and tests/abi_layout.c would not
 * catch the drift because it asserts against the kernel header, not this one.
 */

#ifndef ZSU_USERSPACE_ZEROSU_H
#define ZSU_USERSPACE_ZEROSU_H

#include "uapi/zerosu.h"

#endif /* ZSU_USERSPACE_ZEROSU_H */

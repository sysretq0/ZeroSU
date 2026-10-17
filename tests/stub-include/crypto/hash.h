/* SPDX-License-Identifier: GPL-2.0 */
/*
 * The real kernel's shash API lives in <crypto/hash.h>, not <linux/crypto.h>.
 * The stub's shash subset is already in stub.h, so this is just the include
 * path the kernel build uses.
 */
#include <stub.h>

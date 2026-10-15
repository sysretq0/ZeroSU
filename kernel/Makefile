# SPDX-License-Identifier: GPL-2.0
#
# ZeroSU - kernel/Makefile
#
# Thin wrapper so the module builds from inside this directory without the
# caller having to remember the -C/-M incantation.
#
#   make KDIR=/path/to/kernel   # build zerosu.ko
#   make KDIR=/path/to/kernel clean
#   make check                  # syntax/ABI checks, no kernel tree needed
#
# KDIR is required for a real build. There is deliberately no fallback that
# guesses a kernel tree: a module compiled against the wrong headers is worse
# than no build at all.

KDIR ?=
PWD := $(shell pwd)

.PHONY: all modules clean check

all: modules

modules:
	@if [ -z "$(KDIR)" ]; then \
		echo "error: KDIR is not set."; \
		echo "  usage: make KDIR=/path/to/kernel-tree"; \
		echo "  (the tree must be configured: run make in it at least once)"; \
		exit 2; \
	fi
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	@if [ -n "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean; \
	else \
		rm -f *.o *.ko *.mod *.mod.c .*.cmd modules.order Module.symvers \
		      .tmp_versions 2>/dev/null || true; \
	fi

# Does not need a kernel tree: this is the check that can actually run
# anywhere, and it is what CI should run.
check:
	@sh $(PWD)/../tests/syntax-check.sh
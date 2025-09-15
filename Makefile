# Root Makefile
# Part of the Sherlock project
#
# Copyright (c) 2025 Mohammad Shehar Yaar Tausif
#
# This file is licensed under the MIT License.

SUBDIRS := watson irene
BUILD_DIR := build

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ BUILD_DIR=$(abspath $(BUILD_DIR))

clean:
	for dir in $(SUBDIRS); do \
		$(MAKE) -C $$dir clean BUILD_DIR=$(abspath $(BUILD_DIR)); \
	done
	rm -rf $(BUILD_DIR)

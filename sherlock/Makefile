# Sherlock Makefile
# Part of the Sherlock project
#
# Copyright (c) 2025 Mohammad Shehar Yaar Tausif
#
# This file is licensed under the MIT License.

# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -Wextra -g
LDFLAGS := -lm -D_DEFAULT_SOURCE -D_XOPEN_SOURCE=600 -lncursesw

TARGET  := sherlock
BUILD_DIR ?= ../build
BIN      := $(BUILD_DIR)/$(TARGET)

# Debug flag (default off)
DEBUG ?= 0
ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG=1
endif

# No colors flag (default off)
NOCOLORS ?= 0
ifeq ($(NOCOLORS),1)
	CFLAGS += -DNOCOLORS=1
endif

# Sources and objects
SRC  := $(wildcard *.c) \
        $(wildcard helpers/*.c)
HEADERS := $(wildcard *.h)
OBJ  := $(SRC:.c=.o)

# Ensure object directories exist
$(shell mkdir -p $(dir $(OBJ)))

.PHONY: all clean

all: $(BIN)

# Link (binary goes to build/)
$(BIN): $(OBJ)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Compile each .c to .o (in same folder as source)
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule (removes local .o and top-level binary)
clean:
	rm -f $(OBJ) $(BIN)

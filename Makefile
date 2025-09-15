# Compiler and flags
CC      := gcc
CFLAGS  := -Wall -Wextra -g
LDFLAGS := 

TARGET  := sherlock

# Debug flag (default off)
DEBUG ?= 0
ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG=1
endif

# Sources and objects
SRC  := $(wildcard *.c) \
		$(wildcard helpers/*.c)

HEADERS := $(wildcard *.h)
OBJ  := $(SRC:.c=.o)


all: $(TARGET)

# Link and build
$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $@ $(LDFLAGS)

# Compile (each .c -> .o)
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Clean rule
clean:
	rm -f $(OBJ) $(TARGET)


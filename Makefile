# Makefile for isa-dnsproxy

TARGET   := isa-dnsproxy

SRC_DIR  := src
INC_DIR  := include
OBJ_DIR  := build

CC       ?= cc
CSTD     := -std=c11
# getline, strdup, strncasecmp, strtok_r ... are POSIX, not plain C11
CPPFLAGS := -I$(INC_DIR) -D_POSIX_C_SOURCE=200809L -MMD -MP
CFLAGS   := $(CSTD) -Wall -Wextra -Wpedantic -O2
LDFLAGS  :=
# Add -lcurl (DoH) and -pthread (if you use threads) when you get there
LDLIBS   :=

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS     := $(OBJS:.o=.d)

.PHONY: all clean debug NixDevShellName

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

# Debug build with sanitizers: make clean && make debug
debug: CFLAGS := $(CSTD) -Wall -Wextra -Wpedantic -O0 -g -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefinedS
debug: $(TARGET)

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

# Required by the course guidelines: prints the language devShell name
NixDevShellName:
	@echo c

-include $(DEPS)
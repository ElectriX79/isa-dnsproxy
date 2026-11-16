# Makefile for isa-dnsproxy
#
# AI usage: this Makefile was written with the help of an AI assistant
# (Claude, Anthropic) and reviewed by the author, see "Use of AI" in README.md.
#
# Targets:
#   make                      build ./isa-dnsproxy
#   make test                 build and run the automated tests (pytest, see README.md)
#   make test-fast            the same without the slow tests (TCP idle timeout)
#   make debug                build with debug symbols and sanitizers
#   make clean                remove build artifacts
#   make zip LOGIN=xlogin99   create the submission archive xlogin99.zip
#   make NixDevShellName      print the dev-envs devShell used by this project

TARGET   := isa-dnsproxy

SRC_DIR  := src
INC_DIR  := include
OBJ_DIR  := build
TEST_DIR := tests

CC       ?= cc
PYTHON   ?= python3

# getline, strdup, strcasecmp, clock_gettime ... are POSIX, not plain C17
CPPFLAGS := -I$(INC_DIR) -D_POSIX_C_SOURCE=200809L -MMD -MP
CFLAGS   := -std=c17 -Wall -Wextra -Wpedantic -O2
LDFLAGS  :=
LDLIBS   := -lcurl

SRCS     := $(wildcard $(SRC_DIR)/*.c)
OBJS     := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS     := $(OBJS:.o=.d)

LOGIN    ?= xlogin99

.PHONY: all clean debug test test-fast zip NixDevShellName

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

# debug build: symbols, no optimisation, AddressSanitizer + UBSan
# (run "make clean" before switching between a normal and a debug build)
debug: CFLAGS := -std=c17 -Wall -Wextra -Wpedantic -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer
debug: LDFLAGS := -fsanitize=address,undefined
debug: $(TARGET)

# automated tests: black-box tests of the built executable (pytest)
test: $(TARGET)
	@$(PYTHON) -c "import pytest" 2>/dev/null || \
	  { echo "make test: pytest is not available for $(PYTHON), see the Testing section of README.md" >&2; exit 1; }
	ISA_BIN=./$(TARGET) $(PYTHON) -m pytest -v -rs $(TEST_DIR)

test-fast: $(TARGET)
	ISA_BIN=./$(TARGET) $(PYTHON) -m pytest -v -rs -m "not slow" $(TEST_DIR)

clean:
	rm -rf $(OBJ_DIR) $(TARGET) $(TEST_DIR)/__pycache__ .pytest_cache

# submission archive: sources, tests, docs; no build artifacts, .git or caches
zip: clean
	rm -f $(LOGIN).zip
	zip -r $(LOGIN).zip Makefile README.md LICENSE CHANGELOG.md $(SRC_DIR) $(INC_DIR) $(TEST_DIR) \
	    $(wildcard examples) -x '*/__pycache__/*' '*.pyc'

NixDevShellName:
	@echo c

-include $(DEPS)
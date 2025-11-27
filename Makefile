CC ?= gcc
CFLAGS ?= -g -std=c11 -Wall -Wextra
CPPFLAGS ?= -I. -Ilibssh -Ilibdepds/libssh-0.9.3/include -Iphy_sql -Itty -Iprompt
CPPFLAGS += -D_GNU_SOURCE
LDFLAGS ?=
LDFLAGS += -Llibdepds/libssh-0.9.3/lib
LDLIBS ?= -lssh -lpthread -lm -ldl -lutil

BUILD_DIR ?= build
OBJ_DIR = $(BUILD_DIR)/obj
GET_TARGET = $(BUILD_DIR)/get
EXCLUDE_SRCS := ./prompt/fzy.c ./async/async_server.c ./async/server.c ./tty/mytty.c
SERVER_SRCS := $(filter-out $(EXCLUDE_SRCS), \
        $(shell find . -path './get' -prune -o -path './async' -prune -o -name '*.c' -print))
SERVER_OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SERVER_SRCS))
SERVER_BIN = $(BUILD_DIR)/server

ifeq ($(MAKECMDGOALS),deb)
BUILD_DIR := Debug
CFLAGS += -g
endif

ifeq ($(MAKECMDGOALS),res)
BUILD_DIR := Release
CFLAGS := -O2 -std=c11 -Wall -Wextra
endif

.PHONY: all server get clean deb res

all: $(SERVER_BIN) $(GET_TARGET)

$(SERVER_BIN): $(SERVER_OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SERVER_OBJS) $(LDLIBS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

server: $(SERVER_BIN)

get: $(GET_TARGET)

$(GET_TARGET):
	@mkdir -p $(BUILD_DIR)
	$(MAKE) -C get TARGET=$(abspath $(GET_TARGET)) OBJDIR=$(abspath $(BUILD_DIR))/get_objs BINDIR=$(abspath $(BUILD_DIR))

deb: all

res: all

clean:
	rm -rf $(BUILD_DIR) Debug Release
	find . -name '*.o' -not -path './get/*' -delete
	$(MAKE) -C get clean

CC ?= gcc
CFLAGS ?= -g -std=c11 -Wall -Wextra
CPPFLAGS ?= -I. -Ilibssh -Ilibdepds/libssh-0.9.3/include -Iphy_sql -Itty -Iprompt
CPPFLAGS += -D_GNU_SOURCE
LDFLAGS ?=
LDFLAGS += -Llibdepds/libssh-0.9.3/lib
LDLIBS ?= -lssh -lpthread -lm -ldl -lutil

GET_TARGET := get
EXCLUDE_SRCS := ./prompt/fzy.c ./async/async_server.c ./async/server.c ./tty/mytty.c
SERVER_SRCS := $(filter-out $(EXCLUDE_SRCS), $(shell find . -path './get' -prune -o -path './async' -prune -o -name '*.c' -print))
SERVER_OBJS := $(SERVER_SRCS:.c=.o)
SERVER_BIN := server

.PHONY: all server get clean

all: $(SERVER_BIN) get

$(SERVER_BIN): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SERVER_OBJS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

server: $(SERVER_BIN)

get:
	$(MAKE) -C get TARGET=$(GET_TARGET)

clean:
	rm -f $(SERVER_BIN) $(SERVER_OBJS)
	find . -name '*.o' -not -path './get/*' -delete
	$(MAKE) -C get clean

CC=gcc
CFLAGS=-g -std=c11 -Wall -Wextra -I. -Istubs
OBJDIR?=.
BINDIR?=.
TARGET?=$(BINDIR)/get
SRCS=main.c config.c channel_client.c
OBJS=$(addprefix $(OBJDIR)/,$(SRCS:.c=.o))

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

tests/fake_server: tests/fake_server.c protocol.h
	$(CC) $(CFLAGS) -o $@ $<

test: $(TARGET) tests/fake_server
	./tests/run_tests.sh ./$(TARGET) ./tests/fake_server

clean:
	rm -f $(TARGET) $(OBJS) tests/fake_server
	@if [ "$(OBJDIR)" != "." ]; then rm -rf $(OBJDIR); fi
	rm -rf tests/tmp*

.PHONY: all clean test

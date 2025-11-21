CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -I. -Istubs
TARGET=get_client
SRCS=main.c config.c channel_client.c
OBJS=$(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

tests/fake_server: tests/fake_server.c protocol.h
	$(CC) $(CFLAGS) -o $@ $<

test: $(TARGET) tests/fake_server
	./tests/run_tests.sh ./$(TARGET) ./tests/fake_server

clean:
	rm -f $(TARGET) $(OBJS) tests/fake_server
	rm -rf tests/tmp*

.PHONY: all clean test

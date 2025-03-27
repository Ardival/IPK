# Author: Juraj Budai
# Login: xbudai02
# Date: 26.3.2025

CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -pthread -lpcap
TARGET = ipk-l4-scan
SRCS = ipk-l4-scan.c recv.c send_tcp.c send_udp.c
OBJS = $(SRCS:.c=.o)
DEPS = ipk.h

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c ipk.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

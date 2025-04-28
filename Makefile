CC     = gcc
CFLAGS = -Wall -Wextra -O2 -std=gnu17
LFLAGS =

.PHONY: all clean

TARGET1 = peer-time-sync

all: $(TARGET1)

$(TARGET1): $(TARGET1).o err.o known-peer.o time.o

peer-time-sync.o: peer-time-sync.c err.h
err.o: err.c err.h
known-peer.o: known-peer.c known-peer.h err.h
time.o: time.c time.h

clean:
	rm -f $(TARGET1) *.o *~

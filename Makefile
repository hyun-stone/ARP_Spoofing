CC = g++
CFLAGS = -g -Wall
OBJS = main.o
TARGET = arp-spoofing

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -lpcap
	rm *.o

main.o: hdr.h main.cpp

clean:
	rm -rf *.o $(TARGET)

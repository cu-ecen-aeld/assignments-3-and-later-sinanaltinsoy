CC := gcc
CROSS_COMPILE :=
TARGET := writer

ifeq ($(CROSS_COMPILE),aarch64-none-linux-gnu-)
	CC := $(CROSS_COMPILE)$(CC)
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): writer.o
	$(CC) -o $(TARGET) writer.o

writer.o: writer.c
	$(CC) -c writer.c

clean:
	rm -f $(TARGET) writer.o
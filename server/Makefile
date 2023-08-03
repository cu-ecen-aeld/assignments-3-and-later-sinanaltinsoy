SRC := aesdsocket.c
TARGET = aesdsocket
OBJS := $(SRC:.c=.o)


CC := $(CROSS_COMPILE)gcc

all: $(TARGET)

$(TARGET) : $(OBJS)

ifeq ($(CROSS_COMPILE), native)
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) -o $(TARGET) $(LDFLAGS)
endif

ifeq ($(CROSS_COMPILE), aarch64-none-linux-gnu-)
	$(CC) -g -Wall -c -o $(OBJS) $(SRC)
	$(CC) -g -Wall -I/ $(OBJS) -o  $(TARGET)
endif


clean:
	-rm -f *.o $(TARGET)
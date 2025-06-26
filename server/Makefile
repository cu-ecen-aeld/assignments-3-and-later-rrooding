CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Werror
TARGET 	?= aesdsocket
LDFLAGS ?= -lpthread -lrt
SRC = aesdsocket.c
OBJ = $(SRC:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o 
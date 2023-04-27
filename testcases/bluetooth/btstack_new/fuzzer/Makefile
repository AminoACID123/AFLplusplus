
SRC = $(wildcard src/*) 

OBJ := $(SRC:.c=.o)

CFLAGS = -g -Iinclude

LIBS := $(NIMBLE_LDFLAGS) -lrt -lpthread -lstdc++

.PHONY: all clean
.DEFAULT: all

all: btfuzz

clean:
	rm $(OBJ) -f
	rm btfuzz -f

%.o: %.c
	gcc -c $(CFLAGS) -o $@ $<

btfuzz: $(OBJ)
	gcc -static -o $@ $^ 
	size $@

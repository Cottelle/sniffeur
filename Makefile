CC ?= "gcc"
CFLAGS ?=-Wall -Wextra -Werror -g
LIB ?=-lpcap

TARGET = analyseur

SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o) 

analyseur: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIB)

%.o: %.c
	gcc -o $@ -c $^ $(CFLAGS) $(LIB)

clean:
	rm -f *.o
	rm -f analyseur


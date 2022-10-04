CC ?= "gcc"
CFLAGS ?=-Wall -Wextra -Werror -g
LIB ?=-lpcap

TARGET = analyseur

SRC = protocol.c analyseur.c
OBJ = $(SRC:.c=.o) 

analyseur: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIB)

%.o: %.c
	gcc -o $@ -c $^ $(CFLAGS) $(LIB)



# analyseur.o: analyseur.c
# 	gcc -o analyseur.o -c analyseur.c $(CFLAGS)

# dhcp.o: dhcp.c
# 	gcc -o dhcp.o -c dhcp.c $(CFLAGS)

clean:
	rm -f *.o
	rm -f analyseur


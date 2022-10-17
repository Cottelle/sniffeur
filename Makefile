CC ?= "gcc"
CFLAGS ?=-Wall -Wextra -Werror -g
LIB ?=-lpcap

TARGET = analyseur

SRC = $(wildcard *.c)
# SRC = analyseur.c args-parser.c my_ethernet.c trameinfo.c my_ip.c my_tcp.c my_udp.c my_bootp.c my_dhcp.c
OBJ = $(SRC:.c=.o) 

analyseur: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIB)

%.o: %.c
	gcc -o $@ -c $^ $(CFLAGS) $(LIB)

clean:
	rm -f *.o
	rm -f analyseur


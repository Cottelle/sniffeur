CFLAGS ?= -Wall -Wextra -Werror -g
LIB ?= -lpcap

analyseur: analyseur.o dhcp.o
	gcc -o analyseur analyseur.o dhcp.o	$(CFLAGS) $(LIB)

analyseur.o: analyseur.c
	gcc -o analyseur.o -c analyseur.c $(CFLAGS)

dhcp.o: dhcp.c
	gcc -o dhcp.o -c dhcp.c $(CFLAGS)

clean:
	rm *.o
	rm analyseur


CC=gcc
LIB=/logiciels/openldap/2.4/lib
#-std=c99 option for allowing variable length array
INCLUDE=/logiciels/openldap/2.4/include
CFLAGS=-W -Wall -ansi -std=c99 -pedantic -I $(INCLUDE) -D_REENTRANT
LDFLAGS=-L $(LIB) -lpthread -lldap_r -llber
EXEC=perfsldap

all: $(EXEC)

$(EXEC): main.o
	$(CC) -o $(EXEC) main.o $(LDFLAGS)

main.o: main.c
	$(CC) -o main.o -c main.c $(CFLAGS)

clean:
	rm -rf *.o

fullclean: clean
	rm -rf $(EXEC)

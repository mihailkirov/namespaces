
COMPI=gcc
OPT=-Wall
OPT1=-c
all: main

main: main.o namespaces.o networking.o
	$(COMPI) $(OPT)  $^ -o $@

main.o: main.c namespaces.h networking.h
	$(COMPI) $(OPT1) $<

namespaces.o: namespaces.c namespaces.h networking.h
	$(COMPI) $(OPT1)  $<

networking.o: networking.c networking.h

clean:
	rm *.o;
	rm -rf rootfs;

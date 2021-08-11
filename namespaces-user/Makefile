
all: dep main

dep:
	sudo apt-get install libcap-dev
main: user_ns.c
	gcc -Wall $< -lcap -o $@ 
	

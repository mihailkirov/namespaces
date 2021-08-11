#define _GNU_SOURCE
#include </usr/include/sys/capability.h>

#include </usr/include/x86_64-linux-gnu/sys/types.h>
#include </usr/include/x86_64-linux-gnu/sys/wait.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define STACKS (1024*1024)

static char child_stack[STACKS];

static int capability_show(void *args){
		
		cap_t capabilties;

        capabilties = cap_get_proc();
		printf("Capabilities of child process viewed from child namespace %s \n", cap_to_text(capabilties, NULL));
        printf("Namespaced process eUID = %ld;  eGID = %ld;  ",
                (long) geteuid(), (long) getegid());


    	exit(EXIT_SUCCESS);
}


int main(int argc, char *argv[]) {
 		pid_t pid;
		
		cap_t capabilties;
		// stack growing downwards
		if ((pid=clone(capability_show, child_stack + STACKS, CLONE_NEWUSER | SIGCHLD, NULL )) == -1) {
				fprintf(stderr, "Error on clone");
				exit(EXIT_FAILURE);
		}
		
        capabilties = cap_get_proc();
		printf("Capabilities of child process viewed from parent namespace %s\n", cap_to_text(capabilties, NULL));	
	

		if (waitpid(pid, NULL, 0) == -1){
				fprintf(stderr, "Error wait for child to exit");
				exit(EXIT_FAILURE);
		}
	
		return 0;
}

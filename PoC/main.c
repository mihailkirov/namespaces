#include "namespaces.h"
#include "networking.h"

int main(int argc, char *argv[]){
		

		Params *c = calloc(1, sizeof(Params));
		// init the pipe
		pipe(c->fd);
		parse_args(argc, argv, c);
		
		// recieve signal on child process termination
		 int flags = SIGCHLD | CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC| CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWCGROUP;
		 pid_t pid; 
		 // we assume that the child stack growns downwards 
		 if((pid=clone(cmd_exec, stack_child + STACK_SIZE, flags, c)) == -1) {
				 fprintf(stderr,"Error clone %s", strerror(errno));
				 exit(EXIT_FAILURE);
		}

		prepare_user_ns(pid);
		prepare_netns(pid);
		int sig = 1;
		write(c->fd[1], &sig, sizeof(int));
		close(c->fd[1]);
		waitpid(pid, NULL, 0);
		free(c);
		return 0;
}

#include "namespaces.h"
#include "networking.h"
int cmd_exec(void *args){
		
		Params *c = (Params*)args;

		// terminate child process if its father has terminated		
		if(prctl(PR_SET_PDEATHSIG, SIGKILL)){
				fprintf(stderr,"Father process died - terminating\n");
				exit(EXIT_FAILURE);
		}		

		int cont;
	        // sync	
		read(c->fd[0], &cont, sizeof(int)); // blocking read
		close(c->fd[0]);
		
		// prepare mount ns and uts namespace
		prepare_mount_ns();	
		prepare_uts_ns();
		char program[1024];
		
		// assuming the process is remapped to a unprivileged user in the above user namespace
		// set the uid and gid of the process to root
		// this drop superuser privileges
		if ((setgid(0) == -1) || (setuid(0) == -1)){
		 	fprintf(stderr," Error setting uid/gid inside userns of child process -%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		 }
		

		if(c->type_shell == 1) {
			sprintf(program, "/bin/%s", "bash");
		} else {
			sprintf(program, "/bin/%s", "sh");
		}
		char *args_exec[] = {program , NULL}; 
		if(execvp(program, args_exec) == -1){
			fprintf(stderr,"Error opening program -%s\n  %s\n", program, strerror(errno));
			exit(EXIT_FAILURE);
		}
		return 0;
}

void usage(char *argv[]){
		fprintf(stderr," %s <type-of-shell-sh|bash> <type of image - alpine|busybox> <uid-to-remap>\n", argv[0]);	
		exit(EXIT_FAILURE);
}


void parse_args(int argc, char *argv[], Params *c) {
	
	if(argc != 4){
			fprintf(stderr,"Bad number of arguments\n");
			usage(argv);
	}
	
	if(!(strcmp("bash", argv[1]))) {
		c->type_shell = 1;
	} else if (!strcmp("sh", argv[1])) {
		c->type_shell = 0;
	} else {
		fprintf(stderr, "Bad shell argument - defaulting to sh\n");
		c->type_shell = 0;
	}
	
	if(!(strcmp("alpine", argv[2]))) {
		c->type_image = 1;
	} else if(!strcmp("busybox", argv[2])) {
		c->type_image = 0;
	}else if(!strcmp("ubuntu", argv[2])) {
		c->type_image = 2;
	
	} else {
		fprintf(stderr, "Bad image argument - defaulting to alpine\n");
		c->type_image = 1;
		c->type_shell = 0;
	} 
	if((c->type_image == 1 || c->type_image == 0)  && c->type_shell == 1 ) {
			fprintf(stderr,"Incorrect shell dependant on image -> defaulting to sh\n");
			c->type_shell = 0;
	}
	
	unsigned int uid_remap = atoi(argv[3]);
	extract_image(c->type_image, uid_remap);

}

// helper function to deletedir 
static int rmFiles(const char *pathname, const struct stat *sbuf, int type, struct FTW *ftwb)
{
    if(remove(pathname) < 0)
    {
        fprintf(stderr,"ERROR: remove -%s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    return 0;
}

/*
 * Delete the contents of the rootfs directory
 */
static int deletedir(char *dirname) {
	if (nftw(dirname, rmFiles, 10, FTW_DEPTH|FTW_MOUNT|FTW_PHYS) < 0){
        	fprintf(stderr, "ERROR: ntfw %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
    	}
}
// extract chosen image inside fd
static void extract_image(int type, int uid_remap){
	
	pid_t pid;
	char image[100];
	unsigned short exist;
	DIR* dir;
       
	if((dir=opendir("rootfs"))) {
    		/* Directory exists. */
		closedir(dir);
		deletedir("rootfs");
		if(mkdir("rootfs", 0766) == -1){
			fprintf(stderr, "Error creating directory after delete -%s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}	
	} else if (ENOENT==errno && (mkdir("rootfs", 0766)==-1)){
		fprintf(stderr, "Error creating rootfs - %s\n", strerror(errno));
		exit(EXIT_FAILURE);	
	} else if (ENOENT != errno) {
		fprintf(stderr, "Error opening directory rootfs - %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	if(!(pid = fork())) {

		char *args_exec[] = {"/bin/tar","--overwrite", "-xf", image,  "-C", "rootfs",  NULL}; 
		switch (type){
			case 1:
				strcpy(image, "alpine.tar");
				break;	
			case 2:
				strcpy(image, "ubuntu.tar");
				break;	
			default :
				strcpy(image, "busybox.tar");
		}
		// untar the corresponding file system
		if(execve("/bin/tar",  args_exec, NULL) == -1){
			fprintf(stderr,"Error extracting %s filesystem  %s\n", image, strerror(errno));
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);	
	}
	int status;
	waitpid(pid, &status, 0); // check for status 
	if(WIFEXITED(status) && WEXITSTATUS(status) ) {
  		exit(EXIT_FAILURE);	
  	}
	// change ownership
	if(!(pid = fork())) {
		memset(image, 0x00, 100);
		sprintf(image, "%d:%d", uid_remap, uid_remap);
		
		char *args_exec[] = {"/bin/chown","-R", image, "rootfs",  NULL}; 	
		if(execve("/bin/chown",  args_exec, NULL) == -1){
			fprintf(stderr,"Error changing permissions of  %s filesystem  %s\n", image, strerror(errno));
			exit(EXIT_FAILURE);
		}
		exit(EXIT_SUCCESS);
	}
	// wait for status
	waitpid(pid, &status, 0); // check for status 
	if(WIFEXITED(status) && WEXITSTATUS(status) ) {
  		exit(EXIT_FAILURE);	
	}

	if(chown("rootfs", 1000, 1000) == -1){
		fprintf(stderr,"Error changing permissions of filesystem %s", strerror(errno));
	}
}



/*
 * Write the line line to the file designated by path
 */
void write_file(char *path, char *line)
{
    FILE *f ;
    if (!(f=fopen(path,"w"))) {	
	fprintf(stderr, "Error on opening file %s", strerror(errno));
    	exit(EXIT_FAILURE);
	}

    if (fwrite(line, 1, strlen(line), f) != strlen(line)) {
	fprintf(stderr, "Error on opening file %s\n%s", path, strerror(errno));
    	exit(EXIT_FAILURE);
    }

    if (fclose(f)) {
        fprintf(stderr, "Error on closing file %s\n%s", path, strerror(errno));
    	exit(EXIT_FAILURE);
    }
}


void prepare_user_ns(pid_t pid)
{
    char path[PATH_MAX];
    char line[20];
    // remap the UID
    sprintf(path, "/proc/%d/uid_map", pid);
    sprintf(line, "0 1000 1\n");
    write_file(path, line);	
     // IN order to define a group mapping
     // we have to disable the setgroups syscall
    sprintf(path, "/proc/%d/setgroups", pid);
    sprintf(line, "deny");
    write_file(path, line);
    // remapt the GID
    sprintf(path, "/proc/%d/gid_map", pid);
    sprintf(line, "0 1000 1\n");
    write_file(path, line);
}
// Changing the root filesystem of the executing process
void prepare_mount_ns() {
	
	int ret;
	if((ret=mount("rootfs", "rootfs", "ext4",  MS_BIND, NULL)) == -1){
		fprintf(stderr, "Error bind mounting rootfs %s\n", strerror(errno));
	        exit(EXIT_FAILURE);	
	}
	// go inside the new mount point
	if((ret=chdir("rootfs")) == -1){

		fprintf(stderr, "Error chdir %s", strerror(errno));
	        exit(EXIT_FAILURE);	
	}
	
	// configure the pid namespace
	prepare_pid_ns();
	
	// change the root of the process
	if((ret=pivot_root(".", "."))==-1){
		fprintf(stderr, "Error changing root directory %s", strerror(errno));
		exit(EXIT_FAILURE);
	}	
	
	// detach from the old root
	umount2(".", MNT_DETACH);
		
	// change root directory
	if((ret=chdir("/")) == -1){
		fprintf(stderr, "Error chdir %s", strerror(errno));
	        exit(EXIT_FAILURE);	
	}

}
// Prepare the pid namespace by mounting the procfs vfs in order to obtain results of the currently running processes
void prepare_pid_ns() {
	
	if(mkdir("/proc", 0555) && errno != EEXIST){
		fprintf(stderr, "Error creating procfs %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	int ret;

	// mount the procfs inside the new mount namespace
	if((ret=mount("/proc", "proc", "proc", 0, NULL)) == -1){
		fprintf(stderr, "Error mounting procfs %s\n", strerror(errno));
	        exit(EXIT_FAILURE);	
	}
				
}

 // Change the root directory of the calling process via syscall
int pivot_root(const char *new_root, const char *put_old) {
           return syscall(SYS_pivot_root, new_root, put_old);
}


// Executed by cloned process
// Setting the hostname in the isolated UTS namespace
void prepare_uts_ns(){
	
	if(sethostname("isolated", strlen("isolated") == -1)) {
		fprintf(stderr,"Error setting hostname %s", strerror(errno));
		exit(EXIT_FAILURE);
	
	}
}
// Setup the network namespace
void prepare_netns(int child_pid){

    // Create our netlink socket
    int sock_fd = create_socket(
            PF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

    // ... and our veth pair veth0 <=> veth1.
    create_pair_veth(sock_fd, VETH, PEER);

    // veth0 is in our current (initial) namespace
    // so we can bring it up immediately.
    assign_ip_netmask(VETH, VETHADDR, NETMASK);

    // ... veth1 will be moved to the command namespace.
    // To do that though we need to grab a file descriptor
    // to and enter the commands namespace but first we must
    // remember our current namespace so we can get back to it
    // when we're done.
    int mynetns = get_netns_fd(getpid());
    int child_netns = get_netns_fd(child_pid);

    // Move veth1 to the command network namespace.
    move_if_to_pid_netns(sock_fd, PEER, child_netns);

    // ... then enter it
    if (setns(child_netns, CLONE_NEWNET)) {
        fprintf(stderr, "cannot setns for child at pid %d: %s\n", child_pid, strerror(errno));
    }

    // ... and bring veth1 up
    assign_ip_netmask(PEER, PEERADDR, NETMASK);

    // ... before moving back to our initial network namespace.
    if (setns(mynetns, CLONE_NEWNET)) {
        fprintf(stderr, "cannot restore previous netns: %s\n", strerror(errno));
    }

    close(sock_fd);
}

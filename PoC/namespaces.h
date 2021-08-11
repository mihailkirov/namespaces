// This code is mainly inspired by https://github.com/iffyio/isolate/tree/part-4
#ifndef MAIN_H
#define MAIN_H
#define _GNU_SOURCE
#include <stdio.h>
#include <sched.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <wait.h>
#include <memory.h>
#include <syscall.h>
#include <dirent.h>
#include <ftw.h>
#include <errno.h>
#include </usr/include/x86_64-linux-gnu/sys/syscall.h>
#include </usr/include/x86_64-linux-gnu/sys/mount.h>
#include </usr/include/x86_64-linux-gnu/sys/prctl.h>
#include <fcntl.h>
// definitions
#define STACK_SIZE (1024 * 1024)
#define PATH_MAX 4096
// network namespace definitions
#define VETHADDR "192.168.06.1"
#define PEERADDR "192.167.06.2"
#define VETH "veth0"
#define PEER "veth1"
#define NETMASK "255.255.255.0"
#define DIRECTORYNAME "rootfs"

typedef struct {
	int fd[2]; // communication pipe
	int type_image;
	int type_shell;
} Params;
char stack_child[STACK_SIZE];
void parse_args(int argc, char *argv[], Params *c);
static void extract_image(int type, int uid_remap);
// which command is going to be executed by the child process
int cmd_exec(void *args);
void usage(char *argv[]);
//void get_image(Params *c);
static void write_file(char *path, char *str);
// remap child user namespaced process to root within the namespace
void prepare_user_ns(pid_t pid);
 void prepare_uts_ns();
void prepare_net_ns();
void cleanup_net_ns();
// prepare the mount namespace
void prepare_mount_ns();
void prepare_pid_ns();
void prepare_netns();
int pivot_root(const char *new_root, const char *put_old);
#endif

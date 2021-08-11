// This code is mainly inspired by https://github.com/iffyio/isolate/tree/part-4

#ifndef NETWORKING_H 
#define NETWORKING_H
#define _GNU_SOURCE
#include <stdio.h>
#include <stdio.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <errno.h>
#include <string.h>
#include <linux/rtnetlink.h>
#include <linux/veth.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include </usr/include/x86_64-linux-gnu/sys/ioctl.h>
#include <sched.h>

#define MAX_PAYLOAD 1024
struct nl_req {
    struct nlmsghdr n;
    struct ifinfomsg i;
    char buf[MAX_PAYLOAD];
};
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

void create_pair_veth(int sockfd, char *ifname, char *peername);
int create_socket(int domain, int type, int protocol);
void assign_ip_netmask(char *ifname, char *ip, char *netmask);
int get_netns_fd(int pid);
void move_if_to_pid_netns(int sock_fd, char *ifname, int netns);
#endif

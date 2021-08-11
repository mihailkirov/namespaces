#include "networking.h"

 /*
  * open socket to communicate with the kernel in order to create veth's
 */
int create_socket(int domain, int type, int protocol)
{
    int sock_fd = socket(domain, type, protocol);
    if (sock_fd < 0){
        fprintf(stderr, "cannot open socket: %s\n", strerror(errno));
    	exit(EXIT_FAILURE);
    }
    return sock_fd;
}


static void addattr_l(
        struct nlmsghdr *n, int maxlen, __u16 type,
        const void *data, __u16 datalen)
{
    __u16 attr_len = RTA_LENGTH(datalen);

    __u32 newlen = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(attr_len);
    if (newlen > maxlen){
        fprintf(stderr, "cannot add attribute. size (%d) exceeded maxlen (%d)\n",
            newlen, maxlen);
    	exit(EXIT_FAILURE);
    }
    struct rtattr *rta;
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = attr_len;
    if (datalen)
        memcpy(RTA_DATA(rta), data, datalen);

    n->nlmsg_len = newlen;
}

static struct rtattr *addattr_nest(
		struct nlmsghdr *n, int maxlen, __u16 type)
{
    struct rtattr *nest = NLMSG_TAIL(n);

    addattr_l(n, maxlen, type, NULL, 0);
    return nest;
}

static void addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
}

static ssize_t read_response(int fd, struct msghdr *msg, char **response){
    struct iovec *iov = msg->msg_iov;
    iov->iov_base = *response;
    iov->iov_len = MAX_PAYLOAD;

    ssize_t resp_len = recvmsg(fd, msg, 0);

    if (resp_len == 0){
        fprintf(stderr, "EOF on netlink\n");
    	exit(EXIT_FAILURE);
    }else if (resp_len < 0){
        fprintf(stderr,"netlink receive error: %m\n");
    	exit(EXIT_FAILURE);
    }
    return resp_len;
}

static void check_response(int sock_fd){
    struct iovec iov;
    struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1
    };
    char *resp = malloc(MAX_PAYLOAD);

    ssize_t resp_len = read_response(sock_fd, &msg, &resp);

    struct nlmsghdr *hdr = (struct nlmsghdr *) resp;
    int nlmsglen = hdr->nlmsg_len;
    int datalen = nlmsglen - sizeof(*hdr);

    // Did we read all data?
    if (datalen < 0 || nlmsglen > resp_len) {
        if (msg.msg_flags & MSG_TRUNC)
            fprintf(stderr, "received truncated message\n");

        fprintf(stderr, "malformed message: nlmsg_len=%d\n", nlmsglen);
    	exit(EXIT_FAILURE);
    }

    // Was there an error?
    if (hdr->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *) NLMSG_DATA(hdr);

        if (datalen < sizeof(struct nlmsgerr)){
            fprintf(stderr, "ERROR truncated!\n");
		exit(EXIT_FAILURE);
	}

        if(err->error) {
            errno = -err->error;
            fprintf(stderr, "RTNETLINK: %s\n", strerror(errno));
        	exit(EXIT_FAILURE);
	}
    }

    free(resp);
}

static void send_nlmsg(int sock_fd, struct nlmsghdr *n)
{
    struct iovec iov = {
            .iov_base = n,
            .iov_len = n->nlmsg_len
    };

    struct msghdr msg = {
            .msg_name = NULL,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1
    };

    n->nlmsg_seq++;

    ssize_t status = sendmsg(sock_fd, &msg, 0);
    if (status < 0){
        fprintf(stderr, "cannot talk to rtnetlink: %s\n", strerror(errno));
	exit(EXIT_FAILURE);
 	}
    check_response(sock_fd);
}

int get_netns_fd(int pid){
    char path[256];
    sprintf(path, "/proc/%d/ns/net", pid);

    int fd = open(path, O_RDONLY);

    if (fd < 0){
        fprintf(stderr, "cannot read netns file %s: %s\n", path, strerror(errno));
	exit(EXIT_FAILURE);
    }
    return fd;
}
/*
 * Create a veth pair 
 */
void create_pair_veth(int sockfd, char *ifname, char *peername){ 
   /* 
    	struct nl_req {
    	struct nlmsghdr n;     // Netlink message header
    	struct ifinfomsg i;    // Payload starting with NIS module info
    	char buf[MAX_PAYLOAD]; // Remaining payload
	};
   */		
   
    __u16 flags =
            NLM_F_REQUEST  // This is a request message
            | NLM_F_CREATE // Create the device if it doesn't exist
            | NLM_F_EXCL   // If it already exists, do nothing
            | NLM_F_ACK;   // Reply with an acknowledgement or error

    // Initialise request message.
    struct nl_req req = {
            .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .n.nlmsg_flags = flags,
            .n.nlmsg_type = RTM_NEWLINK, // This is a netlink message
            .i.ifi_family = PF_NETLINK,
    };
    struct nlmsghdr *n = &req.n;
    int maxlen = sizeof(req);

    /*
     * Create an attribute r0 with the veth info. e.g if ifname is veth0
     * then the following will be appended to the message
     * {
     *   rta_type: IFLA_IFNAME
     *   rta_len: 5 (len(veth0) + 1)
     *   data: veth0\0
     * }
     */
    addattr_l(n, maxlen, IFLA_IFNAME, ifname, strlen(ifname) + 1);

    // Add a nested attribute r1 within r0 containing iface info
    struct rtattr *linfo = addattr_nest(n, maxlen, IFLA_LINKINFO);
    // Specify the device type is veth
    addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, "veth", 5);

    // Add another nested attribute r2
    struct rtattr *linfodata =
            addattr_nest(n, maxlen, IFLA_INFO_DATA);

    // This next nested attribute r3 one contains the peer name e.g veth1
    struct rtattr *peerinfo = addattr_nest(n, maxlen, VETH_INFO_PEER);
    n->nlmsg_len += sizeof(struct ifinfomsg);
    addattr_l(n, maxlen, IFLA_IFNAME, peername, strlen(peername) + 1);
    addattr_nest_end(n, peerinfo); // end r3 nest
    addattr_nest_end(n, linfodata); // end r2 nest
    addattr_nest_end(n, linfo); // end r1 nest
    // Send the message
    send_nlmsg(sockfd, n);

}


// $ ip link set veth1 netns coke
void move_if_to_pid_netns(int sock_fd, char *ifname, int netns)
{
    struct nl_req req = {
            .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
            .n.nlmsg_type = RTM_NEWLINK,
            .i.ifi_family = PF_NETLINK,
    };

    addattr_l(&req.n, sizeof(req), IFLA_NET_NS_FD, &netns, 4);
    addattr_l(&req.n, sizeof(req), IFLA_IFNAME,
              ifname, strlen(ifname) + 1);
    send_nlmsg(sock_fd, &req.n);
}

/*
 * assign IP and netmask and put the interface up
 */
void assign_ip_netmask(char *ifname, char *ip, char *netmask)
{
    int sock_fd = create_socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    strncpy(ifr.ifr_name, ifname, strlen(ifname));

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 0;

    char *p = (char *) &saddr;

    saddr.sin_addr.s_addr = inet_addr(ip);
    memcpy(((char *)&(ifr.ifr_addr)), p, sizeof(struct sockaddr));
    if (ioctl(sock_fd, SIOCSIFADDR, &ifr)){
        fprintf(stderr, "cannot set ip addr %s, %s: %s\n", ifname, ip, strerror(errno));
    	exit(EXIT_FAILURE);
    }
    saddr.sin_addr.s_addr = inet_addr(netmask);
    memcpy(((char *)&(ifr.ifr_addr)), p, sizeof(struct sockaddr));
    if (ioctl(sock_fd, SIOCSIFNETMASK, &ifr)){
        fprintf(stderr, "cannot set netmask for addr %s, %s: %s\n", ifname, netmask, strerror(errno));
    
    	exit(EXIT_FAILURE);
    }
    ifr.ifr_flags |= IFF_UP | IFF_BROADCAST |
                     IFF_RUNNING | IFF_MULTICAST;
    if (ioctl(sock_fd, SIOCSIFFLAGS, &ifr)){
        fprintf(stderr, "cannot set flags for addr %s, %s: %s\n", ifname, ip, strerror(errno));
    	exit(EXIT_FAILURE);
    }
    close(sock_fd);
}




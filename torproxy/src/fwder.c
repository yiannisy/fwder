#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <limits.h>
#include <pthread.h>

#define LISTEN_PORT 9999

#define TUNNEL_UNINIT 0
#define TUNNEL_TOR 1
#define TUNNEL_WEB 2

#define FP_LEN 40

#define MAX_SOCKETS 255
#define MAX_TUNNELS 127

#define MAX_RELAYS 10000
#define DIRECTORY_IP "128.31.0.34"
#define DIRECTORY_PORT 9131
#define DIRECTORY_URL "dannenberg.ccc.de"

#define TUN_GRANTED 0x5a
#define TUN_REJECTED 0x5b

static bool is_tor = false;
static bool is_web = false;

struct tunnel {
	uint16_t tunnel_id; // unique ID
	uint16_t type; // type for the tunnel
	uint16_t rate_limit; // in Kbps
	bool is_init; // whether we've completed the tunnel to the other side
	bool is_reserved; // whether the tunnel is reserved
	bool is_active;
	struct pollfd * in_pfd; // incoming polling socket
	struct pollfd * out_pfd; // outgoig polling socket
	struct sockaddr_in nexthop_addr; // the address to forward data to
	char nexthop_fp[41];
};

struct socks_hdr {
	uint8_t version;
	uint8_t code;
	uint16_t port;
	uint32_t ipaddr;
};

struct relay_info {
  uint32_t ipaddr;
  uint16_t port;
  uint16_t dir_port;
};

/* Get the latest consensus from a TOR directory. */
static void
update_tor_dir(struct relay_info * relays){
  char * buffer;
  char path[1024];
  char request[1024];
  int sock, n_read;
  char * status;
  char * nextline;
  char * nextword;
  struct sockaddr_in dir_addr;
  int i;
  int offset;
  char relay_addr[15];
  int relay_port;
  int relay_dir_port;
  char crap1[100];
  char crap2[100];
  char crap3[100];
  char crap4[100];
  char crap5[100];

  dir_addr.sin_family = AF_INET;
  dir_addr.sin_port = htons(DIRECTORY_PORT);
  dir_addr.sin_addr.s_addr = inet_addr(DIRECTORY_IP);
  offset = 0;

  buffer = malloc(1000000);
  if(!buffer){
    printf("could not allocate memory for dir info...\n");
    return;
  }

  sprintf(path,"/tor/status-vote/current/consensus");
  sprintf(request, "GET %s HTTP/1.0\r\nHOST:%s \r\n\r\n", path, DIRECTORY_URL);
  sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if(connect(sock, (struct sockaddr*)&dir_addr, sizeof(struct sockaddr)) < 0){
    printf("cannot connect to the directory\n");
    return;
  }
  else{
    write(sock, request, strlen(request));
    while((n_read = recvfrom(sock, buffer + offset, 32768, 0, NULL, NULL)) > 0){
      offset += n_read;
    }
  }

  i = 0;
  nextline = strtok(buffer,"\n");
  while(nextline){
    /* check if this is a relay info line
     * and if it is, extract address and ports information */
    if(!strncmp(nextline,"r ",2)){
      sscanf(nextline,"r %s %s %s %s %s %s %d %d",
	     crap1, crap2, crap3, crap4, crap5,
	     relay_addr,&relay_port,&relay_dir_port);
      relays[i].port = relay_port;
      relays[i].dir_port = relay_dir_port;
      relays[i].ipaddr = inet_addr(relay_addr);
      i += 1;
    }
    nextline = strtok(NULL,"\n");
  }
  printf("learned %d relays\n", i);
}

static void
tunnel_teardown(struct tunnel * tun){
	close(tun->in_pfd->fd);
	tun->in_pfd->fd = -1;
	close(tun->out_pfd->fd);
	tun->out_pfd->fd = -1;
	tun->type = TUNNEL_UNINIT;
	tun->is_active = false;
}

static int
socks_extract_details(struct tunnel * tun){
	struct socks_hdr * hdr;
	int n_read, n_write;
	char * username;
	struct in_addr addr;
	char buffer[1024];

	n_read = recvfrom(tun->in_pfd->fd, buffer, 1024, 0, NULL, NULL);

	hdr = (struct socks_hdr *)buffer;
	addr.s_addr = hdr->ipaddr;
	username = &buffer[sizeof(struct socks_hdr)];

	if(!strcmp(username,"MOZ")){
	  tun->type = TUNNEL_WEB;
	}
	else{
	  tun->type = TUNNEL_TOR;
	}
	tun->nexthop_addr.sin_family = AF_INET;
	tun->nexthop_addr.sin_port = hdr->port;
	tun->nexthop_addr.sin_addr = addr;

	return 0;
}

static int
tunnel_send_reply(struct tunnel * tun, uint8_t code){
  struct socks_hdr reply;

  reply.version = 0;
  reply.code = code;
  reply.port = 0;
  reply.ipaddr = 0;

  write(tun->in_pfd->fd, (char *)&reply, sizeof(struct socks_hdr));
}

/* Checks whether a web tunnel request is allowed. */
static int
check_tunnel_web(struct tunnel *tun){
	if (is_web == true){
		return 0;
	}
	else{
		return -1;
	}
}

/* Checks whether a tor tunnel request is allowed. */
static int
check_tunnel_tor(struct tunnel * tun, struct relay_info * relays){
	int i;

	if (is_tor == true){
		return 0;
	}
	else{
		return -1;
	}


	for (i=0;i<3000;i++){
		if ((tun->nexthop_addr.sin_addr.s_addr == relays[i].ipaddr) &&
				((tun->nexthop_addr.sin_port == htons(relays[i].port)) ||
				(tun->nexthop_addr.sin_port == htons(relays[i].dir_port)))){
			return 0;
		}
	}
	return -1;
}

/* Initializes a tunnel request.
 * Checks whether the tunnel is valid. If it is it connects to the other
 * peer and sets up the tunnel.
 */
static int
tunnel_init(struct tunnel * tun, struct relay_info * relays){
	int peer_fd;

	if(socks_extract_details(tun) == -1){
		printf("cannot extract tunnel details...\n");
		return -1;
	}
	if(tun->type == TUNNEL_TOR){
	  if (check_tunnel_tor(tun, relays) == -1){
	    printf("Rejecting TOR tunnel to %s:%d\n",
	    		inet_ntoa(tun->nexthop_addr.sin_addr),
	    		ntohs(tun->nexthop_addr.sin_port));
	    tunnel_send_reply(tun,TUN_REJECTED);
	    tunnel_teardown(tun);
	    return -1;
	  }
	}
	else if(tun->type == TUNNEL_WEB){
	  if (check_tunnel_web(tun) == -1){
	    printf("Rejecting WEB tunnel to %s:%d\n",
	    		inet_ntoa(tun->nexthop_addr.sin_addr),
	    		ntohs(tun->nexthop_addr.sin_port));
	    tunnel_send_reply(tun,TUN_REJECTED);
	    tunnel_teardown(tun);
	    return -1;
	  }
	}
	else{
	  printf("tunnel type unknown - not granted\n");
	  tunnel_send_reply(tun,TUN_REJECTED);
	  tunnel_teardown(tun);
	  return -1;
	}

	peer_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect(peer_fd, (struct sockaddr*)&tun->nexthop_addr,
			sizeof(struct sockaddr)) < 0){
		printf("cannot connect to peer - skipping tunnel...\n");
		tunnel_teardown(tun);
	}
	else{
		/* if we managed to get up until here we are good */
		tunnel_send_reply(tun, TUN_GRANTED);
		printf("Setup tunnel of type %s to %s:%d\n",
				(tun->type == TUNNEL_TOR)? "TOR": "WEB",
				inet_ntoa(tun->nexthop_addr.sin_addr),
				ntohs(tun->nexthop_addr.sin_port));
		tun->out_pfd->fd = peer_fd;
	}
	return 0;
}


/* forwards from one pfd to the other */
static void
tunnel_forward(struct pollfd *a, struct pollfd *b, struct tunnel * tun){
	char buffer[32768];
	int n_read, n_write;
	n_read = n_write = 0;
	n_read = recvfrom(a->fd, buffer, 32768, 0, NULL, NULL);
	if(n_read == 0){
		tunnel_teardown(tun);
	}
	else{
		n_write = write(b->fd, buffer, n_read);
		if(n_write == 0){
			tunnel_teardown(tun);
		}
	}
	if(n_read != n_write){
		printf("Could not write all data (read:%d, written:%d\n",n_read,n_write);
	}
}

/* Checks whether any of the two ends of the tunnel is ready.
 * Depending on the situation, it will initialize the tunnel, forward data
 * over it, or teardown the tunnel.
 */
static void
process_tunnel(struct tunnel * tun, struct relay_info * relays){
	if (tun->in_pfd->revents & (POLLIN | POLLERR)){
		/* there is sg in input */
		if (tun->type == TUNNEL_UNINIT){
		  tunnel_init(tun, relays);
		}
		else if (tun->out_pfd->fd != -1){
			tunnel_forward(tun->in_pfd, tun->out_pfd, tun);
		}
		else{
			printf("not forwarding data because peer is down...\n");
		}
	}
	else if (tun->out_pfd->revents & (POLLIN | POLLERR)){
		if (tun->type == TUNNEL_UNINIT){
			printf("strange...shouldn't receive data from an uninit tunnel..\n");
		}
		else if (tun->in_pfd->fd != -1){
			tunnel_forward(tun->out_pfd, tun->in_pfd, tun);
		}
		else{
			printf("not forwarding data because tor peer is down...\n");
		}
	}
}


/* Looks the first (listening) socket for listening connections.
 * If one exists, accept it and assign a new tunnel for it.
 */
static void
check_new_connection(struct pollfd * fds, struct tunnel * tunnels){
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	int i;

	if(fds[0].revents & POLLIN) {
		/* accept connection and assign a poll_fds struct */
		int conn_fd = accept(fds[0].fd, (struct sockaddr*)&client_addr,
				&client_addr_len);
		for (i = 1; i < MAX_TUNNELS; i++){
			if (tunnels[i].is_active == 0){
				tunnels[i].is_active = 1;
				tunnels[i].in_pfd->fd = conn_fd;
				break;
			}
		}
		if (i == MAX_TUNNELS){
			printf("error - no tunnel available...\n");
		}
	}
}

/* Parse options. */
static void
parse_options(int argc, char *argv[])
{
	int c;

	while( (c = getopt(argc, argv, "tw")) != -1) {
		switch(c)
			{
			case 't':
				printf("Accepting Requests for TOR tunnels\n");
				is_tor = true;
				break;
			case 'w':
				printf("Accepting Requests for WEB tunnels\n");
				is_web = true;
				break;
			default:
				printf("unknown option\n");
				break;
			}
	}
}


int
main(int argc, char *argv[])
{
	int bytes_read;
	int i;
	int listen_fd;
	int max_fd, n_ready;
	/* TODO: this should definitely be replaced by a
	 * hash-table or bloom filter. */
	struct relay_info relays[3000];
	struct sockaddr_in listen_addr;
	struct pollfd fds[MAX_SOCKETS];
	struct tunnel tunnels[MAX_TUNNELS];

	parse_options(argc,argv);

	if(is_tor == true){
		printf("Downloading TOR directory\n");
		update_tor_dir(relays);
	}

	/* initialize the sockets */
	for (i=0; i < MAX_SOCKETS; i++){
		fds[i].fd = -1;
		fds[i].events = POLLIN;
	}

	/* initialize the tunnels */
	for (i = 0; i < MAX_TUNNELS; i++){
		//tunnels[i].id = 0;
		tunnels[i].type = TUNNEL_UNINIT;
		tunnels[i].is_reserved = false;
		tunnels[i].is_active = false;
		tunnels[i].in_pfd = &fds[2*i + 1];
		tunnels[i].out_pfd = &fds[2*i + 2];

	}


	/* Listen for new connections */
	if((listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0){
		printf("Can't create listening socket (%s)\n", strerror(errno));
		exit(1);
	}
	bzero(&listen_addr, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	listen_addr.sin_port = htons(LISTEN_PORT);

	/* allow reuse of port on restart */
	int optval = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof optval);

	if(bind(listen_fd, (const struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0){
		printf("Can't bind to listening socket (%s)\n", strerror(errno));
		exit(1);
	}
	listen(listen_fd, 5);

	/* This will be the first socket to poll */
	fds[0].fd = listen_fd;
	fds[0].events = POLLIN;
	max_fd = 0;

	printf("Listening for new tunnel requests\n");
	for ( ; ; ){
		n_ready = poll(fds, MAX_SOCKETS + 1, -1);
		if (n_ready == -1){
			printf("error on poll - quitting...(%s)",strerror(errno));
			exit(1);
		}

		/* check for new connections */
		check_new_connection(fds, tunnels);

		/* process all the tunnels */
		for (i=0; i < MAX_TUNNELS; i++){
			if (tunnels[i].is_active == 1){
			  process_tunnel(&tunnels[i], relays);
			}
		}

		/* if time has elapsed, update the directories */
		// update_tor_dir();

		fflush(stdout);
	}
}

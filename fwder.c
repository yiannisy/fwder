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

#define LISTEN_PORT 9999

#define TUNNEL_UNINIT 0
#define TUNNEL_TOR 1
#define FP_LEN 40

#define MAX_SOCKETS 255
#define MAX_TUNNELS 127
#define TUN_HDR_LEN 48

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
};

struct tunnel_hdr {
	uint32_t addr;
	uint16_t port;
	uint16_t type;
	char fp[FP_LEN];
};

static void
update_tor_dir(){
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
tunnel_extract_details(struct tunnel * tun){
	struct tunnel_hdr hdr;
	int n_read;
	char tmp_buf[41];

	n_read = recvfrom(tun->in_pfd->fd, (char *)&hdr, TUN_HDR_LEN, 0, NULL, NULL);
	if(n_read != TUN_HDR_LEN){
		printf("cannot extract tunnel details - not enough info (%d bytes received)\n",
				n_read);
	}

	/* add null-based term character */
	memcpy(tmp_buf,hdr.fp,40);
	tmp_buf[40] = '\0';

	tun->type = ntohs(hdr.type);
	tun->nexthop_addr.sin_family = AF_INET;
	tun->nexthop_addr.sin_port = hdr.port;
	tun->nexthop_addr.sin_addr.s_addr = hdr.addr;

	printf("Setting up tunnel of type %d with %s:%d (fp:%s)\n", tun->type, inet_ntoa(tun->nexthop_addr.sin_addr), ntohs(hdr.port), tmp_buf);
	return 0;
}

static int
tunnel_verify(struct tunnel * tun){
	return 0;
}

static int
tunnel_init(struct tunnel * tun){
	int peer_fd;

	if(tunnel_extract_details(tun) == -1){
		printf("cannot extract tunnel details...\n");
		return -1;
	}
	if (tunnel_verify(tun) == -1){
		printf("cannot verify tunnel...\n");
		return -1;
	}
	printf("Connecting to peer...");
	peer_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect(peer_fd, (struct sockaddr*)&tun->nexthop_addr, sizeof(struct sockaddr)) < 0){
		printf("cannot connect to peer - skipping tunnel...\n");
		tunnel_teardown(tun);
	}
	else{
		printf("connected!\n");
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
		printf("No data received - teardown the tunnel\n");
		tunnel_teardown(tun);
	}
	else{
		n_write = write(b->fd, buffer, n_read);
		if(n_write == 0){
			printf("No data written - teardown the tunnel\n");
			tunnel_teardown(tun);
		}
	}
	if(n_read != n_write){
		printf("Could not write all data (read:%d, written:%d\n",n_read,n_write);
	}
}

static void
process_tunnel(struct tunnel * tun){
	if (tun->in_pfd->revents & (POLLIN | POLLERR)){
		/* there is sg in input */
		if (tun->type == TUNNEL_UNINIT){
			tunnel_init(tun);
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


/* looks the first (listening) socket for listening connections.
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
		else{
			printf("accepted new connection from tor-client\n");
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
	struct sockaddr_in listen_addr;
	struct pollfd fds[MAX_SOCKETS];
	struct tunnel tunnels[MAX_TUNNELS];

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
				process_tunnel(&tunnels[i]);
			}
		}

		/* if time has elapsed, update the directories */
		update_tor_dir();

	}
}

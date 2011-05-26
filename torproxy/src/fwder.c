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
#define TUN_HDR_LEN 48

#define MAX_RELAYS 10000
#define DIRECTORY_IP "193.23.244.244"
#define DIRECTORY_URL "dannenberg.ccc.de"

#define TUN_GRANTED 0x5a
#define TUN_REJECTED 0x5b

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

struct tunnel_hdr {
	uint32_t addr;
	uint16_t port;
	uint16_t type;
	char fp[FP_LEN];
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
  dir_addr.sin_port = htons(80);
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
      relays[i].port = ntohs(relay_port);
      relays[i].dir_port = ntohs(relay_dir_port);
      relays[i].ipaddr = inet_addr(relay_addr);
      i += 1;
    }
    nextline = strtok(NULL,"\n");
  }
  printf("learned %d relays\n", i);
}

//static void *
//directory_service(void *arg){
//	int sock;
//	struct sockaddr_in dir_addr;
//	int resp_len = 0;
//	char buffer[1600];
//	char response[MAX_RELAY*10000]
//	int n_read;
//
//	char request =
//
//
//	while(1){
//		printf("Updating from directory\n");
//		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
//		if (connect(sock, (struct sockaddr*)dir_addr, sizeof(struct sockaddr)) < 0){
//			printf("cannot connect to the directory\n");
//		}
//		else{
//			write(sock, request, req_len);
//			while (n_read = recvfrom(sock, buffer, 32768, 0, NULL, NULL) > 0){
//				memcpy(response, buffer, n_read);
//				resp_len += n_read;
//			}
//		}
//
//	}
//}

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
	printf("Socks IP:Port:%s:%d (%s)\n",inet_ntoa(addr),ntohs(hdr->port), username);

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
	memcpy(tun->nexthop_fp,tmp_buf, 41);

	printf("Setting up tunnel of type %d with %s:%d (fp:%s)\n", tun->type, inet_ntoa(tun->nexthop_addr.sin_addr), ntohs(hdr.port), tmp_buf);
	return 0;
}

static int
tunnel_verify_web(struct tunnel *tun){
  return -1;
}

static int
tunnel_verify_local(struct tunnel * tun, struct relay_info * relays){
  int i;

  for (i=0;i<3000;i++){
    if (relays[i].ipaddr == tun->nexthop_addr.sin_addr.s_addr){
      printf("found relay with same ip address!\n");
      printf("known relay %d, %d\n",relays[i].port, relays[i].dir_port);
      printf("desired relay : %s, %d\n",inet_ntoa(tun->nexthop_addr.sin_addr),tun->nexthop_addr.sin_port);
      return 0;
    }
  }
  return -1;
}
  

static int
tunnel_verify(struct tunnel * tun){
	char request[1000];
	char buffer[32768];
	int offset;
	char path[1000];
	int sock, n_read;
	char * status;
	struct sockaddr_in dir_addr;
	dir_addr.sin_family = AF_INET;
	dir_addr.sin_port = htons(80);
	dir_addr.sin_addr.s_addr = inet_addr(DIRECTORY_IP);
	offset = 0;

	return 0;
	
	sprintf(path,"/tor/server/fp/%s",tun->nexthop_fp);
	sprintf(request, "GET %s HTTP/1.0\r\nHOST:%s \r\n\r\n", path, DIRECTORY_URL);
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(connect(sock, (struct sockaddr*)&dir_addr, sizeof(struct sockaddr)) < 0){
		printf("cannot connect to the directory\n");
		return -1;
	}
	else{
		write(sock, request, strlen(request));
		while((n_read = recvfrom(sock, buffer + offset, 32768, 0, NULL, NULL)) > 0){
			offset += n_read;
		}
		/* the first line contains the http response code. */
		status = strtok(buffer,"\n");
		if (strstr(status,"200")){
			/* status is OK! */
			return 0;
		}
		else if(strstr(status,"404")){
			printf("failed to verify tunnel\n");
			return 0;
		}
		else {
			printf("unknown status while verifying tunnel: %s\n",status);
			return -1;
		}
	}
}

static int
tunnel_init(struct tunnel * tun, struct relay_info * relays){
	int peer_fd;

//	if(tunnel_extract_details(tun) == -1){
	if(socks_extract_details(tun) == -1){
		printf("cannot extract tunnel details...\n");
		return -1;
	}
	if(tun->type == TUNNEL_TOR){
	  if (tunnel_verify_local(tun, relays) == -1){
	    printf("cannot verify tunnel...\n");
	    tunnel_send_reply(tun,TUN_REJECTED);
	    tunnel_teardown(tun);
	    return -1;
	  }
	}
	else if(tun->type == TUNNEL_WEB){
	  if (tunnel_verify_web(tun) == -1){
	    printf("web tunnel not granted...\n");
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
	
	/* if we managed to get up until here we are good */
	tunnel_send_reply(tun, TUN_GRANTED);

	//	printf("successfully initialized and verified tunnel\n");
	//	printf("Connecting to peer...");
	peer_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (connect(peer_fd, (struct sockaddr*)&tun->nexthop_addr, sizeof(struct sockaddr)) < 0){
		printf("cannot connect to peer - skipping tunnel...\n");
		tunnel_teardown(tun);
	}
	else{
	  printf("Setup tunnel of type %d to %s:%d\n",tun->type,inet_ntoa(tun->nexthop_addr.sin_addr),
		 ntohs(tun->nexthop_addr.sin_port));
		 //		printf("connected!\n");
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
	struct relay_info relays[3000];
	struct sockaddr_in listen_addr;
	struct pollfd fds[MAX_SOCKETS];
	struct tunnel tunnels[MAX_TUNNELS];

	struct tunnel known_relays[MAX_RELAYS];
	pthread_t dir_serv;
	/* start a thread for directory updates */
//	pthread_create(&dir_serv,NULL, directory_service, known_relays);



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
	printf("Downloading TOR directory\n");
	update_tor_dir(relays);

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

	}
}

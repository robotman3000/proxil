// Author Phinfinity <rndanish@gmail.com>
/* Transparent HTTP Proxy Wrapper */
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY
#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <atomic>
#include <ios>
#include <iostream>
#include <vector>

#define HTTPSHDRBUFSZ 256  // used for reading/writing HTTPS headers
int VERBOSITY = 0;         // Minimal
const char* PROXY_HOST = "192.168.64.1";
const char* PROXY_PORT = "8080";
const char* PORT = "1234";
int BACKLOG = 20;
std::atomic<int> httpVer;  // -2 is ignore; -1 Is unset; 0 is 1.0; 1 is 1.1
std::atomic<int> tlsResult; // -255 is unset
std::atomic<char*> hostname1;
#define BUFSZ 256

static int parse_tls_header(const char *, size_t, char **, bool);
static int parse_extensions(const char *, size_t, char **);
static int parse_server_name_extension(const char *, size_t, char **);

class test {

};

void display_usage() {
	printf("tproxy: Intermediate transparent HTTPS proxy\n");
	printf("Usage : ./tproxy [-h] [-v] -h proxy_host -a proxy_port -p tproxy_port "
			"\n");
	printf("Written by Anish Shankar <rndanish@gmail.com> , "
			"http://phinfinity.com\n");
	printf("Before running this add iptables rules to intercept packets and "
			"forward them to this "
			"server\n");
	// printf("Usage : ./tproxy [-h] [-v] -h proxy_host -a proxy_port -p
	// tproxy_port -b
	// buffer_size\n");
	printf("\t -h/-?\t-  Print help and this usage information\n");
	printf("\t -v\t- Verbosity. Specify once to display error messages, twice to "
			"display all "
			"connection information\n");
	printf("\t -s\t- Proxy Host. hostname of secondary proxy server to use. "
			"defaults to : %s\n", PROXY_HOST);
	printf("\t -a\t- Proxy Port. Port number of proxy service. defaults to : %s\n", PROXY_PORT);
	printf("\t -p\t- Tproxy Port. Port that tproxy should run intermedeate proxy "
			"on. defaults to : "
			"%s\n", PORT);
	//  printf("\t -b\t- Buffer Size. Buffer Size used to transfer packets.
	//  defaults to : %d\n",
	//  BUFSZ);
	exit(EXIT_FAILURE);
}

static const char* optstring = "p:s:a:vh?";

void parse_commandline(int argc, char** argv) {
	int opt = getopt(argc, argv, optstring);
	while (opt != -1) {
		switch (opt) {
			case 'p':
				PORT = optarg;
				break;
			case 's':
				PROXY_HOST = optarg;
				break;
			case 'a':
				PROXY_PORT = optarg;
				break;
			case 'v':
				VERBOSITY++;
				break;
			case 'h':
			case '?':
				display_usage();
				break;
			default:
				break;
		}
		opt = getopt(argc, argv, optstring);
	}
}

struct addrinfo hints, *proxy_servinfo;

// Get address in human readable IPV4/IPV6
// Returns port (-1 on error) and IP through dst
int get_addr_name(struct sockaddr* sa, char* dst, socklen_t dst_size) {
	void* addr;  // Will be in_addr or in_addr6
	int port;
	if (sa->sa_family == AF_INET) {
		struct sockaddr_in* sav4 = (struct sockaddr_in*) sa;
		addr = &(sav4->sin_addr);
		port = ntohs(sav4->sin_port);
	} else {
		struct sockaddr_in6* sav6 = (struct sockaddr_in6*) sa;
		addr = &(sav6->sin6_addr);
		port = ntohs(sav6->sin6_port);
	}
	if (!inet_ntop(sa->sa_family, addr, dst, dst_size))
		return -1;
	return port;
}

// Returns port (-1 on error), Human readable IP through dst
int get_original_dst(int fd, char* dst, socklen_t dst_size) {
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if (getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, (struct sockaddr*) &addr, &addr_len) == -1)
		return -1;
	int port = get_addr_name((struct sockaddr*) &addr, dst, dst_size);
	if (port == -1)
		return -1;
	// For some reason ^ above doesn't give correct port chk later
	return port;
}

// Returns port (-1 on error), Human readable IP through dst
int get_peername(int fd, char* dst, socklen_t dst_size) {
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	if (getpeername(fd, (struct sockaddr*) &addr, &addr_len) == -1)
		return -1;
	return get_addr_name((struct sockaddr*) &addr, dst, dst_size);
}

/* arg is a pointer to an int array of size 2
 * a[0], a[1] give sockfd's for input and output
 */
void* pipe_data(void* arg) {
	int from_sock = ((int*) arg)[0];
	int to_sock = ((int*) arg)[1];
	int mode = ((int*) arg)[2];
	char* modeStr[2] = { (char*) "C->P Send ................................", (char*) "P->C Recv" };
	int l = 0;
	int k = 0;

	// char *buf = (char*) malloc(BUFSZ);
	char buf[BUFSZ];

	//std::vector<char> packet(BUFSZ);
	char* packet;
	int packetSize = 0;
	char* tempBuf1;

	printf("%s: Starting Reading\n", modeStr[mode]);
	while ((l = recv(from_sock, buf, sizeof(buf), 0)) > 0) {
		printf("%s: Reading %d\n", modeStr[mode], l);

		if (mode == 0) {
			// Rezise packet buffer
			printf("hashedChars: ");
			tempBuf1 = new char[packetSize + l];
			for (int i = 0; i < packetSize; i++) {
				//printf("%s: Index: %d\n", modeStr[mode], i);
				tempBuf1[i] = packet[i];
				printf(" T\'%c\' \t P\'%c\'\n", tempBuf1[i], packet[i]);
			}

			for (int i = 0; i < l; i++) {
				tempBuf1[packetSize + i] = buf[i];
				printf(" T\'%c\' \t B\'%c\'\n", tempBuf1[packetSize + i], buf[i]);
			}
			printf("\n");
			/*if(packet != NULL){
			 delete[] packet;
			 }*/

			delete[] packet;
			packet = new char[packetSize + l];
			packetSize = l + packetSize;
			for (int i = 0; i < packetSize; i++) {
				packet[i] = tempBuf1[i];
			}

			delete[] tempBuf1;
			//packet = tempBuf1;

		}

		/*printf("hashedChars1: ");
		 for (int i = 0; i < packetSize; i++) {
		 printf(" \'%c\' ", packet[i]);
		 if((i % 16) == 0){
		 printf("\n");
		 }
		 }*/
		if (mode == 0 && tlsResult != -255) {
			if ((k = (send(to_sock, buf, l, 0))) == -1) {
				printf("%s: Breaking %d\n", modeStr[mode], k);
				break;
			}
		}

		if (mode == 0 && tlsResult == -255) {
			char* hostname;
			int result = parse_tls_header(packet, packetSize, &hostname, true);
			hostname1.store(hostname);
			printf("%s: Hostname: %s; Result: %d\n", modeStr[mode], hostname, result);
			if (result > 0) {
				tlsResult = result;
				hostname1 = hostname;
				printf("Yay!!!!!!!!\n");
				if ((k = (send(to_sock, buf, l, 0))) == -1) {
					printf("%s: Breaking %d\n", modeStr[mode], k);
				}
			}
		}
		if (httpVer != -2) {
			if (mode == 0) {  // If we are C->P
				// Wait for the other thread to report http version
				struct timespec tim, tim2;
				tim.tv_sec = 0;
				tim.tv_nsec = 500000000L;
				while (httpVer == -1) {
					printf("%s: waiting\n", modeStr[mode]);
					if (nanosleep(&tim, &tim2) < 0) {
						printf("Nano sleep system call failed \n");
					}
				}
				if (httpVer == 0) {
					printf("%s: Ending for HTTP/1.0 %d\n", modeStr[mode], k);
					break;
				} else {
					printf("%s: Continuing for HTTP/1.1 %d\n", modeStr[mode], k);
				}
			} else {
				// Detect and report http version
				if (strncmp(buf, "HTTP/1.0 200", 12) <= 0) {
					printf("%s: Using HTTP/1.0\n", modeStr[mode]);
					httpVer = 0;
				} else {
					printf("%s: Using HTTP/1.1\n", modeStr[mode]);
					httpVer = 1;
				}
			}
		}
	}

	printf("%s: Ending Reading %d\n", modeStr[mode], l);
	// free(buf);
	return NULL;
}

// Returns 0 on success, -1 on failure. Prints errors
int wrap_https_connection(int proxy_fd, const char* dst_host, int dst_port) {
	char buf[HTTPSHDRBUFSZ];

	printf("CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", dst_host, dst_port, dst_host);
	snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", dst_host, dst_port, dst_host);
	if (send(proxy_fd, buf, strlen(buf), 0) == -1) {
		if (VERBOSITY)
			printf("Error writing to https proxy connection\n");
		return -1;
	}
	recv(proxy_fd, buf, sizeof(buf), 0);
	if ((strncmp(buf, "HTTP/1.0 200", 12) != 0) && (strncmp(buf, "HTTP/1.1 200", 12) != 0)) {
		buf[sizeof(buf) - 1] = '\0';
		if (VERBOSITY)
			printf("HTTPS wrapping failed : %s\n", buf);
		return -1;
	}
	return 0;
}

void* handle_connection(void* sock_arg) {
	char peer_name[INET6_ADDRSTRLEN];
	char dst_host[INET6_ADDRSTRLEN];
	int peer_port;
	int dst_port;

	int sock = (long) (sock_arg);

	peer_port = get_peername(sock, peer_name, sizeof(peer_name));
	if (peer_port == -1) {
		if (VERBOSITY)
			perror("Cannot find client IP!");
		close(sock);
		return NULL;
	}

	dst_port = get_original_dst(sock, dst_host, sizeof(dst_host));
	if (dst_port == -1) {
		if (VERBOSITY)
			perror("Cannot find original destination");
		close(sock);
		return NULL;
	}
	if (VERBOSITY > 1)
		printf("Connection from %s:%d for %s:%d\n", peer_name, peer_port, dst_host, dst_port);
	printf("0.-1\n");
// Proxy Socket
	int psock = socket(proxy_servinfo->ai_family, proxy_servinfo->ai_socktype, proxy_servinfo->ai_protocol);
	printf("0\n");
	if (connect(psock, proxy_servinfo->ai_addr, proxy_servinfo->ai_addrlen) != 0) {
		printf("0.1\n");
		if (VERBOSITY)
			perror("Cannot connect to proxy server");
		printf("0.2\n");
		close(sock);
		printf("0.3\n");
		return NULL;
	}

	pthread_t t1, t2;
	int a[2][3] = { { sock, psock, 0 }, { psock, sock, 1 } };
	tlsResult = -255;
	pthread_create(&t1, NULL, pipe_data, (void*) (&a[0]));

	printf("1\n");
	if (dst_port == 443) {
		httpVer = -2;

		struct timespec tim, tim2;
		tim.tv_sec = 0;
		tim.tv_nsec = 500000000L;
		printf("HTTP wait started\n");
		while (tlsResult == -255) {
			if (nanosleep(&tim, &tim2) < 0) {
				printf("Nano sleep system call failed \n");
			}
		}

		if (wrap_https_connection(psock, hostname1.load(), dst_port) == -1) {
			close(psock);
			close(sock);
			return NULL;
		}
	}
	printf("Threading\n");
	pthread_create(&t2, NULL, pipe_data, (void*) (&a[1]));
	pthread_join(t2, NULL);
	printf("Waiting on final thread\n");
	pthread_join(t1, NULL);
	printf("Final thread ended\n");
	close(psock);
	close(sock);
	if (VERBOSITY > 1)
		printf("Closed connection from %s:%d to %s:%d\n", peer_name, peer_port, dst_host, dst_port);
	return NULL;
}

void init() {
	signal(SIGPIPE, SIG_IGN);  // We'll try to manually check write's return
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(PROXY_HOST, PROXY_PORT, &hints, &proxy_servinfo) != 0) {
		fprintf(stderr, "Can't resolve proxy IP\n");
		exit(1);
	}
}

int main(int argc, char** argv) {
	httpVer = -1;
	printf("This program is distributed in the hope that it will be useful, but "
			"WITHOUT ANY "
			"WARRANTY\n");
	init();
	parse_commandline(argc, argv);
	int sockfd, new_fd;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;  // connector's address information
	socklen_t sin_size;
	int yes = 1;
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

// loop through all the results and bind to the first we can
	for (p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("tproxy failed to create socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("tproxy failed to setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("tproxy failed to bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		return 2;
	}

	freeaddrinfo(servinfo);  // all done with this structure

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	printf("Listening on port : %s , secondary proxy : %s:%s\n", PORT, PROXY_HOST, PROXY_PORT);
	printf("server: waiting for connections...\n");

	while (1) {  // main accept() loop
		sin_size = sizeof their_addr;
		new_fd = accept(sockfd, (struct sockaddr*) &their_addr, &sin_size);
		if (new_fd == -1) {
			if (VERBOSITY)
				perror("accept");
			continue;
		}
		pthread_t tmp_thread;
		pthread_create(&tmp_thread, NULL, handle_connection, (void*) (long) (new_fd));
	}

	return 0;
}

// Taken from the sniproxy project

#define SERVER_NAME_LEN 256
#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

static const char tls_alert[] = { 0x15, /* TLS Alert */
0x03, 0x01, /* TLS version  */
0x00, 0x02, /* Payload length */
0x02, 0x28, /* Fatal, handshake failure */
};

/* Parse a TLS packet for the Server Name Indication extension in the client
 * hello handshake, returning the first servername found (pointer to static
 * array)
 *
 * Returns:
 *  >=0  - length of the hostname and updates *hostname
 *         caller is responsible for freeing *hostname
 *  -1   - Incomplete request
 *  -2   - No Host header included in this request
 *  -3   - Invalid hostname pointer
 *  -4   - malloc failure
 *  < -4 - Invalid TLS client hello
 */
static int parse_tls_header(const char *data, size_t data_len, char **hostname, bool ignoreLen = false) {
	printf("d0\n");
	char tls_content_type;
	char tls_version_major;
	char tls_version_minor;
	size_t pos = TLS_HEADER_LEN;
	size_t len;
	printf("d1\n");
	if (hostname == NULL)
		return -3;
	printf("d2\n");
	/* Check that our TCP payload is at least large enough for a TLS header */
	if (data_len < TLS_HEADER_LEN)
		return -1;
	printf("d3\n");
	/* SSL 2.0 compatible Client Hello
	 *
	 * High bit of first byte (length) and content type is Client Hello
	 *
	 * See RFC5246 Appendix E.2
	 */
	if (data[0] & 0x80 && data[2] == 1) {
		printf("d3.1\n");
		printf("Received SSL 2.0 Client Hello which can not support SNI.\n");
		return -2;
	}
	printf("d4\n");
	tls_content_type = data[0];
	if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
		printf("Request did not begin with TLS handshake.\n");
		return -5;
	}
	printf("d1\n");
	tls_version_major = data[1];
	tls_version_minor = data[2];
	if (tls_version_major < 3) {
		printf("Received SSL %d.%d handshake which can not support SNI.\n", tls_version_major, tls_version_minor);

		return -2;
	}

	/* TLS record length */
	len = ((unsigned char) data[3] << 8) + (unsigned char) data[4] + TLS_HEADER_LEN;
	data_len = MIN(data_len, len);

	/* Check we received entire TLS record length */
	if (data_len < len && ignoreLen == false)
		return -1;

	/*
	 * Handshake
	 */
	if (pos + 1 > data_len) {
		return -5;
	}
	if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
		printf("Not a client hello\n");

		return -5;
	}

	/* Skip past fixed length records:
	 1	Handshake Type
	 3	Length
	 2	Version (again)
	 32	Random
	 to	Session ID Length
	 */
	pos += 38;

	/* Session ID */
	if (pos + 1 > data_len)
		return -5;
	len = (unsigned char) data[pos];
	pos += 1 + len;

	/* Cipher Suites */
	if (pos + 2 > data_len)
		return -5;
	len = ((unsigned char) data[pos] << 8) + (unsigned char) data[pos + 1];
	pos += 2 + len;

	/* Compression Methods */
	if (pos + 1 > data_len)
		return -5;
	len = (unsigned char) data[pos];
	pos += 1 + len;

	if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
		printf("Received SSL 3.0 handshake without extensions\n");
		return -2;
	}

	/* Extensions */
	if (pos + 2 > data_len)
		return -5;
	len = ((unsigned char) data[pos] << 8) + (unsigned char) data[pos + 1];
	pos += 2;

	if (pos + len > data_len)
		return -5;
	return parse_extensions(data + pos, len, hostname);
}

static int parse_extensions(const char *data, size_t data_len, char **hostname) {
	size_t pos = 0;
	size_t len;

	/* Parse each 4 bytes for the extension header */
	while (pos + 4 <= data_len) {
		/* Extension Length */
		len = ((unsigned char) data[pos + 2] << 8) + (unsigned char) data[pos + 3];

		/* Check if it's a server name extension */
		if (data[pos] == 0x00 && data[pos + 1] == 0x00) {
			/* There can be only one extension of each type, so we break
			 our state and move p to beinnging of the extension here */
			if (pos + 4 + len > data_len)
				return -5;
			return parse_server_name_extension(data + pos + 4, len, hostname);
		}
		pos += 4 + len; /* Advance to the next extension header */
	}
	/* Check we ended where we expected to */
	if (pos != data_len)
		return -5;

	return -2;
}

static int parse_server_name_extension(const char *data, size_t data_len, char **hostname) {
	size_t pos = 2; /* skip server name list length */
	size_t len;

	while (pos + 3 < data_len) {
		len = ((unsigned char) data[pos + 1] << 8) + (unsigned char) data[pos + 2];

		if (pos + 3 + len > data_len)
			return -5;

		switch (data[pos]) { /* name type */
			case 0x00: /* host_name */
				*hostname = (char*) malloc(len + 1);
				if (*hostname == NULL) {
					printf("malloc() failure\n");
					return -4;
				}

				strncpy(*hostname, data + pos + 3, len);

				(*hostname)[len] = '\0';

				return len;
			default:
				printf("Unknown server name extension name type: %d\n", data[pos]);
		}
		pos += 3 + len;
	}
	/* Check we ended where we expected to */
	if (pos != data_len)
		return -5;

	return -2;
}

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

static volatile sig_atomic_t end = 0;
static volatile sig_atomic_t updAddr = 1;

static const char *netif;

static struct addr_t {
	uint32_t network;
	uint32_t netmask;
} *localAddr = NULL;
static int localAddrCount = 0;

static const clockid_t clocks[] = {
	CLOCK_MONOTONIC_COARSE,
	CLOCK_MONOTONIC,
	CLOCK_REALTIME_COARSE,
	CLOCK_REALTIME
};

static void sighandler(int signo)
{
	switch (signo)
	{
	case SIGINT:
	case SIGTERM:
		end = 1;
		break;
	case SIGUSR1:
		updAddr = 1;
		break;
	}
}

static void updateAddresses()
{
	struct ifaddrs *ifaddr, *ifa;
	uint32_t network, netmask;
	int i;

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return;
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		/* ignore non-IPv4 */
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;

		/* ignore other interfaces */
		if (strcmp(ifa->ifa_name, netif))
			continue;

		netmask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
		network = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr.s_addr & netmask;

		/* ignore if already known */
		for (i = 0; i < localAddrCount; i++) {
			if (localAddr[i].network == network && localAddr[i].netmask == netmask)
				break;
		}
		if (i != localAddrCount)
			continue;

		localAddr = realloc(localAddr, sizeof(*localAddr) * (localAddrCount+1));
		if (localAddr == NULL)
			perror("realloc");

		localAddr[localAddrCount].network = network;
		localAddr[localAddrCount].netmask = netmask;
		localAddrCount++;
	}

	freeifaddrs(ifaddr);
}

int main(int argc, char *argv[])
{
	static const struct sigaction act = {
		.sa_handler = sighandler
	};

	struct sockaddr_ll addr;
	struct timespec ts;
	struct iphdr hdr;
	socklen_t addrlen;
	ssize_t len;
	clockid_t clockid = CLOCK_REALTIME;
	int sockfd = -1;
	int result = EXIT_FAILURE;
	int i;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <netif>\n", argv[0]);
		return EXIT_FAILURE;
	}
	netif = argv[1];

	for (i = 0; i < (sizeof(clocks) / sizeof(clocks[0])); i++) {
		if (clock_getres(clocks[i], NULL) == 0) {
			clockid = clocks[i];
			break;
		}
	}

	if (sigaction(SIGINT, &act, NULL) == -1
	 || sigaction(SIGTERM, &act, NULL) == -1
	 || sigaction(SIGINT, &act, NULL) == -1) {
		perror("sigaction");
		goto error;
	}

	sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (sockfd == -1) {
		perror("socket");
		goto error;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = if_nametoindex(netif);
	if (addr.sll_ifindex == 0) {
		perror("if_nametoindex");
		goto error;
	}

	if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("bind");
		goto error;
	}

	while (!end) {
		if (updAddr) {
			updateAddresses();
			updAddr = 0;
		}

		addrlen = sizeof(addr);
		len = recvfrom(sockfd, &hdr, sizeof(hdr), 0, (struct sockaddr *)&addr, &addrlen);
		if (len == -1) {
			if (errno != EINTR) {
				perror("recvfrom");
				goto error;
			}
		} else if (len < sizeof(hdr)) {
			fprintf(stderr, "Short read\n");
		} else {
			for (i = 0; i < localAddrCount; i++) {
				if (localAddr[i].network == (hdr.saddr & localAddr[i].netmask))
					break;
			}
			if (i == localAddrCount)
				continue;

			clock_gettime(clockid, &ts);

			printf("%s <> %s\n",
				ether_ntoa((struct ether_addr *)addr.sll_addr),
				inet_ntoa(*((struct in_addr*)&hdr.saddr)));
		}
	}

	result = EXIT_SUCCESS;

error:
	if (sockfd != -1)
		close(sockfd);

	free(localAddr);

	return result;
}

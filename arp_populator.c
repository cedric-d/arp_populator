#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <poll.h>

#define RING_BLOCK_SIZE 4096
#define RING_FRAME_SIZE TPACKET_ALIGN(TPACKET_ALIGN(TPACKET3_HDRLEN) + sizeof(struct iphdr))
#define RING_BLOCK_NR   8
#define RING_FRAME_NR   (RING_BLOCK_NR * (RING_BLOCK_SIZE / RING_FRAME_SIZE))
#define RING_TIMEOUT    1000

static const struct tpacket_req3 RING_REQ = {
	.tp_block_size     = RING_BLOCK_SIZE,
	.tp_block_nr       = RING_BLOCK_NR,
	.tp_frame_size     = RING_FRAME_SIZE,
	.tp_frame_nr       = RING_FRAME_NR,
	.tp_retire_blk_tov = RING_TIMEOUT,
};

static volatile sig_atomic_t endRequested = 0;
static volatile sig_atomic_t addressUpdateRequested = 1;

static const char *netif;

struct addr_t {
	uint32_t network;
	uint32_t netmask;
};

static struct addr_t *localAddr = NULL;
static unsigned int localAddrCount = 0;

static void sighandler(int signo)
{
	switch (signo)
	{
	case SIGINT:
	case SIGTERM:
		endRequested = 1;
		break;
	case SIGUSR1:
		addressUpdateRequested = 1;
		break;
	}
}

static void update_local_addresses()
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

static bool create_socket(int *sockfd, void **ring_buf)
{
	struct sockaddr_ll addr = {
		.sll_family   = AF_PACKET,
		.sll_protocol = htons(ETH_P_IP),
		.sll_ifindex  = if_nametoindex(netif)
	};
	int v;

	if (addr.sll_ifindex == 0) {
		perror("if_nametoindex");
		return false;
	}

	*sockfd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
	if (*sockfd == -1) {
		perror("socket");
		return false;
	}

	v = TPACKET_V3;
	if (setsockopt(*sockfd, SOL_PACKET, PACKET_VERSION, &v, sizeof(v)) == -1) {
		perror("setsockopt(SOL_PACKET, PACKET_VERSION)");
		return false;
	}

	if (setsockopt(*sockfd, SOL_PACKET, PACKET_RX_RING, &RING_REQ, sizeof(RING_REQ)) == -1) {
		perror("setsockopt(SOL_PACKET, PACKET_RX_RING)");
		return false;
	}

	if (bind(*sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		perror("bind");
		return false;
	}

	*ring_buf = mmap(NULL, RING_REQ.tp_block_size * RING_REQ.tp_block_nr, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_LOCKED, *sockfd, 0);
	if (*ring_buf == MAP_FAILED) {
		perror("mmap");
		return false;
	}

	return true;
}

static void process_block(struct tpacket_block_desc *block)
{
	struct sockaddr_ll *llAddr;
	struct iphdr *ipHdr;
	struct tpacket3_hdr *pkt;
	const unsigned int nbPkts = block->hdr.bh1.num_pkts;
	unsigned int i, j;
	struct tm tstm;
	time_t tst;
	char ts[32];

	for (i = 0, pkt = (void *)block + block->hdr.bh1.offset_to_first_pkt;
	     i < nbPkts;
	     i++, pkt = (void *)pkt + pkt->tp_next_offset) {
		llAddr = (void *)pkt + TPACKET_ALIGN(sizeof(struct tpacket3_hdr));
		ipHdr = (void *)pkt + pkt->tp_net;

		for (j = 0; j < localAddrCount; j++) {
			if (localAddr[j].network == (ipHdr->saddr & localAddr[j].netmask))
				break;
		}
		if (j == localAddrCount)
			continue;

		tst = pkt->tp_sec;
		gmtime_r(&tst, &tstm);
		strftime(ts, sizeof(ts), "%FT%T", &tstm);
		printf("[%s.%.9u] %s <> %s\n", ts, pkt->tp_nsec,
			ether_ntoa((struct ether_addr *)llAddr->sll_addr),
			inet_ntoa(*((struct in_addr*)&ipHdr->saddr)));
	}
}

static bool receive_packets(int sockfd, struct iovec blocks[])
{
	struct tpacket_block_desc *curBlockDesc;
	struct pollfd pfd;
	int curBlock = 0;

	while (!endRequested) {
		if (addressUpdateRequested) {
			update_local_addresses();
			addressUpdateRequested = 0;
		}

		pfd.fd = sockfd;
		pfd.events = POLLIN|POLLERR;
		pfd.revents = 0;

		switch (poll(&pfd, 1, -1)) {
		case -1:
			if (errno != EINTR) {
				perror("poll");
				return false;
			}
			break;
		case 0:
			break;
		default:
			curBlockDesc = (struct tpacket_block_desc *)blocks[curBlock].iov_base;
			if ((curBlockDesc->hdr.bh1.block_status & TP_STATUS_USER) != 0) {
				process_block(curBlockDesc);
				curBlockDesc->hdr.bh1.block_status = TP_STATUS_KERNEL;
				curBlock = (curBlock + 1) % RING_REQ.tp_block_nr;
			}
			break;
		}
	}

	return true;
}

int main(int argc, char *argv[])
{
	static struct sigaction act = {
		.sa_handler = sighandler
	};

	struct iovec blocks[RING_REQ.tp_block_nr];
	void *ring_buf = MAP_FAILED;
	int sockfd = -1;
	int result = EXIT_FAILURE;
	int i;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <netif>\n", argv[0]);
		return EXIT_FAILURE;
	}
	netif = argv[1];

	if (sigaction(SIGINT, &act, NULL) == -1
	 || sigaction(SIGTERM, &act, NULL) == -1
	 || sigaction(SIGINT, &act, NULL) == -1) {
		perror("sigaction");
		goto error;
	}

	if (!create_socket(&sockfd, &ring_buf)) {
		goto error;
	}

	for (i = 0; i < RING_REQ.tp_block_nr; i++) {
		blocks[i].iov_base = ring_buf + i * RING_REQ.tp_block_size;
		blocks[i].iov_len = RING_REQ.tp_block_size;
	}

	if (receive_packets(sockfd, blocks)) {
		result = EXIT_SUCCESS;
	}

error:
	if (ring_buf != MAP_FAILED)
		munmap(ring_buf, RING_REQ.tp_block_size * RING_REQ.tp_block_nr);
	if (sockfd != -1)
		close(sockfd);

	free(localAddr);

	return result;
}

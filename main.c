#include "defs.h"

// settings

char *shared_secret;
char *local_id;
char *remote_id;

char *lan_interface_ip_str;
char *wan_interface_ip_str;

char *lan_host_ip_str;
char *wan_host_ip_str;

char *local_network_start_str;
char *local_network_end_str;

char *remote_network_start_str;
char *remote_network_end_str;

char *my_lan_ip_str;
char *my_wan_ip_str;

char *sonicwall_lan_ip_str;
char *sonicwall_wan_ip_str;

// ipv4 addresses in big endian

unsigned char local_network_start[4];
unsigned char local_network_end[4];

unsigned char remote_network_start[4];
unsigned char remote_network_end[4];

unsigned char my_lan_ip[4];
unsigned char my_wan_ip[4];

unsigned char sonicwall_lan_ip[4];
unsigned char sonicwall_wan_ip[4];

unsigned char lan_interface_ip[4];
unsigned char wan_interface_ip[4];

unsigned char lan_host_ip[4];
unsigned char wan_host_ip[4];

// global vars

int debug = 1;
struct rte_mempool *mempool;
time_t current_time;
int lan_fd;
int wan_fd;
unsigned lan_checksum_correction;
unsigned wan_checksum_correction;
int ipv6_link;
struct sa ike_sa[NUM_IKE_SA];
unsigned char bigbuf[10000];
unsigned char ether_addr[2][6];

#define PORT0_IP 0x14000002 // 20.0.0.2
#define PORT1_IP 0x15000002 // 21.0.0.2

#define PORT0_GW 0x14000001 // 20.0.0.1 (X20 on 9800)
#define PORT1_GW 0x15000001 // 21.0.0.1 (X21 on 9800)

#define SRC_IP PORT1_IP // send on port 1
#define DST_IP PORT0_IP // receive on port 0

#define GATEWAY_IP PORT1_GW

#define NFLOW 250 // number of udp flows
#define IP_LENGTH 128

//#define PACKETS_PER_SECOND 2500000 // 2500000 //2700000
#define PACKETS_PER_SECOND 250	// 2500000 //2700000

#define SRC_PORT 60000 //10000
#define DST_PORT 60001 //10001

#define N_RX_DESC 512 //128
#define N_TX_DESC 512
#define NB_MBUF 8192
#define MAX_PKT_BURST 32

const struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.header_split   = 0, /**< Header Split disabled */
		.hw_ip_checksum = 0, /**< IP checksum offload disabled */
		.hw_vlan_filter = 0, /**< VLAN filtering disabled */
		.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
		.hw_strip_crc   = 0, /**< CRC stripped by hardware */
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

int
main(int argc, char **argv)
{
	int i, n;
	time_t t;
	struct sa *p;

	n = rte_eal_init(argc, argv);
	if (n < 0) {
		printf("rte_eal_init (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}
	argc -= n;
	argv += n;
	init_mempool();
	init_ether(0, 1);
	init_ether(1, 1);
	init_arp();

	if (argc < 2)
		read_config_file("infile");
	else
		read_config_file(argv[1]);

	compute_checksum_corrections();

	resolve_dmac(LAN_PORT_ID, my_lan_ip, sonicwall_lan_ip, ether_addr[LAN_PORT_ID]);
	resolve_dmac(WAN_PORT_ID, my_wan_ip, sonicwall_wan_ip, ether_addr[WAN_PORT_ID]);

	for (i = 0; i < 2; i++)
		printf("%d: %02x:%02x:%02x:%02x:%02x:%02x\n", i,
			ether_addr[i][0],
			ether_addr[i][1],
			ether_addr[i][2],
			ether_addr[i][3],
			ether_addr[i][4],
			ether_addr[i][5]);

	init_lan_tunnel_interface();
	init_wan_tunnel_interface();

	srandom(time(NULL));

	aes_init();

	time(&current_time);

	p = &ike_sa[0];
	init_sa(p);
	send_initiator_ike_init(p);
	p->state = 1;
	p->timer = current_time;
	p->retry = 0;

	for (;;) {
		check_dpdk_receive(0, 0);
		check_dpdk_receive(1, 0);
		handle_socket_events();
		time(&t);
		if (t == current_time)
			continue;
		current_time = t;
		check_arp_timers();
		check_ike_timers();
	}
}

void
stop(int line, char *errmsg)
{
	printf("%s: line number %d\n", errmsg, line);
	exit(1);
}

void
init_mempool(void)
{
	if (eal_proc_type_detect() == RTE_PROC_PRIMARY)
		mempool = rte_pktmbuf_pool_create("mempool", NB_MBUF, 32, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	else
		mempool = rte_mempool_lookup("mempool");
	if (mempool == NULL) {
		printf("rte_pktmbuf_pool_create/lookup (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}
}

void
init_ether(int port_id, int nq)
{
	int err, i, n;

	err = rte_eth_dev_configure(port_id, nq, nq, &port_conf);

	if (err < 0) {
		printf("rte_eth_dev_configure (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}

	// setup receive queues

	for (i = 0; i < nq; i++) {
		err = rte_eth_rx_queue_setup(port_id, i, N_RX_DESC, rte_eth_dev_socket_id(0), NULL, mempool);
		if (err < 0) {
			printf("rte_eth_rx_queue_setup (%s, line %d)\n", __FILE__, __LINE__);
			exit(1);
		}
	}

	// setup transmit queues

	for (i = 0; i < nq; i++) {
		err = rte_eth_tx_queue_setup(port_id, i, N_TX_DESC, rte_eth_dev_socket_id(0), NULL);
		if (err < 0) {
			printf("rte_eth_tx_queue_setup (%s, line %d)\n", __FILE__, __LINE__);
			exit(1);
		}
	}

	err = rte_eth_dev_start(port_id);

	if (err < 0) {
		printf("rte_eth_dev_start err=%d (%s, line %d)\n", err, __FILE__, __LINE__);
		exit(1);
	}

	rte_eth_promiscuous_enable(port_id); // for ipv6 neighbor discovery protocol
}

unsigned
get_spa(int port)
{
	switch (port) {
	case LAN_PORT_ID:
		return my_lan_ip[0] << 24 | my_lan_ip[1] << 16 | my_lan_ip[2] << 8 | my_lan_ip[3];
	case WAN_PORT_ID:
		return my_wan_ip[0] << 24 | my_wan_ip[1] << 16 | my_wan_ip[2] << 8 | my_wan_ip[3];
	}
	printf("error (%s, line %d)\n", __FILE__, __LINE__);
	exit(1);
	return 0;
}

// returns the dpdk port number

int
route_ipv4(unsigned next_hop)
{
	if (next_hop == ntohl(*((unsigned *) sonicwall_lan_ip)))
		return LAN_PORT_ID;
	if (next_hop == ntohl(*((unsigned *) sonicwall_wan_ip)))
		return WAN_PORT_ID;
	printf("error (%s, line %d)\n", __FILE__, __LINE__);
	exit(1);
	return -1;
}

// buf points to start of ip header

void
update_checksums(unsigned char *buf, unsigned m)
{
	update_ip_checksum(buf, m);
	update_tcp_checksum(buf, m);
	update_udp_checksum(buf, m ^ 0xffff);
}

void
update_ip_checksum(unsigned char *buf, unsigned m)
{
	m = (buf[10] << 8 | buf[11]) - m;
	if (m > 65535)
		m = m - 1;
	buf[10] = m >> 8;
	buf[11] = m;
}

void
update_tcp_checksum(unsigned char *buf, unsigned m)
{
	int ip_hdr_len;
	if (buf[9] != 6)
		return; // not tcp
	ip_hdr_len = 4 * (buf[0] & 0xf);
	m = (buf[ip_hdr_len + 16] << 8 | buf[ip_hdr_len + 17]) - m;
	if (m > 0xffff)
		m = m - 1;
	buf[ip_hdr_len + 16] = m >> 8;
	buf[ip_hdr_len + 17] = m;
}

void
update_udp_checksum(unsigned char *buf, unsigned m)
{
	int ip_hdr_len;
	if (buf[9] != 17)
		return; // not udp
	ip_hdr_len = 4 * (buf[0] & 0xf);
	if (buf[ip_hdr_len + 6] == 0 && buf[ip_hdr_len + 7] == 0)
		return; // no checksum
	m = (buf[ip_hdr_len + 6] << 8 | buf[ip_hdr_len + 7]) + m;
	if (m > 0xffff)
		m = m + 1;
	buf[ip_hdr_len + 6] = m >> 8;
	buf[ip_hdr_len + 7] = m;
}

void
update_tcp_checksum_ipv6(unsigned char *buf, unsigned m)
{
	m = (buf[56] << 8 | buf[57]) - m;
	if (m > 65535)
		m = m - 1;
	buf[56] = m >> 8;
	buf[57] = m;
}

#if 0
void
set_ip_checksum_ipv4(unsigned char *buf)
{
	int i, ip_hdr_len;
	unsigned sum = 0;
	ip_hdr_len = 4 * (buf[0] & 0xf);
	buf[10] = 0;
	buf[11] = 0;
	for (i = 0; i < ip_hdr_len; i += 2)
		sum += buf[i] << 8 | buf[i + 1];
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum ^= 0xffff;
	buf[10] = sum >> 8;
	buf[11] = sum;
}
#endif

void
set_tcp_checksum_ipv4(unsigned char *buf)
{
	int i, ip_hdr_len, ip_len, tcp_len;
	unsigned sum;
	ip_hdr_len = 4 * (buf[0] & 0xf);
	ip_len = buf[2] << 8 | buf[3];
	tcp_len = ip_len - ip_hdr_len;
	sum = buf[12] << 8 | buf[13]; // src ip addr
	sum += buf[14] << 8 | buf[15];
	sum += buf[16] << 8 | buf[17]; // dst ip addr
	sum += buf[18] << 8 | buf[19];
	sum += 0x0006; // tcp
	sum += tcp_len;
	buf[ip_hdr_len + 16] = 0;
	buf[ip_hdr_len + 17] = 0;
	for (i = ip_hdr_len; i < ip_len - 1; i += 2)
		sum += buf[i] << 8 | buf[i + 1];
	if (tcp_len & 1)
		sum += buf[ip_len - 1] << 8; // odd length
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum ^= 0xffff;
	buf[ip_hdr_len + 16] = sum >> 8;
	buf[ip_hdr_len + 17] = sum;
}

void
set_udp_checksum_ipv4(unsigned char *buf)
{
	int i, ip_hdr_len, ip_len, udp_len;
	unsigned sum;
	ip_hdr_len = 4 * (buf[0] & 0xf);
	ip_len = buf[2] << 8 | buf[3];
	udp_len = ip_len - ip_hdr_len;
	sum = buf[12] << 8 | buf[13]; // src ip addr
	sum += buf[14] << 8 | buf[15];
	sum += buf[16] << 8 | buf[17]; // dst ip addr
	sum += buf[18] << 8 | buf[19];
	sum += 17; // udp
	sum += udp_len;
	buf[ip_hdr_len + 6] = 0;
	buf[ip_hdr_len + 7] = 0;
	for (i = ip_hdr_len; i < ip_len - 1; i += 2)
		sum += buf[i] << 8 | buf[i + 1];
	if (udp_len & 1)
		sum += buf[ip_len - 1] << 8; // odd length
	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);
	sum ^= 0xffff;
	if (sum == 0)
		sum = 0xffff;
	buf[ip_hdr_len + 6] = sum >> 8;
	buf[ip_hdr_len + 7] = sum;
}

// ipv6 extension headers not supported

void
set_tcp_checksum_ipv6(unsigned char *buf)
{
	int i;
	unsigned sum, tcp_len;

	tcp_len = buf[4] << 8 | buf[5];

	sum = tcp_len + 0x0006; // tcp = 6

	// sum over ip addresses

	for (i = 0; i < 16; i += 2) {
		sum += buf[i + 8] << 8 | buf[i + 9]; // src
		sum += buf[i + 24] << 8 | buf[i + 25]; // dst
	}

	// set checksum to zero

	buf[56] = 0;
	buf[57] = 0;

	// sum over tcp header and text

	for (i = 0; i < tcp_len - 1; i += 2)
		sum += buf[i + 40] << 8 | buf[i + 41];

	// if odd length then sum over last octet

	if (tcp_len & 1)
		sum += buf[i + 40] << 8;

	// sum over all carry bits

	sum = (sum >> 16) + (sum & 0xffff);
	sum = (sum >> 16) + (sum & 0xffff);

	// store ones complement of checksum in tcp header

	sum ^= 0xffff;

	buf[56] = sum >> 8;
	buf[57] = sum;
}

void
read_config_file(char *filename)
{
	int k, t;
	char *s, **tab;

	tab = tokenize(filename);

	if (tab == NULL) {
		printf("config file error\n");
		exit(1);
	}

	k = 0;

	while (tab[k]) {

		s = tab[k++];

		if (strcmp(s, "shared_secret") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			shared_secret = s;
			continue;
		}

		if (strcmp(s, "local_id") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			local_id = s;
			continue;
		}

		if (strcmp(s, "remote_id") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			remote_id = s;
			continue;
		}

		if (strcmp(s, "lan_interface_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			lan_interface_ip_str = s;
			continue;
		}

		if (strcmp(s, "wan_interface_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			wan_interface_ip_str = s;
			continue;
		}

		if (strcmp(s, "lan_host_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			lan_host_ip_str = s;
			continue;
		}

		if (strcmp(s, "wan_host_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			wan_host_ip_str = s;
			continue;
		}

		if (strcmp(s, "sonicwall_lan_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			sonicwall_lan_ip_str = s;
			continue;
		}

		if (strcmp(s, "sonicwall_wan_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			sonicwall_wan_ip_str = s;
			continue;
		}

		if (strcmp(s, "my_lan_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			my_lan_ip_str = s;
			continue;
		}

		if (strcmp(s, "my_wan_ip") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			my_wan_ip_str = s;
			continue;
		}

		if (strcmp(s, "local_network_start") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			local_network_start_str = s;
			continue;
		}

		if (strcmp(s, "local_network_end") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			local_network_end_str = s;
			continue;
		}

		if (strcmp(s, "remote_network_start") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			remote_network_start_str = s;
			continue;
		}

		if (strcmp(s, "remote_network_end") == 0) {
			s = tab[k++];
			if (s == NULL)
				break;
			remote_network_end_str = s;
			continue;
		}

		printf("infile: %s?\n", s);
		exit(1);
	}

	if (inet_pton(AF_INET, local_network_start_str, local_network_start) != 1) {
		printf("infile: local_network_start?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, local_network_end_str, local_network_end) != 1) {
		printf("infile: local_network_end?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, remote_network_start_str, remote_network_start) != 1) {
		printf("infile: remote_network_start?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, remote_network_end_str, remote_network_end) != 1) {
		printf("infile: remote_network_end?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, my_lan_ip_str, my_lan_ip) != 1) {
		printf("infile: my_lan_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, my_wan_ip_str, my_wan_ip) != 1) {
		printf("infile: my_wan_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, sonicwall_lan_ip_str, sonicwall_lan_ip) != 1) {
		printf("infile: sonicwall_lan_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, sonicwall_wan_ip_str, sonicwall_wan_ip) != 1) {
		printf("infile: sonicwall_wan_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, lan_interface_ip_str, lan_interface_ip) != 1) {
		printf("infile: lan_interface_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, wan_interface_ip_str, wan_interface_ip) != 1) {
		printf("infile: wan_interface_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, lan_host_ip_str, lan_host_ip) != 1) {
		printf("infile: lan_host_ip?\n");
		exit(1);
	}

	if (inet_pton(AF_INET, wan_host_ip_str, wan_host_ip) != 1) {
		printf("infile: wan_host_ip?\n");
		exit(1);
	}
}

// returns a NULL-terminated table of token strings

char **
tokenize(char *filename)
{
	int c, fd, i, j, k, n;
	long len;
	char *buf, **tab;

	// buffer the file

	fd = open(filename, O_RDONLY);

	if (fd < 0)
		return NULL;

	len = lseek(fd, 0L, SEEK_END);

	if (len < 1) {
		close(fd);
		return NULL;
	}

	if (lseek(fd, 0L, SEEK_SET) != 0) {
		close(fd);
		return NULL;
	}

	buf = malloc(len);

	if (buf == NULL) {
		close(fd);
		return NULL;
	}

	if (read(fd, buf, len) != len) {
		free(buf);
		close(fd);
		return NULL;
	}

	close(fd);

	// count tokens

	c = 0;
	n = 0;

	for (i = 0; i < len; i++) {
		if (c <= ' ' && buf[i] > ' ')
			n++;
		c = buf[i];
	}

	// create token table

	tab = malloc((n + 1) * sizeof (char *));

	if (tab == NULL) {
		free(buf);
		return NULL;
	}

	k = 0;

	for (i = 0; i < n; i++) {

		// skip white space

		while (buf[k] <= ' ')
			k++;

		// copy token

		j = k;

		do
			k++;
		while (k < len && buf[k] > ' ');

		tab[i] = malloc(k - j + 1);

		if (tab[i] == NULL) {
			free(buf);
			free(tab);
			return NULL;
		}

		memcpy(tab[i], buf + j, k - j);

		tab[i][k - j] = '\0';
	}

	tab[n] = NULL;

	free(buf);

	return tab;
}

void
init_lan_tunnel_interface()
{
	int err;
	char s[100];
	Trace
	lan_fd = create_tun("LAN");
	if (lan_fd < 0) {
		printf("%s %d\n", __FILE__, __LINE__);
		perror("create_tun");
		exit(1);
	}
	snprintf(s, sizeof s, "ip addr add dev LAN %s/24", lan_interface_ip_str);
	err = system(s);
	if (err) {
		printf("%s %d\n", __FILE__, __LINE__);
		perror(s);
		exit(1);
	}
	system("ip link set LAN up");
}

void
init_wan_tunnel_interface()
{
	int err;
	char s[100];
	Trace
	wan_fd = create_tun("WAN");
	if (wan_fd < 0) {
		printf("%s %d\n", __FILE__, __LINE__);
		perror("create_tun");
		exit(1);
	}
	snprintf(s, sizeof s, "ip addr add dev WAN %s/24", wan_interface_ip_str);
	err = system(s);
	if (err) {
		printf("%s %d\n", __FILE__, __LINE__);
		perror(s);
		exit(1);
	}
	system("ip link set WAN up");
}

int
create_tun(char *name)
{
	int err, fd;
	struct ifreq ifr;

	fd = open("/dev/net/tun", O_RDWR);

	if (fd < 0)
		return fd;

	memset(&ifr, 0, sizeof ifr);

	/* TUN device without packet information */
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);

	err = ioctl(fd, TUNSETIFF, (void *) &ifr);

	if (err < 0) {
		close(fd);
		return err;
	}

	return fd;
}

void
init_sa(struct sa *p)
{
	Trace
	if (strchr(local_network_start_str, ':'))
		init_sa_ipv6(p);
	else
		init_sa_ipv4(p);
}

void
init_sa_ipv4(struct sa *p)
{
	int i;
	Trace

	p->state = 1;
	p->udp_port = UDP_PORT;

	p->initiator = 1;
	p->initiator_spi = (unsigned long long) random() << 32 | random();
	p->prf_length = 20;
	strcpy((char *) p->shared_secret, shared_secret);
	p->shared_secret_length = strlen(shared_secret); // TODO check length
	p->id_type_i = ID_KEY_ID;
	strcpy((char *) p->id_i, local_id);
	p->id_i_length = strlen(local_id); // TODO check length
	p->dh_key_length = 128; // Diffie-Hellman Group 2

	p->esp.esp_initiator = 1;
	p->esp.esp_spi_receive = random() << 16 | 0 << 8 | 0; // j,k == 0

	p->esp.selector_src[0].data[0] = TS_IPV4_ADDR_RANGE;
	p->esp.selector_src[0].data[1] = 0; // ip protocol
	p->esp.selector_src[0].data[4] = 0x00; // start port
	p->esp.selector_src[0].data[5] = 0x00;
	p->esp.selector_src[0].data[6] = 0xff; // end port
	p->esp.selector_src[0].data[7] = 0xff;
	inet_pton(AF_INET, local_network_start_str, (unsigned int *) (p->esp.selector_src[0].data + 8));
	inet_pton(AF_INET, local_network_end_str, (unsigned int *) (p->esp.selector_src[0].data + 12));

	p->esp.selector_dst[0].data[0] = TS_IPV4_ADDR_RANGE;
	p->esp.selector_dst[0].data[1] = 0; // ip protocol
	p->esp.selector_dst[0].data[4] = 0x00; // start port
	p->esp.selector_dst[0].data[5] = 0x00;
	p->esp.selector_dst[0].data[6] = 0xff; // end port
	p->esp.selector_dst[0].data[7] = 0xff;
	inet_pton(AF_INET, remote_network_start_str, (unsigned int *) (p->esp.selector_dst[0].data + 8));
	inet_pton(AF_INET, remote_network_end_str, (unsigned int *) (p->esp.selector_dst[0].data + 12));

	p->nonce_1_length = 20;
	for (i = 0; i < 20; i++)
		p->nonce_1[i] = random();

	make_dh_keys(p);
}

void
init_sa_ipv6(struct sa *p)
{
	int i;
	Trace

	p->state = 1;
	p->udp_port = UDP_PORT;

	p->initiator = 1;
	p->initiator_spi = (unsigned long long) random() << 32 | random();
	p->prf_length = 20;
	strcpy((char *) p->shared_secret, shared_secret);
	p->shared_secret_length = strlen(shared_secret);
	p->id_type_i = ID_KEY_ID;
	strcpy((char *) p->id_i, local_id);
	p->id_i_length = strlen(local_id);
	p->dh_key_length = 128; // Diffie-Hellman Group 2

	p->esp.esp_initiator = 1;
	p->esp.esp_spi_receive = random() << 16 | 0 << 8 | 0; // j,k == 0

	p->esp.selector_src[0].data[0] = TS_IPV6_ADDR_RANGE;
	p->esp.selector_src[0].data[1] = 0; // ip protocol
	p->esp.selector_src[0].data[4] = 0x00; // start port
	p->esp.selector_src[0].data[5] = 0x00;
	p->esp.selector_src[0].data[6] = 0xff; // end port
	p->esp.selector_src[0].data[7] = 0xff;
	inet_pton(AF_INET6, local_network_start_str, (unsigned int *) (p->esp.selector_src[0].data + 8));
	inet_pton(AF_INET6, local_network_end_str, (unsigned int *) (p->esp.selector_src[0].data + 24));

	p->esp.selector_dst[0].data[0] = TS_IPV6_ADDR_RANGE;
	p->esp.selector_dst[0].data[1] = 0; // ip protocol
	p->esp.selector_dst[0].data[4] = 0x00; // start port
	p->esp.selector_dst[0].data[5] = 0x00;
	p->esp.selector_dst[0].data[6] = 0xff; // end port
	p->esp.selector_dst[0].data[7] = 0xff;
	inet_pton(AF_INET6, remote_network_start_str, (unsigned int *) (p->esp.selector_dst[0].data + 8));
	inet_pton(AF_INET6, remote_network_end_str, (unsigned int *) (p->esp.selector_dst[0].data + 24));

	p->nonce_1_length = 20;
	for (i = 0; i < 20; i++)
		p->nonce_1[i] = random();

	make_dh_keys(p);
}

void
check_dpdk_receive(int port_id, int queue_id)
{
int j;
	int i, len, n;
	unsigned char *buf;
	struct rte_mbuf *m[MAX_PKT_BURST];
	n = rte_eth_rx_burst(port_id, queue_id, m, MAX_PKT_BURST);
	for (i = 0; i < n; i++) {
		buf = rte_pktmbuf_mtod(m[i], unsigned char *);
		len = rte_pktmbuf_pkt_len(m[i]);
		if (len < 14)
			continue;
		switch (buf[12] << 8 | buf[13]) { // switch on ether type
		case 0x0800:
			switch (port_id) {
			case LAN_PORT_ID:
				receive_from_sonicwall_lan_interface(buf + 14, len - 14);
				break;
			case WAN_PORT_ID:
				receive_from_sonicwall_wan_interface(buf + 14, len - 14);
				break;
			}
			break;
		case 0x0806:
			arp_packet_in(port_id, m[i]);
			break;
		}
		rte_pktmbuf_free(m[i]);
	}
}

// buf points to start of ip header

void
receive_from_sonicwall_lan_interface(unsigned char *buf, int len)
{
	Trace
	send_to_lan_fd(buf, len);
}

// buf points to start of ip header

void
receive_from_sonicwall_wan_interface(unsigned char *buf, int len)
{
	int ip_hdr_len, ip_length, udp_length, dport;
	unsigned char *payload;
	Trace

	if (len < 20)
		return;

	ip_hdr_len = 4 * (buf[0] & 0xf);

	if (ip_hdr_len < 20)
		return;

	ip_length = buf[2] << 8 | buf[3];

	if (ip_length < ip_hdr_len || ip_length > len)
		return;

	payload = buf + ip_hdr_len;

	// switch on ip protocol

	switch (buf[9]) {

	case 17:
		udp_length = payload[4] << 8 | payload[5];
		if (udp_length < 8 || ip_length != ip_hdr_len + udp_length)
			break;
		dport = payload[2] << 8 | payload[3];
		if (dport == 500)
			handle_ike(payload + 8, udp_length - 8);
		break;

	case 50:
		esp_payload_in(payload, ip_length - ip_hdr_len);
		break;
	}
}

void
handle_socket_events()
{
	int n;
	struct pollfd pollfd[2];

	pollfd[0].fd = lan_fd;
	pollfd[1].fd = wan_fd;

	pollfd[0].events = POLLIN;
	pollfd[1].events = POLLIN;

	n = poll(pollfd, 2, 0);

	if (n < 0) {
		perror("poll");
		printf("%s, line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	if (pollfd[0].revents & POLLIN)
		receive_from_lan_fd();

	if (pollfd[1].revents & POLLIN)
		receive_from_wan_fd();
}

void
receive_from_lan_fd()
{
	int n;
	Trace

	n = read(lan_fd, bigbuf, sizeof bigbuf);

	if (n < 1) {
		perror("read");
		printf("%s, line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	if (memcmp(bigbuf + 12, lan_interface_ip, 4) != 0) // check src ip
		return;

	if (memcmp(bigbuf + 16, lan_host_ip, 4) != 0) // check dst ip
		return;

	// nat

	memcpy(bigbuf + 12, remote_network_start, 4);
	memcpy(bigbuf + 16, local_network_start, 4);

	update_checksums(bigbuf, lan_checksum_correction);

	send_ipv4_packet(LAN_PORT_ID, bigbuf); // send to sonicwall
}

void
receive_from_wan_fd()
{
	int n;
	Trace

	n = read(wan_fd, bigbuf + 24, sizeof bigbuf - 64);

	if (n < 1) {
		perror("read");
		printf("%s, line %d\n", __FILE__, __LINE__);
		exit(1);
	}

	if (memcmp(bigbuf + 24 + 12, wan_interface_ip, 4) != 0) // check src ip
		return;

	if (memcmp(bigbuf + 24 + 16, wan_host_ip, 4) != 0) // check dst ip
		return;

	// nat

	memcpy(bigbuf + 24 + 12, local_network_start, 4);
	memcpy(bigbuf + 24 + 16, remote_network_start, 4);

	update_checksums(bigbuf + 24, wan_checksum_correction);

	handle_encryption(n); // send to sonicwall (see esp.c)
}

void
compute_checksum_corrections()
{
	unsigned m;

	m = 0;

	m += (lan_interface_ip[0] << 8 | lan_interface_ip[1]) ^ 0xffff;
	m += (lan_interface_ip[2] << 8 | lan_interface_ip[3]) ^ 0xffff;

	m += (lan_host_ip[0] << 8 | lan_host_ip[1]) ^ 0xffff;
	m += (lan_host_ip[2] << 8 | lan_host_ip[3]) ^ 0xffff;

	m += local_network_start[0] << 8 | local_network_start[1];
	m += local_network_start[2] << 8 | local_network_start[3];

	m += remote_network_start[0] << 8 | remote_network_start[1];
	m += remote_network_start[2] << 8 | remote_network_start[3];

	m = (m >> 16) + (m & 0xffff);
	m = (m >> 16) + (m & 0xffff);

	lan_checksum_correction = m;

	m = 0;

	m += (wan_interface_ip[0] << 8 | wan_interface_ip[1]) ^ 0xffff;
	m += (wan_interface_ip[2] << 8 | wan_interface_ip[3]) ^ 0xffff;

	m += (wan_host_ip[0] << 8 | wan_host_ip[1]) ^ 0xffff;
	m += (wan_host_ip[2] << 8 | wan_host_ip[3]) ^ 0xffff;

	m += local_network_start[0] << 8 | local_network_start[1];
	m += local_network_start[2] << 8 | local_network_start[3];

	m += remote_network_start[0] << 8 | remote_network_start[1];
	m += remote_network_start[2] << 8 | remote_network_start[3];

	m = (m >> 16) + (m & 0xffff);
	m = (m >> 16) + (m & 0xffff);

	wan_checksum_correction = m;
}

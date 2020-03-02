#include "defs.h"

extern struct rte_mempool *mempool;
extern unsigned char ether_addr[2][6];
extern unsigned char my_lan_ip[4];
extern unsigned char my_wan_ip[4];
extern unsigned char dut_lan_ip[4];
extern unsigned char dut_wan_ip[4];

extern unsigned char local_network_start[4];
extern unsigned char remote_network_start[4];

extern unsigned char lan_interface_ip[4];
extern unsigned char lan_host_ip[4];

extern unsigned char wan_interface_ip[4];
extern unsigned char wan_host_ip[4];

extern unsigned lan_checksum_correction;
extern unsigned wan_checksum_correction;

extern int lan_fd;
extern int wan_fd;

int lan_id;
int wan_id;

void
send_ike_msg(struct sa *p, unsigned char *buf, int len)
{
	Trace
	send_ike_packet(buf, len);
	memcpy(p->retrans_buffer, buf, len);
	p->retrans_length = len;
}

void
retransmit(struct sa *p)
{
	Trace
	send_ike_packet(p->retrans_buffer, p->retrans_length);
}

void
send_ike_packet(unsigned char *buf, int len)
{
	unsigned char *p;
	struct rte_mbuf *m;
	Trace

	wan_id++;

	m = rte_pktmbuf_alloc(mempool);

	if (m == NULL) {
		printf("rte_pktmbuf_alloc (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}

	p = (unsigned char *) rte_pktmbuf_append(m, len + 42);

	if (p == NULL) {
		printf("rte_pktmbuf_append (%s, line %d)\n", __FILE__, __LINE__);
		rte_pktmbuf_free(m);
		exit(1);
	}

	memcpy(p + 42, buf, len);

	// udp header

	p[34] = 500 >> 8;
	p[35] = 500 & 0xff;

	p[36] = 500 >> 8;
	p[37] = 500 & 0xff;

	p[38] = (len + 8) >> 8 & 0xff;
	p[39] = (len + 8) & 0xff;

	p[40] = 0;
	p[41] = 0;

	// ip header

	p[14] = 0x45;
	p[15] = 0x00;

	p[16] = (len + 28) >> 8 & 0xff;
	p[17] = (len + 28) & 0xff;

	p[18] = wan_id >> 8 & 0xff;
	p[19] = wan_id & 0xff;

	p[20] = 0; // fragment
	p[21] = 0;

	p[22] = 64; // ttl
	p[23] = 17; // protocol (udp)

	p[26] = my_wan_ip[0]; // src ip addr
	p[27] = my_wan_ip[1];
	p[28] = my_wan_ip[2];
	p[29] = my_wan_ip[3];

	p[30] = dut_wan_ip[0]; // dst ip addr
	p[31] = dut_wan_ip[1];
	p[32] = dut_wan_ip[2];
	p[33] = dut_wan_ip[3];

	set_ipv4_checksum(p + 14);

	// ether header

	memcpy(p, ether_addr[WAN_PORT_ID], 6); // dst
	rte_eth_macaddr_get(WAN_PORT_ID, (struct ether_addr *) (p + 6)); // src

	p[12] = 0x08;
	p[13] = 0x00;

	send_to_port(WAN_PORT_ID, m);
}

// buf points to start of esp payload

#define N 1480
void
send_esp_packet(unsigned char *buf, int len)
{
	unsigned offset = 0;
	Trace
	wan_id++;
	while (len > N) {
		send_esp_fragment(buf, N, 0x2000 | offset);
		buf += N;
		len -= N;
		offset += N / 8;
	}
	send_esp_fragment(buf, len, offset);
}

void
send_esp_fragment(unsigned char *buf, int len, unsigned frag)
{
	unsigned char *p;
	struct rte_mbuf *m;
	Trace

	m = rte_pktmbuf_alloc(mempool);

	if (m == NULL) {
		printf("rte_pktmbuf_alloc (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}

	p = (unsigned char *) rte_pktmbuf_append(m, len + 34);

	if (p == NULL) {
		printf("rte_pktmbuf_append (%s, line %d)\n", __FILE__, __LINE__);
		rte_pktmbuf_free(m);
		exit(1);
	}

	memcpy(p + 34, buf, len);

	// ip header

	p[14] = 0x45;
	p[15] = 0x00;

	p[16] = (len + 20) >> 8 & 0xff;
	p[17] = (len + 20) & 0xff;

	p[18] = wan_id >> 8 & 0xff;
	p[19] = wan_id & 0xff;

	p[20] = frag >> 8 & 0xff;
	p[21] = frag & 0xff;

	p[22] = 64; // ttl
	p[23] = 50; // protocol (esp)

	p[26] = my_wan_ip[0]; // src ip addr
	p[27] = my_wan_ip[1];
	p[28] = my_wan_ip[2];
	p[29] = my_wan_ip[3];

	p[30] = dut_wan_ip[0]; // dst ip addr
	p[31] = dut_wan_ip[1];
	p[32] = dut_wan_ip[2];
	p[33] = dut_wan_ip[3];

	set_ipv4_checksum(p + 14);

	// ether header

	memcpy(p, ether_addr[WAN_PORT_ID], 6); // dst
	rte_eth_macaddr_get(WAN_PORT_ID, (struct ether_addr *) (p + 6)); // src

	p[12] = 0x08;
	p[13] = 0x00;

	send_to_port(WAN_PORT_ID, m);
}

void
send_ipv4_packet(int port, unsigned char *buf)
{
	int len;
	unsigned char *p;
	struct rte_mbuf *m;
	Trace

	len = buf[2] << 8 | buf[3]; // get length from ip header

	m = rte_pktmbuf_alloc(mempool);

	if (m == NULL) {
		printf("rte_pktmbuf_alloc (%s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}

	p = (unsigned char *) rte_pktmbuf_append(m, len + 14);

	if (p == NULL) {
		printf("rte_pktmbuf_append (%s, line %d)\n", __FILE__, __LINE__);
		rte_pktmbuf_free(m);
		exit(1);
	}

	memcpy(p + 14, buf, len);

	// ether header

	memcpy(p, ether_addr[port], 6); // dst
	rte_eth_macaddr_get(port, (struct ether_addr *) (p + 6)); // src

	p[12] = 0x08;
	p[13] = 0x00;

	send_to_port(port, m);
}

void
set_ipv4_checksum(unsigned char *buf)
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

// called from arp.c

void
send_to_next_hop(unsigned next_hop, struct rte_mbuf *m)
{
	int port;
	unsigned char *buf;
	port = route_ipv4(next_hop);
	if (port < 0) {
		rte_pktmbuf_free(m);
		return;
	}
	buf = rte_pktmbuf_mtod(m, unsigned char *);
	rte_eth_macaddr_get(port, (struct ether_addr *) (buf + 6)); // src mac
	buf[12] = 0x08;
	buf[13] = 0x00;
	send_to_port(port, m);
}

void
send_to_port(int port, struct rte_mbuf *m)
{
	int n;
	n = rte_eth_tx_burst(port, 0, &m, 1);
	if (n < 1) {
		printf("rte_eth_tx_burst (%s, line %d)\n", __FILE__, __LINE__);
		rte_pktmbuf_free(m);
		exit(1);
	}
}

// buf points to start of ip header

void
send_to_wan_fd(unsigned char *buf, int len)
{
	int n;
	Trace

	if (memcmp(buf + 12, remote_network_start, 4) != 0) // check src ip
		return;

	if (memcmp(buf + 16, local_network_start, 4) != 0) // check dst ip
		return;

	// nat

	memcpy(buf + 12, wan_host_ip, 4);
	memcpy(buf + 16, wan_interface_ip, 4);

	update_checksums(buf, wan_checksum_correction ^ 0xffff);

	n = write(wan_fd, buf, len);

	if (n < len) {
		perror("write");
		printf("%s, line %d\n", __FILE__, __LINE__);
		exit(1);
	}
}

// buf points to start of ip header

void
send_to_lan_fd(unsigned char *buf, int len)
{
	int n;
	Trace

	if (memcmp(buf + 12, local_network_start, 4) != 0) // check src ip
		return;

	if (memcmp(buf + 16, remote_network_start, 4) != 0) // check dst ip
		return;

	// nat

	memcpy(buf + 12, lan_host_ip, 4);
	memcpy(buf + 16, lan_interface_ip, 4);

	update_checksums(buf, lan_checksum_correction ^ 0xffff);

	n = write(lan_fd, buf, len);

	if (n < len) {
		perror("write");
		printf("%s, line %d\n", __FILE__, __LINE__);
		exit(1);
	}
}

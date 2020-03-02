#include "defs.h"

#define NARP 100

struct arp_entry_t {
	int state;
	unsigned next_hop;
	time_t timer;
	struct rte_mbuf *m;
	unsigned char lladdr[6];
} arptab[NARP];

static struct rte_fbk_hash_params hash_params = {
        .name = "arp",
        .entries = 1024,
        .entries_per_bucket = 4,
        .socket_id = 0,
        .hash_func = NULL,
        .init_val = 0,
};

#define OP (14 + 6)
#define SHA (14 + 8)  // sender hardware address (mac addr)
#define SPA (14 + 14) // sender protocol address (ip addr)
#define THA (14 + 18) // target hardware address (mac addr)
#define TPA (14 + 24) // target protocol address (ip addr)

// states

#define UNUSED 0
#define PENDING1 1 // lladdr is unknown
#define PENDING2 2 // lladdr is valid
#define RESOLVED 3

struct rte_fbk_hash_table *arphash;
extern struct rte_mempool *mempool;

void
init_arp(void)
{
	if (eal_proc_type_detect() == RTE_PROC_PRIMARY) {
		hash_params.socket_id = rte_socket_id();
		arphash = rte_fbk_hash_create(&hash_params);
	} else
		arphash = rte_fbk_hash_find_existing(hash_params.name);
	if (arphash == NULL) {
		printf("rte_fbk_hash_create/find: %s\n", rte_strerror(rte_errno));
		exit(1);
	}
}

void
check_arp_timers()
{
	int i;
	struct arp_entry_t *p;
	time_t t;
	time(&t);
	for (i = 0; i < NARP; i++) {
		p = arptab + i;
		switch (p->state) {
		case PENDING1:
		case PENDING2:
			if (t - p->timer > 5) { // 5 second timer
				rte_fbk_hash_delete_key(arphash, p->next_hop);
				if (p->m)
					rte_pktmbuf_free(p->m);
				p->state = UNUSED;
			}
			break;
		case RESOLVED:
			if (t - p->timer > 600) { // 10 minute timer
				p->state = PENDING2;
				time(&p->timer);
				send_arp_request(p->next_hop);
			}
			break;
		}
	}
}

void
send_ipv4_packet_orig(unsigned next_hop, struct rte_mbuf *m)
{
	int err, i;
	struct arp_entry_t *p;
	unsigned char *buf;

	// lookup

	i = rte_fbk_hash_lookup(arphash, next_hop);

	if (i >= 0) {
		p = arptab + i;
		if (p->state == PENDING1)
			rte_pktmbuf_free(m);
		else {
			buf = rte_pktmbuf_mtod(m, unsigned char *);
			memcpy(buf, p->lladdr, 6);
			send_to_next_hop(next_hop, m);
		}
		return;
	}

	// not found, create new arp entry

	for (i = 0; i < NARP; i++)
		if (arptab[i].state == UNUSED)
			break;

	if (i == NARP) {
		rte_pktmbuf_free(m);
		return;
	}

	err = rte_fbk_hash_add_key(arphash, next_hop, i);

	if (err < 0) {
		rte_pktmbuf_free(m);
		return;
	}

	p = arptab + i;

	p->state = PENDING1;
	time(&p->timer);
	p->next_hop = next_hop;
	p->m = m;

	// send arp request

	send_arp_request(p->next_hop);
}

void
arp_packet_in(int port, struct rte_mbuf *m)
{
	int len, op;
	unsigned char *buf;

	buf = rte_pktmbuf_mtod(m, unsigned char *);
	len = rte_pktmbuf_pkt_len(m);

	// check length

	if (len < 42)
		return;

	// check HTYPE

	if ((buf[14] << 8 | buf[15]) != 0x0001)
		return;

	// check PTYPE

	if ((buf[16] << 8 | buf[17]) != 0x0800)
		return;

	// check HLEN

	if (buf[18] != 6)
		return;

	// check PLEN

	if (buf[19] != 4)
		return;

	// check OP

	op = buf[OP] << 8 | buf[OP + 1];

	switch (op) {
	case 1:
		arp_request_in(port, m);
		break;
	case 2:
		arp_reply_in(port, m);
		break;
	default:
		break;
	}
}

void
arp_request_in(int port, struct rte_mbuf *m)
{
	int i;
	unsigned spa, tpa;
	unsigned char *buf, sha[6];

	buf = rte_pktmbuf_mtod(m, unsigned char *);

	tpa = buf[TPA] << 24 | buf[TPA + 1] << 16 | buf[TPA + 2] << 8 | buf[TPA + 3];

	if (tpa != get_spa(port))
		return;

	// get SHA

	sha[0] = buf[SHA + 0];
	sha[1] = buf[SHA + 1];
	sha[2] = buf[SHA + 2];
	sha[3] = buf[SHA + 3];
	sha[4] = buf[SHA + 4];
	sha[5] = buf[SHA + 5];

	// get SPA

	spa = buf[SPA] << 24 | buf[SPA + 1] << 16 | buf[SPA + 2] << 8 | buf[SPA + 3];

#if 0
	// update arp table

	i = rte_fbk_hash_lookup(arphash, spa);

	if (i >= 0) {

		arptab[i].state = RESOLVED;
		time(&arptab[i].timer);

		arptab[i].lladdr[0] = sha[0];
		arptab[i].lladdr[1] = sha[1];
		arptab[i].lladdr[2] = sha[2];
		arptab[i].lladdr[3] = sha[3];
		arptab[i].lladdr[4] = sha[4];
		arptab[i].lladdr[5] = sha[5];

		if (arptab[i].m) {
			buf = rte_pktmbuf_mtod(m, unsigned char *);
			memcpy(buf, arptab[i].lladdr, 6);
			send_to_next_hop(arptab[i].next_hop, m);
			arptab[i].m = NULL;
		}
	}
#endif
	// send arp reply

	m = rte_pktmbuf_alloc(mempool);

	if (m == NULL)
		return;

	rte_pktmbuf_append(m, 64);

	buf = rte_pktmbuf_mtod(m, unsigned char *);

	// dst ether addr

	buf[0] = sha[0];
	buf[1] = sha[1];
	buf[2] = sha[2];
	buf[3] = sha[3];
	buf[4] = sha[4];
	buf[5] = sha[5];

	// src ether addr

	rte_eth_macaddr_get(port, (struct ether_addr *) (buf + 6));

	// ether type

	buf[12] = 0x08;
	buf[13] = 0x06;

	// HTYPE = 0x00001 (ethernet)

	buf[14] = 0x00;
	buf[15] = 0x01;

	// PTYPE = 0x0800 (internet protocol)

	buf[16] = 0x08;
	buf[17] = 0x00;

	// byte length of hardware address

	buf[18] = 6;

	// byte length of protocol address

	buf[19] = 4;

	// OPER (arp reply)

	buf[20] = 0x00;
	buf[21] = 0x02;

	// SHA (sender ethernet address)

	rte_eth_macaddr_get(port, (struct ether_addr *) (buf + 22));

	// SPA (sender ip address)

	buf[28] = tpa >> 24;
	buf[29] = tpa >> 16;
	buf[30] = tpa >> 8;
	buf[31] = tpa;

	// THA (target ethernet address, copy from SHA of arp request)

	buf[32] = sha[0];
	buf[33] = sha[1];
	buf[34] = sha[2];
	buf[35] = sha[3];
	buf[36] = sha[4];
	buf[37] = sha[5];

	// TPA (target ip address, copy from SPA of arp request)

	buf[38] = spa >> 24;
	buf[39] = spa >> 16;
	buf[40] = spa >> 8;
	buf[41] = spa;

	send_to_port(port, m);
}

void
arp_reply_in(int port, struct rte_mbuf *m)
{
	int i;
	unsigned int spa;
	unsigned char *buf, sha[6];

	buf = rte_pktmbuf_mtod(m, unsigned char *);

	// get SHA

	sha[0] = buf[SHA + 0];
	sha[1] = buf[SHA + 1];
	sha[2] = buf[SHA + 2];
	sha[3] = buf[SHA + 3];
	sha[4] = buf[SHA + 4];
	sha[5] = buf[SHA + 5];

	// get SPA

	spa = buf[SPA] << 24 | buf[SPA + 1] << 16 | buf[SPA + 2] << 8 | buf[SPA + 3];

	// update arp table

	i = rte_fbk_hash_lookup(arphash, spa);

	if (i < 0)
		return;

	arptab[i].state = RESOLVED;
	time(&arptab[i].timer);

	arptab[i].lladdr[0] = sha[0];
	arptab[i].lladdr[1] = sha[1];
	arptab[i].lladdr[2] = sha[2];
	arptab[i].lladdr[3] = sha[3];
	arptab[i].lladdr[4] = sha[4];
	arptab[i].lladdr[5] = sha[5];

	if (arptab[i].m) {
		buf = rte_pktmbuf_mtod(m, unsigned char *);
		memcpy(buf, arptab[i].lladdr, 6);
		send_to_next_hop(arptab[i].next_hop, m);
		arptab[i].m = NULL;
	}
}

void
send_arp_request(unsigned next_hop)
{
	int port;
	struct rte_mbuf *m;
	unsigned char *buf;
	unsigned spa;

	port = route_ipv4(next_hop);

	if (port < 0)
		return;

	m = rte_pktmbuf_alloc(mempool);

	if (m == NULL)
		return;

	rte_pktmbuf_append(m, 64);

	buf = rte_pktmbuf_mtod(m, unsigned char *);

	// dst ether addr

	buf[0] = 0xff;
	buf[1] = 0xff;
	buf[2] = 0xff;
	buf[3] = 0xff;
	buf[4] = 0xff;
	buf[5] = 0xff;

	// src ether addr

	rte_eth_macaddr_get(port, (struct ether_addr *) (buf + 6));

	// ether type (arp)

	buf[12] = 0x08;
	buf[13] = 0x06;

	// HTYPE = 0x0001 (ethernet)

	buf[14] = 0x00;
	buf[15] = 0x01;

	// PTYPE = 0x0800 (internet protocol)

	buf[16] = 0x08;
	buf[17] = 0x00;

	// byte length of hardware address

	buf[18] = 6;

	// byte length of protocol address

	buf[19] = 4;

	// OPER (arp request)

	buf[20] = 0x00;
	buf[21] = 0x01;

	// SHA (sender ethernet address)

	rte_eth_macaddr_get(port, (struct ether_addr *) (buf + 22));

	// SPA (sender ip address)

	spa = get_spa(port);

	buf[28] = spa >> 24;
	buf[29] = spa >> 16;
	buf[30] = spa >> 8;
	buf[31] = spa;

	// THA (target hardware address, unknown)

	buf[32] = 0x00;
	buf[33] = 0x00;
	buf[34] = 0x00;
	buf[35] = 0x00;
	buf[36] = 0x00;
	buf[37] = 0x00;

	// TPA (target ip address)

	buf[38] = next_hop >> 24;
	buf[39] = next_hop >> 16;
	buf[40] = next_hop >> 8;
	buf[41] = next_hop;

	send_to_port(port, m);
}

void
print_arp_table(void)
{
	int i;
	struct arp_entry_t *p;
	for (i = 0; i < NARP; i++) {
		p = arptab + i;
		if (p->state == UNUSED)
			continue;
		printf("%d.%d.%d.%d %02x:%02x:%02x:%02x:%02x:%02x\n", p->next_hop >> 24 & 0xff, p->next_hop >> 16 & 0xff, p->next_hop >> 8 & 0xff, p->next_hop & 0xff, p->lladdr[0], p->lladdr[1], p->lladdr[2], p->lladdr[3], p->lladdr[4], p->lladdr[5]);
	}
}

void
send_arp_request_packet(int port_id, unsigned char *src_ip_addr, unsigned char *dst_ip_addr)
{
	int n;
	struct rte_mbuf *m;
	unsigned char *buf;

	m = rte_pktmbuf_alloc(mempool);

	if (m == NULL) {
		printf("mempool (file %s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}

	rte_pktmbuf_append(m, 42);

	buf = rte_pktmbuf_mtod(m, unsigned char *);

	// dst ether addr

	buf[0] = 0xff;
	buf[1] = 0xff;
	buf[2] = 0xff;
	buf[3] = 0xff;
	buf[4] = 0xff;
	buf[5] = 0xff;

	// src ether addr

	rte_eth_macaddr_get(port_id, (struct ether_addr *) (buf + 6));

	// ether type (arp)

	buf[12] = 0x08;
	buf[13] = 0x06;

	// HTYPE = 0x0001 (ethernet)

	buf[14] = 0x00;
	buf[15] = 0x01;

	// PTYPE = 0x0800 (internet protocol)

	buf[16] = 0x08;
	buf[17] = 0x00;

	// byte length of hardware address

	buf[18] = 6;

	// byte length of protocol address

	buf[19] = 4;

	// OPER (arp request)

	buf[20] = 0x00;
	buf[21] = 0x01;

	// SHA (sender ethernet address)

	rte_eth_macaddr_get(port_id, (struct ether_addr *) (buf + 22));

	// SPA (sender ip address)

	buf[28] = src_ip_addr[0];
	buf[29] = src_ip_addr[1];
	buf[30] = src_ip_addr[2];
	buf[31] = src_ip_addr[3];

	// THA (target hardware address, unknown)

	buf[32] = 0x00;
	buf[33] = 0x00;
	buf[34] = 0x00;
	buf[35] = 0x00;
	buf[36] = 0x00;
	buf[37] = 0x00;

	// TPA (target ip address)

	buf[38] = dst_ip_addr[0];
	buf[39] = dst_ip_addr[1];
	buf[40] = dst_ip_addr[2];
	buf[41] = dst_ip_addr[3];

	// send arp request

	n = rte_eth_tx_burst(port_id, 0, &m, 1);

	if (n < 1) {
		printf("rte_eth_tx_burst (file %s, line %d)\n", __FILE__, __LINE__);
		exit(1);
	}
}

void
resolve_dmac(int port_id, unsigned char *src_ip_addr, unsigned char *dst_ip_addr, unsigned char *dmac)
{
	int i, k, len, n;
	struct rte_mbuf *m[32];
	unsigned char *buf;
	uint64_t t;

	send_arp_request_packet(port_id, src_ip_addr, dst_ip_addr);

	k = 1;
	t = rte_rdtsc();

	for (;;) {

		if (rte_rdtsc() - t >= rte_get_tsc_hz()) {
			if (k == 5) {
				printf("arp timeout for %d.%d.%d.%d\n", dst_ip_addr[0], dst_ip_addr[1], dst_ip_addr[2], dst_ip_addr[3]);
				exit(1);
			}
			send_arp_request_packet(port_id, src_ip_addr, dst_ip_addr);
			k++;
			t += rte_get_tsc_hz();
		}

		n = rte_eth_rx_burst(port_id, 0, m, 32);
		for (i = 0; i < n; i++) {
			buf = rte_pktmbuf_mtod(m[i], unsigned char *);
			len = rte_pktmbuf_pkt_len(m[i]);
			while (t) {
				if (len < 42)
					break; // bad length
				if ((buf[12] << 8 | buf[13]) != 0x0806)
					break; // not arp
				if ((buf[14] << 8 | buf[15]) != 0x0001)
					break;
				if ((buf[16] << 8 | buf[17]) != 0x0800)
					break;
				if (buf[18] != 6)
					break;
				if (buf[19] != 4)
					break;
				if ((buf[20] << 8 | buf[21]) != 0x0002)
					break; // not arp reply
				if (buf[28] != dst_ip_addr[0])
					break;
				if (buf[29] != dst_ip_addr[1])
					break;
				if (buf[30] != dst_ip_addr[2])
					break;
				if (buf[31] != dst_ip_addr[3])
					break;
				memcpy(dmac, buf + 22, 6);
				t = 0;
			};
			rte_pktmbuf_free(m[i]);
		}
		if (t == 0)
			return;
	}
}

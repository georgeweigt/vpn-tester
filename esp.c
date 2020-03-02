#include "defs.h"
#include <sys/types.h>
#include <sys/socket.h>

// FIXME rekey before sequence number wraps

#define IPV4_VERSION 4
#define IPV6_VERSION 6
#define PROTOCOL pkt[9]
#define SADDR (pkt + 12)
#define DADDR (pkt + 16)
#define SPORT (pkt + ip_hdr_len)
#define DPORT (pkt + ip_hdr_len + 2)
#define IPV6_SADDR (pkt + 8)
#define IPV6_DADDR (pkt + 24)

/* Format of data buffer for sendto
	 _________
	|___SPI___|   4 bytes
	|___SEQ___|   4 bytes
	|         |
	|   IV    |   16 bytes
	|_________|
	|         |
	|         |
	|Encrypted|
	|Tunneled |   len bytes
	|Packet   |
	|         |
	|_________|
	|         |
	|   AH    |   12 bytes
	|_________|

Notes:

1. Tunneled packet includes IP header which is used to find the SA.

2. AH is a hash of all the bytes that precede it.

3. The above format is for the cipher suite SHA1 AES-128. */

extern int wan_fd;

static int esp_fd; // FIXME use dpdk instead of sockets
static int tun_fd; // FIXME use dpdk instead of sockets

// FIXME get rid of this stuff
struct sockaddr_in saddr;
struct sockaddr_in6 saddr6;
struct sockaddr_in6 dst6;

void
handle_encryption(int n)
{
	int i, len;
	unsigned int hash[5];
	struct esp_struct *esp;
	Trace

	esp = find_sa(bigbuf + 24); // get sa from ip header info

	if (esp == NULL)
		return;

	((unsigned int *) bigbuf)[0] = htonl(esp->esp_spi_send);
	((unsigned int *) bigbuf)[1] = htonl(++esp->send_seq);

	((unsigned int *) bigbuf)[2] = random();
	((unsigned int *) bigbuf)[3] = random();
	((unsigned int *) bigbuf)[4] = random();
	((unsigned int *) bigbuf)[5] = random();

	len = encrypt_esp(esp, bigbuf + 24, n);

	len += 24;

	// 96-bit integrity checksum

	if (esp->esp_initiator)
		prf_hmac_sha1(esp->esp_ai, 20, bigbuf, len, hash);
	else
		prf_hmac_sha1(esp->esp_ar, 20, bigbuf, len, hash);

	for (i = 0; i < 3; i++) {
		bigbuf[len + 4 * i + 0] = hash[i] >> 24;
		bigbuf[len + 4 * i + 1] = hash[i] >> 16;
		bigbuf[len + 4 * i + 2] = hash[i] >> 8;
		bigbuf[len + 4 * i + 3] = hash[i];
	}

	len += 12;

	send_esp_packet(bigbuf, len);
}

#if 0
void
handle_encryption_over_udp()
{
	int i, len, n;
	unsigned int hash[5];
	struct esp_struct *esp;
	Trace

	n = read(tun_fd, bigbuf + 24, sizeof bigbuf - 24 - 12);

	if (n < 1)
		return; // FIXME handle disconnect n == 0

	esp = find_sa(bigbuf + 24);

	if (esp == NULL)
		return;

	((unsigned int *) bigbuf)[0] = htonl(esp->esp_spi_send);
	((unsigned int *) bigbuf)[1] = htonl(++esp->send_seq);

	((unsigned int *) bigbuf)[2] = random();
	((unsigned int *) bigbuf)[3] = random();
	((unsigned int *) bigbuf)[4] = random();
	((unsigned int *) bigbuf)[5] = random();

	len = encrypt_esp(esp, bigbuf + 24, n);

	len += 24;

	// 96-bit integrity checksum

	if (esp->esp_initiator)
		prf_hmac_sha1(esp->esp_ai, 20, bigbuf, len, hash);
	else
		prf_hmac_sha1(esp->esp_ar, 20, bigbuf, len, hash);

	for (i = 0; i < 3; i++) {
		bigbuf[len + 4 * i + 0] = hash[i] >> 24;
		bigbuf[len + 4 * i + 1] = hash[i] >> 16;
		bigbuf[len + 4 * i + 2] = hash[i] >> 8;
		bigbuf[len + 4 * i + 3] = hash[i];
	}

	len += 12;

	if (ipv6_link)
		n = sendto(net_fd, bigbuf, len, 0, (struct sockaddr *) &saddr6, sizeof saddr6);
	else
		n = sendto(net_fd, bigbuf, len, 0, (struct sockaddr *) &saddr, sizeof saddr);

	if (n == -1)
		perror("sendto");
	else if (n < len)
		printf("sendto short\n");
}
#endif

/*
 _________
|___SPI___|   4 bytes
|___SEQ___|   4 bytes
|         |
|   IV    |   16 bytes
|_________|
|         |
|         |
|Encrypted|
|Tunneled |   len bytes
|Packet   |
|         |
|_________|
|         |
|   AH    |   12 bytes
|_________|
*/

void
esp_payload_in(unsigned char *buf, int esp_length)
{
	int i, j, k, len, pad;
	int next_header;
	unsigned char *payload;
	unsigned spi;
	unsigned seq;
	unsigned hash[5], t;
	struct esp_struct *esp;
	Trace

	// check length

	len = esp_length - 24 - 12; // subtract header and trailer

	if (len < 16 || (len & 0xf) != 0)
		return;

	// look up the ESP SA

	spi = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
	seq = buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7];

	j = buf[2]; // non-standard hack
	k = buf[3];

	if (j >= NUM_IKE_SA || k >= NUM_ESP_SA)
		return;

	esp = ike_sa[j].esp_tab + k;

	if (spi != esp->esp_spi_receive)
		return;

	// verify 96-bit integrity checksum

	len = esp_length - 12;

	if (esp->esp_initiator)
		prf_hmac_sha1(esp->esp_ar, 20, buf, len, hash);
	else
		prf_hmac_sha1(esp->esp_ai, 20, buf, len, hash);

	k = len;

	for (i = 0; i < 3; i++) {
		t = buf[k] << 24 | buf[k + 1] << 16 | buf[k + 2] << 8 | buf[k + 3];
		if (t != hash[i]) {
			esp->auth_count++;
			printf("auth kaput\n"); // FIXME remove
			return;
		}
		k += 4;
	}

	if (anti_replay(esp, seq)) {
		esp->replay_count++;
		printf("replay detected, seq %08x\n", esp); // FIXME remove
		return;
	}

	payload = buf + 24;
	len = esp_length - 24 - 12;
	decrypt_esp(esp, payload, len);
	pad = payload[len - 2];
	next_header = payload[len - 1];
	len = len - pad - 2;

	if (len < 1)
		return;

	if (next_header == 59)
		return; // dummy packet, see RFC 4303, p. 16

	send_to_wan_fd(payload, len);
}

struct esp_struct *
find_sa(unsigned char *pkt)
{
	Trace
	switch (pkt[0] & 0xf0) {
	case 0x40:
		return find_sa_ipv4(pkt);
	case 0x60:
		return find_sa_ipv6(pkt);
	}
	return NULL;
}

struct esp_struct *
find_sa_ipv4(unsigned char *pkt)
{
	int i, j;
	int ip_hdr_len;
	struct esp_struct *p;
	Trace

	ip_hdr_len = 4 * (pkt[0] & 0xf);

	for (i = 0; i < NUM_IKE_SA; i++) {
		if (ike_sa[i].state == 0)
			continue;
		for (j = 0; j < NUM_ESP_SA; j++) {
			p = ike_sa[i].esp_tab + j;
			if (p->esp_state == 0)
				continue;
			if (match_src(p, IPV4_VERSION, PROTOCOL, SADDR, SPORT)
			&& match_dst(p, IPV4_VERSION, PROTOCOL, DADDR, DPORT))
				return p;
		}
	}

	return NULL;
}

struct esp_struct *
find_sa_ipv6(unsigned char *pkt)
{
	int i, j, k;
	int next_header;
	int ip_hdr_len;
	struct esp_struct *p;
	Trace

	next_header = pkt[6];
	ip_hdr_len = 40;

	// skip extension headers

	while (next_header == 0 || next_header == 43 || next_header == 44 || next_header == 60) {
		next_header = pkt[ip_hdr_len];
		ip_hdr_len += 8 * pkt[ip_hdr_len + 1] + 8;
	}

	for (i = 0; i < NUM_IKE_SA; i++) {
		if (ike_sa[i].state == 0)
			continue;
		for (j = 0; j < NUM_ESP_SA; j++) {
			p = ike_sa[i].esp_tab + j;
			if (p->esp_state == 0)
				continue;
			if (match_src(p, IPV6_VERSION, next_header, IPV6_SADDR, SPORT)
			&& match_dst(p, IPV6_VERSION, next_header, IPV6_DADDR, DPORT))
				return p;
		}
	}

	return NULL;
}

int
match_src(struct esp_struct *p, int ip_version, int protocol, unsigned char *addr, unsigned char *port)
{
	int i;
	for (i = 0; i < NUM_TS; i++) {
		if (p->selector_src[i].data[0] == 0)
			break;
		if (match(p->selector_src[i].data, ip_version, protocol, addr, port))
			return 1;
	}
	return 0;
}

int
match_dst(struct esp_struct *p, int ip_version, int protocol, unsigned char *addr, unsigned char *port)
{
	int i;
	for (i = 0; i < NUM_TS; i++) {
		if (p->selector_dst[i].data[0] == 0)
			break;
		if (match(p->selector_dst[i].data, ip_version, protocol, addr, port))
			return 1;
	}
	return 0;
}

/*                      1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   TS Type     |IP Protocol ID*|       Selector Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Start Port*         |           End Port*           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Starting Address*                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Ending Address*                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 20: Traffic Selector
*/

#define TS_TYPE 0
#define TS_PROTOCOL 1
#define START_PORT 4
#define END_PORT 6
#define START_IPV4_ADDR 8
#define END_IPV4_ADDR 12
#define START_IPV6_ADDR 8
#define END_IPV6_ADDR 24

int
match(unsigned char *selector, int ip_version, int protocol, unsigned char *addr, unsigned char *port)
{
	switch (selector[TS_TYPE]) {
	case TS_IPV4_ADDR_RANGE:
		if (ip_version == IPV4_VERSION)
			return match_ipv4(selector, protocol, addr, port);
		break;
	case TS_IPV6_ADDR_RANGE:
		if (ip_version == IPV6_VERSION)
			return match_ipv6(selector, protocol, addr, port);
		break;
	}
	return 0;
}

int
match_ipv4(unsigned char *selector, int protocol, unsigned char *addr, unsigned char *port)
{
	if (selector[TS_PROTOCOL] && selector[TS_PROTOCOL] != protocol)
		return 0;

	if (less_than(addr, selector + START_IPV4_ADDR, 4))
		return 0;

	if (greater_than(addr, selector + END_IPV4_ADDR, 4))
		return 0;

	if (selector[TS_PROTOCOL] != 6 && selector[TS_PROTOCOL] != 17)
		return 1;

	if (less_than(port, selector + START_PORT, 2))
		return 0;

	if (greater_than(port, selector + END_PORT, 2))
		return 0;

	return 1;
}

int
match_ipv6(unsigned char *selector, int protocol, unsigned char *addr, unsigned char *port)
{
	if (selector[TS_PROTOCOL] && selector[TS_PROTOCOL] != protocol)
		return 0;

	if (less_than(addr, selector + START_IPV6_ADDR, 16))
		return 0;

	if (greater_than(addr, selector + END_IPV6_ADDR, 16))
		return 0;

	if (selector[TS_PROTOCOL] != 6 && selector[TS_PROTOCOL] != 17)
		return 1;

	if (less_than(port, selector + START_PORT, 2))
		return 0;

	if (greater_than(port, selector + END_PORT, 2))
		return 0;

	return 1;
}

// a and b are in network order

int
less_than(unsigned char *a, unsigned char *b, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (a[i] < b[i])
			return 1;
		if (a[i] > b[i])
			return 0;
	}
	return 0; // a == b
}

// a and b are in network order

int
greater_than(unsigned char *a, unsigned char *b, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		if (a[i] < b[i])
			return 0;
		if (a[i] > b[i])
			return 1;
	}
	return 0; // a == b
}

// returns 1 if packet should be dropped

int
anti_replay(struct esp_struct *p, unsigned int seq)
{
	int d, i, t;

	d = seq - p->receive_seq;				// note 1

	if (d < 1) {						// note 2
		if (d < -63)					// note 3
			return 1;
		else {
			i = seq & 0x3f;				// note 4
			t = p->anti_replay_buffer[i];		// note 5
			p->anti_replay_buffer[i] = 1;
			return t;
		}
	}

	if (d > 64)						// note 6
		d = 64;

	for (i = 1; i < d; i++)					// note 7
		p->anti_replay_buffer[(seq - i) & 0x3f] = 0;

	p->anti_replay_buffer[seq & 0x3f] = 1;			// note 8

	p->receive_seq = seq;					// note 9

	return 0;
}

/* Notes:

1. d is the distance from receive_seq to this packet's sequence number, i.e.,

        (p->receive_seq + d) mod 2^32 == seq

   d is a signed value which means that d is negative for d > 0x7fffffff.

2. If d < 1 then this is potentially a replay packet. For example, d == 0
   when seq == p->receive_seq.

3. The only valid indices for the replay buffer are

        (p->receive_seq-0, -1, ..., -63) mod 64

   If d < -63 then seq is beyond the length of the buffer so drop the packet.

4. This is equivalent to (seq mod 64).

5. Mark the buffer and return the old value. If the packet has already been
   seen then 1 is returned.

6. Normally seq == p->receive_seq + 1. However, the sequence number may jump by
   2 or more due to packet loss or packet reordering.

   If seq jumps by more than 64 then this is beyond the length of the replay
   buffer so truncate to 64.

7. Clear the replay buffer for jumps more than one. For example, if the jump is
   2 then clear the replay buffer for seq-1. At most 63 zeroes are written to
   the replay buffer.

8. Mark the replay buffer for the current packet.

9. Update the receive sequence number.

*/

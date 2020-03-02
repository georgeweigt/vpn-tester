#include "defs.h"

#define ROTL(n, x) ((x << n) | (x >> (32 - n)))

#define F1(x, y, z) ((x & y) ^ (~x & z))
#define F2(x, y, z) (x ^ y ^ z)
#define F3(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define F4(x, y, z) (x ^ y ^ z)

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

void
sha1(unsigned char *buf, int len, unsigned *hash)
{
	int i, n, r;
	unsigned char tmp[64];

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
	hash[4] = 0xc3d2e1f0;

	for (i = 0; i < n; i++) {
		sha128_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	bzero(tmp, 64);
	memcpy(tmp, buf, r);
	tmp[r] = 0x80;

	if (r > 55) {
		sha128_hash_block(tmp, hash);
		bzero(tmp, 64);
	}

	n = 8 * len; // number of bits

	tmp[60] = n >> 24;
	tmp[61] = n >> 16;
	tmp[62] = n >> 8;
	tmp[63] = n;

	sha128_hash_block(tmp, hash);
}

void
sha128_with_key(unsigned char *key, unsigned char *buf, int len, unsigned *hash)
{
	int i, n, r;
	unsigned char tmp[64];

	n = len / 64;	// number of blocks
	r = len % 64;	// remainder bytes

	hash[0] = 0x67452301;
	hash[1] = 0xefcdab89;
	hash[2] = 0x98badcfe;
	hash[3] = 0x10325476;
	hash[4] = 0xc3d2e1f0;

	sha128_hash_block(key, hash);

	for (i = 0; i < n; i++) {
		sha128_hash_block(buf, hash);
		buf += 64;
	}

	// depending on remainder, hash 1 or 2 more blocks

	bzero(tmp, 64);
	memcpy(tmp, buf, r);
	tmp[r] = 0x80;

	if (r > 55) {
		sha128_hash_block(tmp, hash);
		bzero(tmp, 64);
	}

	n = 8 * len + 512; // number of bits

	tmp[60] = n >> 24;
	tmp[61] = n >> 16;
	tmp[62] = n >> 8;
	tmp[63] = n;

	sha128_hash_block(tmp, hash);
}

void
sha128_hash_block(unsigned char *buf, unsigned *hash)
{
	int i, n, t;
	unsigned int a, b, c, d, e, f, w[80], T;

	for (t = 0; t < 16; t++) {
		w[t] = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
		buf += 4;
	}

	for (t = 16; t < 80; t++) {
		T = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
		w[t] = ROTL(1, T);
	}

	a = hash[0];
	b = hash[1];
	c = hash[2];
	d = hash[3];
	e = hash[4];

	for (t = 0; t < 20; t++) {
		f = F1(b, c, d);
		T = ROTL(5, a) + f + e + K1 + w[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	for (t = 20; t < 40; t++) {
		f = F2(b, c, d);
		T = ROTL(5, a) + f + e + K2 + w[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	for (t = 40; t < 60; t++) {
		f = F3(b, c, d);
		T = ROTL(5, a) + f + e + K3 + w[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	for (t = 60; t < 80; t++) {
		f = F4(b, c, d);
		T = ROTL(5, a) + f + e + K4 + w[t];
		e = d;
		d = c;
		c = ROTL(30, b);
		b = a;
		a = T;
	}

	hash[0] += a;
	hash[1] += b;
	hash[2] += c;
	hash[3] += d;
	hash[4] += e;
}

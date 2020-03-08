#include "defs.h"

unsigned prime_number[32] = {
	0xFFFFFFFF, 0xFFFFFFFF, 0xC90FDAA2, 0x2168C234, 0xC4C6628B, 0x80DC1CD1,
	0x29024E08, 0x8A67CC74, 0x020BBEA6, 0x3B139B22, 0x514A0879, 0x8E3404DD,
	0xEF9519B3, 0xCD3A431B, 0x302B0A6D, 0xF25F1437, 0x4FE1356D, 0x6D51C245,
	0xE485B576, 0x625E7EC6, 0xF44C42E9, 0xA637ED6B, 0x0BFF5CB6, 0xF406B7ED,
	0xEE386BFB, 0x5A899FA5, 0xAE9F2411, 0x7C4B1FE6, 0x49286651, 0xECE65381,
	0xFFFFFFFF, 0xFFFFFFFF,
};

// my_public_key = (2 ** my_private_key) mod prime_number

void
make_dh_keys(struct sa *sa)
{
	int i;
	unsigned *a, *b, *c, *y;
	// private_key = random
	for (i = 0; i < 128; i++)
		sa->private_key[i] = random();
	// a = 2
	a = mnew(1);
	a[0] = 2;
	// b = private_key
	b = mnew(32);
	for (i = 0; i < 32; i++)
		b[31 - i] =	sa->private_key[4 * i + 0] << 24 |
				sa->private_key[4 * i + 1] << 16 |
				sa->private_key[4 * i + 2] << 8 |
				sa->private_key[4 * i + 3];
	// c = prime_number, reverse the word order
	c = mnew(32);
	for (i = 0; i < 32; i++)
		c[31 - i] = prime_number[i];
	// y = (a ** b) mod c
	y = mmodpow(a, b, c);
	// least significant byte is stored at highest address
	for (i = 0; i < y[-1]; i++) {
		sa->public_key_1[128 - 4 * i - 4] = y[i] >> 24;
		sa->public_key_1[128 - 4 * i - 3] = y[i] >> 16;
		sa->public_key_1[128 - 4 * i - 2] = y[i] >> 8;
		sa->public_key_1[128 - 4 * i - 1] = y[i];
	}
	// result may be less than 32 words, fill remaining with zeroes
	for (i = y[-1]; i < 32; i++) {
		sa->public_key_1[128 - 4 * i - 4] = 0;
		sa->public_key_1[128 - 4 * i - 3] = 0;
		sa->public_key_1[128 - 4 * i - 2] = 0;
		sa->public_key_1[128 - 4 * i - 1] = 0;
	}
	mfree(a);
	mfree(b);
	mfree(c);
	mfree(y);
}

// secret_key = (far_public_key ** my_private_key) mod prime_number

void
compute_secret_key(struct sa *sa)
{
	int i;
	unsigned *a, *b, *c, *y;
	// a = public_key
	a = mnew(32);
	for (i = 0; i < 32; i++)
		a[31 - i] =	sa->public_key_2[4 * i + 0] << 24 |
				sa->public_key_2[4 * i + 1] << 16 |
				sa->public_key_2[4 * i + 2] << 8 |
				sa->public_key_2[4 * i + 3];
	// b = private_key
	b = mnew(32);
	for (i = 0; i < 32; i++)
		b[31 - i] =	sa->private_key[4 * i + 0] << 24 |
				sa->private_key[4 * i + 1] << 16 |
				sa->private_key[4 * i + 2] << 8 |
				sa->private_key[4 * i + 3];
	// c = prime_number, reverse the word order
	c = mnew(32);
	for (i = 0; i < 32; i++)
		c[31 - i] = prime_number[i];
	// y = (a ** b) mod c
	y = mmodpow(a, b, c);
	// least significant byte is stored at highest address
	for (i = 0; i < y[-1]; i++) {
		sa->secret_key[128 - 4 * i - 4] = y[i] >> 24;
		sa->secret_key[128 - 4 * i - 3] = y[i] >> 16;
		sa->secret_key[128 - 4 * i - 2] = y[i] >> 8;
		sa->secret_key[128 - 4 * i - 1] = y[i];
	}
	// result may be less than 32 words, fill remaining with zeroes
	for (i = y[-1]; i < 32; i++) {
		sa->secret_key[128 - 4 * i - 4] = 0;
		sa->secret_key[128 - 4 * i - 3] = 0;
		sa->secret_key[128 - 4 * i - 2] = 0;
		sa->secret_key[128 - 4 * i - 1] = 0;
	}
	mfree(a);
	mfree(b);
	mfree(c);
	mfree(y);
}

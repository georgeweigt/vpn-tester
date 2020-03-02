#include "defs.h"

void
prf(unsigned char *key, int nk, unsigned char *s, int ns, unsigned int *hash)
{
	prf_hmac_sha1(key, nk, s, ns, hash);
}

void
prf_hmac_sha1(unsigned char *k, int nk, unsigned char *s, int ns, unsigned int *hash)
{
	int i;
	unsigned char key[64], tmp[20];

	// keys longer than 64 are hashed

	if (nk > 64) {
		sha1(k, nk, hash);
		for (i = 0; i < 5; i++) {
			key[4 * i + 0] = hash[i] >> 24;
			key[4 * i + 1] = hash[i] >> 16;
			key[4 * i + 2] = hash[i] >> 8;
			key[4 * i + 3] = hash[i];
		}
		nk = 20;
	} else
		memcpy(key, k, nk);

	// pad with zeroes

	bzero(key + nk, 64 - nk);

	// xor ipad

	for (i = 0; i < 64; i++)
		key[i] ^= 0x36;

	// hash

	sha128_with_key(key, s, ns, hash);

	for (i = 0; i < 5; i++) {
		tmp[4 * i + 0] = hash[i] >> 24;
		tmp[4 * i + 1] = hash[i] >> 16;
		tmp[4 * i + 2] = hash[i] >> 8;
		tmp[4 * i + 3] = hash[i];
	}

	// xor opad

	for (i = 0; i < 64; i++)
		key[i] ^= 0x36 ^ 0x5c;

	// hash

	sha128_with_key(key, tmp, 20, hash);
}

int
test_prf_hmac_sha1()
{
	unsigned hash[5];

	prf_hmac_sha1((unsigned char *) "", 0, (unsigned char *) "", 0, hash);

	if (hash[0] == 0xfbdb1d1b
	&& hash[1] == 0x18aa6c08
	&& hash[2] == 0x324b7d64
	&& hash[3] == 0xb71fb763
	&& hash[4] == 0x70690e1d)
		;
	else
		return 0;

	prf_hmac_sha1((unsigned char *) "key", 3, (unsigned char *) "The quick brown fox jumps over the lazy dog", 43, hash);

	if (hash[0] == 0xde7c9b85
	&& hash[1] == 0xb8b78aa6
	&& hash[2] == 0xbc8a7a36
	&& hash[3] == 0xf70a9070
	&& hash[4] == 0x1c9db4d9)
		;
	else
		return 0;

	return 1;
}

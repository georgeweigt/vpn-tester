#include "defs.h"

/* SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr
   160    160     160     128     128     160     160
   bits   bits    bits    bits    bits    bits    bits

   Total for all keys is 1056 bits.

	5 * 160 + 2 * 128 = 1056 bits

   Each hash generates 160 bits hence at least 7 hashes are needed.

	7 * 160 = 1120 bits = 140 bytes = 35 words

   Notes

   1. For Diffie-Hellman Group 2 the key length is 1024 bits.

   2. For SHA1 the block length is 512 bits (B = 64 bytes).

   3. For SHA1 the hash output is 160 bits (L = 20 bytes).
*/

static unsigned char buf[1024];
static unsigned int hash[35];
static int h;

void
generate_keys(struct sa *sa)
{
	generate_skeyseed(sa);
	generate_key_material(sa);

	h = 0;

	grab_hash(sa->sk_d, 5);
	grab_hash(sa->sk_ai, 5);
	grab_hash(sa->sk_ar, 5);
	grab_hash(sa->sk_ei, 4);
	grab_hash(sa->sk_er, 4);
	grab_hash(sa->sk_pi, 5);
	grab_hash(sa->sk_pr, 5);
}

void
generate_keys_rekey(struct sa *sa)
{
	generate_skeyseed_rekey(sa);
	generate_key_material(sa);

	h = 0;

	grab_hash(sa->sk_d, 5);
	grab_hash(sa->sk_ai, 5);
	grab_hash(sa->sk_ar, 5);
	grab_hash(sa->sk_ei, 4);
	grab_hash(sa->sk_er, 4);
	grab_hash(sa->sk_pi, 5);
	grab_hash(sa->sk_pr, 5);
}

/* See RFC 5996, p. 47

   SKEYSEED = prf(Ni | Nr, g^ir)
*/

void
generate_skeyseed(struct sa *p)
{
	int n;

	// initiator's nonce goes first

	n = 0;

	if (p->initiator) {
		memcpy(buf + n, p->nonce_1, p->nonce_1_length);
		n += p->nonce_1_length;
		memcpy(buf + n, p->nonce_2, p->nonce_2_length);
		n += p->nonce_2_length;
	} else {
		memcpy(buf + n, p->nonce_2, p->nonce_2_length);
		n += p->nonce_2_length;
		memcpy(buf + n, p->nonce_1, p->nonce_1_length);
		n += p->nonce_1_length;
	}

	prf(buf, n, p->secret_key, 128, hash);

	h = 0;

	grab_hash(p->skeyseed, 5);
}

/* See RFC 5996, p. 53

   SKEYSEED = prf(SK_d (old), g^ir (new) | Ni | Nr)
*/

void
generate_skeyseed_rekey(struct sa *p)
{
	int n;

	memcpy(buf, p->secret_key, 128); // this is g^ir

	// initiator's nonce goes first

	n = 128;

	if (p->initiator) {
		memcpy(buf + n, p->nonce_1, p->nonce_1_length);
		n += p->nonce_1_length;
		memcpy(buf + n, p->nonce_2, p->nonce_2_length);
		n += p->nonce_2_length;
	} else {
		memcpy(buf + n, p->nonce_2, p->nonce_2_length);
		n += p->nonce_2_length;
		memcpy(buf + n, p->nonce_1, p->nonce_1_length);
		n += p->nonce_1_length;
	}

	prf(p->sk_d, 20, buf, n, hash);

	h = 0;

	grab_hash(p->skeyseed, 5);
}

/* See RFC 5996, p. 46

   K = SKEYSEED

   S = Ni | Nr | SPIi | SPIr

   T1 = prf(K, S | 0x01)
   T2 = prf(K, T1 | S | 0x02)
   T3 = prf(K, T2 | S | 0x03)
   .
   .
   .
   T7 = prf(K, T6 | S | 0x05)
*/

void
generate_key_material(struct sa *sa)
{
	int i, n;

	n = 20; // make room for T1, T2, etc.

	// initiator's nonce goes first

	if (sa->initiator) {
		memcpy(buf + n, sa->nonce_1, sa->nonce_1_length);
		n += sa->nonce_1_length;
		memcpy(buf + n, sa->nonce_2, sa->nonce_2_length);
		n += sa->nonce_2_length;
	} else {
		memcpy(buf + n, sa->nonce_2, sa->nonce_2_length);
		n += sa->nonce_2_length;
		memcpy(buf + n, sa->nonce_1, sa->nonce_1_length);
		n += sa->nonce_1_length;
	}

	buf[n++] = sa->initiator_spi >> 56;
	buf[n++] = sa->initiator_spi >> 48;
	buf[n++] = sa->initiator_spi >> 40;
	buf[n++] = sa->initiator_spi >> 32;
	buf[n++] = sa->initiator_spi >> 24;
	buf[n++] = sa->initiator_spi >> 16;
	buf[n++] = sa->initiator_spi >> 8;
	buf[n++] = sa->initiator_spi;

	buf[n++] = sa->responder_spi >> 56;
	buf[n++] = sa->responder_spi >> 48;
	buf[n++] = sa->responder_spi >> 40;
	buf[n++] = sa->responder_spi >> 32;
	buf[n++] = sa->responder_spi >> 24;
	buf[n++] = sa->responder_spi >> 16;
	buf[n++] = sa->responder_spi >> 8;
	buf[n++] = sa->responder_spi;

	buf[n++] = 0x01;

	prf(sa->skeyseed, 20, buf + 20, n - 20, hash);

	h = 0;

	for (i = 0; i < 6; i++) {
		grab_hash(buf, 5);
		buf[n - 1]++;
		prf(sa->skeyseed, 20, buf, n, hash + h);
	}
}

void
grab_hash(unsigned char *dest, int count)
{
	int i;
	for (i = 0; i < count; i++) {
		dest[4 * i + 0] = hash[h] >> 24;
		dest[4 * i + 1] = hash[h] >> 16;
		dest[4 * i + 2] = hash[h] >> 8;
		dest[4 * i + 3] = hash[h];
		h++;
	}
}

void
make_esp_keys(struct sa *p)
{
	int i, n;

	n = 20; // make room for T1, T2, etc.

	// initiator's nonce goes first

	if (p->esp.esp_initiator) {
		memcpy(buf + n, p->nonce_1, p->nonce_1_length);
		n += p->nonce_1_length;
		memcpy(buf + n, p->nonce_2, p->nonce_2_length);
		n += p->nonce_2_length;
	} else {
		memcpy(buf + n, p->nonce_2, p->nonce_2_length);
		n += p->nonce_2_length;
		memcpy(buf + n, p->nonce_1, p->nonce_1_length);
		n += p->nonce_1_length;
	}

	buf[n++] = 0x01;

	prf(p->sk_d, 20, buf + 20, n - 20, hash);

	h = 0;

	for (i = 0; i < 6; i++) {
		grab_hash(buf, 5);
		buf[n - 1]++;
		prf(p->sk_d, 20, buf, n, hash + h);
	}

	h = 0;

	grab_hash(p->esp.esp_ei, 4);
	grab_hash(p->esp.esp_ai, 5);
	grab_hash(p->esp.esp_er, 4);
	grab_hash(p->esp.esp_ar, 5);
}

void
randomize_nonce(struct sa *p)
{
	int i;
	for (i = 0; i < 256 / 4; i++)
		((unsigned int *) p->nonce_1)[i] = random();
}

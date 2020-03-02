#include "defs.h"

static unsigned char buf[2000];

void
compute_auth(struct sa *sa)
{
	if (sa->initiator)
		compute_auth_i(sa);
	else
		compute_auth_r(sa);
}

void
check_auth(struct sa *sa)
{
	int i;

	sa->auth_ok = 0;

	if (sa->auth_received_length != 20)
		return;

	if (sa->initiator)
		compute_auth_r(sa);
	else
		compute_auth_i(sa);

	for (i = 0; i < 20; i++)
		if (sa->auth_received[i] != sa->auth_computed[i])
			return;

	sa->auth_ok = 1;
}

void
compute_auth_i(struct sa *sa)
{
	int i, n;
	unsigned int hash[5];
	unsigned char key[20];

	hash_id_i(sa, hash); // clobbers buf

	memcpy(buf, sa->ike_init_msg_i, sa->ike_init_msg_i_length);
	n = sa->ike_init_msg_i_length;

	if (sa->initiator) {
		memcpy(buf + n, sa->nonce_2, sa->nonce_2_length);
		n += sa->nonce_2_length;
	} else {
		memcpy(buf + n, sa->nonce_1, sa->nonce_1_length);
		n += sa->nonce_1_length;
	}

	for (i = 0; i < 5; i++) {
		buf[n + 4 * i + 0] = hash[i] >> 24;
		buf[n + 4 * i + 1] = hash[i] >> 16;
		buf[n + 4 * i + 2] = hash[i] >> 8;
		buf[n + 4 * i + 3] = hash[i];
	}

	n += 20;

	prf(sa->shared_secret, sa->shared_secret_length, (unsigned char *) "Key Pad for IKEv2", 17, hash);

	for (i = 0; i < 5; i++) {
		key[4 * i + 0] = hash[i] >> 24;
		key[4 * i + 1] = hash[i] >> 16;
		key[4 * i + 2] = hash[i] >> 8;
		key[4 * i + 3] = hash[i];
	}

	prf(key, 20, buf, n, hash);

	for (i = 0; i < 5; i++) {
		sa->auth_computed[4 * i + 0] = hash[i] >> 24;
		sa->auth_computed[4 * i + 1] = hash[i] >> 16;
		sa->auth_computed[4 * i + 2] = hash[i] >> 8;
		sa->auth_computed[4 * i + 3] = hash[i];
	}
}

void
compute_auth_r(struct sa *sa)
{
	int i, n;
	unsigned int hash[5];
	unsigned char key[20];

	hash_id_r(sa, hash); // clobbers buf

	memcpy(buf, sa->ike_init_msg_r, sa->ike_init_msg_r_length);
	n = sa->ike_init_msg_r_length;

	if (sa->initiator) {
		memcpy(buf + n, sa->nonce_1, sa->nonce_1_length);
		n += sa->nonce_1_length;
	} else {
		memcpy(buf + n, sa->nonce_2, sa->nonce_2_length);
		n += sa->nonce_2_length;
	}

	for (i = 0; i < 5; i++) {
		buf[n + 4 * i + 0] = hash[i] >> 24;
		buf[n + 4 * i + 1] = hash[i] >> 16;
		buf[n + 4 * i + 2] = hash[i] >> 8;
		buf[n + 4 * i + 3] = hash[i];
	}

	n += 20;

	prf(sa->shared_secret, sa->shared_secret_length, (unsigned char *) "Key Pad for IKEv2", 17, hash);

	for (i = 0; i < 5; i++) {
		key[4 * i + 0] = hash[i] >> 24;
		key[4 * i + 1] = hash[i] >> 16;
		key[4 * i + 2] = hash[i] >> 8;
		key[4 * i + 3] = hash[i];
	}

	prf(key, 20, buf, n, hash);

	for (i = 0; i < 5; i++) {
		sa->auth_computed[4 * i + 0] = hash[i] >> 24;
		sa->auth_computed[4 * i + 1] = hash[i] >> 16;
		sa->auth_computed[4 * i + 2] = hash[i] >> 8;
		sa->auth_computed[4 * i + 3] = hash[i];
	}
}

void
hash_id_i(struct sa *sa, unsigned *hash)
{
	buf[0] = sa->id_type_i;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;

	memcpy(buf + 4, sa->id_i, sa->id_i_length);

	prf(sa->sk_pi, 20, buf, sa->id_i_length + 4, hash);
}

void
hash_id_r(struct sa *sa, unsigned *hash)
{
	buf[0] = sa->id_type_r;
	buf[1] = 0;
	buf[2] = 0;
	buf[3] = 0;

	memcpy(buf + 4, sa->id_r, sa->id_r_length);

	prf(sa->sk_pr, 20, buf, sa->id_r_length + 4, hash);
}

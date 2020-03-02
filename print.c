#include "defs.h"

void
print_buf(unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++) {
		printf(" %02x", buf[i]);
		if (i % 4 == 3)
			printf("\n");
	}
	printf("\n");
}

void
print_response(struct sa *p)
{
	static struct sa t;
	static unsigned char buf[1000];

	memcpy(&t, p, sizeof (struct sa));
	memcpy(buf, p->buf, p->len);

	t.initiator = t.initiator ? 0 : 1;

	printf("\n");
	printf("******************\n");
	printf("Start IKE Response\n");

	parse(&t, buf, p->len);

	printf("\n");
	printf("End IKE Response\n");
	printf("****************\n");
}

#define FMT "%02x"

void
print_keys(struct sa *sa)
{
	int i;

	printf("secret key ");
	for (i = 0; i < 128; i++)
		printf(FMT, sa->secret_key[i]);
	printf("\n");

	printf("nonce_1 ");
	for (i = 0; i < sa->nonce_1_length; i++)
		printf(FMT, sa->nonce_1[i]);
	printf("\n");

	printf("nonce_2 ");
	for (i = 0; i < sa->nonce_2_length; i++)
		printf(FMT, sa->nonce_2[i]);
	printf("\n");

	printf("SPIi %llu\n", sa->initiator_spi);
	printf("SPIr %llu\n", sa->responder_spi);

	printf("skeyseed ");
	for (i = 0; i < 20; i++)
		printf(FMT, sa->skeyseed[i]);
	printf("\n");

	printf("SK_d ");
	for (i = 0; i < 20; i++)
		printf(FMT, sa->sk_d[i]);
	printf("\n");

	printf("SK_ai ");
	for (i = 0; i < 20; i++)
		printf(FMT, sa->sk_ai[i]);
	printf("\n");

	printf("SK_ar ");
	for (i = 0; i < 20; i++)
		printf(FMT, sa->sk_ar[i]);
	printf("\n");

	printf("SK_ei ");
	for (i = 0; i < 16; i++)
		printf(FMT, sa->sk_ei[i]);
	printf("\n");

	printf("SK_er ");
	for (i = 0; i < 16; i++)
		printf(FMT, sa->sk_er[i]);
	printf("\n");

	printf("SK_pi ");
	for (i = 0; i < 20; i++)
		printf(FMT, sa->sk_pi[i]);
	printf("\n");

	printf("SK_pr ");
	for (i = 0; i < 20; i++)
		printf(FMT, sa->sk_pr[i]);
	printf("\n");
}

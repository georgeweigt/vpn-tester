#include "defs.h"

unsigned Te0[256]; // encryption tables
unsigned Te1[256];
unsigned Te2[256];
unsigned Te3[256];

unsigned Td0[256]; // decryption tables
unsigned Td1[256];
unsigned Td2[256];
unsigned Td3[256];

unsigned rcon[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

// sbox[] and inv_sbox[] are from FIPS Publication 197

unsigned char sbox[256] = {
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

unsigned char inv_sbox[256] = {
0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

// multiply a and b mod x^8 + x^4 + x^3 + x + 1 (see FIPS Pub 197, p. 10)

int
mul(int a, int b)
{
	int i, t = 0;
	for (i = 0; i < 8; i++) {
		t <<= 1;
		if (t & 0x100)
			t ^= 0x11b;
		a <<= 1;
		if (a & 0x100)
			t ^= b;
	}
	return t;
}

// multiply a times column b

#define MUL(a, b0, b1, b2, b3) mul(a, b0) | mul(a, b1) << 8 | mul(a, b2) << 16 | mul(a, b3) << 24

void
aes_init()
{
	int i, k;

	for (i = 0; i < 256; i++) {
		k = sbox[i];
		Te0[i] = MUL(k, 2, 1, 1, 3);
		Te1[i] = MUL(k, 3, 2, 1, 1);
		Te2[i] = MUL(k, 1, 3, 2, 1);
		Te3[i] = MUL(k, 1, 1, 3, 2);
		k = inv_sbox[i];
		Td0[i] = MUL(k, 14, 9, 13, 11);
		Td1[i] = MUL(k, 11, 14, 9, 13);
		Td2[i] = MUL(k, 13, 11, 14, 9);
		Td3[i] = MUL(k, 9, 13, 11, 14);
	}
}

// w is for encryption, v is for decryption

void
key_expansion(unsigned char *key, unsigned int *w, unsigned int *v)
{
	int i;
	unsigned *k, tmp;

	k = w;

	k[0] = ((unsigned *) key)[0];
	k[1] = ((unsigned *) key)[1];
	k[2] = ((unsigned *) key)[2];
	k[3] = ((unsigned *) key)[3];

	for (i = 0; i < 10; i++) {
		tmp  = k[3];
		k[4] = k[0] ^
			(Te2[(tmp >>  8) & 0xff] & 0x000000ff) ^
			(Te3[(tmp >> 16) & 0xff] & 0x0000ff00) ^
			(Te0[(tmp >> 24)       ] & 0x00ff0000) ^
			(Te1[(tmp      ) & 0xff] & 0xff000000) ^
			rcon[i];
		k[5] = k[1] ^ k[4];
		k[6] = k[2] ^ k[5];
		k[7] = k[3] ^ k[6];
		k += 4;
	}

	for (i = 0; i < 44; i++)
		v[i] = w[i];

	k = v;

	for (i = 0; i < 9; i++) {
		k += 4;
		k[0] =
			Td0[Te1[(k[0] >>  0) & 0xff] >> 24] ^
			Td1[Te1[(k[0] >>  8) & 0xff] >> 24] ^
			Td2[Te1[(k[0] >> 16) & 0xff] >> 24] ^
			Td3[Te1[(k[0] >> 24) & 0xff] >> 24];
		k[1] =
			Td0[Te1[(k[1] >>  0) & 0xff] >> 24] ^
			Td1[Te1[(k[1] >>  8) & 0xff] >> 24] ^
			Td2[Te1[(k[1] >> 16) & 0xff] >> 24] ^
			Td3[Te1[(k[1] >> 24) & 0xff] >> 24];
		k[2] =
			Td0[Te1[(k[2] >>  0) & 0xff] >> 24] ^
			Td1[Te1[(k[2] >>  8) & 0xff] >> 24] ^
			Td2[Te1[(k[2] >> 16) & 0xff] >> 24] ^
			Td3[Te1[(k[2] >> 24) & 0xff] >> 24];
		k[3] =
			Td0[Te1[(k[3] >>  0) & 0xff] >> 24] ^
			Td1[Te1[(k[3] >>  8) & 0xff] >> 24] ^
			Td2[Te1[(k[3] >> 16) & 0xff] >> 24] ^
			Td3[Te1[(k[3] >> 24) & 0xff] >> 24];
	}
}

void
init_ike_aes(struct sa *p)
{
	key_expansion(p->sk_ei, p->ike_encrypt_i, p->ike_decrypt_i);
	key_expansion(p->sk_er, p->ike_encrypt_r, p->ike_decrypt_r);
}

void
init_esp_aes(struct sa *p)
{
	static unsigned int w[44], v[44];
	if (p->esp.esp_initiator) {
		key_expansion(p->esp.esp_ei, w, v);
		memcpy(p->esp.encrypt_tab, w, sizeof w);
		key_expansion(p->esp.esp_er, w, v);
		memcpy(p->esp.decrypt_tab, v, sizeof v);
	} else {
		key_expansion(p->esp.esp_er, w, v);
		memcpy(p->esp.encrypt_tab, w, sizeof w);
		key_expansion(p->esp.esp_ei, w, v);
		memcpy(p->esp.decrypt_tab, v, sizeof v);
	}
}

#if 0

#define s00 ((unsigned char *) &s0)[0]
#define s01 ((unsigned char *) &s0)[1]
#define s02 ((unsigned char *) &s0)[2]
#define s03 ((unsigned char *) &s0)[3]

#define s10 ((unsigned char *) &s1)[0]
#define s11 ((unsigned char *) &s1)[1]
#define s12 ((unsigned char *) &s1)[2]
#define s13 ((unsigned char *) &s1)[3]

#define s20 ((unsigned char *) &s2)[0]
#define s21 ((unsigned char *) &s2)[1]
#define s22 ((unsigned char *) &s2)[2]
#define s23 ((unsigned char *) &s2)[3]

#define s30 ((unsigned char *) &s3)[0]
#define s31 ((unsigned char *) &s3)[1]
#define s32 ((unsigned char *) &s3)[2]
#define s33 ((unsigned char *) &s3)[3]

#define t00 ((unsigned char *) &t0)[0]
#define t01 ((unsigned char *) &t0)[1]
#define t02 ((unsigned char *) &t0)[2]
#define t03 ((unsigned char *) &t0)[3]

#define t10 ((unsigned char *) &t1)[0]
#define t11 ((unsigned char *) &t1)[1]
#define t12 ((unsigned char *) &t1)[2]
#define t13 ((unsigned char *) &t1)[3]

#define t20 ((unsigned char *) &t2)[0]
#define t21 ((unsigned char *) &t2)[1]
#define t22 ((unsigned char *) &t2)[2]
#define t23 ((unsigned char *) &t2)[3]

#define t30 ((unsigned char *) &t3)[0]
#define t31 ((unsigned char *) &t3)[1]
#define t32 ((unsigned char *) &t3)[2]
#define t33 ((unsigned char *) &t3)[3]

#else

#define s03 (s0 >> 24)
#define s02 (s0 >> 16 & 0xff)
#define s01 (s0 >> 8 & 0xff)
#define s00 (s0 & 0xff)

#define s13 (s1 >> 24)
#define s12 (s1 >> 16 & 0xff)
#define s11 (s1 >> 8 & 0xff)
#define s10 (s1 & 0xff)

#define s23 (s2 >> 24)
#define s22 (s2 >> 16 & 0xff)
#define s21 (s2 >> 8 & 0xff)
#define s20 (s2 & 0xff)

#define s33 (s3 >> 24)
#define s32 (s3 >> 16 & 0xff)
#define s31 (s3 >> 8 & 0xff)
#define s30 (s3 & 0xff)

#define t03 (t0 >> 24)
#define t02 (t0 >> 16 & 0xff)
#define t01 (t0 >> 8 & 0xff)
#define t00 (t0 & 0xff)

#define t13 (t1 >> 24)
#define t12 (t1 >> 16 & 0xff)
#define t11 (t1 >> 8 & 0xff)
#define t10 (t1 & 0xff)

#define t23 (t2 >> 24)
#define t22 (t2 >> 16 & 0xff)
#define t21 (t2 >> 8 & 0xff)
#define t20 (t2 & 0xff)

#define t33 (t3 >> 24)
#define t32 (t3 >> 16 & 0xff)
#define t31 (t3 >> 8 & 0xff)
#define t30 (t3 & 0xff)

#endif

void
encrypt_1_block(unsigned *w, unsigned char *in, unsigned char *out)
{
	unsigned s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = ((unsigned *) in)[0] ^ w[0];
	s1 = ((unsigned *) in)[1] ^ w[1];
	s2 = ((unsigned *) in)[2] ^ w[2];
	s3 = ((unsigned *) in)[3] ^ w[3];
//1
   	t0 = Te0[s00] ^ Te1[s11] ^ Te2[s22] ^ Te3[s33] ^ w[ 4];
   	t1 = Te0[s10] ^ Te1[s21] ^ Te2[s32] ^ Te3[s03] ^ w[ 5];
   	t2 = Te0[s20] ^ Te1[s31] ^ Te2[s02] ^ Te3[s13] ^ w[ 6];
   	t3 = Te0[s30] ^ Te1[s01] ^ Te2[s12] ^ Te3[s23] ^ w[ 7];
//2
   	s0 = Te0[t00] ^ Te1[t11] ^ Te2[t22] ^ Te3[t33] ^ w[ 8];
   	s1 = Te0[t10] ^ Te1[t21] ^ Te2[t32] ^ Te3[t03] ^ w[ 9];
   	s2 = Te0[t20] ^ Te1[t31] ^ Te2[t02] ^ Te3[t13] ^ w[10];
   	s3 = Te0[t30] ^ Te1[t01] ^ Te2[t12] ^ Te3[t23] ^ w[11];
//3
   	t0 = Te0[s00] ^ Te1[s11] ^ Te2[s22] ^ Te3[s33] ^ w[12];
   	t1 = Te0[s10] ^ Te1[s21] ^ Te2[s32] ^ Te3[s03] ^ w[13];
   	t2 = Te0[s20] ^ Te1[s31] ^ Te2[s02] ^ Te3[s13] ^ w[14];
   	t3 = Te0[s30] ^ Te1[s01] ^ Te2[s12] ^ Te3[s23] ^ w[15];
//4
   	s0 = Te0[t00] ^ Te1[t11] ^ Te2[t22] ^ Te3[t33] ^ w[16];
   	s1 = Te0[t10] ^ Te1[t21] ^ Te2[t32] ^ Te3[t03] ^ w[17];
   	s2 = Te0[t20] ^ Te1[t31] ^ Te2[t02] ^ Te3[t13] ^ w[18];
   	s3 = Te0[t30] ^ Te1[t01] ^ Te2[t12] ^ Te3[t23] ^ w[19];
//5
   	t0 = Te0[s00] ^ Te1[s11] ^ Te2[s22] ^ Te3[s33] ^ w[20];
   	t1 = Te0[s10] ^ Te1[s21] ^ Te2[s32] ^ Te3[s03] ^ w[21];
   	t2 = Te0[s20] ^ Te1[s31] ^ Te2[s02] ^ Te3[s13] ^ w[22];
   	t3 = Te0[s30] ^ Te1[s01] ^ Te2[s12] ^ Te3[s23] ^ w[23];
//6
   	s0 = Te0[t00] ^ Te1[t11] ^ Te2[t22] ^ Te3[t33] ^ w[24];
   	s1 = Te0[t10] ^ Te1[t21] ^ Te2[t32] ^ Te3[t03] ^ w[25];
   	s2 = Te0[t20] ^ Te1[t31] ^ Te2[t02] ^ Te3[t13] ^ w[26];
   	s3 = Te0[t30] ^ Te1[t01] ^ Te2[t12] ^ Te3[t23] ^ w[27];
//7
   	t0 = Te0[s00] ^ Te1[s11] ^ Te2[s22] ^ Te3[s33] ^ w[28];
   	t1 = Te0[s10] ^ Te1[s21] ^ Te2[s32] ^ Te3[s03] ^ w[29];
   	t2 = Te0[s20] ^ Te1[s31] ^ Te2[s02] ^ Te3[s13] ^ w[30];
   	t3 = Te0[s30] ^ Te1[s01] ^ Te2[s12] ^ Te3[s23] ^ w[31];
//8
   	s0 = Te0[t00] ^ Te1[t11] ^ Te2[t22] ^ Te3[t33] ^ w[32];
   	s1 = Te0[t10] ^ Te1[t21] ^ Te2[t32] ^ Te3[t03] ^ w[33];
   	s2 = Te0[t20] ^ Te1[t31] ^ Te2[t02] ^ Te3[t13] ^ w[34];
   	s3 = Te0[t30] ^ Te1[t01] ^ Te2[t12] ^ Te3[t23] ^ w[35];
//9
   	t0 = Te0[s00] ^ Te1[s11] ^ Te2[s22] ^ Te3[s33] ^ w[36];
   	t1 = Te0[s10] ^ Te1[s21] ^ Te2[s32] ^ Te3[s03] ^ w[37];
   	t2 = Te0[s20] ^ Te1[s31] ^ Te2[s02] ^ Te3[s13] ^ w[38];
   	t3 = Te0[s30] ^ Te1[s01] ^ Te2[s12] ^ Te3[s23] ^ w[39];

	s0 =
		(Te2[t00] & 0x000000ff) ^
		(Te3[t11] & 0x0000ff00) ^
		(Te0[t22] & 0x00ff0000) ^
		(Te1[t33] & 0xff000000) ^
		w[40];

	s1 =
		(Te2[t10] & 0x000000ff) ^
		(Te3[t21] & 0x0000ff00) ^
		(Te0[t32] & 0x00ff0000) ^
		(Te1[t03] & 0xff000000) ^
		w[41];

	s2 =
		(Te2[t20] & 0x000000ff) ^
		(Te3[t31] & 0x0000ff00) ^
		(Te0[t02] & 0x00ff0000) ^
		(Te1[t13] & 0xff000000) ^
		w[42];

	s3 =
		(Te2[t30] & 0x000000ff) ^
		(Te3[t01] & 0x0000ff00) ^
		(Te0[t12] & 0x00ff0000) ^
		(Te1[t23] & 0xff000000) ^
		w[43];

	((unsigned *) out)[0] = s0;
	((unsigned *) out)[1] = s1;
	((unsigned *) out)[2] = s2;
	((unsigned *) out)[3] = s3;
}

void
decrypt_1_block(unsigned *v, unsigned char *in, unsigned char *out)
{
	unsigned s0, s1, s2, s3, t0, t1, t2, t3;

	s0 = ((unsigned *) in)[0] ^ v[40];
	s1 = ((unsigned *) in)[1] ^ v[41];
	s2 = ((unsigned *) in)[2] ^ v[42];
	s3 = ((unsigned *) in)[3] ^ v[43];
//1
	t0 = Td0[s00] ^ Td1[s31] ^ Td2[s22] ^ Td3[s13] ^ v[36];
	t1 = Td0[s10] ^ Td1[s01] ^ Td2[s32] ^ Td3[s23] ^ v[37];
	t2 = Td0[s20] ^ Td1[s11] ^ Td2[s02] ^ Td3[s33] ^ v[38];
	t3 = Td0[s30] ^ Td1[s21] ^ Td2[s12] ^ Td3[s03] ^ v[39];
//2
	s0 = Td0[t00] ^ Td1[t31] ^ Td2[t22] ^ Td3[t13] ^ v[32];
	s1 = Td0[t10] ^ Td1[t01] ^ Td2[t32] ^ Td3[t23] ^ v[33];
	s2 = Td0[t20] ^ Td1[t11] ^ Td2[t02] ^ Td3[t33] ^ v[34];
	s3 = Td0[t30] ^ Td1[t21] ^ Td2[t12] ^ Td3[t03] ^ v[35];
//3
	t0 = Td0[s00] ^ Td1[s31] ^ Td2[s22] ^ Td3[s13] ^ v[28];
	t1 = Td0[s10] ^ Td1[s01] ^ Td2[s32] ^ Td3[s23] ^ v[29];
	t2 = Td0[s20] ^ Td1[s11] ^ Td2[s02] ^ Td3[s33] ^ v[30];
	t3 = Td0[s30] ^ Td1[s21] ^ Td2[s12] ^ Td3[s03] ^ v[31];
//4
	s0 = Td0[t00] ^ Td1[t31] ^ Td2[t22] ^ Td3[t13] ^ v[24];
	s1 = Td0[t10] ^ Td1[t01] ^ Td2[t32] ^ Td3[t23] ^ v[25];
	s2 = Td0[t20] ^ Td1[t11] ^ Td2[t02] ^ Td3[t33] ^ v[26];
	s3 = Td0[t30] ^ Td1[t21] ^ Td2[t12] ^ Td3[t03] ^ v[27];
//5
	t0 = Td0[s00] ^ Td1[s31] ^ Td2[s22] ^ Td3[s13] ^ v[20];
	t1 = Td0[s10] ^ Td1[s01] ^ Td2[s32] ^ Td3[s23] ^ v[21];
	t2 = Td0[s20] ^ Td1[s11] ^ Td2[s02] ^ Td3[s33] ^ v[22];
	t3 = Td0[s30] ^ Td1[s21] ^ Td2[s12] ^ Td3[s03] ^ v[23];
//6
	s0 = Td0[t00] ^ Td1[t31] ^ Td2[t22] ^ Td3[t13] ^ v[16];
	s1 = Td0[t10] ^ Td1[t01] ^ Td2[t32] ^ Td3[t23] ^ v[17];
	s2 = Td0[t20] ^ Td1[t11] ^ Td2[t02] ^ Td3[t33] ^ v[18];
	s3 = Td0[t30] ^ Td1[t21] ^ Td2[t12] ^ Td3[t03] ^ v[19];
//7
	t0 = Td0[s00] ^ Td1[s31] ^ Td2[s22] ^ Td3[s13] ^ v[12];
	t1 = Td0[s10] ^ Td1[s01] ^ Td2[s32] ^ Td3[s23] ^ v[13];
	t2 = Td0[s20] ^ Td1[s11] ^ Td2[s02] ^ Td3[s33] ^ v[14];
	t3 = Td0[s30] ^ Td1[s21] ^ Td2[s12] ^ Td3[s03] ^ v[15];
//8
	s0 = Td0[t00] ^ Td1[t31] ^ Td2[t22] ^ Td3[t13] ^ v[ 8];
	s1 = Td0[t10] ^ Td1[t01] ^ Td2[t32] ^ Td3[t23] ^ v[ 9];
	s2 = Td0[t20] ^ Td1[t11] ^ Td2[t02] ^ Td3[t33] ^ v[10];
	s3 = Td0[t30] ^ Td1[t21] ^ Td2[t12] ^ Td3[t03] ^ v[11];
//9
	t0 = Td0[s00] ^ Td1[s31] ^ Td2[s22] ^ Td3[s13] ^ v[ 4];
	t1 = Td0[s10] ^ Td1[s01] ^ Td2[s32] ^ Td3[s23] ^ v[ 5];
	t2 = Td0[s20] ^ Td1[s11] ^ Td2[s02] ^ Td3[s33] ^ v[ 6];
	t3 = Td0[s30] ^ Td1[s21] ^ Td2[s12] ^ Td3[s03] ^ v[ 7];

   	s0 =
   		(inv_sbox[t00]      ) ^
   		(inv_sbox[t31] <<  8) ^
   		(inv_sbox[t22] << 16) ^
   		(inv_sbox[t13] << 24) ^
   		v[0];

   	s1 =
   		(inv_sbox[t10]      ) ^
   		(inv_sbox[t01] <<  8) ^
   		(inv_sbox[t32] << 16) ^
   		(inv_sbox[t23] << 24) ^
   		v[1];

   	s2 =
   		(inv_sbox[t20]      ) ^
   		(inv_sbox[t11] <<  8) ^
   		(inv_sbox[t02] << 16) ^
   		(inv_sbox[t33] << 24) ^
   		v[2];

   	s3 =
   		(inv_sbox[t30]      ) ^
   		(inv_sbox[t21] <<  8) ^
   		(inv_sbox[t12] << 16) ^
   		(inv_sbox[t03] << 24) ^
   		v[3];

	((unsigned *) out)[0] = s0;
	((unsigned *) out)[1] = s1;
	((unsigned *) out)[2] = s2;
	((unsigned *) out)[3] = s3;
}

#define BLOCK_SIZE 16

void
encrypt_n_blocks(unsigned int *w, unsigned char *buf, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		((unsigned int *) buf)[0] ^= ((unsigned int *) buf)[-4];
		((unsigned int *) buf)[1] ^= ((unsigned int *) buf)[-3];
		((unsigned int *) buf)[2] ^= ((unsigned int *) buf)[-2];
		((unsigned int *) buf)[3] ^= ((unsigned int *) buf)[-1];
		encrypt_1_block(w, buf, buf);
		buf += 16;
	}
}

void
decrypt_n_blocks(unsigned int *v, unsigned char *buf, int n)
{
	int i;
	buf += BLOCK_SIZE * n;
	for (i = 0; i < n; i++) {
		buf -= BLOCK_SIZE;
		decrypt_1_block(v, buf, buf);
		((unsigned int *) buf)[0] ^= ((unsigned int *) buf)[-4];
		((unsigned int *) buf)[1] ^= ((unsigned int *) buf)[-3];
		((unsigned int *) buf)[2] ^= ((unsigned int *) buf)[-2];
		((unsigned int *) buf)[3] ^= ((unsigned int *) buf)[-1];
	}
}

void
encrypt_payload(struct sa *sa)
{
	int k, len;
	unsigned char *buf;

	buf = sa->buf + sa->k0 + 4 + BLOCK_SIZE; // skip over IV
	len = sa->k - sa->k0 - 4 - BLOCK_SIZE;

	k = 0;
	while ((len & (BLOCK_SIZE - 1)) != BLOCK_SIZE - 1) {
		buf[len++] = 0;
		k++;
	}

	buf[len++] = k; // number of pad bytes

	if (sa->initiator)
		encrypt_n_blocks(sa->ike_encrypt_i, buf, len / BLOCK_SIZE);
	else
		encrypt_n_blocks(sa->ike_encrypt_r, buf, len / BLOCK_SIZE);

	sa->k = sa->k0 + 4 + BLOCK_SIZE + len;
}

void
decrypt_payload(struct sa *sa, unsigned char *buf, int len)
{
	if (sa->initiator)
		decrypt_n_blocks(sa->ike_decrypt_r, buf, len / BLOCK_SIZE);
	else
		decrypt_n_blocks(sa->ike_decrypt_i, buf, len / BLOCK_SIZE);
}

int
test_aes128()
{
	int i;
	unsigned char buf[16];
	unsigned int w[44], v[44];

	unsigned char key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
	unsigned char inp[16] = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
	unsigned char out[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};

	key_expansion(key, w, v);

	encrypt_1_block(w, inp, buf);

	for (i = 0; i < 16; i++)
		if (buf[i] != out[i])
			return 0;

	decrypt_1_block(v, buf, buf);

	for (i = 0; i < 16; i++)
		if (buf[i] != inp[i])
			return 0;

	return 1;
}

// buf points to an ip packet

int
encrypt_esp(struct esp_struct *p, unsigned char *buf, int len)
{
	int k = 0;

	// pad

	while ((len & 0xf) != 14)
		buf[len++] = ++k;

	// pad length

	buf[len++] = k;

	// next header (see rfc 4303, p. 16)

	if ((*buf & 0xf0) == 0x60)
		buf[len++] = 41; // ipv6
	else
		buf[len++] = 4; // ipv4

	encrypt_n_blocks(p->encrypt_tab, buf, len / 16);

	return len;
}

void
decrypt_esp(struct esp_struct *p, unsigned char *buf, int len)
{
	decrypt_n_blocks(p->decrypt_tab, buf, len / 16);
}

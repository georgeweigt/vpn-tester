#define UDP_PORT 500
//#define UDP_PORT 4500
#define NUM_IKE_SA 1
#define NUM_ESP_SA 10000	// number of ESP SA per IKE SA
#define NUM_TS 1	// number of TS per ESP SA

struct selector {
	unsigned char data[40];
};

struct esp_struct {

	int esp_state;
	int esp_initiator;

	unsigned int auth_count;
	unsigned int replay_count;

	unsigned int esp_spi_send;
	unsigned int esp_spi_receive;

	unsigned int send_seq;
	unsigned int receive_seq;

	unsigned char esp_ai[20];
	unsigned char esp_ar[20];

	unsigned char esp_ei[16];
	unsigned char esp_er[16];

	unsigned int encrypt_tab[44];
	unsigned int decrypt_tab[44];

	struct selector selector_src[NUM_TS];
	struct selector selector_dst[NUM_TS];

	unsigned char anti_replay_buffer[64];
};

struct sa {

	struct esp_struct esp_tab[NUM_ESP_SA];
	struct esp_struct esp;

	unsigned int ike_encrypt_i[44];
	unsigned int ike_encrypt_r[44];

	unsigned int ike_decrypt_i[44];
	unsigned int ike_decrypt_r[44];

	int state;
	int timer;
	int retry;
	int initiator;
	int udp_port;

	int err;
	int line;

	int rekey_flag;
	int rekey_protocol;
	int rekey_spi_size;
	unsigned long long rekey_spi;

	int auth_ok;

	unsigned long long arg1;

	//unsigned int ike_timer;
	//unsigned int ike_keep_alive_timer;
	//unsigned int ike_dead_peer_timer;

	unsigned char *ike_header;

	unsigned long long initiator_spi;
	unsigned long long responder_spi;

	unsigned int send_seq;
	unsigned int receive_seq;

	unsigned int send_msg_id;
	unsigned int receive_msg_id;

	unsigned int flags;

	unsigned char public_key_1[128]; // my public key
	unsigned char public_key_2[128]; // the other guy's public key

	unsigned char private_key[128];
	unsigned char secret_key[128];

	int dh_key_length; // in bytes (128 for DK Group 2)

	unsigned char nonce_1[256]; // my nonce
	unsigned char nonce_2[256]; // the other guy's nonce

	int nonce_1_length;
	int nonce_2_length;

	unsigned char skeyseed[20];

	unsigned char sk_d[20];
	unsigned char sk_ai[20];
	unsigned char sk_ar[20];
	unsigned char sk_ei[16];
	unsigned char sk_er[16];
	unsigned char sk_pi[20];
	unsigned char sk_pr[20];

	int prf_length;

//	int auth_method_i;
//	int auth_method_r;

	unsigned char auth_received[20];
	int auth_received_length;

	unsigned char auth_computed[20];
	int auth_computed_length;

	int id_type_i;
	int id_type_r;

	unsigned char id_i[100];
	unsigned char id_r[100];

	int id_i_length;
	int id_r_length;

	unsigned char shared_secret[128];
	int shared_secret_length;

	int k, k0, len;
	unsigned char *buf;

	unsigned char ike_init_msg_i[2000];
	int ike_init_msg_i_length;

	unsigned char ike_init_msg_r[2000];
	int ike_init_msg_r_length;

	unsigned long long msg_spi_i;
	unsigned long long msg_spi_r;
	int exchange_type;
	int msg_id;
	int msg_len;
	int delete_ike;

	struct {
		int accepted;
		int protocol;
		int encr;
		int attr;
		int prf;
		int integ;
		int dh;
		int esn;
		int spi_size;
		unsigned long long spi;
	} proposal;

	int retrans_length;

	unsigned char retrans_buffer[3000];
};

// sa states

#define IDLE 0
#define WAITING_FOR_IKE_INIT 1
#define WAITING_FOR_IKE_AUTH 2
#define WAITING_FOR_IKE_CHILD_SA 3
#define CONNECTED 4

// sa actions

#define IKE_INIT_FROM_INITIATOR 1
#define IKE_INIT_FROM_RESPONDER 2
#define IKE_AUTH_FROM_INITIATOR 3
#define IKE_AUTH_FROM_RESPONDER 4

// exchange types (see RFC 5996, p. 72)

#define IKE_INIT 34
#define IKE_AUTH 35
#define CREATE_CHILD_SA 36
#define INFORMATIONAL 37

// payload types (see RFC 5996, p. 74)

#define TYPE_SA 33
#define TYPE_KE 34
#define TYPE_IDI 35
#define TYPE_IDR 36
#define TYPE_CERT 37
#define TYPE_CERTREQ 38
#define TYPE_AUTH 39
#define TYPE_NONCE 40
#define TYPE_NOTIFY 41
#define TYPE_DELETE 42
#define TYPE_VENDOR_ID 43
#define TYPE_TSI 44
#define TYPE_TSR 45
#define TYPE_SK 46
#define TYPE_CP 47
#define TYPE_EAP 48

// protocol identifiers (see RFC 5996, p. 79)

#define PROTOCOL_IKE 1
#define PROTOCOL_AH 2
#define PROTOCOL_ESP 3

// transform types (see RFC 5996, p. 80)

#define TRANS_ENCR 1
#define TRANS_PRF 2
#define TRANS_INTEG 3
#define TRANS_DH 4
#define TRANS_ESN 5

// encryption types (see RFC 5996, p. 81)

#define ENCR_DES_IV64 1
#define ENCR_DES 2
#define ENCR_3DES 3
#define ENCR_RC5 4
#define ENCR_IDEA 5
#define ENCR_CAST 6
#define ENCR_BLOWFISH 7
#define ENCR_3IDEA 8
#define ENCR_DES_IV32 9
#define ENCR_NULL 11
#define ENCR_AES_CBC 12
#define ENCR_AES_CTR 13

// pseudo-random function types (see RFC 5996, p. 81)

#define PRF_HMAC_MD5 1
#define PRF_HMAC_SHA1 2
#define PRF_HMAC_TIGER 3

// identification types

#define ID_IPV4_ADDR 1
#define ID_FQDN 2
#define ID_KEY_ID 11

// authentication types (see RFC 5996, p. 81)

#define AUTH_NONE 0
#define AUTH_HMAC_MD5_96 1
#define AUTH_HMAC_SHA1_96 2
#define AUTH_DES_MAC 3
#define AUTH_KPDK_MD5 4
#define AUTH_AES_XCBC_96 5

// authentication methods (see RFC 5996, p. 95)

#define AUTH_METHOD_RSA 1
#define AUTH_METHOD_SHARED_KEY 2
#define AUTH_METHOD_DSS 3

// diffie-hellman groups

#define DH_GROUP_2 2

// traffic selector types

#define TS_IPV4_ADDR_RANGE 7
#define TS_IPV6_ADDR_RANGE 8

// configuration types

#define CFG_REQUEST 1
#define CFG_REPLY 2
#define CFG_SET 3
#define CFG_ACK 4

// configuration attributes

#define INTERNAL_IP4_ADDRESS 1
#define INTERNAL_IP4_NETMASK 2
#define INTERNAL_IP4_DNS 3
#define INTERNAL_IP4_NBNS 4
#define INTERNAL_IP4_DHCP 6
#define APPLICATION_VERSION 7
#define INTERNAL_IP6_ADDRESS 8
#define INTERNAL_IP6_DNS 10
#define INTERNAL_IP6_DHCP 12
#define INTERNAL_IP4_SUBNET 13
#define SUPPORTED_ATTRIBUTES 14
#define INTERNAL_IP6_SUBNET 15

// notify message types (see RFC5996, p. 98)

#define UNSUPPORTED_CRITICAL_PAYLOAD 1
#define INVALID_IKE_SPI 4
#define INVALID_MAJOR_VERSION 5
#define INVALID_SYNTAX 7
#define INVALID_MESSAGE_ID 9
#define INVALID_SPI 11
#define NO_PROPOSAL_CHOSEN 14
#define INVALID_KE_PAYLOAD 17
#define AUTHENTICATION_FAILED 24
#define SINGLE_PAIR_REQUIRED 34
#define NO_ADDITIONAL_SAS 35
#define INTERNAL_ADDRESS_FAILURE 36
#define FAILED_CP_REQUIRED 37
#define TS_UNACCEPTABLE 38
#define INVALID_SELECTORS 39
#define TEMPORARY_FAILURE 43
#define CHILD_SA_NOT_FOUND 44

#define REKEY_SA 16393

// scanner error codes

#define ERR_BUFFER_LENGTH 1
#define ERR_MESSAGE_LENGTH 2
#define ERR_IPSEC_VERSION 3
#define ERR_PAYLOAD_LENGTH 4
#define ERR_SK_CHECKSUM 5

#define ERR_NONCE_LENGTH 10

extern int ipv6_link;
extern int debug;
extern unsigned char bigbuf[10000];
extern struct sa ike_sa[NUM_IKE_SA];
extern time_t current_time;

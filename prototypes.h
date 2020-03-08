// aes.c
int mul(int a, int b);
void aes_init();
void key_expansion(unsigned char *key, unsigned int *w, unsigned int *v);
void init_ike_aes(struct sa *p);
void init_esp_aes(struct sa *p);
void encrypt_1_block(unsigned *w, unsigned char *in, unsigned char *out);
void decrypt_1_block(unsigned *v, unsigned char *in, unsigned char *out);
void encrypt_n_blocks(unsigned int *w, unsigned char *buf, int n);
void decrypt_n_blocks(unsigned int *v, unsigned char *buf, int n);
void encrypt_payload(struct sa *sa);
void decrypt_payload(struct sa *sa, unsigned char *buf, int len);
int test_aes128();
int encrypt_esp(struct esp_struct *p, unsigned char *buf, int len);
void decrypt_esp(struct esp_struct *p, unsigned char *buf, int len);
// arp.c
void init_arp(void);
void check_arp_timers();
void arp_packet_in(int port, struct rte_mbuf *m);
void arp_request_in(int port, struct rte_mbuf *m);
void arp_reply_in(int port, struct rte_mbuf *m);
void print_arp_table(void);
void send_arp_request(int port_id, unsigned char *src_ip_addr, unsigned char *dst_ip_addr);
void resolve_dmac(int port_id, unsigned char *src_ip_addr, unsigned char *dst_ip_addr, unsigned char *dmac);
// auth.c
void compute_auth(struct sa *sa);
void check_auth(struct sa *sa);
void compute_auth_i(struct sa *sa);
void compute_auth_r(struct sa *sa);
void hash_id_i(struct sa *sa, unsigned *hash);
void hash_id_r(struct sa *sa, unsigned *hash);
// bignum.c
uint32_t * modpow(uint32_t *a, uint32_t *b, uint32_t *c);
uint32_t * madd(uint32_t *u, uint32_t *v);
uint32_t * msub(uint32_t *u, uint32_t *v);
uint32_t * mmul(uint32_t *u, uint32_t *v);
uint32_t * mdiv(uint32_t *u, uint32_t *v);
void mmod(uint32_t *u, uint32_t *v);
uint32_t * mpow(uint32_t *u, uint32_t *v);
void mshr(uint32_t *u);
int mcmp(uint32_t *u, uint32_t *v);
uint32_t * mnew(int n);
void mfree(uint32_t *u);
uint32_t * mcopy(uint32_t *u);
void mnorm(uint32_t *u);
// dh.c
void make_dh_keys(struct sa *sa);
void compute_secret_key(struct sa *sa);
// esp.c
void handle_encryption(int n);
void handle_encryption_over_udp();
void esp_payload_in(unsigned char *buf, int esp_length);
struct esp_struct * find_sa(unsigned char *pkt);
struct esp_struct * find_sa_ipv4(unsigned char *pkt);
struct esp_struct * find_sa_ipv6(unsigned char *pkt);
int match_src(struct esp_struct *p, int ip_version, int protocol, unsigned char *addr, unsigned char *port);
int match_dst(struct esp_struct *p, int ip_version, int protocol, unsigned char *addr, unsigned char *port);
int match(unsigned char *selector, int ip_version, int protocol, unsigned char *addr, unsigned char *port);
int match_ipv4(unsigned char *selector, int protocol, unsigned char *addr, unsigned char *port);
int match_ipv6(unsigned char *selector, int protocol, unsigned char *addr, unsigned char *port);
int less_than(unsigned char *a, unsigned char *b, int n);
int greater_than(unsigned char *a, unsigned char *b, int n);
int anti_replay(struct esp_struct *p, unsigned int seq);
// ike_part1.c
void handle_ike(unsigned char *payload, int len);
void receive_ike_init(struct sa *sa);
void receive_ike_auth(struct sa *sa);
void receive_ike_create_child_sa(struct sa *sa);
void handle_ike_connected(struct sa *p);
void handle_create_child(struct sa *p);
void rekey_ike(struct sa *p);
void rekey_esp(struct sa *p);
void create_esp(struct sa *p);
void delete_ike(struct sa *p);
void check_ike_timers();
// ike_part2.c
unsigned int get16(unsigned char *buf);
unsigned int get32(unsigned char *buf);
unsigned long long get64(unsigned char *buf);
void parse(struct sa *p, unsigned char *buf, int buflen);
void clear_proposal(struct sa *p);
void parse_next_payload(int next_payload, unsigned char *buf, struct sa *p);
void parse_security_association(unsigned char *buf, struct sa *p);
void parse_proposal(unsigned char *buf, struct sa *p);
void parse_transform(unsigned char *buf, struct sa *p);
void parse_key_exchange(unsigned char *buf, struct sa *p);
void parse_identification(int initiator, unsigned char *buf, struct sa *p);
void parse_certificate(unsigned char *buf, struct sa *p);
void parse_certificate_request(unsigned char *buf, struct sa *p);
void parse_authentication(unsigned char *buf, struct sa *p);
void parse_nonce(unsigned char *buf, struct sa *p);
void parse_notify(unsigned char *buf, struct sa *p);
void parse_delete(unsigned char *buf, struct sa *p);
void parse_vendor_id(unsigned char *buf, struct sa *p);
void parse_traffic_selector(int dir, unsigned char *buf, struct sa *p);
void parse_encrypted_and_authenticated(unsigned char *buf, struct sa *p);
void parse_configuration(unsigned char *buf, struct sa *p);
void parse_extensible_authentication(unsigned char *buf, struct sa *p);
void parse_error(int line, char *err);
void kaput(struct sa *p, int err, const char *func, int line);
void handle_ike_header(struct sa *p, unsigned long long initiator_spi, unsigned long long responder_spi, int version, int exchange_type, int flags, int message_id, int message_length);
void handle_configuration_attribute(struct sa *p, int configuration_type, int attribute_type, int len, unsigned char *buf);
void handle_eap_message(struct sa *p, int code, int type, int len, unsigned char *buf);
void handle_proposal(struct sa *p, int number, int protocol, int spi_size, unsigned long long spi, int num_transforms);
void handle_proposal_end(struct sa *p);
void handle_transform(struct sa *p, int transform_type, int transform_id);
void handle_transform_attribute(struct sa *p, int transform_type, int transform_id, int attribute_type, int length, unsigned char *buf);
void handle_key_exchange(struct sa *p, int dh_group_number, int len, unsigned char *buf);
void handle_identification(struct sa *p, int type, int len, unsigned char *buf);
void handle_certificate(struct sa *p, int cert_encoding, int cert_length, unsigned char *cert);
void handle_certificate_request(struct sa *p, int cert_encoding, int auth_length, unsigned char *auth);
void handle_authentication(struct sa *p, int method, int len, unsigned char *buf);
void handle_nonce(struct sa *p, int len, unsigned char *buf);
void handle_notify(struct sa *p, int protocol, int spi_size, int notify_type, unsigned long long spi);
void handle_delete(struct sa *p, int protocol, int spi_size, unsigned char *spi);
void handle_vendor_id(struct sa *p, int id_length, unsigned char *id);
void handle_ipv4_traffic_selector(struct sa *p, int dir, int selector_number, unsigned char *buf);
void handle_ipv6_traffic_selector(struct sa *p, int dir, int selector_number, unsigned char *buf);
// ike_part3.c
void send_initiator_ike_init(struct sa *p);
void send_initiator_ike_auth(struct sa *p);
void send_initiator_create_child_sa(struct sa *p);
void emit_ike_sa(struct sa *p);
void emit_ike_proposal(struct sa *p);
void emit_esp_sa(struct sa *p);
void emit_ke(struct sa *p);
void emit_nonce(struct sa *p);
void emit_id_payload(struct sa *p);
void emit_auth_payload(struct sa *p);
void start_payload(struct sa *p, int payload_type);
void end_payload(struct sa *p);
void emit64(struct sa *p, unsigned long long data);
void emit32(struct sa *p, unsigned int data);
void emit24(struct sa *p, unsigned int data);
void emit16(struct sa *p, unsigned int data);
void emit8(struct sa *p, unsigned int data);
void emit_data(struct sa *p, unsigned char *data, int len);
void send_responder_ike_init(struct sa *p);
void send_responder_ike_auth(struct sa *p);
void emit_traffic_selectors_i(struct sa *p);
void emit_traffic_selectors_r(struct sa *p);
void emit_traffic_selectors(struct sa *p, struct selector *selector, int type);
void emit_config_payload(struct sa *p);
void send_no_additional_sas(struct sa *p);
void emit_no_additional_sas_payload(struct sa *p);
void send_child_not_found(struct sa *p);
void emit_child_not_found_payload(struct sa *p);
void send_invalid_syntax(struct sa *p);
void emit_invalid_syntax_payload(struct sa *p);
void send_info_response(struct sa *p);
void emit_info_encrypted(struct sa *p);
void send_create_child_error(struct sa *p, int error);
void emit_notify_payload(struct sa *p, int error);
void emit_checksum(struct sa *p);
void send_empty_info_response(struct sa *p);
void emit_empty_payload(struct sa *p);
void send_rekey_esp_response(struct sa *p);
void emit_rekey_esp_response_payload(struct sa *p);
void emit_rekey_notify(struct sa *p);
void send_rekey_ike_response(struct sa *p);
void emit_rekey_ike(struct sa *p);
void emit_rekey_ike_sa(struct sa *p);
void send_create_esp_response(struct sa *p);
void emit_create_esp_response_payload(struct sa *p);
void emit_notify_use_transport_mode(struct sa *p);
// keys.c
void generate_keys(struct sa *sa);
void generate_keys_rekey(struct sa *sa);
void generate_skeyseed(struct sa *p);
void generate_skeyseed_rekey(struct sa *p);
void generate_key_material(struct sa *sa);
void grab_hash(unsigned char *dest, int count);
void make_esp_keys(struct sa *p);
void randomize_nonce(struct sa *p);
// main.c
int main(int argc, char **argv);
void stop(int line, char *errmsg);
void init_mempool(void);
void init_ether(int port_id, int nq);
int check_tpa(int port, unsigned tpa);
int route_ipv4(unsigned next_hop);
void update_checksums(unsigned char *buf, unsigned m);
void update_ip_checksum(unsigned char *buf, unsigned m);
void update_tcp_checksum(unsigned char *buf, unsigned m);
void update_udp_checksum(unsigned char *buf, unsigned m);
void update_tcp_checksum_ipv6(unsigned char *buf, unsigned m);
void set_ip_header_checksum(unsigned char *buf);
void set_tcp_checksum_ipv4(unsigned char *buf);
void set_udp_checksum_ipv4(unsigned char *buf);
void set_tcp_checksum_ipv6(unsigned char *buf);
void read_config_file(char *filename);
char ** tokenize(char *filename);
void init_lan_tunnel_interface();
void init_wan_tunnel_interface();
int create_tun(char *name);
void init_sa(struct sa *p, int sa_index, int esp_index);
void init_sa_ipv4(struct sa *p, int sa_index, int esp_index);
void init_sa_ipv6(struct sa *p, int sa_index, int esp_index);
void check_dpdk_receive(int port_id, int queue_id);
void packet_from_dut_lan_interface(unsigned char *buf, int len);
void packet_from_dut_wan_interface(unsigned char *buf, int len);
void handle_socket_events();
void receive_from_lan_fd();
void receive_from_wan_fd();
void compute_checksum_corrections();
void start_vpn_connection(void);
void print_status(void);
void packet_from_tunnel(unsigned char *buf, int len);
void send_ping_vpn_to_lan(void);
void send_ping_lan_to_vpn(void);
void send_ping_vpn_to_vpn(void);
// prf.c
void prf(unsigned char *key, int nk, unsigned char *s, int ns, unsigned int *hash);
void prf_hmac_sha1(unsigned char *k, int nk, unsigned char *s, int ns, unsigned int *hash);
int test_prf_hmac_sha1();
// print.c
void print_buf(unsigned char *buf, int len);
void print_response(struct sa *p);
void print_keys(struct sa *sa);
// send.c
void send_ike_msg(struct sa *p, unsigned char *buf, int len);
void retransmit(struct sa *p);
void send_ike_packet(unsigned char *buf, int len);
void send_esp_packet(unsigned char *buf, int len);
void send_esp_fragment(unsigned char *buf, int len, unsigned frag);
void send_ipv4_packet(int port, unsigned char *buf);
void set_ipv4_checksum(unsigned char *buf);
void send_to_next_hop(unsigned next_hop, struct rte_mbuf *m);
void send_to_port(int port, struct rte_mbuf *m);
void send_to_wan_fd(unsigned char *buf, int len);
void send_to_lan_fd(unsigned char *buf, int len);
// sha.c
void sha1(unsigned char *buf, int len, unsigned *hash);
void sha128_with_key(unsigned char *key, unsigned char *buf, int len, unsigned *hash);
void sha128_hash_block(unsigned char *buf, unsigned *hash);
// stringify.c
char * str_transform_type(int type);
char * str_transform_id(int type, int id);
char * str_transform_encr(int id);
char * str_transform_prf(int id);
char * str_transform_integ(int id);
char * str_transform_dh(int id);
char * str_transform_esn(int id);
char * str_exchange_type(int type);
char * str_notify_type(int type);
char * str_protocol_id(int id);

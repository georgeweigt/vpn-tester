#include "defs.h"

#define IDLE 0
#define WAITING_FOR_IKE_INIT 1
#define WAITING_FOR_IKE_AUTH 2
#define CONNECTED 3

static int buflen;

// two remote machines could use same spi_i, need to match ip as well?

void
handle_ike(unsigned char *payload, int len)
{
	int i;
	struct sa *sa;
	unsigned long long spi_i;
	unsigned long long spi_r;
	Trace

	memcpy(bigbuf, payload, len); // FIXME hack for now
	buflen = len;

//	buflen = read(net_fd, bigbuf, sizeof bigbuf);

#if UDP_PORT == 4500
	if (((unsigned *) bigbuf)[0] != 0) {
printf("**********");
		handle_decryption_ipv6_4500(buflen);
		return;
	}
	buflen -= 4;
	memmove(bigbuf, bigbuf + 4, buflen);
#endif

	if (buflen < 28)
		return; // less than IKE header length

	spi_i = 0;
	spi_r = 0;

	for (i = 0; i < 8; i++) {
		spi_i = spi_i << 8 | bigbuf[i];
		spi_r = spi_r << 8 | bigbuf[8 + i];
	}

	if (spi_i == 0) {
		Trace
		return;
	}

	if (spi_r == 0) {
		Trace
		return; // FIXME connection request
	}

	// look for an SA match

	for (i = 0; i < NUM_IKE_SA; i++) {
		sa = ike_sa + i;
		if (sa->initiator_spi == spi_i && sa->responder_spi == spi_r)
			break;
	}

	if (i == NUM_IKE_SA) {
		// no match, look for pending connection
		for (i = 0; i < NUM_IKE_SA; i++) {
			sa = ike_sa + i;
			if (sa->initiator_spi == spi_i && sa->state == WAITING_FOR_IKE_INIT)
				break;
		}
		if (i == NUM_IKE_SA)
			return; // do not reply, received packet might be an attacker's probe
	}

	switch (sa->state) {
	case WAITING_FOR_IKE_INIT:
		sa->responder_spi = spi_r; // FIXME check valid msg first?
		receive_ike_init(sa);
		break;
	case WAITING_FOR_IKE_AUTH:
		receive_ike_auth(sa);
		break;
	case CONNECTED:
		handle_ike_connected(sa);
		break;
	default:
		Trace
		break;
	}
}

// sent IKE_INIT, now receive IKE_INIT from responder

void
receive_ike_init(struct sa *sa)
{
	Trace

#if UDP_PORT == 500 || 1
	memcpy(sa->ike_init_msg_r, bigbuf, buflen);
	sa->ike_init_msg_r_length = buflen;
	parse(sa, bigbuf, buflen);
#else
	memcpy(sa->ike_init_msg_r, bigbuf + 4, buflen);
	sa->ike_init_msg_r_length = buflen - 4;
	parse(sa, bigbuf + 4, buflen - 4);
#endif

	compute_secret_key(sa);
	generate_keys(sa);
	init_ike_aes(sa);

	send_initiator_ike_auth(sa);

	sa->state = WAITING_FOR_IKE_AUTH;
}

// sent IKE_AUTH, now receive IKE_AUTH from responder

void
receive_ike_auth(struct sa *sa)
{
	Trace

#if UDP_PORT == 500 || 1
	parse(sa, bigbuf, buflen);
#else
	parse(sa, bigbuf + 4, buflen - 4);
#endif
	check_auth(sa);

	if (sa->auth_ok == 0)
		stop(__LINE__, "auth not ok");

	// FIXME check proposal

	sa->esp.esp_spi_send = sa->proposal.spi;

	make_esp_keys(sa);
	init_esp_aes(sa);
	memcpy(sa->esp_tab, &sa->esp, sizeof (struct esp_struct));
	sa->esp_tab[0].esp_state = 1;
	sa->esp_tab[0].send_seq = 0;
	sa->esp_tab[0].receive_seq = 0;

	sa->send_seq = 0;
	sa->receive_seq = 0;

	sa->state = CONNECTED;
}

void
handle_ike_connected(struct sa *p)
{
	Trace

	bzero(&p->esp, sizeof (struct esp_struct));

	parse(p, bigbuf, buflen);

	if (p->msg_id != p->receive_seq)
		// FIXME handle retransmission
		return;

	p->receive_seq++;

	if (p->err) {
		send_invalid_syntax(p);
		return;
	}

	switch (p->exchange_type) {
	case CREATE_CHILD_SA:
		handle_create_child(p);
		break;
	case INFORMATIONAL:
		if (p->delete_ike)
			delete_ike(p);
		else
			send_info_response(p);
		break;
	}
}

void
handle_create_child(struct sa *p)
{
	Trace

	if (p->proposal.accepted == 0) {
		send_create_child_error(p, NO_PROPOSAL_CHOSEN);
		return;
	}

	switch (p->proposal.protocol) {
	case PROTOCOL_IKE:
		rekey_ike(p);
		break;
	case PROTOCOL_AH:
		// FIXME do something
		break;
	case PROTOCOL_ESP:
		if (p->rekey_flag)
			rekey_esp(p);
		else
			create_esp(p);
		break;
	}
}

void
rekey_ike(struct sa *p)
{
	Trace

	make_dh_keys(p);
	randomize_nonce(p);

	p->arg1 = (unsigned long long) random() << 32 | random();

	send_rekey_ike_response(p);

	// keys depend on this stuff so must be done first

	p->initiator = 0;
	p->initiator_spi = p->proposal.spi;
	p->responder_spi = p->arg1;

	compute_secret_key(p);
	generate_keys_rekey(p);
	init_ike_aes(p);

	p->send_seq = 0;
	p->receive_seq = 0;
}

void
rekey_esp(struct sa *p)
{
	int j, k;
	Trace

	// FIXME check NOTIFY syntax

	// find the existing ESP SA

	for (k = 0; k < NUM_ESP_SA; k++)
		if (p->esp_tab[k].esp_spi_send == p->rekey_spi)
			break;

	if (k == NUM_ESP_SA) {
		send_child_not_found(p);
		return;
	}

	j = p - ike_sa; // index of SA

	p->arg1 = p->esp_tab[k].esp_spi_receive; // sent in NOTIFY payload

	p->esp.esp_spi_send = p->proposal.spi;
	p->esp.esp_spi_receive = random() << 16 | j << 8 | k; // sent in SA payload

	randomize_nonce(p);

	send_rekey_esp_response(p);

	make_esp_keys(p);
	init_esp_aes(p);

	p->esp.esp_state = 1;
	p->esp.esp_initiator = 0;

	p->esp.send_seq = 0;
	p->esp.receive_seq = 0;

	memcpy(p->esp_tab + k, &p->esp, sizeof (struct esp_struct));
}

void
create_esp(struct sa *p)
{
	int i, j, k, n;
	Trace

	// FIXME check NOTIFY syntax

	// find an unused ESP SA

	for (k = 0; k < NUM_ESP_SA; k++)
		if (p->esp_tab[k].esp_state == 0)
			break;

	if (k == NUM_ESP_SA) {
		send_no_additional_sas(p);
		return;
	}

	j = p - ike_sa; // index of SA

	p->esp.esp_spi_send = p->proposal.spi;
	p->esp.esp_spi_receive = random() << 16 | j << 8 | k; // send in SA payload

	randomize_nonce(p);

	send_create_esp_response(p);

	make_esp_keys(p);
	init_esp_aes(p);

	p->esp.esp_state = 1;
	p->esp.esp_initiator = 0;

	p->esp.send_seq = 0;
	p->esp.receive_seq = 0;

	memcpy(p->esp_tab + k, &p->esp, sizeof (struct esp_struct));

	// delete any ESP SAs with matching selectors

	// FIXME fails if traffic selector elements are in a different order

	n = NUM_TS * sizeof (struct selector);

	for (i = 0; i < NUM_ESP_SA; i++) {
		if (i == k)
			continue;
		if (memcmp(p->esp_tab[i].selector_src, p->esp.selector_src, n) != 0)
			continue;
		if (memcmp(p->esp_tab[i].selector_dst, p->esp.selector_dst, n) != 0)
			continue;
		bzero(&p->esp_tab[i], sizeof (struct esp_struct));
	}
}

void
delete_ike(struct sa *p)
{
	Trace
	send_empty_info_response(p);
	bzero(p, sizeof (struct sa));
}

void
check_ike_timers()
{
	int i;
	struct sa *p;
	for (i = 0; i < NUM_IKE_SA; i++) {
		p = ike_sa + i;
		switch (p->state) {
		case WAITING_FOR_IKE_INIT:
		case WAITING_FOR_IKE_AUTH:
			if (current_time - p->timer < 10)
				break;
			if (p->retry == 2) {
				// FIXME handle too many retries
				delete_ike(p);
				break;
			}
			retransmit(p);
			p->timer = current_time;
			p->retry++;
			break;
		default:
			break;
		}
	}
}

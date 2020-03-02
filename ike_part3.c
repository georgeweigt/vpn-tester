#include "defs.h"

void
send_initiator_ike_init(struct sa *p)
{
	Trace

	p->exchange_type = IKE_INIT;

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, 0);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, IKE_INIT);		// exchange type
	emit8(p, 0x08);			// flags (initiator bit)

	emit32(p, 0);			// message id

	emit32(p, 0);			// message length (0 for now)

	emit_ike_sa(p);
	emit_ke(p);
	emit_nonce(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	// save a copy of the message

	memcpy(p->ike_init_msg_i, p->buf, p->len);
	p->ike_init_msg_i_length = p->len;

	send_ike_msg(p, p->buf, p->len);
}

void
send_initiator_ike_auth(struct sa *p)
{
	int i, t;
	Trace

	p->exchange_type = IKE_AUTH;

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, IKE_AUTH);		// exchange type
	emit8(p, 0x08);			// flags (initiator bit)

	emit32(p, 1);			// message id

	emit32(p, 0);			// message length (0 for now)

	start_payload(p, TYPE_SK);	// start TYPE_SK

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	emit_id_payload(p);
	emit_auth_payload(p);
	emit_esp_sa(p);
	emit_traffic_selectors_i(p);
	emit_traffic_selectors_r(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for 96-bit integrity checksum

	end_payload(p);			// end TYPE_SK

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);
}

void
send_initiator_create_child_sa(struct sa *p)
{
	int i, t;
	Trace

	p->exchange_type = CREATE_CHILD_SA;

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	emit8(p, 0x08);			// flags (initiator bit)

	emit32(p, p->send_msg_id);	// message id

	emit32(p, 0);			// message length (0 for now)

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	emit_esp_sa(p);
	emit_nonce(p);
	emit_traffic_selectors_i(p);
	emit_traffic_selectors_r(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for 96-bit integrity checksum

	end_payload(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);
}

void
emit_ike_sa(struct sa *p)
{
	Trace
	start_payload(p, TYPE_SA);
	emit_ike_proposal(p);
	end_payload(p);
}

void
emit_ike_proposal(struct sa *p)
{
	int k, n, t;
	Trace

	k = p->k;

	emit8(p, 0);			// last
	emit8(p, 0);			// reserved
	emit16(p, 0);			// proposal length (0 for now)

	emit8(p, 1);			// proposal number
	emit8(p, PROTOCOL_IKE);		// protocol id
	emit8(p, 0);			// no spi
	emit8(p, 4);			// number of transforms

	// 1st transfrom

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 12);			// length

	emit8(p, TRANS_ENCR);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, ENCR_AES_CBC);	// transform id
	emit16(p, 0x8000 + 14);		// attribute type
	emit16(p, 128);			// attribute value

	// 2nd transform

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_PRF);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, PRF_HMAC_SHA1);	// transform id

	// 3rd transform

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_INTEG);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, AUTH_HMAC_SHA1_96);	// transform id

	// 4th transform

	emit8(p, 0);			// no more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_DH);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, DH_GROUP_2);		// transform id

	// update proposal length

	t = p->k;
	n = t - k;
	p->k = k + 2;
	emit16(p, n);
	p->k = t;
}

void
emit_esp_sa(struct sa *p)
{
	int k, n, t;
	Trace

	start_payload(p, TYPE_SA);

	k = p->k;

	emit8(p, 0);			// last
	emit8(p, 0);			// reserved
	emit16(p, 0);			// proposal length (0 for now)

	emit8(p, 1);			// proposal number
	emit8(p, PROTOCOL_ESP);		// protocol id
	emit8(p, 4);			// 4 octets for spi
	emit8(p, 3);			// 3 transforms

	// spi

	emit32(p, p->esp.esp_spi_receive);

	// 1st transfrom ENCR

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 12);			// length

	emit8(p, TRANS_ENCR);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, ENCR_AES_CBC);	// transform id
	emit16(p, 0x8000 + 14);		// attribute type
	emit16(p, 128);			// attribute value

	// 2nd transform INTEG

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_INTEG);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, AUTH_HMAC_SHA1_96);	// transform id

	// 3rd transform ESN

	emit8(p, 0);			// no more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_ESN);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, 0);			// no ESN

	// update proposal length

	t = p->k;
	n = t - k;
	p->k = k + 2;
	emit16(p, n);
	p->k = t;

	end_payload(p);
}

// key exchange

void
emit_ke(struct sa *p)
{
	int i;
	Trace

	start_payload(p, TYPE_KE);

	emit16(p, 2);			// diffie-hellman group number
	emit16(p, 0);			// reserved

	for (i = 0; i < 128; i++)
		emit8(p, p->public_key_1[i]);

	end_payload(p);
}

void
emit_nonce(struct sa *p)
{
	Trace
	start_payload(p, TYPE_NONCE);
	emit_data(p, p->nonce_1, p->nonce_1_length);
	end_payload(p);
}

void
emit_id_payload(struct sa *p)
{
	Trace

	if (p->initiator)
		start_payload(p, TYPE_IDI);
	else
		start_payload(p, TYPE_IDR);

	emit8(p, ID_KEY_ID);

	emit24(p, 0);

	if (p->initiator)
		emit_data(p, p->id_i, p->id_i_length);
	else
		emit_data(p, p->id_r, p->id_r_length);

	end_payload(p);
}

void
emit_auth_payload(struct sa *p)
{
	Trace
	start_payload(p, TYPE_AUTH);
	emit8(p, AUTH_METHOD_SHARED_KEY);
	emit24(p, 0);
	compute_auth(p);
	emit_data(p, p->auth_computed, 20);
	end_payload(p);
}

void
start_payload(struct sa *p, int payload_type)
{
	Trace
	p->buf[p->k0] = payload_type;
	p->k0 = p->k;
	emit32(p, 0);
}

void
end_payload(struct sa *p)
{
	int n, t;
	Trace
	n = p->k - p->k0;
	t = p->k;
	p->k = p->k0 + 2;
	emit16(p, n);			// payload length
	p->k = t;
}

void
emit64(struct sa *p, unsigned long long data)
{
	emit32(p, data >> 32);
	emit32(p, data);
}

void
emit32(struct sa *p, unsigned int data)
{
	p->buf[p->k++] = data >> 24;
	p->buf[p->k++] = data >> 16;
	p->buf[p->k++] = data >> 8;
	p->buf[p->k++] = data;
}

void
emit24(struct sa *p, unsigned int data)
{
	p->buf[p->k++] = data >> 16;
	p->buf[p->k++] = data >> 8;
	p->buf[p->k++] = data;
}

void
emit16(struct sa *p, unsigned int data)
{
	p->buf[p->k++] = data >> 8;
	p->buf[p->k++] = data;
}

void
emit8(struct sa *p, unsigned int data)
{
	p->buf[p->k++] = data;
}

void
emit_data(struct sa *p, unsigned char *data, int len)
{
	memcpy(p->buf + p->k, data, len);
	p->k += len;
}

void
send_responder_ike_init(struct sa *p)
{
	Trace

	p->exchange_type = IKE_INIT;

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, IKE_INIT);		// exchange type
	emit8(p, 0x20);			// flags (response bit)

	emit32(p, 0);			// message id

	emit32(p, 0);			// message length (0 for now)

	emit_ike_sa(p);
	emit_ke(p);
	emit_nonce(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	// save a copy of the message

	memcpy(p->ike_init_msg_r, p->buf, p->len);
	p->ike_init_msg_r_length = p->len;

	send_ike_msg(p, p->buf, p->len);
}

void
send_responder_ike_auth(struct sa *p)
{
	int i, t;
	Trace

	p->exchange_type = IKE_AUTH;

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, IKE_AUTH);		// exchange type
	emit8(p, 0x20);			// flags (response bit)

	emit32(p, 1);			// message id

	emit32(p, 0);			// message length (0 for now)

	start_payload(p, TYPE_SK);	// start TYPE_SK

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	emit_id_payload(p);
	emit_auth_payload(p);
	emit_esp_sa(p);
	emit_traffic_selectors_i(p);
	emit_traffic_selectors_r(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for 96-bit integrity checksum

	end_payload(p);			// end TYPE_SK

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);
}

void
emit_traffic_selectors_i(struct sa *p)
{
	struct selector *s;
	Trace

	switch (p->exchange_type) {
	case IKE_AUTH:
		if (p->initiator)
			s = p->esp.selector_src;
		else
			s = p->esp.selector_dst;
		break;
	case CREATE_CHILD_SA:
		if (p->esp.esp_initiator)
			s = p->esp.selector_src;
		else
			s = p->esp.selector_dst;
		break;
	default:
		return;
	}

	emit_traffic_selectors(p, s, TYPE_TSI);
}

void
emit_traffic_selectors_r(struct sa *p)
{
	struct selector *s;
	Trace

	switch (p->exchange_type) {
	case IKE_AUTH:
		if (p->initiator)
			s = p->esp.selector_dst;
		else
			s = p->esp.selector_src;
		break;
	case CREATE_CHILD_SA:
		if (p->esp.esp_initiator)
			s = p->esp.selector_dst;
		else
			s = p->esp.selector_src;
		break;
	default:
		return;
	}

	emit_traffic_selectors(p, s, TYPE_TSR);
}

void
emit_traffic_selectors(struct sa *p, struct selector *selector, int type)
{
	int i;
	Trace

	// count the number of selectors

	for (i = 0; i < NUM_TS; i++)
		if (selector[i].data[0] == 0)
			break;

	if (i == 0)
		return;

	start_payload(p, type);

	emit8(p, i);			// number of traffic selectors
	emit24(p, 0);			// reserved

	for (i = 0; i < NUM_TS; i++) {
		switch (selector[i].data[0]) {
		case TS_IPV4_ADDR_RANGE:
			emit8(p, TS_IPV4_ADDR_RANGE);
			emit8(p, selector[i].data[1]); // ip protocol
			emit16(p, 16); // selector length
			emit_data(p, selector[i].data + 4, 12);
			break;
		case TS_IPV6_ADDR_RANGE:
			emit8(p, TS_IPV6_ADDR_RANGE);
			emit8(p, selector[i].data[1]); // ip protocol
			emit16(p, 40); // selector length
			emit_data(p, selector[i].data + 4, 36);
			break;
		}
	}

	end_payload(p);
}

void
emit_config_payload(struct sa *p)
{
	Trace

	start_payload(p, TYPE_CP);

	emit8(p, CFG_REQUEST);		// configuration type
	emit24(p, 0);			// reserved

	emit16(p, INTERNAL_IP4_ADDRESS);
	emit16(p, 0);			// length

	end_payload(p);
}

void
send_no_additional_sas(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_no_additional_sas_payload(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_no_additional_sas_payload(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	start_payload(p, TYPE_NOTIFY);

	emit8(p, PROTOCOL_ESP);
	emit8(p, 0);			// no spi
	emit16(p, NO_ADDITIONAL_SAS);

	end_payload(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for 96-bit integrity checksum

	end_payload(p);
}

void
send_child_not_found(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_child_not_found_payload(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_child_not_found_payload(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	start_payload(p, TYPE_NOTIFY);	// start NOTIFY payload

	emit8(p, PROTOCOL_ESP);
	emit8(p, 4);
	emit16(p, CHILD_SA_NOT_FOUND);
	emit32(p, p->proposal.spi);

	end_payload(p);			// end NOTIFY payload

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for 96-bit integrity checksum

	end_payload(p);
}

void
send_invalid_syntax(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_invalid_syntax_payload(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_invalid_syntax_payload(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	start_payload(p, TYPE_NOTIFY);

	emit8(p, 0);			// no protocol
	emit8(p, 0);			// no spi
	emit16(p, INVALID_SYNTAX);

	end_payload(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for checksum

	end_payload(p);
}

void
send_info_response(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, INFORMATIONAL);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_info_encrypted(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_info_encrypted(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

					// no payload

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for checksum

	end_payload(p);
}

void
send_create_child_error(struct sa *p, int error)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_notify_payload(p, error);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_notify_payload(struct sa *p, int error)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	start_payload(p, TYPE_NOTIFY);

	emit8(p, 0);			// no protocol
	emit8(p, 0);			// no spi
	emit16(p, error);

	end_payload(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for checksum

	end_payload(p);
}

void
emit_checksum(struct sa *p)
{
	int i;
	unsigned int hash[5];
	Trace

	if (p->initiator)
		prf_hmac_sha1(p->sk_ai, 20, p->buf, p->len - 12, hash);
	else
		prf_hmac_sha1(p->sk_ar, 20, p->buf, p->len - 12, hash);

	for (i = 0; i < 3; i++) {
		p->buf[p->len - 12 + 4 * i + 0] = hash[i] >> 24;
		p->buf[p->len - 12 + 4 * i + 1] = hash[i] >> 16;
		p->buf[p->len - 12 + 4 * i + 2] = hash[i] >> 8;
		p->buf[p->len - 12 + 4 * i + 3] = hash[i];
	}
}

void
send_empty_info_response(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, INFORMATIONAL);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	//emit_empty_payload(p);	// FIXME forgot why this is commented out

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	//emit_checksum(p);		// FIXME forgot why this is commented out

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_empty_payload(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

					// empty

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for checksum

	end_payload(p);
}

void
send_rekey_esp_response(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_rekey_esp_response_payload(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_rekey_esp_response_payload(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	emit_rekey_notify(p);		// payloads
	emit_esp_sa(p);
	emit_nonce(p);
	emit_traffic_selectors_i(p);
	emit_traffic_selectors_r(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for 96-bit integrity checksum

	end_payload(p);
}

void
emit_rekey_notify(struct sa *p)
{
	Trace

	start_payload(p, TYPE_NOTIFY);

	emit8(p, PROTOCOL_ESP);
	emit8(p, 4);			// spi size
	emit16(p, REKEY_SA);

	emit32(p, p->arg1);		// spi of original ESP SA

	end_payload(p);
}

void
send_rekey_ike_response(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_rekey_ike(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_rekey_ike(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	emit_rekey_ike_sa(p);		// emit payloads SA, N1, KE
	emit_nonce(p);
	emit_ke(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for checksum

	end_payload(p);
}

void
emit_rekey_ike_sa(struct sa *p)
{
	int k, n, t;
	Trace

	start_payload(p, TYPE_SA);

	k = p->k;			// need this for proposal length

	emit8(p, 0);			// last
	emit8(p, 0);			// reserved
	emit16(p, 0);			// proposal length (0 for now)

	emit8(p, 1);			// proposal number
	emit8(p, PROTOCOL_IKE);		// protocol id
	emit8(p, 8);			// spi_size
	emit8(p, 4);			// number of transforms

	// spi

	emit64(p, p->arg1);

	// 1st transfrom

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 12);			// length

	emit8(p, TRANS_ENCR);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, ENCR_AES_CBC);	// transform id
	emit16(p, 0x8000 + 14);		// attribute type
	emit16(p, 128);			// attribute value

	// 2nd transform

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_PRF);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, PRF_HMAC_SHA1);	// transform id

	// 3rd transform

	emit8(p, 3);			// more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_INTEG);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, AUTH_HMAC_SHA1_96);	// transform id

	// 4th transform

	emit8(p, 0);			// no more
	emit8(p, 0);			// reserved
	emit16(p, 8);			// length

	emit8(p, TRANS_DH);		// transform type
	emit8(p, 0);			// reserved
	emit16(p, DH_GROUP_2);		// transform id

	// update proposal length

	t = p->k;
	n = t - k;
	p->k = k + 2;
	emit16(p, n);
	p->k = t;

	end_payload(p);
}

void
send_create_esp_response(struct sa *p)
{
	Trace

	p->buf = bigbuf + 4;
	p->k = 0;
	p->k0 = 16;

	emit64(p, p->initiator_spi);
	emit64(p, p->responder_spi);

	emit8(p, 0);			// next payload (0 for now)
	emit8(p, 0x20);			// version 2.0
	emit8(p, CREATE_CHILD_SA);	// exchange type
	if (p->initiator)
		emit8(p, 0x28);		// flags (response and initiator bits)
	else
		emit8(p, 0x20);		// flags (response bit)

	emit32(p, p->msg_id);		// message id

	emit32(p, 0);			// message length (0 for now)

	emit_create_esp_response_payload(p);

	p->len = p->k;			// update message length
	p->k = 24;
	emit32(p, p->len);

	emit_checksum(p);

	send_ike_msg(p, p->buf, p->len);

	if (debug)
		print_response(p);
}

void
emit_create_esp_response_payload(struct sa *p)
{
	int i, t;
	Trace

	start_payload(p, TYPE_SK);

	t = p->k0;			// nested payloads, save k0

	for (i = 0; i < 4; i++)
		emit32(p, random());	// emit IV

	emit_esp_sa(p);			// payloads
	emit_nonce(p);
	emit_traffic_selectors_i(p);
	emit_traffic_selectors_r(p);

	p->k0 = t;			// restore k0

	encrypt_payload(p);

	p->k += 12;			// make room for checksum

	end_payload(p);
}

void
emit_notify_use_transport_mode(struct sa *p)
{
	Trace

	start_payload(p, TYPE_NOTIFY);

	emit8(p, PROTOCOL_ESP);
	emit8(p, 4);			// 4 byte spi
	emit16(p, 16391);		// USE_TRANSPORT_MODE (see RFC 5996, p. 100)

	emit32(p, p->esp.esp_spi_receive);

	end_payload(p);
}

#include "defs.h"

unsigned int
get16(unsigned char *buf)
{
	return (buf[0] << 8) | buf[1];
}

unsigned int
get32(unsigned char *buf)
{
	return (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
}

unsigned long long
get64(unsigned char *buf)
{
	return ((unsigned long long) get32(buf) << 32) | get32(buf + 4);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Initiator's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IKE SA Responder's SPI                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Next Payload | MjVer | MnVer | Exchange Type |     Flags     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          Message ID                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Length                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 4:  IKE Header Format

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Figure 5:  Generic Payload Header
*/

void
parse(struct sa *p, unsigned char *buf, int buflen)
{
	int i, n;
	int next_payload;
	int payload_length;
	int version;
	int msglen;

	unsigned long long spi_i;
	unsigned long long spi_r;

	p->ike_header = buf;

	p->err = 0;
	p->line = 0;

	if (buflen < 28) {
		kaput(p, ERR_BUFFER_LENGTH, __FUNCTION__, __LINE__);
		return;
	}

	spi_i = 0;
	spi_r = 0;

	for (i = 0; i < 8; i++) {
		spi_i = spi_i << 8 | buf[i];
		spi_r = spi_r << 8 | buf[8 + i];
	}

	buf += 16;

	next_payload = *buf++;
	version = *buf++;
	p->exchange_type = *buf++;
	p->flags = *buf++;
	p->receive_msg_id = get32(buf);
	buf += 4;
	msglen = get32(buf);
	buf += 4;

	if (msglen > buflen) {
		kaput(p, ERR_MESSAGE_LENGTH, __FUNCTION__, __LINE__);
		return;
	}

	if (version != 0x20) {
		kaput(p, ERR_IPSEC_VERSION, __FUNCTION__, __LINE__);
		return;
	}

	handle_ike_header(p, spi_i, spi_r, version, p->exchange_type, p->flags, p->msg_id, msglen);

	clear_proposal(p);
	p->rekey_flag = 0;
	p->delete_ike = 0;

	n = msglen - 28;

	while (next_payload) {
		if (n < 4) {
			kaput(p, ERR_PAYLOAD_LENGTH, __FUNCTION__, __LINE__);
			return;
		}
		payload_length = get16(buf + 2);
		if (payload_length < 4 || payload_length > n) {
			kaput(p, ERR_PAYLOAD_LENGTH, __FUNCTION__, __LINE__);
			return;
		}
		parse_next_payload(next_payload, buf, p);
		if (next_payload == TYPE_SK)
			break; // by definition SK must be last payload
		next_payload = *buf;
		buf += payload_length;
		n -= payload_length;
	}
}

void
clear_proposal(struct sa *p)
{
	p->proposal.accepted = 0;
	p->proposal.protocol = -1;
	p->proposal.encr = -1;
	p->proposal.attr = -1;
	p->proposal.prf = -1;
	p->proposal.integ = -1;
	p->proposal.dh = -1;
	p->proposal.esn = -1;
	p->proposal.spi_size = -1;
	p->proposal.spi = 0;
}

/*
      Next Payload Type                Notation  Value
      --------------------------------------------------
      No Next Payload                             0
      Security Association             SA         33
      Key Exchange                     KE         34
      Identification - Initiator       IDi        35
      Identification - Responder       IDr        36
      Certificate                      CERT       37
      Certificate Request              CERTREQ    38
      Authentication                   AUTH       39
      Nonce                            Ni, Nr     40
      Notify                           N          41
      Delete                           D          42
      Vendor ID                        V          43
      Traffic Selector - Initiator     TSi        44
      Traffic Selector - Responder     TSr        45
      Encrypted and Authenticated      SK         46
      Configuration                    CP         47
      Extensible Authentication        EAP        48
*/

void
parse_next_payload(int next_payload, unsigned char *buf, struct sa *p)
{
	switch (next_payload) {
	case 33:
		parse_security_association(buf, p);
		break;
	case 34:
		parse_key_exchange(buf, p);
		break;
	case 35:
		parse_identification(0, buf, p);
		break;
	case 36:
		parse_identification(1, buf, p);
		break;
	case 37:
		parse_certificate(buf, p);
		break;
	case 38:
		parse_certificate_request(buf, p);
		break;
	case 39:
		parse_authentication(buf, p);
		break;
	case 40:
		parse_nonce(buf, p);
		break;
	case 41:
		parse_notify(buf, p);
		break;
	case 42:
		parse_delete(buf, p);
		break;
	case 43:
		parse_vendor_id(buf, p);
		break;
	case 44:
		parse_traffic_selector(1, buf, p);
		break;
	case 45:
		parse_traffic_selector(0, buf, p);
		break;
	case 46:
		parse_encrypted_and_authenticated(buf, p);
		break;
	case 47:
		parse_configuration(buf, p);
		break;
	case 48:
		parse_extensible_authentication(buf, p);
		break;
	default:
		parse_error(__LINE__, "unknown payload type");
		break;
	}
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                          <Proposals>                          ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 6:  Security Association Payload

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | 0 (last) or 2 |   RESERVED    |         Proposal Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Proposal Num  |  Protocol ID  |    SPI Size   |Num  Transforms|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                        SPI (variable)                         ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                        <Transforms>                           ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 7:  Proposal Substructure

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | 0 (last) or 3 |   RESERVED    |        Transform Length       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Transform Type |   RESERVED    |          Transform ID         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                      Transform Attributes                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 8:  Transform Substructure

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |A|       Attribute Type        |    AF=0  Attribute Length     |
   |F|                             |    AF=1  Attribute Value      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   AF=0  Attribute Value                       |
   |                   AF=1  Not Transmitted                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                   Figure 9:  Data Attributes
*/

void
parse_security_association(unsigned char *buf, struct sa *p)
{
	int k, n, last;
	int payload_length;
	int proposal_length;
	int proposal_number;

	payload_length = get16(buf + 2);
	buf += 4;

	k = 1;
	n = payload_length - 4;
	do {
		if (n < 8) {
			parse_error(__LINE__, "SA length");
			return;
		}
		proposal_length = get16(buf + 2);
		if (proposal_length < 8 || proposal_length > n) {
			parse_error(__LINE__, "SA length");
			return;
		}
		last = buf[0];

		proposal_number = buf[4];
		if (proposal_number != k++) {
			parse_error(__LINE__, "SA proposal number");
			return;
		}
		parse_proposal(buf, p);
		buf += proposal_length;
		n -= proposal_length;
	} while (last == 2);
}

void
parse_proposal(unsigned char *buf, struct sa *p)
{
	int i, n;
	int proposal_length;
	int proposal_number;
	int protocol_id;
	int spi_size;
	int num_transforms;
	int transform_length;
	unsigned long long spi;

	proposal_length = get16(buf + 2);
	proposal_number = buf[4];
	protocol_id = buf[5];
	spi_size = buf[6];
	num_transforms = buf[7];

	if (spi_size > proposal_length - 8) {
		parse_error(__LINE__, "SA proposal length");
		return;
	}

	spi = 0;

	for (i = 0; i < spi_size; i++)
		spi = spi << 8 | buf[8 + i];

	handle_proposal(p, proposal_number, protocol_id, spi_size, spi, num_transforms);

	buf += 8 + spi_size; // 8 bytes header followed by spi
	n = proposal_length - spi_size - 8;
	for (i = 0; i < num_transforms; i++) {
		if (n < 8) {
			parse_error(__LINE__, "SA proposal");
			return;
		}
		transform_length = get16(buf + 2);
		if (transform_length < 8 || transform_length > n) {
			parse_error(__LINE__, "SA proposal length");
			return;
		}
		parse_transform(buf, p);
		buf += transform_length;
		n -= transform_length;
	}

	handle_proposal_end(p);
}

void
parse_transform(unsigned char *buf, struct sa *p)
{
	int n;
	int transform_length;
	int transform_type;
	int transform_id;
	int attribute_type;
	int attribute_length;

	transform_length = get16(buf + 2);
	transform_type = buf[4];
	transform_id = get16(buf + 6);

	handle_transform(p, transform_type, transform_id);

	buf += 8;
	n = transform_length - 8;
	while (n) {
		if (n < 4) {
			parse_error(__LINE__, "SA transform length");
			return;
		}
		attribute_type = get16(buf);
		if (attribute_type & 0x8000) {
			attribute_length = 4;
			handle_transform_attribute(p, transform_type, transform_id, attribute_type, 2, buf + 2);
		} else {
			attribute_length = get16(buf + 2);
			if (attribute_length < 4 || attribute_length > n) {
				parse_error(__LINE__, "SA attribute length");
				return;
			}
			handle_transform_attribute(p, transform_type, transform_id, attribute_type, attribute_length - 4, buf + 4);
		}
		buf += attribute_length;
		n -= attribute_length;
	}
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Diffie-Hellman Group Num    |           RESERVED            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       Key Exchange Data                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 10:  Key Exchange Payload Format
*/

void
parse_key_exchange(unsigned char *buf, struct sa *p)
{
	int payload_length;
	int diffie_hellman_group_number;

	payload_length = get16(buf + 2);

	if (payload_length < 8) {
		parse_error(__LINE__, "KE length");
		return;
	}

	diffie_hellman_group_number = get16(buf + 4);

	handle_key_exchange(p, diffie_hellman_group_number, payload_length - 8, buf + 8);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ID Type     |                 RESERVED                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                   Identification Data                         ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 11:  Identification Payload Format
*/

void
parse_identification(int initiator, unsigned char *buf, struct sa *p)
{
	int payload_length;
	int id_type;

	if (p->initiator != initiator) {
		parse_error(__LINE__, "id payload mismatch");
		return;
	}

	payload_length = get16(buf + 2);

	if (payload_length < 8) {
		parse_error(__LINE__, "ID length");
		return;
	}

	id_type = buf[4];

	handle_identification(p, id_type, payload_length - 8, buf + 8);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Cert Encoding |                                               |
   +-+-+-+-+-+-+-+-+                                               |
   ~                       Certificate Data                        ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

             Figure 12:  Certificate Payload Format
*/

void
parse_certificate(unsigned char *buf, struct sa *p)
{
	int payload_length;
	int cert_encoding;

	payload_length = get16(buf + 2);

	if (payload_length < 5) {
		parse_error(__LINE__, "CERT payload length");
		return;
	}

	cert_encoding = buf[4];

	handle_certificate(p, cert_encoding, payload_length - 5, buf + 5);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Cert Encoding |                                               |
   +-+-+-+-+-+-+-+-+                                               |
   ~                    Certification Authority                    ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

         Figure 13:  Certificate Request Payload Format
*/

void
parse_certificate_request(unsigned char *buf, struct sa *p)
{
	int payload_length;
	int cert_encoding;

	payload_length = get16(buf + 2);

	if (payload_length < 5) {
		parse_error(__LINE__, "CERTREQ payload length");
		return;
	}

	cert_encoding = buf[4];

	handle_certificate_request(p, cert_encoding, payload_length - 5, buf + 5);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Auth Method   |                RESERVED                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                      Authentication Data                      ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

              Figure 14:  Authentication Payload Format
*/

void
parse_authentication(unsigned char *buf, struct sa *p)
{
	int payload_length;
	int auth_method;

	payload_length = get16(buf + 2);

	if (payload_length < 8) {
		parse_error(__LINE__, "AUTH payload length");
		return;
	}

	auth_method = buf[4];

	handle_authentication(p, auth_method, payload_length - 8, buf + 8);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                            Nonce Data                         ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                Figure 15:  Nonce Payload Format
*/

void
parse_nonce(unsigned char *buf, struct sa *p)
{
	int payload_length;

	payload_length = get16(buf + 2);

	if (payload_length < 4) {
		parse_error(__LINE__, "Nonce payload length");
		return;
	}

	handle_nonce(p, payload_length - 4, buf + 4);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Protocol ID  |   SPI Size    |      Notify Message Type      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                Security Parameter Index (SPI)                 ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       Notification Data                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 16:  Notify Payload Format
*/

void
parse_notify(unsigned char *buf, struct sa *p)
{
	int i;
	int payload_length;
	int protocol_id;
	int spi_size;
	int notify_type;
	int notify_length;
	unsigned long long spi;

	payload_length = get16(buf + 2);

	if (payload_length < 8) {
		parse_error(__LINE__, "Notify payload length");
		return;
	}

	protocol_id = buf[4];
	spi_size = buf[5];
	notify_type = get16(buf + 6);

	if (spi_size > payload_length - 8) {
		parse_error(__LINE__, "Notify payload length");
		return;
	}

	notify_length = payload_length - spi_size - 8;

	spi = 0;

	for (i = 0; i < spi_size; i++)
		spi = spi << 8 | buf[8 + i];

	handle_notify(p, protocol_id, spi_size, notify_type, spi);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Protocol ID   |   SPI Size    |          Num of SPIs          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~               Security Parameter Index(es) (SPI)              ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 17:  Delete Payload Format
*/

void
parse_delete(unsigned char *buf, struct sa *p)
{
	int i, n;
	int payload_length;
	int protocol;
	int spi_size;
	int num_spi;

	payload_length = get16(buf + 2);

	if (payload_length < 8) {
		parse_error(__LINE__, "Delete payload length");
		return;
	}

	protocol = buf[4];
	spi_size = buf[5];
	num_spi = get16(buf + 6);

	n = spi_size * num_spi;

	if (n > payload_length - 8) {
		parse_error(__LINE__, "Delete payload length");
		return;
	}

	if (protocol == 1 && spi_size == 0) {
		handle_delete(p, protocol, spi_size, NULL);
		return;
	}

	if ((protocol == 2 || protocol == 3) && spi_size == 4) {
		for (i = 0; i < num_spi; i++)
			handle_delete(p, protocol, spi_size, buf + 8 + i * spi_size);
		return;
	}

	parse_error(__LINE__, "Delete payload syntax: protocol id and spi size");
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                        Vendor ID (VID)                        ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

              Figure 18:  Vendor ID Payload Format
*/

void
parse_vendor_id(unsigned char *buf, struct sa *p)
{
	int payload_length;

	payload_length = get16(buf + 2);

	if (payload_length < 4) {
		parse_error(__LINE__, "Vendor ID payload length");
		return;
	}

	handle_vendor_id(p, payload_length - 4, buf + 4);
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Number of TSs |                 RESERVED                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       <Traffic Selectors>                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 19:  Traffic Selectors Payload Format

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   TS Type     |IP Protocol ID*|       Selector Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Start Port*         |           End Port*           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Starting Address*                     ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                         Ending Address*                       ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

               Figure 20: Traffic Selector
*/

void
parse_traffic_selector(int dir, unsigned char *buf, struct sa *p)
{
	int i, n;
	int payload_length;
	int num_ts;
	int ts_type;
	int selector_length;

	payload_length = get16(buf + 2);

	if (payload_length < 8) {
		parse_error(__LINE__, "TS payload length");
		return;
	}

	num_ts = buf[4];

	buf += 8;
	n = payload_length - 8;
	for (i = 0; i < num_ts; i++) {
		if (n < 4) {
			parse_error(__LINE__, "TS payload length");
			return;
		}
		selector_length = get16(buf + 2);
		if (selector_length < 4 || selector_length > n) {
			parse_error(__LINE__, "TS selector length");
			return;
		}
		ts_type = buf[0];
		switch (ts_type) {
		case TS_IPV4_ADDR_RANGE:
			if (selector_length < 16) {
				parse_error(__LINE__, "TS selector length");
				return;
			}
			handle_ipv4_traffic_selector(p, dir, i, buf);
			break;
		case TS_IPV6_ADDR_RANGE:
			if (selector_length < 40) {
				parse_error(__LINE__, "TS selector length");
				return;
			}
			handle_ipv6_traffic_selector(p, dir, i, buf);
			break;
		default:
			parse_error(__LINE__, "TS type");
			break;
		}
		buf += selector_length;
		n -= selector_length;
	}
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Initialization Vector                     |
   |         (length is block size for encryption algorithm)       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Encrypted IKE Payloads                     ~
   +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |             Padding (0-255 octets)            |
   +-+-+-+-+-+-+-+-+                               +-+-+-+-+-+-+-+-+
   |                                               |  Pad Length   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   ~                    Integrity Checksum Data                    ~
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 21:  Encrypted Payload Format
*/

void
parse_encrypted_and_authenticated(unsigned char *buf, struct sa *p)
{
	int i, n;
	int next_payload;
	int payload_length;
	unsigned int hash[5];

	next_payload = *buf;
	payload_length = get16(buf + 2);

	if (payload_length < 4 + 16 + 16 + 12) {
		parse_error(__LINE__, "payload length");
		return;
	}

	// verify 96-bit integrity checksum

	n = buf - p->ike_header + payload_length - 12;

	if (p->initiator)
		prf_hmac_sha1(p->sk_ar, 20, p->ike_header, n, hash);
	else
		prf_hmac_sha1(p->sk_ai, 20, p->ike_header, n, hash);

	for (i = 0; i < 3; i++) {
		hash[i] ^= buf[payload_length - 12 + 4 * i + 0] << 24;
		hash[i] ^= buf[payload_length - 12 + 4 * i + 1] << 16;
		hash[i] ^= buf[payload_length - 12 + 4 * i + 2] << 8;
		hash[i] ^= buf[payload_length - 12 + 4 * i + 3];
	}

	if (hash[0] || hash[1] || hash[2]) {
		kaput(p, ERR_SK_CHECKSUM, __FUNCTION__, __LINE__);
		return;
	}

	buf += 4 + 16;
	n = payload_length - 4 - 16 - 12;
	decrypt_payload(p, buf, n);

	while (next_payload) {
		if (n < 4) {
			parse_error(__LINE__, "payload length");
			return;
		}
		payload_length = get16(buf + 2);
		if (payload_length < 4 || payload_length > n) {
			parse_error(__LINE__, "payload length");
			return;
		}
		parse_next_payload(next_payload, buf, p);
		next_payload = *buf;
		buf += payload_length;
		n -= payload_length;
	}
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C| RESERVED    |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   CFG Type    |                    RESERVED                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                   Configuration Attributes                    ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 22:  Configuration Payload Format


                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |R|         Attribute Type      |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                             Value                             ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Figure 23:  Configuration Attribute Format
*/

void
parse_configuration(unsigned char *buf, struct sa *p)
{
	int n;
	int payload_length;
	int configuration_type;
	int attribute_type;
	int attribute_length;

	payload_length = get16(buf + 2);
	if (payload_length < 8) {
		parse_error(__LINE__, "CP payload length");
		return;
	}
	configuration_type = buf[4];
	buf += 8;

	n = payload_length - 8;
	while (n) {
		if (n < 4) {
			parse_error(__LINE__, "CP payload length");
			return;
		}
		attribute_type = get16(buf);
		attribute_length = get16(buf + 2);
		if (attribute_length > n) {
			parse_error(__LINE__, "CP payload length");
			return;
		}
		handle_configuration_attribute(p, configuration_type, attribute_type, attribute_length - 4, buf + 4);
		buf += attribute_length + 4;
		n -= attribute_length + 4;
	}
}

/*
                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Next Payload  |C|  RESERVED   |         Payload Length        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   ~                       EAP Message                             ~
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                   Figure 24:  EAP Payload Format

                        1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      | Identifier    |           Length              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      | Type_Data...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

                   Figure 25:  EAP Message Format
*/

void
parse_extensible_authentication(unsigned char *buf, struct sa *p)
{
	int n;
	int payload_length;
	int code;
	int length;
	int type;

	payload_length = get16(buf + 2);
	if (payload_length < 4) {
		parse_error(__LINE__, "EAP payload length");
		return;
	}
	buf += 4;

	n = payload_length - 4;
	while (n) {
		if (n < 5) {
			parse_error(__LINE__, "EAP payload length");
			return;
		}
		length = get16(buf + 2);
		if (length < 5 || length > n) {
			parse_error(__LINE__, "EAP payload length");
			return;
		}
		code = buf[0];
		type = buf[4];
		handle_eap_message(p, code, type, length - 5, buf + 5);
		buf += length;
		n -= length;
	}
}

void
parse_error(int line, char *err)
{
	printf("%s error on line %d\n", err, line);
}

void
kaput(struct sa *p, int err, const char *func, int line)
{
	printf("Kaput in %s, line number %d\n", func, line);
	p->err = err;
	p->line = line;
}

void
handle_ike_header(struct sa *p, unsigned long long initiator_spi, unsigned long long responder_spi, int version, int exchange_type, int flags, int message_id, int message_length)
{
	PRINT_IKE_HEADER

	if (exchange_type != IKE_INIT)
		return;

	if (p->initiator)
		p->responder_spi = responder_spi;
	else
		p->initiator_spi = initiator_spi;
}

void
handle_configuration_attribute(struct sa *p, int configuration_type, int attribute_type, int len, unsigned char *buf)
{
}

void
handle_eap_message(struct sa *p, int code, int type, int len, unsigned char *buf)
{
}

void
handle_proposal(struct sa *p, int number, int protocol, int spi_size, unsigned long long spi, int num_transforms)
{
	PRINT_PROPOSAL

	if (p->proposal.accepted)
		return; // have accepted a previous proposal

	p->proposal.protocol = protocol;
	p->proposal.spi_size = spi_size;
	p->proposal.spi = spi;
}

void
handle_proposal_end(struct sa *p)
{
	if (p->proposal.accepted)
		return; // have accepted a previous proposal

	if (p->proposal.protocol == PROTOCOL_ESP &&
		p->proposal.encr == ENCR_AES_CBC &&
		p->proposal.attr == 128 &&
		p->proposal.prf == -1 &&
		p->proposal.integ == AUTH_HMAC_SHA1_96 &&
		p->proposal.dh == -1 &&
		p->proposal.esn == 0 &&
		p->proposal.spi_size == 4 &&
		p->proposal.spi != 0) {

		p->proposal.accepted = 1;
		return;
	}

	if (p->proposal.protocol == PROTOCOL_IKE &&
		p->proposal.encr == ENCR_AES_CBC &&
		p->proposal.attr == 128 &&
		p->proposal.prf == PRF_HMAC_SHA1 &&
		p->proposal.integ == AUTH_HMAC_SHA1_96 &&
		p->proposal.dh == DH_GROUP_2) {

		p->proposal.accepted = 1;
		return;
	}

	clear_proposal(p);
}

void
handle_transform(struct sa *p, int transform_type, int transform_id)
{
	PRINT_TRANSFORM

	if (p->proposal.accepted)
		return; // have accepted a previous proposal

	switch (transform_type) {
	case TRANS_ENCR:
		if (p->proposal.encr != -1)
			break; // already chosen
		if (transform_id == ENCR_AES_CBC)
			p->proposal.encr = transform_id;
		break;
	case TRANS_PRF:
		if (p->proposal.prf != -1)
			break; // already chosen
		if (transform_id == PRF_HMAC_SHA1)
			p->proposal.prf = transform_id;
		break;
	case TRANS_INTEG:
		if (p->proposal.integ != -1)
			break; // already chosen
		if (transform_id == AUTH_HMAC_SHA1_96)
			p->proposal.integ = transform_id;
		break;
	case TRANS_DH:
		if (p->proposal.dh != -1)
			break; // already chosen
		if (transform_id == DH_GROUP_2)
			p->proposal.dh = transform_id;
		break;
	case TRANS_ESN:
		if (p->proposal.esn != -1)
			break; // already chosen
		if (transform_id == 0)
			p->proposal.esn = transform_id;
		break;
	}
}

void
handle_transform_attribute(struct sa *p, int transform_type, int transform_id, int attribute_type, int length, unsigned char *buf)
{
	PRINT_TRANSFORM_ATTRIBUTE

	int i, val;

	if (p->proposal.accepted)
		return; // have accepted a previous proposal

	if (transform_type != TRANS_ENCR)
		return;

	val = 0;

	for (i = 0; i < length; i++) {
		val = val << 8 |  buf[i];
		if (val > 0xffff)
			return;
	}

	p->proposal.attr = val;
}

void
handle_key_exchange(struct sa *p, int dh_group_number, int len, unsigned char *buf)
{
	PRINT_KEY_EXCHANGE_PAYLOAD

	// FIXME check length

	memcpy(p->public_key_2, buf, len);
}

void
handle_identification(struct sa *p, int type, int len, unsigned char *buf)
{
	PRINT_IDENTIFICATION_PAYLOAD

	// FIXME check length

	if (p->initiator) {
		p->id_type_r = type;
		p->id_r_length = len;
		memcpy(p->id_r, buf, len);
	} else {
		p->id_type_i = type;
		p->id_i_length = len;
		memcpy(p->id_i, buf, len);
	}
}

void
handle_certificate(struct sa *p, int cert_encoding, int cert_length, unsigned char *cert)
{
}

void
handle_certificate_request(struct sa *p, int cert_encoding, int auth_length, unsigned char *auth)
{
}

void
handle_authentication(struct sa *p, int method, int len, unsigned char *buf)
{
	PRINT_AUTH_PAYLOAD

	// FIXME check length

	//p->auth_method = auth_method;
	p->auth_received_length = len;
	memcpy(p->auth_received, buf, len);
}

void
handle_nonce(struct sa *p, int len, unsigned char *buf)
{
	PRINT_NONCE_PAYLOAD

	// see RFC 5996, p. 96

	if (len < 16 || len > 256) {
		kaput(p, ERR_NONCE_LENGTH, __FUNCTION__, __LINE__);
		return;
	}

	memcpy(p->nonce_2, buf, len);
	p->nonce_2_length = len;
}

void
handle_notify(struct sa *p, int protocol, int spi_size, int notify_type, unsigned long long spi)
{
	PRINT_NOTIFY

	switch (notify_type) {
	case REKEY_SA:
		p->rekey_flag = 1;
		p->rekey_protocol = protocol;
		p->rekey_spi_size = spi_size;
		p->rekey_spi = spi;
		break;
	}
}

void
handle_delete(struct sa *p, int protocol, int spi_size, unsigned char *spi)
{
	PRINT_DELETE

	if (protocol == PROTOCOL_IKE) {
		p->delete_ike = 1;
		return;
	}
}

void
handle_vendor_id(struct sa *p, int id_length, unsigned char *id)
{
}

void
handle_ipv4_traffic_selector(struct sa *p, int dir, int selector_number, unsigned char *buf)
{
	PRINT_IPV4_TRAFFIC_SELECTOR

	struct selector *s;

	if (selector_number >= NUM_TS)
		return; // FIXME do something

	// TSi and TSr are session relative, switch to local perspective

	switch (p->exchange_type) {
	case IKE_AUTH:
		if (p->initiator == dir)
			s = p->esp.selector_src;	// i am the initiator and i've received TSi or
							// i am the responder and i've received TSr
		else
			s = p->esp.selector_dst;
		break;
	case CREATE_CHILD_SA:
		if (p->esp.esp_initiator == dir)
			s = p->esp.selector_src;	// i am the initiator and i've received TSi or
							// i am the responder and i've received TSr
		else
			s = p->esp.selector_dst;
		break;
	default:
		return; // FIXME syntax error?
	}

	s += selector_number;

	memcpy(s->data, buf, 16);
}

void
handle_ipv6_traffic_selector(struct sa *p, int dir, int selector_number, unsigned char *buf)
{
	PRINT_IPV6_TRAFFIC_SELECTOR

	struct selector *s;

	if (selector_number >= NUM_TS)
		return; // FIXME do something

	// TSi and TSr are session relative, switch to local perspective

	switch (p->exchange_type) {
	case IKE_AUTH:
		if (p->initiator == dir)
			s = p->esp.selector_src;
		else
			s = p->esp.selector_dst;
		break;
	case CREATE_CHILD_SA:
		if (p->esp.esp_initiator == dir)
			s = p->esp.selector_src;
		else
			s = p->esp.selector_dst;
		break;
	default:
		return; // FIXME syntax error?
	}

	s += selector_number;

	memcpy(s->data, buf, 40);
}

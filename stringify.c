#include "defs.h"

char *
str_transform_type(int type)
{
	switch (type) {
	case TRANS_ENCR:
		return "ENCR";
	case TRANS_PRF:
		return "PRF";
	case TRANS_INTEG:
		return "INTEG";
	case TRANS_DH:
		return "DH";
	case TRANS_ESN:
		return "ESN";
	}
	return "unknown";
}

char *
str_transform_id(int type, int id)
{
	switch (type) {
	case TRANS_ENCR:
		return str_transform_encr(id);
	case TRANS_PRF:
		return str_transform_prf(id);
	case TRANS_INTEG:
		return str_transform_integ(id);
	case TRANS_DH:
		return str_transform_dh(id);
	case TRANS_ESN:
		return str_transform_esn(id);
	}
	return "unknown";
}

char *
str_transform_encr(int id)
{
	switch (id) {
	case 1:
		return "ENCR_DES_IV64";
	case 2:
		return "ENCR_DES";
	case 3:
		return "ENCR_3DES";
	case 4:
		return "ENCR_RC5";
	case 5:
		return "ENCR_IDEA";
	case 6:
		return "ENCR_CAST";
	case 7:
		return "ENCR_BLOWFISH";
	case 8:
		return "ENCR_3IDEA";
	case 9:
		return "ENCR_DES_IV32";
	case 11:
		return "ENCR_NULL";
	case 12:
		return "ENCR_AES_CBC";
	case 13:
		return "ENCR_AES_CTR";
	}
	return "unknown";
}

char *
str_transform_prf(int id)
{
	switch (id) {
	case 1:
		return "PRF_HMAC_MD5";
	case 2:
		return "PRF_HMAC_SHA1";
	case 3:
		return "PRF_HMAC_TIGER";
	}
	return "unknown";
}

char *
str_transform_integ(int id)
{
	switch (id) {
	case 0:
		return "AUTH_NONE";
	case 1:
		return "AUTH_HMAC_MD5_96";
	case 2:
		return "AUTH_HMAC_SHA1_96";
	case 3:
		return "AUTH_DES_MAC";
	case 4:
		return "AUTH_KPDK_MD5";
	case 5:
		return "AUTH_AES_XCBC_96";
	}
	return "unknown";
}

char *
str_transform_dh(int id)
{
	switch (id) {
	case 0:
		return "NONE";
	case 1:
		return "768-bit MODP";
	case 2:
		return "1024-bit MODP";
	case 5:
		return "1536-bit MODP";
	case 14:
		return "2048-bit MODP";
	case 15:
		return "3072-bit MODP";
	case 16:
		return "4096-bit MODP";
	case 17:
		return "6144-bit MODP";
	case 18:
		return "8192-bit MODP";
	}
	return "unknown";
}

char *
str_transform_esn(int id)
{
	switch (id) {
	case 0:
		return "No Extended Sequence Numbers";
	case 1:
		return "Extended Sequence Numbers";
	}
	return "unknown";
}

char *
str_exchange_type(int type)
{
	switch (type) {
	case 34:
		return "IKE_SA_INIT";
	case 35:
		return "IKE_AUTH";
	case 36:
		return "CREATE_CHILD_SA";
	case 37:
		return "INFORMATIONAL";
	}
	return "unknown";
}

char *
str_notify_type(int type)
{
	switch (type) {
	case 1:
		return "UNSUPPORTED_CRITICAL_PAYLOAD";
	case 4:
		return "INVALID_IKE_SPI";
	case 5:
		return "INVALID_MAJOR_VERSION";
	case 7:
		return "INVALID_SYNTAX";
	case 9:
		return "INVALID_MESSAGE_ID";
	case 11:
		return "INVALID_SPI";
	case 14:
		return "NO_PROPOSAL_CHOSEN";
	case 17:
		return "INVALID_KE_PAYLOAD";
	case 24:
		return "AUTHENTICATION_FAILED";
	case 34:
		return "SINGLE_PAIR_REQUIRED";
	case 35:
		return "NO_ADDITIONAL_SAS";
	case 36:
		return "INTERNAL_ADDRESS_FAILURE";
	case 37:
		return "FAILED_CP_REQUIRED";
	case 38:
		return "TS_UNACCEPTABLE";
	case 39:
		return "INVALID_SELECTORS";
	case 43:
		return "TEMPORARY_FAILURE";
	case 44:
		return "CHILD_SA_NOT_FOUND";
	case 16384:
		return "INITIAL_CONTACT";
	case 16385:
		return "SET_WINDOW_SIZE";
	case 16386:
		return "ADDITIONAL_TS_POSSIBLE";
	case 16387:
		return "IPCOMP_SUPPORTED";
	case 16388:
		return "NAT_DETECTION_SOURCE_IP";
	case 16389:
		return "NAT_DETECTION_DESTINATION_IP";
	case 16390:
		return "COOKIE";
	case 16391:
		return "USE_TRANSPORT_MODE";
	case 16392:
		return "HTTP_CERT_LOOKUP_SUPPORTED";
	case 16393:
		return "REKEY_SA";
	case 16394:
		return "ESP_TFC_PADDING_NOT_SUPPORTED";
	case 16395:
		return "NON_FIRST_FRAGMENTS_ALSO";
	}
	return "unknown";
}

char *
str_protocol_id(int id)
{
	switch (id) {
	case 0:
		return "no SPI";
	case PROTOCOL_IKE:
		return "PROTOCOL_IKE";
	case PROTOCOL_AH:
		return "PROTOCOL_AH";
	case PROTOCOL_ESP:
		return "PROTOCOL_ESP";
	}
	return "unknown";
}

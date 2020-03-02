#define PRINT_IKE_HEADER if (debug) {\
printf("\nIKE Header\n");\
printf("initiator spi 0x%016llx\n", initiator_spi);\
printf("responder spi 0x%016llx\n", responder_spi);\
printf("version 0x%02x\n", version);\
printf("exchange type %d (%s)\n", exchange_type, str_exchange_type(exchange_type));\
printf("flags 0x%02x\n", flags);\
printf("message id %d\n", message_id);\
printf("message length %d bytes\n", message_length);}

#define PRINT_PROPOSAL if (debug) {\
printf("\nSecurity Association Payload\n");\
printf("proposal number %d\n", number);\
printf("protocol %d (%s)\n", protocol, str_protocol_id(protocol));\
printf("spi size %d\n", spi_size);\
printf("spi 0x%08llx\n", spi);}

#define PRINT_TRANSFORM if (debug) {\
printf("\nTransform\n");\
printf("type %d (%s)\n", transform_type, str_transform_type(transform_type));\
printf("id %d (%s)\n", transform_id, str_transform_id(transform_type, transform_id));}

#define PRINT_TRANSFORM_ATTRIBUTE if (debug) {\
int i;\
printf("\nTransform Attribute\n");\
printf("type 0x%04x (%s)\n", attribute_type, (attribute_type & 0x7fff) == 14 ? "key length" : "unknown");\
printf("length %d bytes\n", length);\
printf("value 0x");\
for (i = 0; i < length; i++) printf("%02x", buf[i]);\
printf("\n");}

#define PRINT_NOTIFY if (debug) {\
printf("\nNotify Payload\n");\
printf("protocol %d (%s)\n", protocol, str_protocol_id(protocol));\
printf("notify type %d (%s)\n", notify_type, str_notify_type(notify_type));\
printf("spi size %d bytes\n", spi_size);\
printf("spi 0x%08x\n", spi);}

#define PRINT_IPV4_TRAFFIC_SELECTOR if (debug) {\
printf("\nIPv4 Traffic Selector ");\
if (dir) printf("(I)\n"); else printf("(R)\n");\
printf("start port %d\n", buf[4] << 8 | buf[5]);\
printf("end port %d\n", buf[6] << 8 | buf[7]);\
printf("start addr 0x%08x\n", buf[8] << 24 | buf[9] << 16 | buf[10] << 8 | buf[11]);\
printf("end addr 0x%08x\n", buf[12] << 24 | buf[13] << 16 | buf[14] << 8 | buf[15]);}

#define PRINT_IPV6_TRAFFIC_SELECTOR if (debug) {\
int i;\
printf("\nIPv6 Traffic Selector (%s)\n", dir ? "Initiator" : "Responder");\
printf("start port %d\n", buf[4] << 8 | buf[5]);\
printf("end port %d\n", buf[6] << 8 | buf[7]);\
printf("start addr");\
for (i = 0; i < 8; i++) printf(" %04x", buf[2 * i + 8] << 8 | buf[2 * i + 9]);\
printf("\nend addr");\
for (i = 0; i < 8; i++) printf(" %04x", buf[2 * i + 24] << 8 | buf[2 * i + 25]);\
printf("\n");}

#define PRINT_AUTH_PAYLOAD if (debug) {\
int i;\
printf("\nAuthentication Payload\n");\
printf("method %d\n", method);\
printf("length %d bytes\n", len);\
printf("value ");\
for (i = 0; i < len; i++) printf("%02x", buf[i]);\
printf("\n");}

#define PRINT_KEY_EXCHANGE_PAYLOAD if (debug) {\
int i;\
printf("\nKey Exchange Payload\n");\
printf("DH group number %d\n", dh_group_number);\
printf("length %d bytes (%d bits)\n", len, 8 * len);\
printf("value ");\
for (i = 0; i < len; i++) printf("%02x", buf[i]);\
printf("\n");}

#define PRINT_IDENTIFICATION_PAYLOAD if (debug) {\
int i;\
printf("\nIdentification Payload\n");\
printf("type %d\n", type);\
printf("length %d bytes\n", len);\
printf("value ");\
for (i = 0; i < len; i++) printf("%02x", buf[i]);\
printf("\n");}

#define PRINT_NONCE_PAYLOAD if (debug) {\
int i;\
printf("\nNonce Payload\n");\
printf("length %d bytes (%d bits)\n", len, 8 * len);\
printf("value ");\
for (i = 0; i < len; i++) printf("%02x", buf[i]);\
printf("\n");}

#define PRINT_DELETE if (debug) {\
int i;\
printf("\nDelete Payload\n");\
printf("protocol %d (%s)\n", protocol, str_protocol_id(protocol));\
printf("spi size %d bytes\n", spi_size);\
printf("spi 0x");\
for (i = 0; i < spi_size; i++) printf("%02x", spi[i]);\
printf("\n");}


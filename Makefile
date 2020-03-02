
RTE_SDK=$(HOME)/dpdk
RTE_TARGET=x86_64-native-linuxapp-gcc
include $(RTE_SDK)/mk/rte.vars.mk

# binary name
APP = main

# all source are stored in SRCS-y
SRCS-y := main.c arp.c aes.c dh.c bignum.c ike_part1.c ike_part2.c ike_part3.c prf.c sha.c keys.c print.c auth.c stringify.c esp.c send.c

CFLAGS += -O0

include $(RTE_SDK)/mk/rte.extapp.mk

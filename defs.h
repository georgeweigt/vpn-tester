#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <net/if_arp.h>
#include <netinet/ip6.h>
#include <poll.h>
#include <time.h>
#include <netpacket/packet.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_ring.h>
#include <rte_debug.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_memcpy.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_lpm.h>
#include <rte_fbk_hash.h>
#include <rte_timer.h>
#include <rte_errno.h>
#include <rte_random.h>
#include <rte_cycles.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include "ipsec.h"
#include "debug.h"
#include "prototypes.h"

#define LAN_PORT_ID 0 // swap these to match physical nic connections
#define WAN_PORT_ID 1

#define Trace //printf("%s\n", __func__);

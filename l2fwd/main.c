/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

static volatile bool force_quit;

/* MAC updating enabled by default */
static int mac_updating = 1;

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST 32  // 限定突发数据包的数量。
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define MEMPOOL_CACHE_SIZE 256

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;  // Rx Desc 的数量
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;  // Tx Desc 的数量

/* ethernet addresses of ports */
static struct ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

/* 是一个二进制掩码，用于标记哪些 Ports 是启用的，哪些是禁用的。*/
static uint32_t l2fwd_enabled_port_mask = 0;

/* 二层转发目标端口的列表，最多 32 个。 */
static uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

static unsigned int l2fwd_rx_queue_per_lcore = 1;  // 限定每个 lcore 拥有的 Rx queue 的数量。

#define MAX_RX_QUEUE_PER_LCORE 16  // 每个 lcore 最大处理 16 个 Rx queue。
#define MAX_TX_QUEUE_PER_PORT 16   // 每个 Port 最大处理 16 个 Tx queue。
struct lcore_queue_conf {
	unsigned n_rx_port;                             // Rx port 的数量
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];  // Rx port 的数组
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];  // 全局变量，各个 lcore 对应的 Rx queue 配置信息。

static struct rte_eth_dev_tx_buffer *tx_buffer[RTE_MAX_ETHPORTS];  // 每个 Ethernet device 对应的 Tx buffer，存储了多个 rte_mbuf。

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CRC_STRIP,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_mempool * l2fwd_pktmbuf_pool = NULL;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t tx;
	uint64_t rx;
	uint64_t dropped;
} __rte_cache_aligned;
struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

#define MAX_TIMER_PERIOD 86400 /* 1 day max */

/* 是一个 tsc-based 计时器，周期为 10s。*/
static uint64_t timer_period = 10;

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H','\0' };

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned dest_portid)
{
	struct ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned portid)
{
	unsigned dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_dst_ports[portid];  // 转发的目标端口，初始化阶段通过 “奇数-偶数” 算法进行了两两配对。

	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);  // 将 Frame 的 dstMAC 设置为 02:00:00:00:00:xx。

	buffer = tx_buffer[dst_port];  // 匹配到 Port 的 Tx buffer 空间。

	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);  // 将单个 rte_mbuf 缓存到 Tx buffer，等待后续 rte_eth_tx_buffer_flush 一次性发送。
	if (sent)
		port_statistics[dst_port].tx += sent;  // 数据统计
}

/* 数据面 Slave lcore threads 的 main 入口。*/
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];  // 批量处理 32 个 rte_mbufs。
	struct rte_mbuf *m;
	int sent;
	unsigned lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, timer_tsc;
	unsigned i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	const uint64_t drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;  // 排空周期阈值。
	struct rte_eth_dev_tx_buffer *buffer;

	prev_tsc = 0;
	timer_tsc = 0;

	lcore_id = rte_lcore_id();            // 获得当前 lcore 的 id。
	qconf = &lcore_queue_conf[lcore_id];  // 通过 lcore id 获得自己的 Rx queue 配置信息。

	/* 没有可用的 Rx Port，退出。*/
	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		// 获得分配给当前 lcore 的所有 Ports。
		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id, portid);

	}

	/************************ L2 forwarding 收发包处理 ***************************/
	while (!force_quit) {

		cur_tsc = rte_rdtsc();

		/*
		 * 周期性批量发送 Tx buffer 中的数据包。
		 */
		diff_tsc = cur_tsc - prev_tsc;         // 计算时间戳的差值，用于判断是否需要执行TX队列的排空操作。
		if (unlikely(diff_tsc > drain_tsc)) {  // 如果时间戳差值超过排空阈值，开始发包。

			/* 对每个转发目标端口的 Tx buffer 执行排空操作 */
			for (i = 0; i < qconf->n_rx_port; i++) {

				portid = l2fwd_dst_ports[qconf->rx_port_list[i]];  // 获取转发的目标端口。
				buffer = tx_buffer[portid];                        // 匹配得到指定端口的 Tx buffer 空间。

				/* 将 Tx buffer 中的数据包从指定端口发送出去，返回成功发送的数量，然后更新相应的统计信息。*/
				sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
				if (sent)
					port_statistics[portid].tx += sent;
			}

			/* if timer is enabled */
			if (timer_period > 0) {

				timer_tsc += diff_tsc;  // 叠加定时器的时间戳。

				/* 如果定时器已达到超时时间 */
				if (unlikely(timer_tsc >= timer_period)) {

					/* 在 Master lcore 上周期打印统计数据 */
					if (lcore_id == rte_get_master_lcore()) {
						print_stats();
						/* 重置定时器时间戳 */
						timer_tsc = 0;
					}
				}
			}

			prev_tsc = cur_tsc;  // 更新时间戳
		}

		/*
		 * 从 RX queues 中接受数据包。
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {
			portid = qconf->rx_port_list[i];

			/* 批量收包。
			 * 	nb_rx 返回批量收到的数据包的数量。
			 * 	rte_mbuf 的指针都被保存在 pkts_burst。*/
			nb_rx = rte_eth_rx_burst(portid, 0, pkts_burst, MAX_PKT_BURST);

			/* 统计数据。*/
			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));  // 数据预取函数，用于将地址指向的 rte_mbuf 从 Memory 预先加载到 CPU Cache 中，从而提高访问这些数据的效率。
				l2fwd_simple_forward(m, portid);             // 进入 L2 forwarding 逻辑。
			}
		}
	}
}

static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}

/* display usage */
static void
l2fwd_usage(const char *prgname)
{
	printf("%s [EAL options] -- -p PORTMASK [-q NQ]\n"
	       "  -p PORTMASK: hexadecimal bitmask of ports to configure\n"
	       "  -q NQ: number of queue (=ports) per lcore (default is 1)\n"
		   "  -T PERIOD: statistics will be refreshed each PERIOD seconds (0 to disable, 10 default, 86400 maximum)\n"
		   "  --[no-]mac-updating: Enable or disable MAC addresses updating (enabled by default)\n"
		   "      When enabled:\n"
		   "       - The source MAC address is replaced by the TX port MAC address\n"
		   "       - The destination MAC address is replaced by 02:00:00:00:00:TX_PORT_ID\n",
	       prgname);
}

static int
l2fwd_parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static unsigned int
l2fwd_parse_nqueue(const char *q_arg)
{
	char *end = NULL;
	unsigned long n;

	/* parse hexadecimal string */
	n = strtoul(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;
	if (n == 0)
		return 0;
	if (n >= MAX_RX_QUEUE_PER_LCORE)
		return 0;

	return n;
}

static int
l2fwd_parse_timer_period(const char *q_arg)
{
	char *end = NULL;
	int n;

	/* parse number string */
	n = strtol(q_arg, &end, 10);
	if ((q_arg[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;
	if (n >= MAX_TIMER_PERIOD)
		return -1;

	return n;
}

static const char short_options[] =
	"p:"  /* portmask */
	"q:"  /* number of queues */
	"T:"  /* timer period */
	;

#define CMD_LINE_OPT_MAC_UPDATING "mac-updating"
#define CMD_LINE_OPT_NO_MAC_UPDATING "no-mac-updating"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

/* --[no-]mac-updating 指定开启或关闭 MAC 地址更新功能（默认为开启）。*/
static const struct option lgopts[] = {
	{ CMD_LINE_OPT_MAC_UPDATING, no_argument, &mac_updating, 1},
	{ CMD_LINE_OPT_NO_MAC_UPDATING, no_argument, &mac_updating, 0},
	{NULL, 0, 0, 0}
};

/**
 * 解析 l2fwd 专属的 CLI options。
 * 	e.g. l2fwd -l 1-2 -- -p 0x3 -q 2 --mac-updating
 */
static int
l2fwd_parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,  // ？？？
				  lgopts, &option_index)) != EOF) {

		switch (opt) {

		/* -p PORTMASK 指定要使用的 Ports 的十六进制位掩码（Bitmap）。*/
		case 'p':
			l2fwd_enabled_port_mask = l2fwd_parse_portmask(optarg);
			if (l2fwd_enabled_port_mask == 0) {
				printf("invalid portmask\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* -q nqueue 指定每个 lcore 的 Rx/Tx 队列数（默认为 1） */
		case 'q':
			l2fwd_rx_queue_per_lcore = l2fwd_parse_nqueue(optarg);
			if (l2fwd_rx_queue_per_lcore == 0) {
				printf("invalid queue number\n");
				l2fwd_usage(prgname);
				return -1;
			}
			break;

		/* timer period */
		case 'T':
			timer_secs = l2fwd_parse_timer_period(optarg);
			if (timer_secs < 0) {
				printf("invalid timer period\n");
				l2fwd_usage(prgname);
				return -1;
			}
			timer_period = timer_secs;
			break;

		/* long options */
		case 0:
			break;

		default:
			l2fwd_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90 /* 9s (90 * 100ms) in total */
	uint16_t portid;
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		if (force_quit)
			return;
		all_ports_up = 1;
		RTE_ETH_FOREACH_DEV(portid) {
			if (force_quit)
				return;
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			printf("done\n");
		}
	}
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

/* 打印 uint16_t 整数的二进制形式，调试时使用。*/
static void print_binary(const char *var_name, uint16_t value) {
	printf("%s :", var_name);
    // 首先定义掩码
    uint16_t mask = 0x8000;
	int i;
    // 循环16次，每次取最高位并输出
    for (i = 0; i < 16; i++) {
        // 使用位与运算符判断最高位是否为1
        if (value & mask) {
            printf("1");
        } else {
            printf("0");
        }
        // 将掩码右移一位，以便检查下一位
        mask >>= 1;
    }
	printf("\n");
}

int
main(int argc, char **argv)
{
	struct lcore_queue_conf *qconf;
	int ret;
	uint16_t nb_ports;
	uint16_t nb_ports_available = 0;
	uint16_t portid, last_port;
	unsigned lcore_id, rx_lcore_id;
	unsigned nb_ports_in_mask = 0;
	unsigned int nb_lcores = 0;  // lcore 的数量。
	unsigned int nb_mbufs;

	/* 根据 EAL options 初始化 EAL 环境设置。*/
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* 提供除了 EAL options 之外的 L2fwd 专属的 CLI options。*/
	ret = l2fwd_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2FWD arguments\n");

	printf("MAC updating %s\n", mac_updating ? "enabled" : "disabled");

	/* convert to number of cycles */
	timer_period *= rte_get_timer_hz();

	/* 获取可用的 Ethernet ports 数量。*/
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");

	/**
	 * 检查 l2fwd_enabled_port_mask (-p portmask) 和 nb_ports 是否匹配。
	 * 	True：没找到任何匹配的 Port；
	 * 	False：找到至少一个匹配的 Port；
	 **/
	if (l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1))
		rte_exit(EXIT_FAILURE, "Invalid portmask; possible (0x%x)\n",
			(1 << nb_ports) - 1);
#ifdef DEBUG
	/**
	 * 测试：
	 * 	l2fwd_enabled_port_mask：0x3
	 * 	nb_ports：3
	*/
	printf("*********************************\n");
	print_binary("nb_ports", nb_ports);                                 // 0000000000000011
	print_binary("l2fwd_enabled_port_mask", l2fwd_enabled_port_mask);   // 0000000000000011
	print_binary("(1 << nb_ports)", (1 << nb_ports));                   // 0000000000001000
	print_binary("(1 << nb_ports) - 1", (1 << nb_ports) - 1);           // 0000000000000111
	print_binary("~((1 << nb_ports) - 1)", ~((1 << nb_ports) - 1));     // 1111111111111000
	print_binary("l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1)", l2fwd_enabled_port_mask & ~((1 << nb_ports) - 1));  // 0000000000000000
#endif

	/* 初始化转发目标端口列表。*/
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++)
		l2fwd_dst_ports[portid] = 0;

	printf("*********************************\n");
	printf("portid: %d\n", portid);	// 此时 portid 为 32

	/**
	 * 宏 RTE_ETH_FOREACH_DEV 是一个 for 循环，用于遍历系统中所有已初始化且无所有者的 Ports。
	 */
	last_port = 0;
	RTE_ETH_FOREACH_DEV(portid) {

		printf("*********************************\n");
		printf("portid: %d\n", portid);  // portid 分别为 0、1 循环了 2 次。

		/* Port 没有 Enabled，跳过。*/
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			printf("skip port [%d] that are not enabled\n", portid);
			continue;

		/**
		 * Port 已经 Enabled。
		 * 执行 “偶数-奇数” 负载均衡算法来分配二层转发的收发端口组。
		 * 将相邻的奇数端口和偶数端口进行配对，例如：有 4 个 Port 时，0-1 配对，2-3 配置。
		 * 这样就可以将 n 个 Ports 分成 n/2 对，每个 Ports-Pair 包含一个奇数和一个偶数端口。
		 */
		if (nb_ports_in_mask % 2) {
			l2fwd_dst_ports[portid] = last_port;
			l2fwd_dst_ports[last_port] = portid;
		}
		else
			last_port = portid;

		nb_ports_in_mask++;
		printf("nb_ports_in_mask: %d\n", nb_ports_in_mask);
	}
	if (nb_ports_in_mask % 2) {
		printf("Notice: odd number of ports in portmask.\n");
		l2fwd_dst_ports[last_port] = last_port;
	}
#ifdef DEBUG
	size_t i;
	size_t len = sizeof(l2fwd_dst_ports) / sizeof(uint32_t);
	for (i = 0; i < len; i++) {
		printf("l2fwd_dst_ports[%zu]: %d\n", i, l2fwd_dst_ports[i]);
	}
#endif


	/**
	 * 宏 RTE_ETH_FOREACH_DEV 是一个 for 循环，用于遍历系统中所有已初始化且无所有者的 Ports。
	 */
	rx_lcore_id = 0;  // 绑定 Rx queue 的 Slave lcore。
	qconf = NULL;
	RTE_ETH_FOREACH_DEV(portid) {

		printf("*********************************\n");
		printf("portid: %d\n", portid);  // 如果 DPDK 接管了 2 个 Ports，那么有效的 portid 分别为 0、1。循环到 2 时跳过处理。

		/* Port 没有 Enabled，跳过。*/
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;

		/**
		 * Port 已经 Enabled。
		 * 如果当前 lcore thread 还没有 enabled，或当前 lcore 的 Rx queue 已经分配了 1 个时：rx_lcore_id+1 处理下一个 lcore thread。
		 */
		while (rte_lcore_is_enabled(rx_lcore_id) == 0 || lcore_queue_conf[rx_lcore_id].n_rx_port == l2fwd_rx_queue_per_lcore) {
			rx_lcore_id++;
			if (rx_lcore_id >= RTE_MAX_LCORE)
				rte_exit(EXIT_FAILURE, "Not enough cores\n");
		}
		printf("rx_lcore_id: %d\n", rx_lcore_id);

		/* 如果当前 lcore 还没有设置 queue_conf，则分配一个 queue_conf 给它。*/
		if (qconf != &lcore_queue_conf[rx_lcore_id]) {
			qconf = &lcore_queue_conf[rx_lcore_id];
			nb_lcores++;
		}
		qconf->rx_port_list[qconf->n_rx_port] = portid;
		qconf->n_rx_port++;

		printf("nb_lcores: %d\n", nb_lcores);
		printf("Rx Lcore (slave) %u: RX port %u\n", rx_lcore_id, portid);  // 如果有 2 个 Ports、1 个 Slave lcore，那么这 2 个 Ports 都会分配给它
	}

	/**
	 * 计算 nb_mbufs 的数量。
	 * RTE_MAX 返回比较大的数字，则最小为 8192 个 unsigned int。
	 */
	nb_mbufs = RTE_MAX(nb_ports * (nb_rxd + nb_txd + MAX_PKT_BURST + nb_lcores * MEMPOOL_CACHE_SIZE),
	 				   8192U);

	/**
	 * 创建给 Rx queue 使用的 Packet mbuf pool，拥有存储接收到的数据包。
	 * rte_socket_id 用于获取 lcore 所在的 NUMA Socket 的 ID，利用 local cache 的优势。
	 */
	l2fwd_pktmbuf_pool = rte_pktmbuf_pool_create(
							"mbuf_pool",
							nb_mbufs,
							MEMPOOL_CACHE_SIZE,
							0,
							RTE_MBUF_DEFAULT_BUF_SIZE,
							rte_socket_id());
	if (l2fwd_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");


	/**
	 * 宏 RTE_ETH_FOREACH_DEV 是一个 for 循环，用于遍历系统中所有已初始化且无所有者的 Ports。
	 */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_rxconf rxq_conf;  // HW Rx queue 的配置信息
		struct rte_eth_txconf txq_conf;  // HW Tx queue 的配置信息

		struct rte_eth_conf local_port_conf = port_conf;  // Ethernet port 的配置信息
		struct rte_eth_dev_info dev_info;                 // Ethernet device 的配置信息

		/* Port 没有 Enabled，跳过。*/
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0) {
			printf("Skipping disabled port %u\n", portid);
			continue;
		}

		nb_ports_available++;
	

		printf("*********************************\n");
		/******************************** Initialize port ********************************/
		printf("Initializing port %u...\n", portid);
		fflush(stdout);  // 刷新
		rte_eth_dev_info_get(portid, &dev_info);  // 获取 portid 对应的 Ethernet device 信息。

		/* 检查 Ethernet device 是否开启 HW Tx offload 功能。*/
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;  // Device supports multi segment send

		/* 设置 Ethernet device 的配置，配置只使用一个 Rx queue 和一个 Tx queue。*/
		ret = rte_eth_dev_configure(portid, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u\n",
				  ret, portid);

		/* 调整（adjust）Ethernet device 的 Rx/Tx queue 的 descriptors 数量。*/
		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd, &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, portid);

		/* 获取 Ethernet device 的 MAC 地址。*/
		rte_eth_macaddr_get(portid,&l2fwd_ports_eth_addr[portid]);


		/******************************** Initialize one RX queue ********************************/
		printf("Initializing one Rx queue of port %u...\n", portid);
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;  // 获取 Rx queue 的配置信息
		rxq_conf.offloads = local_port_conf.rxmode.offloads;  // 修改 offload 配置

		/* 设置 Ethernet device 的 Rx queue 0 配置，指定使用 l2fwd_pktmbuf_pool 存储收到的 rte_mbuf。*/
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, rte_eth_dev_socket_id(portid), &rxq_conf, l2fwd_pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				  ret, portid);

		/******************************** Initialize one Tx queue on each port ********************************/
		printf("Initializing one Tx queue of port %u...\n", portid);
		fflush(stdout);
		txq_conf = dev_info.default_txconf;  // HW Tx queue 的配置信息
		txq_conf.offloads = local_port_conf.txmode.offloads;

		/* 设置 Ethernet device 的 Tx queue 0 配置。Tx queue 不需要指定 Memory pool，直接复制 rte_mbuf 到 Device。但后面需要使用 Tx buffer 机制。*/
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, rte_eth_dev_socket_id(portid), &txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup:err=%d, port=%u\n", ret, portid);
	
		/* 分配 TX buffer 空间，用于批量发送 rte_mbufs。*/
		tx_buffer[portid] = rte_zmalloc_socket("tx_buffer", RTE_ETH_TX_BUFFER_SIZE(MAX_PKT_BURST), 0, rte_eth_dev_socket_id(portid));
		if (tx_buffer[portid] == NULL)
			rte_exit(EXIT_FAILURE, "Cannot allocate buffer for tx on port %u\n", portid);
	
		/* 初始化 TX buffer 空间。*/
		rte_eth_tx_buffer_init(tx_buffer[portid], MAX_PKT_BURST);

		/* 为无法 Send 出去的 rte_mbuf 设置回调函数，用于确保数据的完整性和一致性。*/
		ret = rte_eth_tx_buffer_set_err_callback(
				tx_buffer[portid],
				rte_eth_tx_buffer_count_callback,
				&port_statistics[portid].dropped);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "Cannot set error callback for tx buffer on port %u\n", portid);

		/******************************** Start Ethernet device ********************************/
		printf("Starting Ethernet device of port %u... ", portid);
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n", ret, portid);
		printf("done: \n");

		/* 为 Ethernet device 启用混杂模式收包特性。*/
		rte_eth_promiscuous_enable(portid);

		printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				portid,
				l2fwd_ports_eth_addr[portid].addr_bytes[0],
				l2fwd_ports_eth_addr[portid].addr_bytes[1],
				l2fwd_ports_eth_addr[portid].addr_bytes[2],
				l2fwd_ports_eth_addr[portid].addr_bytes[3],
				l2fwd_ports_eth_addr[portid].addr_bytes[4],
				l2fwd_ports_eth_addr[portid].addr_bytes[5]);

		/* 初始化 Port 的数据统计，包括 rx、tx、drop 等数据。*/
		memset(&port_statistics, 0, sizeof(port_statistics));
	}
	printf("Ethernet device init complate, nb_ports_available: %d\n", nb_ports_available);

	
	if (!nb_ports_available) {
		rte_exit(EXIT_FAILURE, "All available ports are disabled. Please set portmask.\n");
	}

	/* 检查所有 Ports 的 link 状态 */
	check_all_ports_link_status(l2fwd_enabled_port_mask);

	/* 启动所有 lcore threads，开始进入 l2fwd_launch_one_lcore 数据面处理。*/
	rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
	
	/* 永循环所有 Slave lcore 等待退出。*/
	ret = 0;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}


	/**
	 * 宏 RTE_ETH_FOREACH_DEV 是一个 for 循环，用于遍历系统中所有已初始化且无所有者的 Ports。
	 */
	RTE_ETH_FOREACH_DEV(portid) {
		/* Port 没有 Enabled，跳过。*/
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		
		/* Port 已经 Enabled，开始退出。*/
		printf("Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}
	printf("Bye...\n");

	return ret;
}

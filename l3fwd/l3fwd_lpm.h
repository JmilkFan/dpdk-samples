/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#ifndef __L3FWD_LPM_H__
#define __L3FWD_LPM_H__

/* 基于 LPM 的三层转发 */
static __rte_always_inline void
l3fwd_lpm_simple_forward(struct rte_mbuf *m, uint16_t portid,
		struct lcore_conf *qconf)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *ipv4_hdr;
	uint16_t dst_port;

	eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);  // 从 mbuf 中获取 Frame Header

	if (RTE_ETH_IS_IPV4_HDR(m->packet_type)) {  // 查看 mbuf 的 Packet Header type 是不是 IPv4
		/* Handle IPv4 headers.*/
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, sizeof(struct ether_hdr));  // 从 mbuf 中获取 Packet Header

#ifdef DO_RFC_1812_CHECKS
		/* Check to make sure the packet is valid (RFC1812) */
		if (is_valid_ipv4_pkt(ipv4_hdr, m->pkt_len) < 0) {  // 根据 RFC1812 的内容对 mbuf 进行验证。
			rte_pktmbuf_free(m);  // 如果不合法就丢包
			return;
		}
#endif
		 dst_port = lpm_get_ipv4_dst_port(ipv4_hdr, portid, qconf->ipv4_lookup_struct);  // 获取下一跳的目的转发端口

		/* 如果成功获取了目的端口，但端口没有启用或是超过了最大数量的限制，就设置目的端口与收包的端口一样。即：原路返回。*/
		if (dst_port >= RTE_MAX_ETHPORTS ||
			(enabled_port_mask & 1 << dst_port) == 0)
			dst_port = portid;

#ifdef DO_RFC_1812_CHECKS
		/* Update time to live and header checksum */
		--(ipv4_hdr->time_to_live);  // TTL 自减 1
		++(ipv4_hdr->hdr_checksum);
#endif
		/* 根据 dest_eth_addr[dst_port]，改写 eth_hdr 中的 dstMAC 地址字段。*/
		*(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[dst_port];

		/* 根据 ports_eth_addr 数组改写 eth_hdr 中的 srcMAC 地址字段。 */
		ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr);

		/* IP 协议处理完后开始发包 */
		send_single_packet(qconf, m, dst_port);

	} else if (RTE_ETH_IS_IPV6_HDR(m->packet_type)) {
		/* Handle IPv6 headers.*/
		struct ipv6_hdr *ipv6_hdr;

		ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct ipv6_hdr *,
						   sizeof(struct ether_hdr));

		dst_port = lpm_get_ipv6_dst_port(ipv6_hdr, portid,
					qconf->ipv6_lookup_struct);

		if (dst_port >= RTE_MAX_ETHPORTS ||
			(enabled_port_mask & 1 << dst_port) == 0)
			dst_port = portid;

		/* dst addr */
		*(uint64_t *)&eth_hdr->d_addr = dest_eth_addr[dst_port];

		/* src addr */
		ether_addr_copy(&ports_eth_addr[dst_port], &eth_hdr->s_addr);

		send_single_packet(qconf, m, dst_port);
	} else {  // 网络层协议不是 IP 类型
		/* Free the mbuf that contains non-IPV4/IPV6 packet */
		rte_pktmbuf_free(m);  // 丢包
	}
}

static inline void
l3fwd_lpm_no_opt_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
				uint16_t portid, struct lcore_conf *qconf)
{
	int32_t j;

	/* Prefetch first packets */
	for (j = 0; j < PREFETCH_OFFSET && j < nb_rx; j++)
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[j], void *));  // 数据预取函数，用于将地址指向的 rte_mbuf 从 Memory 预先加载到 CPU Cache 中，从而提高访问这些数据的效率。

	/* Prefetch and forward already prefetched packets. */
	for (j = 0; j < (nb_rx - PREFETCH_OFFSET); j++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_burst[
				j + PREFETCH_OFFSET], void *));
		l3fwd_lpm_simple_forward(pkts_burst[j], portid, qconf);  // 转发
	}

	/* Forward remaining prefetched packets */
	for (; j < nb_rx; j++)
		l3fwd_lpm_simple_forward(pkts_burst[j], portid, qconf);
}

#endif /* __L3FWD_LPM_H__ */

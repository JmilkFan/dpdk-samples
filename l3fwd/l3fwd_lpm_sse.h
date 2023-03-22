/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#ifndef __L3FWD_LPM_SSE_H__
#define __L3FWD_LPM_SSE_H__

#include "l3fwd_sse.h"

/*
 * Read packet_type and destination IPV4 addresses from 4 mbufs.
 */
static inline void
processx4_step1(struct rte_mbuf *pkt[FWDSTEP],
		__m128i *dip,
		uint32_t *ipv4_flag)
{
	struct ipv4_hdr *ipv4_hdr;
	struct ether_hdr *eth_hdr;
	uint32_t x0, x1, x2, x3;

	// pkt1
	eth_hdr = rte_pktmbuf_mtod(pkt[0], struct ether_hdr *);  // 获取 Ehternet header
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);             // 获取 Packet header
	x0 = ipv4_hdr->dst_addr;                                 // 获取 dstIP
	ipv4_flag[0] = pkt[0]->packet_type & RTE_PTYPE_L3_IPV4;  // 检查是不是 IPv4 protocol 类型
	// pkt2
	eth_hdr = rte_pktmbuf_mtod(pkt[1], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x1 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[1]->packet_type;
	// pkt3
	eth_hdr = rte_pktmbuf_mtod(pkt[2], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x2 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[2]->packet_type;
	// pkt4
	eth_hdr = rte_pktmbuf_mtod(pkt[3], struct ether_hdr *);
	ipv4_hdr = (struct ipv4_hdr *)(eth_hdr + 1);
	x3 = ipv4_hdr->dst_addr;
	ipv4_flag[0] &= pkt[3]->packet_type;

	// 获得 4 个 pkts 的 dstIP 地址
	dip[0] = _mm_set_epi32(x3, x2, x1, x0);
}

/*
 * Lookup into LPM for destination port.
 * If lookup fails, use incoming port (portid) as destination port.
 */
static inline void
processx4_step2(const struct lcore_conf *qconf,
		__m128i dip,
		uint32_t ipv4_flag,
		uint16_t portid,
		struct rte_mbuf *pkt[FWDSTEP],
		uint16_t dprt[FWDSTEP])
{
	rte_xmm_t dst;
	const  __m128i bswap_mask = _mm_set_epi8(12, 13, 14, 15,
											 8,  9,  10, 11,
											 4,  5,  6,  7,
											 0,  1,  2,  3);

	/* Byte swap 4 IPV4 addresses. */
	dip = _mm_shuffle_epi8(dip, bswap_mask);

	/* if all 4 packets are IPV4. */
	if (likely(ipv4_flag)) {
		
		/* 根据 dstIP 查 LPM表，得到 dstPort。*/
		rte_lpm_lookupx4(qconf->ipv4_lookup_struct, dip, dst.u32, portid);

		/* 为每个 dstPort 去掉未使用的高 16 位。*/
		dst.x = _mm_packs_epi32(dst.x, dst.x);
		*(uint64_t *)dprt = dst.u64[0];

	} else {
		dst.x = dip;
		dprt[0] = lpm_get_dst_port_with_ipv4(qconf, pkt[0], dst.u32[0], portid);
		dprt[1] = lpm_get_dst_port_with_ipv4(qconf, pkt[1], dst.u32[1], portid);
		dprt[2] = lpm_get_dst_port_with_ipv4(qconf, pkt[2], dst.u32[2], portid);
		dprt[3] = lpm_get_dst_port_with_ipv4(qconf, pkt[3], dst.u32[3], portid);
	}
}

/*
 * Buffer optimized handling of packets, invoked
 * from main_loop.
 */
static inline void
l3fwd_lpm_send_packets(int nb_rx, struct rte_mbuf **pkts_burst,
			uint16_t portid, struct lcore_conf *qconf)
{
	int32_t j;
	uint16_t dst_port[MAX_PKT_BURST];      // 存放 pkts 的 Destination Ports
	__m128i dip[MAX_PKT_BURST / FWDSTEP];  // 存放 pkts 转发的 Destination IPs
	uint32_t ipv4_flag[MAX_PKT_BURST / FWDSTEP];
	const int32_t k = RTE_ALIGN_FLOOR(nb_rx, FWDSTEP);

	/* Step1: 获得 4 个 pkts 的 dstIP 地址。*/
	for (j = 0; j != k; j += FWDSTEP)
		processx4_step1(&pkts_burst[j], &dip[j / FWDSTEP],
				&ipv4_flag[j / FWDSTEP]);

	/* Step2: 获得 4 个 pkts 的 output ports。*/
	for (j = 0; j != k; j += FWDSTEP)
		processx4_step2(qconf, dip[j / FWDSTEP],
				ipv4_flag[j / FWDSTEP], portid, &pkts_burst[j], &dst_port[j]);

	/* 将 pkts_burst 中不在 FWDSTEP 批处理中的最后 3 个 pkts 逐一处理 */
	switch (nb_rx % FWDSTEP) {
	case 3:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
		/* fall-through */
	case 2:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
		/* fall-through */
	case 1:
		dst_port[j] = lpm_get_dst_port(qconf, pkts_burst[j], portid);
		j++;
	}

	/* 获得了 pkts 的 dstPorts 之后，执行最后的 Packet header 编辑。*/
	send_packets_multi(qconf, pkts_burst, dst_port, nb_rx);
}

#endif /* __L3FWD_LPM_SSE_H__ */

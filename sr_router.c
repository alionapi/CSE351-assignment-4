/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
* Method: sr_init(void)
* Scope:  Global
*
* Initialize the routing subsystem
*
*---------------------------------------------------------------------*/
void sr_init(struct sr_instance *sr)
{
	/* REQUIRES */
	assert(sr);

	/* Initialize cache and cache cleanup thread */
	sr_arpcache_init(&(sr->cache));

	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;

	pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
* Method: ip_black_list(struct sr_ip_hdr *iph)
* Scope:  Local
*
* This method is called each time the sr_handlepacket() is called.
* Block IP addresses in the blacklist and print the log.
* - Format : "[IP blocked] : <IP address>"
* - e.g.) [IP blocked] : 10.0.2.100
*
*---------------------------------------------------------------------*/
int ip_black_list(struct sr_ip_hdr *iph)
{
    int blk = 0;
    char ip_blacklist[20] = "10.0.2.0";      /* DO NOT MODIFY */
    char mask[20]        = "255.255.255.0";  /* DO NOT MODIFY */

    unsigned int b1, b2, b3, b4;
    unsigned int m1, m2, m3, m4;
    uint32_t net_prefix;
    uint32_t net_mask;
    uint32_t src, dst;
    uint32_t blocked_ip;
    uint8_t o1, o2, o3, o4;

    /* parse dotted-decimal strings into 32-bit integers */
    b1 = b2 = b3 = b4 = 0;
    m1 = m2 = m3 = m4 = 0;
    sscanf(ip_blacklist, "%u.%u.%u.%u", &b1, &b2, &b3, &b4);
    sscanf(mask,        "%u.%u.%u.%u", &m1, &m2, &m3, &m4);

    net_prefix = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
    net_mask   = (m1 << 24) | (m2 << 16) | (m3 << 8) | m4;

    /* convert IPs in header from network byte order to host */
    src = ntohl(iph->ip_src);
    dst = ntohl(iph->ip_dst);

    blocked_ip = 0;

    /* block both inbound and outbound packets */
    if ((src & net_mask) == net_prefix)
    {
        blk = 1;
        blocked_ip = src;
    }
    else if ((dst & net_mask) == net_prefix)
    {
        blk = 1;
        blocked_ip = dst;
    }

    if (blk)
    {
        o1 = (blocked_ip >> 24) & 0xff;
        o2 = (blocked_ip >> 16) & 0xff;
        o3 = (blocked_ip >> 8)  & 0xff;
        o4 = blocked_ip & 0xff;
        printf("[IP blocked] : %u.%u.%u.%u\n", o1, o2, o3, o4);
    }

    return blk;
}

/*---------------------------------------------------------------------
* Method: sr_handlepacket(uint8_t* p,char* interface)
* Scope:  Global
*
* This method is called each time the router receives a packet on the
* interface.  The packet buffer, the packet length and the receiving
* interface are passed in as parameters. The packet is complete with
* ethernet headers.
*
* Note: Both the packet buffer and the character's memory are handled
* by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
* packet instead if you intend to keep it around beyond the scope of
* the method call.
*
*---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    uint8_t *new_pck = NULL;
    unsigned int new_len = 0;
    unsigned int len_r = 0;
    uint16_t checksum = 0;

    struct sr_ethernet_hdr *e_hdr0 = NULL;
    struct sr_ethernet_hdr *e_hdr = NULL;
    struct sr_ip_hdr *i_hdr0 = NULL;
    struct sr_ip_hdr *i_hdr = NULL;
    struct sr_arp_hdr *a_hdr0 = NULL;
    struct sr_arp_hdr *a_hdr = NULL;
    struct sr_icmp_hdr *ic_hdr0 = NULL;
    struct sr_icmp_t0_hdr *ict0_hdr = NULL;
    struct sr_icmp_t3_hdr *ict3_hdr = NULL;
    struct sr_icmp_t11_hdr *ict11_hdr = NULL;

    struct sr_if *ifc = NULL;
    struct sr_if *if_it = NULL;
    struct sr_rt *rtentry = NULL;
    struct sr_arpentry *arpentry = NULL;
    struct sr_arpreq *arpreq = NULL;
    struct sr_packet *p = NULL;

    uint32_t next_hop_ip = 0;

    /* basic validation: need ethernet header */
    if (len < sizeof(struct sr_ethernet_hdr))
        return;

    e_hdr0 = (struct sr_ethernet_hdr *)packet;
    len_r = len - sizeof(struct sr_ethernet_hdr);

    /* ------------------------- IP packet ------------------------- */
    if (e_hdr0->ether_type == htons(ethertype_ip)) {

        if (len_r < sizeof(struct sr_ip_hdr))
            return;

        i_hdr0 = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
        len_r -= sizeof(struct sr_ip_hdr);

        /* IPv4 only */
        if (i_hdr0->ip_v != 4)
            return;

        /* verify IP checksum */
        checksum = i_hdr0->ip_sum;
        i_hdr0->ip_sum = 0;
        if (checksum != cksum(i_hdr0, sizeof(struct sr_ip_hdr)))
            return;
        i_hdr0->ip_sum = checksum;

        /* firewall: drop if blacklisted */
        if (ip_black_list(i_hdr0))
            return;

        /* check if packet is destined to one of our interfaces */
        for (ifc = sr->if_list; ifc != NULL; ifc = ifc->next) {
            if (i_hdr0->ip_dst == ifc->ip)
                break;
        }

        /* ===================== destined to router ===================== */
        if (ifc != NULL) {

            /* ---------- ICMP to router (echo request) ---------- */
            if (i_hdr0->ip_p == ip_protocol_icmp) {

                if (len_r < sizeof(struct sr_icmp_hdr))
                    return;

                ic_hdr0 = (struct sr_icmp_hdr *)((uint8_t *)i_hdr0 +
                                                 sizeof(struct sr_ip_hdr));

                /* only handle echo request (type 8) */
                if (ic_hdr0->icmp_type != 8)
                    return;

                /* validate ICMP checksum over entire ICMP message */
                checksum = ic_hdr0->icmp_sum;
                ic_hdr0->icmp_sum = 0;
                if (checksum != cksum(ic_hdr0,
                                      len - sizeof(struct sr_ethernet_hdr) -
                                      sizeof(struct sr_ip_hdr)))
                    return;
                ic_hdr0->icmp_sum = checksum;

                /* build ICMP echo reply: type 0, code 0 */
                new_len = sizeof(struct sr_ethernet_hdr) +
                          sizeof(struct sr_ip_hdr) +
                          sizeof(struct sr_icmp_t0_hdr);
                new_pck = (uint8_t *)calloc(1, new_len);
                if (!new_pck)
                    return;

                e_hdr = (struct sr_ethernet_hdr *)new_pck;
                i_hdr = (struct sr_ip_hdr *)(new_pck +
                                             sizeof(struct sr_ethernet_hdr));
                ict0_hdr = (struct sr_icmp_t0_hdr *)(new_pck +
                             sizeof(struct sr_ethernet_hdr) +
                             sizeof(struct sr_ip_hdr));

                /* copy original type0 header to preserve id/seq, then modify */
                {
                    struct sr_icmp_t0_hdr *orig_ict0 =
                        (struct sr_icmp_t0_hdr *)ic_hdr0;
                    *ict0_hdr = *orig_ict0;
                }
                ict0_hdr->icmp_type = 0;
                ict0_hdr->icmp_code = 0;
                ict0_hdr->icmp_sum = 0;
                ict0_hdr->icmp_sum = cksum(ict0_hdr,
                                           sizeof(struct sr_icmp_t0_hdr));

                /* IP header */
                i_hdr->ip_v = 4;
                i_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
                i_hdr->ip_tos = 0;
                i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) +
                                      sizeof(struct sr_icmp_t0_hdr));
                i_hdr->ip_id = 0;
                i_hdr->ip_off = 0;
                i_hdr->ip_ttl = INIT_TTL;          /* do not decrement */
                i_hdr->ip_p = ip_protocol_icmp;
                i_hdr->ip_src = ifc->ip;
                i_hdr->ip_dst = i_hdr0->ip_src;
                i_hdr->ip_sum = 0;
                i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

                /* Ethernet header: send back on incoming interface */
                memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost,
                       ETHER_ADDR_LEN);
                memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                e_hdr->ether_type = htons(ethertype_ip);

                sr_send_packet(sr, new_pck, new_len, interface);
                free(new_pck);
                return;
            }
            /* ---------- TCP/UDP to router: send ICMP port unreachable ---------- */
            else if (i_hdr0->ip_p == ip_protocol_tcp ||
                     i_hdr0->ip_p == ip_protocol_udp) {

                /* need original IP header + 8 bytes of data */
                if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                    return;

                new_len = sizeof(struct sr_ethernet_hdr) +
                          sizeof(struct sr_ip_hdr) +
                          sizeof(struct sr_icmp_t3_hdr);
                new_pck = (uint8_t *)calloc(1, new_len);
                if (!new_pck)
                    return;

                e_hdr = (struct sr_ethernet_hdr *)new_pck;
                i_hdr = (struct sr_ip_hdr *)(new_pck +
                                             sizeof(struct sr_ethernet_hdr));
                ict3_hdr = (struct sr_icmp_t3_hdr *)(new_pck +
                             sizeof(struct sr_ethernet_hdr) +
                             sizeof(struct sr_ip_hdr));

                /* ICMP header: type 3, code 3 (port unreachable) */
                ict3_hdr->icmp_type = 3;
                ict3_hdr->icmp_code = 3;
                ict3_hdr->unused = 0;
                ict3_hdr->next_mtu = 0;
                memset(ict3_hdr->data, 0, ICMP_DATA_SIZE);
                memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
                ict3_hdr->icmp_sum = 0;
                ict3_hdr->icmp_sum = cksum(ict3_hdr,
                                           sizeof(struct sr_icmp_t3_hdr));

                /* IP header */
                i_hdr->ip_v = 4;
                i_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
                i_hdr->ip_tos = 0;
                i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) +
                                      sizeof(struct sr_icmp_t3_hdr));
                i_hdr->ip_id = 0;
                i_hdr->ip_off = 0;
                i_hdr->ip_ttl = INIT_TTL;
                i_hdr->ip_p = ip_protocol_icmp;
                i_hdr->ip_src = ifc->ip;
                i_hdr->ip_dst = i_hdr0->ip_src;
                i_hdr->ip_sum = 0;
                i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

                /* Ethernet header */
                memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost,
                       ETHER_ADDR_LEN);
                memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
                e_hdr->ether_type = htons(ethertype_ip);

                sr_send_packet(sr, new_pck, new_len, interface);
                free(new_pck);
                return;
            }
            /* other protocols to router: ignore */
            else {
                return;
            }
        }

        /* ===================== need to forward ===================== */

        /* find route using longest prefix match */
        rtentry = sr_findLPMentry(sr->routing_table, i_hdr0->ip_dst);

        /* no route: ICMP net unreachable (type 3, code 0) */
        if (!rtentry) {

            if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                return;

            new_len = sizeof(struct sr_ethernet_hdr) +
                      sizeof(struct sr_ip_hdr) +
                      sizeof(struct sr_icmp_t3_hdr);
            new_pck = (uint8_t *)calloc(1, new_len);
            if (!new_pck)
                return;

            e_hdr = (struct sr_ethernet_hdr *)new_pck;
            i_hdr = (struct sr_ip_hdr *)(new_pck +
                                         sizeof(struct sr_ethernet_hdr));
            ict3_hdr = (struct sr_icmp_t3_hdr *)(new_pck +
                         sizeof(struct sr_ethernet_hdr) +
                         sizeof(struct sr_ip_hdr));

            /* ICMP header: destination net unreachable */
            ict3_hdr->icmp_type = 3;
            ict3_hdr->icmp_code = 0;
            ict3_hdr->unused = 0;
            ict3_hdr->next_mtu = 0;
            memset(ict3_hdr->data, 0, ICMP_DATA_SIZE);
            memcpy(ict3_hdr->data, i_hdr0, ICMP_DATA_SIZE);
            ict3_hdr->icmp_sum = 0;
            ict3_hdr->icmp_sum = cksum(ict3_hdr,
                                       sizeof(struct sr_icmp_t3_hdr));

            /* send from incoming interface */
            ifc = sr_get_interface(sr, interface);

            i_hdr->ip_v = 4;
            i_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
            i_hdr->ip_tos = 0;
            i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) +
                                  sizeof(struct sr_icmp_t3_hdr));
            i_hdr->ip_id = 0;
            i_hdr->ip_off = 0;
            i_hdr->ip_ttl = INIT_TTL;
            i_hdr->ip_p = ip_protocol_icmp;
            i_hdr->ip_src = ifc->ip;
            i_hdr->ip_dst = i_hdr0->ip_src;
            i_hdr->ip_sum = 0;
            i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

            memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, ETHER_ADDR_LEN);
            memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
            e_hdr->ether_type = htons(ethertype_ip);

            sr_send_packet(sr, new_pck, new_len, interface);
            free(new_pck);
            return;
        }

        /* route found, check TTL */
        if (i_hdr0->ip_ttl <= 1) {

            if (len_r + sizeof(struct sr_ip_hdr) < ICMP_DATA_SIZE)
                return;

            new_len = sizeof(struct sr_ethernet_hdr) +
                      sizeof(struct sr_ip_hdr) +
                      sizeof(struct sr_icmp_t11_hdr);
            new_pck = (uint8_t *)calloc(1, new_len);
            if (!new_pck)
                return;

            e_hdr = (struct sr_ethernet_hdr *)new_pck;
            i_hdr = (struct sr_ip_hdr *)(new_pck +
                                         sizeof(struct sr_ethernet_hdr));
            ict11_hdr = (struct sr_icmp_t11_hdr *)(new_pck +
                           sizeof(struct sr_ethernet_hdr) +
                           sizeof(struct sr_ip_hdr));

            ict11_hdr->icmp_type = 11;   /* time exceeded */
            ict11_hdr->icmp_code = 0;
            ict11_hdr->unused = 0;
            memset(ict11_hdr->data, 0, ICMP_DATA_SIZE);
            memcpy(ict11_hdr->data, i_hdr0, ICMP_DATA_SIZE);
            ict11_hdr->icmp_sum = 0;
            ict11_hdr->icmp_sum = cksum(ict11_hdr,
                                        sizeof(struct sr_icmp_t11_hdr));

            /* reply from incoming interface */
            ifc = sr_get_interface(sr, interface);

            i_hdr->ip_v = 4;
            i_hdr->ip_hl = sizeof(struct sr_ip_hdr) / 4;
            i_hdr->ip_tos = 0;
            i_hdr->ip_len = htons(sizeof(struct sr_ip_hdr) +
                                  sizeof(struct sr_icmp_t11_hdr));
            i_hdr->ip_id = 0;
            i_hdr->ip_off = 0;
            i_hdr->ip_ttl = INIT_TTL;
            i_hdr->ip_p = ip_protocol_icmp;
            i_hdr->ip_src = ifc->ip;
            i_hdr->ip_dst = i_hdr0->ip_src;
            i_hdr->ip_sum = 0;
            i_hdr->ip_sum = cksum(i_hdr, sizeof(struct sr_ip_hdr));

            memcpy(e_hdr->ether_dhost, e_hdr0->ether_shost, ETHER_ADDR_LEN);
            memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
            e_hdr->ether_type = htons(ethertype_ip);

            sr_send_packet(sr, new_pck, new_len, interface);
            free(new_pck);
            return;
        }

        /* normal forwarding: decrement TTL, recompute checksum, ARP lookup */
        i_hdr0->ip_ttl--;
        i_hdr0->ip_sum = 0;
        i_hdr0->ip_sum = cksum(i_hdr0, sizeof(struct sr_ip_hdr));

        /* outgoing interface */
        ifc = sr_get_interface(sr, rtentry->interface);

        /* next hop IP: use gateway if nonzero, else destination IP */
        next_hop_ip = rtentry->gw.s_addr ? rtentry->gw.s_addr : i_hdr0->ip_dst;

        /* set Ethernet source MAC */
        memcpy(e_hdr0->ether_shost, ifc->addr, ETHER_ADDR_LEN);
        e_hdr0->ether_type = htons(ethertype_ip);

        /* ARP cache lookup */
        arpentry = sr_arpcache_lookup(&(sr->cache), next_hop_ip);
        if (arpentry) {
            memcpy(e_hdr0->ether_dhost, arpentry->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, rtentry->interface);
            free(arpentry);
        } else {
            arpreq = sr_arpcache_queuereq(&(sr->cache),
                                          next_hop_ip,
                                          packet,
                                          len,
                                          rtentry->interface);
            sr_arpcache_handle_arpreq(sr, arpreq);
        }

        return;
    }

    /* ------------------------- ARP packet ------------------------- */
    else if (e_hdr0->ether_type == htons(ethertype_arp)) {

        if (len_r < sizeof(struct sr_arp_hdr))
            return;

        a_hdr0 = (struct sr_arp_hdr *)(packet + sizeof(struct sr_ethernet_hdr));

        /* find which interface this ARP is for */
        ifc = NULL;
        for (if_it = sr->if_list; if_it != NULL; if_it = if_it->next) {
            if (a_hdr0->ar_tip == if_it->ip) {
                ifc = if_it;
                break;
            }
        }
        if (!ifc)
            return;

        /* ---------- ARP request for us: send ARP reply ---------- */
        if (a_hdr0->ar_op == htons(arp_op_request)) {

            new_len = sizeof(struct sr_ethernet_hdr) +
                      sizeof(struct sr_arp_hdr);
            new_pck = (uint8_t *)calloc(1, new_len);
            if (!new_pck)
                return;

            e_hdr = (struct sr_ethernet_hdr *)new_pck;
            a_hdr = (struct sr_arp_hdr *)(new_pck +
                                          sizeof(struct sr_ethernet_hdr));

            a_hdr->ar_hrd = htons(arp_hrd_ethernet);
            a_hdr->ar_pro = htons(ethertype_ip);
            a_hdr->ar_hln = ETHER_ADDR_LEN;
            a_hdr->ar_pln = 4;
            a_hdr->ar_op = htons(arp_op_reply);

            memcpy(a_hdr->ar_sha, ifc->addr, ETHER_ADDR_LEN);
            a_hdr->ar_sip = ifc->ip;
            memcpy(a_hdr->ar_tha, a_hdr0->ar_sha, ETHER_ADDR_LEN);
            a_hdr->ar_tip = a_hdr0->ar_sip;

            memcpy(e_hdr->ether_shost, ifc->addr, ETHER_ADDR_LEN);
            memcpy(e_hdr->ether_dhost, a_hdr0->ar_sha, ETHER_ADDR_LEN);
            e_hdr->ether_type = htons(ethertype_arp);

            sr_send_packet(sr, new_pck, new_len, ifc->name);
            free(new_pck);
            return;
        }

        /* ---------- ARP reply to us: update cache and send queued pkts ---------- */
        else if (a_hdr0->ar_op == htons(arp_op_reply)) {

            struct sr_arpreq *req_ins =
                sr_arpcache_insert(&(sr->cache),
                                   a_hdr0->ar_sha,
                                   a_hdr0->ar_sip);
            if (req_ins) {
                for (p = req_ins->packets; p != NULL; p = p->next) {
                    struct sr_ethernet_hdr *p_e_hdr =
                        (struct sr_ethernet_hdr *)p->buf;
                    struct sr_if *out_if = sr_get_interface(sr, p->iface);

                    memcpy(p_e_hdr->ether_shost, out_if->addr,
                           ETHER_ADDR_LEN);
                    memcpy(p_e_hdr->ether_dhost, a_hdr0->ar_sha,
                           ETHER_ADDR_LEN);

                    sr_send_packet(sr, p->buf, p->len, p->iface);
                }
                sr_arpreq_destroy(&(sr->cache), req_ins);
            }

            return;
        }

        /* other ARP opcodes: ignore */
        else {
            return;
        }
    }

    /* other ethertype: ignore */
    else {
        return;
    }
}

struct sr_rt *sr_findLPMentry(struct sr_rt *rtable, uint32_t ip_dst)
{
	struct sr_rt *entry, *lpmentry = NULL;
	uint32_t mask, lpmmask = 0;

	ip_dst = ntohl(ip_dst);

	/* scan routing table */
	for (entry = rtable; entry != NULL; entry = entry->next)
	{
		mask = ntohl(entry->mask.s_addr);
		/* longest match so far */
		if ((ip_dst & mask) == (ntohl(entry->dest.s_addr) & mask) && mask > lpmmask)
		{
			lpmentry = entry;
			lpmmask = mask;
		}
	}

	return lpmentry;
}

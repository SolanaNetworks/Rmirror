/*
 * Author Colin Zeidler <czeidler@solananetworks.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/route.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <net/gre.h>
#include <net/checksum.h>
#include <net/route.h>
#include <net/neighbour.h>
#include <linux/netfilter/x_tables.h>
#include <linux/if_ether.h>

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#define WITH_CONNTRACK 1
#include <net/netfilter/nf_conntrack.h>
#endif

#include "xt_rmirror.h"

static DEFINE_PER_CPU(bool, rmirror_active);

struct rmirror_hdr {
        struct iphdr ip;
        struct gre_base_hdr gre;
};

static struct rmirror_hdr new_rmirror = {
        .ip = {
                .version  = 4,
                .ihl      = 5,
                .tos      = 0,
                .frag_off = 0,
                .ttl      = 0xff,
                .protocol = 0x2F, // GRE
        },
        .gre = {
                .flags    = 0,
                .protocol = htons(0x6558),
        },
};

static const char zeromac[6] = { 0, 0, 0, 0, 0, 0};

/*
 * Apply routing information to skb, 
 * so it can be sent with ip_local_out()
 *
 * Based on net/netfilter/xt_TEE.c, tee_tg_route4
 */
bool rmirror_tg_route4(struct sk_buff *skb, __be32 ip)
{
        const struct iphdr *iph = ip_hdr(skb);
        struct net *net = &init_net;
        struct rtable *rt;
        struct flowi4 fl4;

        memset(&fl4, 0, sizeof(fl4));
        
        fl4.daddr = ip;
        fl4.flowi4_tos = RT_TOS(iph->tos);
        fl4.flowi4_scope = RT_SCOPE_UNIVERSE;
        fl4.flowi4_flags = FLOWI_FLAG_KNOWN_NH;
        rt = ip_route_output_key(net, &fl4);
        if (IS_ERR(rt))
                return false;

        skb_dst_drop(skb);
        skb_dst_set(skb, &rt->dst);
        skb->dev = rt->dst.dev;
        skb->protocol = htons(ETH_P_TEB);
        return true;
}

/*
 * Create new skb that encapsulates data of original
 * skb with GRE
 */
bool encap_packet4(struct sk_buff *skb, const struct xt_rmirror_tginfo *info)
{
        struct rmirror_hdr *rmh;
        struct iphdr *iph;
        struct ethhdr *ehdr;
        struct ethhdr *datamac;
        bool mac_needed = false;

        /* add extra size as we include MAC Header and IP Header */
        int extra_header = sizeof(new_rmirror);

        /*
         * If the skb did not have a mac header, i.e. new outgoing skb
         * create the mac header for the skb we cloned
         * as if it had progressed through the stack
         */
        if (!skb_mac_header_was_set(skb)) {
                if (skb->dev == NULL) {
                        iph = ip_hdr(skb);
                        rmirror_tg_route4(skb, iph->daddr);
                }
                if (skb->dev != NULL) {
                        dev_hard_header(
                                skb,
                                skb->dev,
                                ETH_P_IP,
                                &zeromac,
                                NULL, //NULL sets source addr to dev_addr
                                skb->len);
                        mac_needed = true;
                }

                if (skb_headroom(skb) < extra_header) {
                        pskb_expand_head(skb, extra_header, 0, GFP_ATOMIC);
                }
        } else if (skb_mac_header_was_set(skb)) {
                ehdr = eth_hdr(skb);
                extra_header = extra_header + sizeof(*ehdr);
                if (skb_headroom(skb) < extra_header) {
                        pskb_expand_head(skb, extra_header, 0, GFP_ATOMIC);
                }
                datamac = (struct ethhdr*) skb_push(skb, sizeof(*ehdr));
                memcpy(datamac, ehdr, sizeof(*ehdr));
        }

        skb->encapsulation = 1;

        skb_reset_inner_headers(skb);

        rmh = (struct rmirror_hdr*) skb_push(skb, sizeof(*rmh));
        memcpy(rmh, &new_rmirror, sizeof(*rmh));

        if (info->len > 0)
                skb_trim(skb, sizeof(*rmh) + info->len);

        iph = &(rmh->ip);
        iph->daddr = info->dst.ip;
        iph->tot_len = htons(skb->len);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
        __ip_select_ident(iph, 1);
#else //LINUX_VERSION_CODE
        __ip_select_ident(&init_net, iph, 1);
#endif //LINUX_VERSION_CODE
        ip_send_check(iph);
        skb_reset_network_header(skb);

        return mac_needed;
}

unsigned int rmirror_tg4(
                struct sk_buff *skb,
                const struct xt_action_param *par
                )
{
        const struct xt_rmirror_tginfo *info = par->targinfo;
        struct dst_entry *inner_dst;
        __be32 inner_daddr;
        bool mac_needed;

        if (__this_cpu_read(rmirror_active))
                return XT_CONTINUE;

        skb = skb_clone(skb, GFP_ATOMIC);
#ifdef WITH_CONNTRACK
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,11,0) //version 4.10 and below
        nf_conntrack_put(skb->nfct);
        skb->nfct       = &nf_ct_untracked_get()->ct_general;
        skb->nfctinfo   = IP_CT_NEW;
        nf_conntrack_get(skb->nfct);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,12,0) //version 4.11
	nf_reset(skb);
	nf_ct_set(skb, nf_ct_untracked_get(), IP_CT_NEW);
	nf_conntrack_get(skb_nfct(skb));
#else //version 4.12 and up
        nf_reset(skb);
        nf_ct_set(skb, NULL, IP_CT_UNTRACKED);
#endif //LINUX VERSION CODE
#endif //WITH CONNTRACK
        inner_daddr = ip_hdr(skb)->daddr;

        mac_needed = encap_packet4(skb, info);

        if (mac_needed) {
                inner_dst = skb_dst(skb);
        }

        // Send the cloned skb
        if (rmirror_tg_route4(skb, info->dst.ip)) {
                // set saddr based on output device
                struct in_device *idev = rcu_dereference(skb->dev->ip_ptr);
                struct iphdr *iph = ip_hdr(skb);
                iph->saddr = idev->ifa_list->ifa_address;

                if (mac_needed) {
                        struct neighbour *n;
                        struct ethhdr *inner_eh;
                        inner_eh = (struct ethhdr*) ((char*)iph + sizeof(new_rmirror));
                        n = dst_neigh_lookup(inner_dst, &inner_daddr); 
                        if (n != NULL) {
                                memcpy(inner_eh->h_dest, n->ha, sizeof(char) * 6);
                        } else {
                                memcpy(inner_eh->h_dest, zeromac, sizeof(char) * 6);
                        }
                }

                __this_cpu_write(rmirror_active, true);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,4,0)
                ip_local_out(skb);
#else //Version 4.4 and up
                ip_local_out(&init_net, skb->sk, skb);
#endif //LINUX_VERSION_CODE
                __this_cpu_write(rmirror_active, false);
        } else {
                kfree_skb(skb);
        }

        return XT_CONTINUE;
}

static int rmirror_tg_check(const struct xt_tgchk_param *par)
{
        struct xt_rmirror_tginfo* info = par->targinfo;
        printk(KERN_INFO "len is: %d\n", info->len);
        return 0;
}

static struct xt_target rmirror_tg_reg[] __read_mostly = {
        {
                .name     = "RMIRROR",
                .revision = 0,
                .family   = NFPROTO_IPV4,
                .target   = rmirror_tg4,
                .targetsize = sizeof(struct xt_rmirror_tginfo),
                .checkentry = rmirror_tg_check,
                .me       = THIS_MODULE,
        },
};

static int __init rmirror_tg_init(void)
{
        printk(KERN_INFO "Insert RMIRROR\n");
        return xt_register_targets(rmirror_tg_reg, ARRAY_SIZE(rmirror_tg_reg));
}

static void __exit rmirror_tg_exit(void)
{
        printk(KERN_INFO "Remove RMIRROR\n");
        xt_unregister_targets(rmirror_tg_reg, ARRAY_SIZE(rmirror_tg_reg));
}

module_init(rmirror_tg_init);
module_exit(rmirror_tg_exit);

MODULE_ALIAS("ipt_RMIRROR");

MODULE_AUTHOR("Colin Zeidler, czeidler@solananetworks.com");
MODULE_DESCRIPTION("Xtables: clone and send packet with GRE");
MODULE_LICENSE("GPL")


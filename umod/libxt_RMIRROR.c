/*
 * Author Colin Zeidler <czeidler@solananetworks.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */
#include <sys/socket.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include <xtables.h>
#include <linux/netfilter.h>
#include <linux/netfilter/x_tables.h>
#include "../kmod/xt_rmirror.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

enum {
        O_DST = 0,
        O_LEN = 1,
};

#define s struct xt_rmirror_tginfo
static const struct xt_option_entry rmirror_tg_opts[] = {
        {.name = "target", .id = O_DST, .type = XTTYPE_HOST,
         .flags = XTOPT_MAND | XTOPT_PUT, XTOPT_POINTER(s, dst)},
        {.name = "len", .id = O_LEN, .type = XTTYPE_UINT32,
         .flags = XTOPT_PUT, XTOPT_POINTER(s, len)},
        XTOPT_TABLEEND,
};
#undef s

static void rmirror_tg_help(void)
{
        printf(
        "RMIRROR target options:\n"
        "  --target IPADDR         RMIRROR destination IP\n"
        "  --len BYTES             number of bytes to trim packet to, defaults to full packet\n"
        "       0 is equivilant to full length, Byte count is offset from end of GRE Header\n"
        "\n");
}

static void rmirror_tg_print(const void *ip, const struct xt_entry_target *target, 
                            int numeric)
{
        const struct xt_rmirror_tginfo *info = (const void *)target->data;

        if (numeric)
                printf(" RMIRROR target:%s", xtables_ipaddr_to_numeric(&info->dst.in));
        else
                printf(" RMIRROR target:%s", xtables_ipaddr_to_anyname(&info->dst.in));

        if (&info->len > 0)
                printf(" len: %d", &info->len);
}

static void rmirror_tg_save(const void *ip, const struct xt_entry_target *target)
{
        const struct xt_rmirror_tginfo *info = (const void *)target->data;

        printf(" --target %s", xtables_ipaddr_to_numeric(&info->dst.in));
        printf(" --len %d", &info->len);
}

static struct xtables_target rmirror_tg_reg[] = {
        {
                .name = "RMIRROR",
                .version = XTABLES_VERSION,
                .revision = 0,
                .family = NFPROTO_IPV4,
                .size = XT_ALIGN(sizeof(struct xt_rmirror_tginfo)),
                .userspacesize = XT_ALIGN(sizeof(struct xt_rmirror_tginfo)),
                .help = rmirror_tg_help,
                .print = rmirror_tg_print,
                .save = rmirror_tg_save,
                .x6_parse = xtables_option_parse,
                .x6_options = rmirror_tg_opts,
        },
};

void _init(void)
{
        xtables_register_targets(rmirror_tg_reg, ARRAY_SIZE(rmirror_tg_reg));
}

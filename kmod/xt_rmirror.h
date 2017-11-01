/*
 * Author Colin Zeidler <czeidler@solananetworks.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */
#ifndef _LINUX_NETFILTER_XT_RMIRROR_H
#define _LINUX_NETFILTER_XT_RMIRROR_H

struct xt_rmirror_tginfo {
        union nf_inet_addr dst;
        unsigned int len;
};

#endif /* _LINUX_NETFILTER_XT_RMIRROR_H */

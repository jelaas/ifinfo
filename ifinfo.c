/*
 * File: ifinfo.c
 * Implements: displaying and retreiving network device information
 *
 * Copyright: Jens Låås, 2009
 * Copyright license: According to GPL, see file COPYING in this directory.
 *
 * Parts copied verbatim from ethtool.
 *
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
// #include <net/if.h>
#include <linux/if.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#include <linux/ethtool.h>

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <sys/types.h>

#include "stats64.h"
#include "jelist.h"
#include "jelopt.h"

#ifndef SIOCETHTOOL
#define SIOCETHTOOL     0x8946
#endif

struct {
	int debug;
	int ifindex;
	char *ifname;
	char *key;
	int list, listall, nowhite;
	char *procdir;
	char *prefix, *suffix;
} conf;

struct jlhead *iflist;

struct iftag {
	int ifindex;
	char *ifname;  
	struct jlhead *props;
};

struct ifprop {
	const char *key, *value;
};


const unsigned int speedflags[9] = { SUPPORTED_10000baseT_Full,
				     SUPPORTED_2500baseX_Full,
				     SUPPORTED_1000baseT_Full,
				     SUPPORTED_1000baseT_Half,
				     SUPPORTED_100baseT_Full,
				     SUPPORTED_100baseT_Half,
				     SUPPORTED_10baseT_Full,
				     SUPPORTED_10baseT_Half,
				     0 };

const int speeds[9] = {
	10000,
	2500,
	1000,
	1000,
	100,
	100,
	10,
	10,
	0
};

static int strsuffix(const char *str, const char *suf)
{
	char *p;
	p = str + strlen(str) - strlen(suf);
	if(p < str) return 0;
	return !strcmp(p, suf);
}

int iftag_key(struct iftag *it, const char *key)
{
	if( (it->ifindex == conf.ifindex) ||
	    (conf.ifname && !strcmp(it->ifname, conf.ifname)))
	{
		if(!strcmp(conf.key, key))
			return 1;
	}
	return 0;
}

struct iftag *iftag_new(const char *ifname, int ifindex)
{
	struct iftag *it;
	
	it = malloc(sizeof(struct iftag));
	it->ifindex = ifindex;
	it->ifname = ifname?strdup(ifname):NULL;
	it->props = jl_new();
	return it;
}

struct iftag *iftag_get(struct jlhead *iflist, int ifindex, const char *ifname)
{
	struct iftag *it;
	jl_foreach(iflist, it) {
		if(it->ifindex == ifindex)
			return it;
		if(ifname)
			if(!strcmp(it->ifname, ifname))
				return it;
	}
	it = iftag_new(ifname, ifindex);
	jl_append(iflist, it);
	return it;
}

struct ifprop *ifprop_new(const char *key, const char *value)
{
	struct ifprop *prop;
	if(conf.debug) printf("new prop %s = %s\n", key, value);
	prop = malloc(sizeof(struct ifprop));
	prop->key = key;
	prop->value = value;
	return prop;
}

int iftag_set(struct iftag *it, const char *key, const char *value)
{
	return jl_append(it->props, ifprop_new(key, value));
}

static int netlinkrequest(int fd, int type, int (*fn)(struct nlmsghdr *h))
{
	char buf[102400];
	/* buffer needs to be really large to fit all possible interfaces.
	   there should be some way to read them all anyway in the loop.
	   too small buffer will only return a subset of all ifs
	   use recvmsg to detect truncated messages?
	*/
	int n;
	struct sockaddr_nl nl;
	struct {
		struct nlmsghdr nlh;
		struct rtgenmsg g;
	} req;
	struct nlmsghdr *h;

	memset(&nl, 0, sizeof nl);
	nl.nl_family = AF_NETLINK;

	memset(&req, 0, sizeof(req));
	req.nlh.nlmsg_len = sizeof(req);
	req.nlh.nlmsg_type = type;
	req.nlh.nlmsg_flags = NLM_F_ROOT|NLM_F_MATCH|NLM_F_REQUEST;
	req.nlh.nlmsg_pid = 0;
	req.nlh.nlmsg_seq = 1;
	//	req.g.rtgen_family = AF_PACKET;
	req.g.rtgen_family = AF_NETLINK;

	if(sendto(fd, (void*)&req, sizeof req, 0, (struct sockaddr*)&nl, sizeof nl) < 0)
		return -1;

	while((n=read(fd, buf, sizeof buf)) > 0) {
		for(h=(struct nlmsghdr*)buf; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)){
			if(h->nlmsg_type == NLMSG_DONE) {
				return 0;
			}
			if(h->nlmsg_type == NLMSG_ERROR){
				return -1;
			}
			
			if(fn(h) < 0)
				;//return -1;
		}
	}
	return -1;
}

static int devsocket(void)
{
  /* we couldn't care less which one; just want to talk to the kernel! */
  static int dumb[3] = { AF_INET, AF_PACKET, AF_INET6 };
  int i, fd;
  
  for(i=0; i<3; i++)
    if((fd = socket(dumb[i], SOCK_DGRAM, 0)) >= 0)
      return fd;
  return -1;
}

static int parsertattr(struct rtattr **dst, int ndst, struct nlmsghdr *h, int type, int skip)
{
	struct rtattr *src;
	int len;
	
	len = h->nlmsg_len - NLMSG_LENGTH(skip);
	if(len < 0 || h->nlmsg_type != type){
		return -1;
	}
	src = (struct rtattr*)((char*)NLMSG_DATA(h) + NLMSG_ALIGN(skip));

	memset(dst, 0, ndst*sizeof dst[0]);
	for(; RTA_OK(src, len); src = RTA_NEXT(src, len))
		if(src->rta_type < ndst)
			dst[src->rta_type] = src;
	return 0;
}

static int parsertattr_nested(struct rtattr **dst, int ndst, struct rtattr *src, int len)
{
	memset(dst, 0, ndst*sizeof dst[0]);
	for(; RTA_OK(src, len); src = RTA_NEXT(src, len))
		if(src->rta_type < ndst)
			dst[src->rta_type] = src;
	return 0;
}

static int vlan(struct iftag *it, struct rtattr *linkinfo, int len)
{
  	struct rtattr *attr[IFLA_INFO_MAX+1];
	struct rtattr *vlan_attr[IFLA_VLAN_MAX+1];
        char *kind;
	char str[64];

	if(parsertattr_nested(attr, IFLA_INFO_MAX+1, linkinfo, len) < 0) {
		return -1;
	}

	if (!attr[IFLA_INFO_KIND])
		return -1;
        kind = RTA_DATA(attr[IFLA_INFO_KIND]);
	if(strcmp(kind, "vlan")) return -1;

	if (!attr[IFLA_INFO_DATA]) return 0;
	
	parsertattr_nested(vlan_attr, IFLA_VLAN_MAX+1,
			   RTA_DATA(attr[IFLA_INFO_DATA]),
			   RTA_PAYLOAD(attr[IFLA_INFO_DATA]));
	if(vlan_attr[IFLA_VLAN_ID]) {
		sprintf(str, "%u",
			*(__u16 *)RTA_DATA(vlan_attr[IFLA_VLAN_ID]));
		iftag_set(it, "vlanid", strdup(str));
	}

#if 0
	if(vlan_attr[IFLA_VLAN_FLAGS]) {
		struct ifla_vlan_flags *flags;
		flags = RTA_DATA(vlan_attr[IFLA_VLAN_FLAGS]);
	  //	  vlan_print_flags(f, flags->flags);
	}
#endif
	
	return 0;
}

static int getlink(struct nlmsghdr *h)
{
	char *p, str[128], str2[128];
	int fd;
	struct rtattr *attr[IFLA_MAX+16];
	// Kernel IFLA_MAX may be greater than in libc header. So add 16..
	// Same once more below.
	struct ifinfomsg *ifi;
	struct iftag *it;
	
	ifi = (struct ifinfomsg*)NLMSG_DATA(h);

	if(parsertattr(attr, IFLA_MAX+16, h, RTM_NEWLINK, sizeof(struct ifinfomsg)) < 0)
		return -1;

	if(attr[IFLA_IFNAME])
		p = (char*)RTA_DATA(attr[IFLA_IFNAME]);
	else
	  p = NULL;
	
	it = iftag_get(iflist, ifi->ifi_index, p);

	if(p) iftag_set(it, "ifname", strdup(p));

	if(ifi->ifi_flags & IFF_LOWER_UP)
	  iftag_set(it, "link", "yes");
	else
	  iftag_set(it, "link", "no");
	if(ifi->ifi_flags & IFF_UP)
	  iftag_set(it, "up", "yes");
	else
	  iftag_set(it, "up", "no");
	if(ifi->ifi_flags & IFF_RUNNING)
	  iftag_set(it, "running", "yes");
	else
	  iftag_set(it, "running", "no");
	if(ifi->ifi_flags & IFF_PROMISC)
	  iftag_set(it, "promisc", "yes");
	else
	  iftag_set(it, "promisc", "no");
	if(ifi->ifi_flags & IFF_LOOPBACK)
	  iftag_set(it, "loopback", "yes");
	else
	  iftag_set(it, "loopback", "no");

	sprintf(str, "%d", ifi->ifi_index);
	iftag_set(it, "ifindex", strdup(str));

	if(attr[IFLA_LINKINFO]) {
		/* IFLA_LINKINFO is present for vlan devices */
		if(vlan(it, RTA_DATA(attr[IFLA_LINKINFO]),
			RTA_PAYLOAD(attr[IFLA_LINKINFO])))
			iftag_set(it, "vlan", "no");
		else
			iftag_set(it , "vlan", "yes");
	} else  iftag_set(it, "vlan", "no");

	/* tb[IFLA_VFINFO] && tb[IFLA_NUM_VF] */
	/* struct ifla_vf_info *ivi;
	   See kernel: net/core/rtnetlink.c for implementation.
	   There will be IFLA_NUM_VF nr of IFLA_VFINFO sections.
	 */

	if(attr[IFLA_LINK]) {
		int iflink = *(int*)RTA_DATA(attr[IFLA_LINK]);
		if(iflink) {
			sprintf(str, "%d", iflink);
			iftag_set(it, "parent_ifindex", strdup(str));
		}
	}

	if(attr[IFLA_MTU]) {
		sprintf(str, "%d", *(int*)RTA_DATA(attr[IFLA_MTU]));
		iftag_set(it, "mtu", strdup(str));
	}

	if(attr[ifla_stats64_enum()]) {
		struct ifstats64 *s;

		iftag_set(it, "stats", "64bit");

		s = RTA_DATA(attr[ifla_stats64_enum()]);
		sprintf(str, "%llu", s->rx_dropped);
		iftag_set(it, "rx_dropped", strdup(str));
		sprintf(str, "%llu", s->tx_dropped);
		iftag_set(it, "tx_dropped", strdup(str));
		sprintf(str, "%llu", s->rx_packets);
		iftag_set(it, "rx_packets", strdup(str));
		sprintf(str, "%llu", s->rx_bytes);
		iftag_set(it, "rx_bytes", strdup(str));
		sprintf(str, "%llu", s->tx_packets);
		iftag_set(it, "tx_packets", strdup(str));
		sprintf(str, "%llu", s->tx_bytes);
		iftag_set(it, "tx_bytes", strdup(str));
		sprintf(str, "%llu", s->rx_errors);
		iftag_set(it, "rx_errors", strdup(str));
		sprintf(str, "%llu", s->rx_over_errors);
		iftag_set(it, "rx_over_errors", strdup(str));
		sprintf(str, "%llu", s->rx_fifo_errors);
		iftag_set(it, "rx_fifo_errors", strdup(str));
		sprintf(str, "%llu", s->rx_missed_errors);
		iftag_set(it, "rx_missed_errors", strdup(str));
		sprintf(str, "%llu", s->tx_errors);
		iftag_set(it, "tx_errors", strdup(str));
	} else {
		if(attr[IFLA_STATS]) {
			struct rtnl_link_stats *s;
			
			iftag_set(it, "stats", "32bit");

			s = RTA_DATA(attr[IFLA_STATS]);
			sprintf(str, "%u", s->rx_dropped);
			iftag_set(it, "rx_dropped", strdup(str));
			sprintf(str, "%u", s->tx_dropped);
			iftag_set(it, "tx_dropped", strdup(str));
			sprintf(str, "%u", s->rx_packets);
			iftag_set(it, "rx_packets", strdup(str));
			sprintf(str, "%u", s->rx_bytes);
			iftag_set(it, "rx_bytes", strdup(str));
			sprintf(str, "%u", s->tx_packets);
			iftag_set(it, "tx_packets", strdup(str));
			sprintf(str, "%u", s->tx_bytes);
			iftag_set(it, "tx_bytes", strdup(str));
			sprintf(str, "%u", s->rx_errors);
			iftag_set(it, "rx_errors", strdup(str));
			sprintf(str, "%u", s->rx_over_errors);
			iftag_set(it, "rx_over_errors", strdup(str));
			sprintf(str, "%u", s->rx_fifo_errors);
			iftag_set(it, "rx_fifo_errors", strdup(str));
			sprintf(str, "%u", s->rx_missed_errors);
			iftag_set(it, "rx_missed_errors", strdup(str));
			sprintf(str, "%u", s->tx_errors);
			iftag_set(it, "tx_errors", strdup(str));
		}
	}

	if((fd = devsocket()) > 0) {
		struct ifreq ifr;

		memset(&ifr, 0, sizeof ifr);
		strncpy(ifr.ifr_name, p, IFNAMSIZ);
		if(ioctl(fd, SIOCGIFHWADDR, &ifr) >= 0
		   && ifr.ifr_hwaddr.sa_family == ARPHRD_ETHER) {
			sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
				(unsigned char)ifr.ifr_hwaddr.sa_data[0],
				(unsigned char)ifr.ifr_hwaddr.sa_data[1],
				(unsigned char)ifr.ifr_hwaddr.sa_data[2],
				(unsigned char)ifr.ifr_hwaddr.sa_data[3],
				(unsigned char)ifr.ifr_hwaddr.sa_data[4],
				(unsigned char)ifr.ifr_hwaddr.sa_data[5]);
			iftag_set(it, "mac", strdup(str));
		}
		close(fd);
	}

	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) > 0) {
		struct ifreq ifr;
		struct ethtool_drvinfo drvinfo;
		struct ethtool_cmd cmd;

		memset(&ifr, 0, sizeof ifr);
		strncpy(ifr.ifr_name, p, IFNAMSIZ);
		memset(&drvinfo, 0, sizeof(drvinfo));
		drvinfo.cmd = ETHTOOL_GDRVINFO;
		ifr.ifr_data = (caddr_t)&drvinfo;
		if(ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
			unsigned int n_stats, sz_str, sz_stats;
			int err, i;
			struct ethtool_gstrings *strings;
			struct ethtool_stats *stats;
			
			iftag_set(it, "driver", strdup(drvinfo.driver));
			if(drvinfo.bus_info && drvinfo.bus_info[0])
				iftag_set(it, "bus_info",
					  strdup(drvinfo.bus_info));
			
			n_stats = drvinfo.n_stats;
			if(n_stats > 0) {
				sz_str = n_stats * ETH_GSTRING_LEN;
				sz_stats = n_stats * sizeof(__u64);
				strings = calloc(1, sz_str + sizeof(struct ethtool_gstrings));
				stats = calloc(1, sz_stats + sizeof(struct ethtool_stats));
				strings->cmd = ETHTOOL_GSTRINGS;
				strings->string_set = ETH_SS_STATS;
				strings->len = n_stats;
				ifr.ifr_data = (caddr_t) strings;
				err = ioctl(fd, SIOCETHTOOL, &ifr);
				if (err >= 0) {
					stats->cmd = ETHTOOL_GSTATS;
					stats->n_stats = n_stats;
					ifr.ifr_data = (caddr_t) stats;
					err = ioctl(fd, SIOCETHTOOL, &ifr);
				}
				if (err >= 0) {
					char *name;
					__u64 rxpackets=0, rxbytes=0, txpackets=0, txbytes=0;
					int frxpackets=0, frxbytes=0, ftxpackets=0, ftxbytes=0;
					for (i = 0; i < n_stats; i++) {
						name = &strings->data[i * ETH_GSTRING_LEN];
						if(!strncmp(name, "rx_queue_", 9)) {
							if(strsuffix(name, "packets")) {
								rxpackets += stats->data[i];
								frxpackets=1;
							}
							if(strsuffix(name, "bytes")) {
								rxbytes += stats->data[i];
								frxbytes=1;
							}
						}
						if(!strncmp(name, "tx_queue_", 9)) {
							if(strsuffix(name, "packets")) {
								txpackets += stats->data[i];
								ftxpackets=1;
							}
							if(strsuffix(name, "bytes")) {
								txbytes += stats->data[i];
								ftxbytes=1;
							}
						}
						sprintf(str, "%llu", stats->data[i]);
						sprintf(str2, "gstr_%s", name);
						iftag_set(it,
							  strdup(str2),
							  strdup(str));
					}
					if(frxpackets) {
						sprintf(str, "%llu", rxpackets);
						iftag_set(it, "qsum_rx_packets", strdup(str));
					}
					if(ftxpackets) {
						sprintf(str, "%llu", txpackets);
						iftag_set(it, "qsum_tx_packets", strdup(str));
					}
					if(frxbytes) {
						sprintf(str, "%llu", rxbytes);
						iftag_set(it, "qsum_rx_bytes", strdup(str));
					}
					if(ftxbytes) {
						sprintf(str, "%llu", txbytes);
						iftag_set(it, "qsum_tx_bytes", strdup(str));
					}
				}
				free(strings);
				free(stats);
			}

		}


		memset(&ifr, 0, sizeof ifr);
		strncpy(ifr.ifr_name, p, IFNAMSIZ);
		memset(&cmd, 0, sizeof(cmd));
		cmd.cmd = ETHTOOL_GSET;
		ifr.ifr_data = (caddr_t)&cmd;
		if(ioctl(fd, SIOCETHTOOL, &ifr) >= 0) {
			int i;
			sprintf(str, "%u", cmd.port);
			iftag_set(it, "port", strdup(str));
			
			for(i=0;speedflags[i];i++)
				if(cmd.supported & speedflags[i]) {
					sprintf(str, "%d", speeds[i]);
					iftag_set(it, "speedmax", strdup(str));
					break;
				}
			sprintf(str, "%d", ethtool_cmd_speed(&cmd));
			iftag_set(it, "speed", strdup(str));
			
			if(cmd.supported & SUPPORTED_TP)
				iftag_set(it, "tp", "yes");
			if(cmd.supported & SUPPORTED_FIBRE)
				iftag_set(it, "fibre", "yes");

		}
		close(fd);

		  /* FIXME: nr rxqueues and nr txqueues
		     Currentlty not possible unless we scan /proc/irq for a
		     device that is configured UP */
	}
	return 0;
}

static int getaddr(struct nlmsghdr *h)
{
	char str[128], str2[128];
	struct ifaddrmsg *ifa;
	struct rtattr *attr[IFA_MAX+1];
	struct rtattr *rta;
	unsigned char *p;
	struct iftag *it;
	
	ifa = (struct ifaddrmsg*)NLMSG_DATA(h);
	//printf("ifindex = %d\n", ifa->ifa_index);
	
	it = iftag_get(iflist, ifa->ifa_index, NULL);
	
	if(parsertattr(attr, IFA_MAX+1, h, RTM_NEWADDR, sizeof(struct ifaddrmsg)) < 0)
		return -1;
	
	if(attr[IFA_ADDRESS] == NULL)
		attr[IFA_ADDRESS] = attr[IFA_LOCAL];
	if(attr[IFA_ADDRESS] == NULL)
		return 0;

	rta = attr[IFA_ADDRESS];
	p = RTA_DATA(rta); /* pointer to ip addr */
	if(ifa->ifa_family == AF_INET) {
		sprintf(str, "%d.%d.%d.%d", *p, *(p+1), *(p+2), *(p+3));
		iftag_set(it, "ipv4", strdup(str));
		sprintf(str2, "%s/%d", str, ifa->ifa_prefixlen);
		iftag_set(it, "ipv4prefix", strdup(str2));
	}
	if(ifa->ifa_family == AF_INET6) {
		inet_ntop(AF_INET6, p,
			  str, sizeof(str));
		//sprintf(str, "%02x%02x:%02x%02x", *p, *(p+1), *(p+2), *(p+3));
		iftag_set(it, "ipv6", strdup(str));
		sprintf(str2, "%s/%d", str, ifa->ifa_prefixlen);
		iftag_set(it, "ipv6prefix", strdup(str2));
	}
	
	if(attr[IFA_CACHEINFO]){
		struct ifa_cacheinfo *ci;

		ci = RTA_DATA(attr[IFA_CACHEINFO]);
		sprintf(str, "%d", ci->ifa_prefered);
		iftag_set(it, "prefered", strdup(str));
		sprintf(str, "%d", ci->ifa_valid);
		iftag_set(it, "valid", strdup(str));
	}
	return 0;
}

int if_read_proc(struct iftag *it, const char *iffile, char *buf, size_t bufsize)
{
  char fn[256];
	int fd, rc;
	
	snprintf(fn, sizeof(fn),
		 "%s/sys/net/ipv4/conf/%s/%s",
		 conf.procdir,
		 it->ifname,
		 iffile);
	fd = open(fn, O_RDONLY);
	if(fd == -1) {
		fprintf(stderr, "Failed to open '%s'\n", fn);
		return -1;
	}
	rc = read(fd, buf, bufsize-1);
	if(rc > 1) {
		buf[--rc] = 0;
		close(fd);
		return 0;
	}
	close(fd);
	return -1;
}

int proc_fetch()
{
  /*
export CONFIG_NO_SPOOF=yes
export CONFIG_NO_SOURCE=yes
export CONFIG_PROXY_ARP=no
export CONFIG_REDIRECT=yes
export CONFIG_ACCEPT_REDIRECT=no
export CONFIG_LOG_MARTIANS=yes

labb:/# ls /proc/sys/net/ipv4/conf/eth0/
accept_redirects     arp_notify log_martians      secure_redirects
accept_source_route  bootp_relay mc_forwarding      send_redirects
arp_accept     disable_policy medium_id      shared_media
arp_announce     disable_xfrm promote_secondaries  tag
arp_filter     force_igmp_version  proxy_arp
arp_ignore     forwarding rp_filter

 */
	char buf[1024];
	struct iftag *it;
	
	jl_foreach(iflist, it) {
		if(if_read_proc(it, "proxy_arp", buf, sizeof(buf))==0)
			iftag_set(it, "proxy_arp", strdup(buf));
		if(if_read_proc(it, "forwarding", buf, sizeof(buf))==0)
			iftag_set(it, "forwarding", strdup(buf));
		if(if_read_proc(it, "send_redirects", buf, sizeof(buf))==0)
			iftag_set(it, "send_redirects", strdup(buf));
		if(if_read_proc(it, "secure_redirects", buf, sizeof(buf))==0)
			iftag_set(it, "secure_redirects", strdup(buf));
		if(if_read_proc(it, "accept_redirects", buf, sizeof(buf))==0)
			iftag_set(it, "accept_redirects", strdup(buf));
		if(if_read_proc(it, "log_martians", buf, sizeof(buf))==0)
			iftag_set(it, "log_martians", strdup(buf));
		if(if_read_proc(it, "rp_filter", buf, sizeof(buf))==0)
			iftag_set(it, "rp_filter", strdup(buf));
		if(if_read_proc(it, "shared_media", buf, sizeof(buf))==0)
			iftag_set(it, "shared_media", strdup(buf));
		if(if_read_proc(it, "accept_source_route", buf, sizeof(buf))==0)
			iftag_set(it, "accept_source_route", strdup(buf));
	}
	
	return 0;
}

/*

root@beta:/# bin32/ethtool -i eth0
driver: veth
version: 1.0
firmware-version: N/A
bus-info: 

root@jens:/foo/bifrost-6.1-beta1# bin32/ethtool -i eth0
driver: tg3
version: 3.98
firmware-version: sb v2.04
bus-info: 0000:04:00.0


 */

char *nowhite(const char *s)
{
  char *w, *p;
  if(!conf.nowhite) return strdup(s);
  w = strdup(s);
  for(p=w;*p;p++)
    if(strchr(" \t\n\r", *p))
      *p='_';
  return w;
}

int main(int argc, char **argv)
{
	int fd, err=0, rc=1;
	struct iftag *it;

	conf.ifname = NULL;
	conf.ifindex = -1;
	conf.key = NULL;
	conf.list = 1;
	conf.procdir = "/proc";
	conf.prefix = "";
	conf.suffix = "";

	if(jelopt(argv, 'h', "help", NULL, &err)) {
		printf("ifinfo [-aw] [-ps] [-i IFNAME|-I ifindex] [key]\n"
		       "version " VERSION "\n"
		       " -a --all         Output all keys found.\n"
		       " -w --nowhite     Do not output whitespace in values.\n"
		       " -p --prefix S    Prefix values with string S.\n" 
		       " -s --suffix S    Append string S to values.\n"
		       " --debug\n"
		       "\n"
		       "key = ifname|ifindex|mac|ipv4 ...\n");
		exit(0);
	}

	if(jelopt(argv, 0, "debug", NULL, &err))
		conf.debug = 1;

	if(jelopt(argv, 'a', "all", NULL, &err))
		conf.listall = 1;
	if(jelopt(argv, 'w', "nowhite", NULL, &err))
		conf.nowhite = 1;
	if(jelopt(argv, 'p', "prefix", &conf.prefix, &err))
		;
	if(jelopt(argv, 's', "suffix", &conf.suffix, &err))
		;

	if(jelopt(argv, 'i', "ifname",
		  &conf.ifname, &err))
		conf.list = 0;
	if(jelopt_int(argv, 'I', "ifindex",
		      &conf.ifindex, &err))
		conf.list = 0;
	
	argc = jelopt_final(argv, &err);
	
	if(argc > 2) {
		fprintf(stderr, "You can only request one key at a time.\n");
		exit(1);
	}
	if(argc == 2) {
		conf.key = argv[1];
		/* -a and key are mutually exclusive: key overrides */
		conf.listall = 0;
	}

	iflist = jl_new();

	if(conf.debug) printf("Opening netlink socket\n");
	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if(fd < 0)
		return 1;
	if(conf.debug) printf("Sending netlink requests\n");
	if(netlinkrequest(fd, RTM_GETLINK, getlink) < 0
	|| netlinkrequest(fd, RTM_GETADDR, getaddr) < 0){
		close(fd);
		return 1;
	}
	close(fd);

	/* fetch from /proc */
	proc_fetch();

	/* fetch from /sys ?? works in container? */

	/* print results */
	if(conf.debug) printf("Printing results\n");
	jl_foreach(iflist, it) {
		struct ifprop *prop;

		if(conf.list) {
			if(!conf.key && !conf.listall)
				printf("%s", it->ifname);
		} else {
			if( (conf.ifindex >= 0) &&
			    (conf.ifindex != it->ifindex) )
				continue;
			if( conf.ifname &&
			    strcmp(conf.ifname, it->ifname) )
				continue;
		}
		
		if(conf.key)
			jl_foreach(it->props, prop) {
				if(!strcmp(conf.key, prop->key)) {
					if(conf.list)
						printf("%s:", it->ifname);
					printf("%s%s%s\n",
					       conf.prefix,
					       nowhite(prop->value),
					       conf.suffix);
					rc=0;
				}
			}
		if(conf.listall) {
			jl_foreach(it->props, prop) {
				if(conf.list)
					printf("%s:", it->ifname);
				printf("%s=%s%s%s\n",
				       prop->key,
				       conf.prefix,
				       nowhite(prop->value),
				       conf.suffix);
			}
			rc=0;
		}
		if(conf.list && !conf.listall) printf("%s", conf.key?"":"\n");
	}

	return rc;
}

/*

ifinfo (-i N|-I idx) <key> -> value
keys:
ifname
ifindex
mac
mtu
ipv4prefix
ipv4mask
ipv4addr
ipv6addr
ipv4broadcast
up|down
linkstatus
ipv4forwarding
proxy_arp
rp_filter
ipv4accept_redirect
send_redirect
ESSID-list

 */

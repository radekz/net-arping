/*
 * Arping.xs
 * Copyright (c) 2002. Oleg Prokopyev. All rights reserved. This program is free
 * software; you can redistribute it and/or modify it under the same terms
 * as Perl itself.
 *
 * Thanks to Marvin (marvin@rootbusters.net).
 * I used a little bit his code from 
 * arping utility in my handlepacket function :)
 *
 * Comments/suggestions to riiki@gu.net
 */

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#include <libnet.h>
#include <pcap.h> 
#include <string.h>

#include <net/if.h>
#include <net/if_arp.h>

#include <setjmp.h>

#ifndef ETH_P_IP                                                                
#define ETH_P_IP 0x0800                                                         
#endif

MODULE = Net::Arping		PACKAGE = Net::Arping

SV *
send_arp(dst_ip,timeout,...)
	char *dst_ip
	int timeout
	PREINIT:
		char *device = NULL;
		STRLEN n_a;
	CODE:
		libnet_t *l;
		u_int32_t rr,src_ip; 
		char errbuf[ LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ? LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE ];
		int packet_size, i;
		struct libnet_ether_addr *src_mac;
		libnet_ptag_t ptag;

		struct bpf_program filter;
		pcap_t *handle;
		jmp_buf Env;

		u_char enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 

		char filter_app[] = "arp";

		char ttt[17]="0";

		/*
		Handle Packet Procedure
		*/

		void
		handlepacket(const char *unused, struct pcap_pkthdr *h,u_char *packet)
		{
			struct ethhdr *eth;
			struct arphdr *harp;
			u_int32_t ip;
			unsigned char *cp;
			unsigned int i;

			char tt[4];


			eth = (struct ethhdr*)packet;
			harp = (struct arphdr*)((char*)eth + sizeof(struct libnet_ethernet_hdr));
			memcpy(&ip, (char*)harp + harp->ar_hln + sizeof(struct arphdr), 4);
			cp = (u_char*)harp + sizeof(struct arphdr);

			if ((htons(harp->ar_op) == ARPOP_REPLY)
				&& (htons(harp->ar_pro) == ETH_P_IP) 
				&& (htons(harp->ar_hrd) == ARPHRD_ETHER)
				&& ((u_int32_t)rr == ip))
			{
				strcpy(ttt,"");

				for (i = 0; i < harp->ar_hln-1;i++)
				{
	    			    snprintf(tt, 4, "%.2x:", *cp++);
				    strcat(ttt,tt);
				}
				snprintf(tt, 3, "%.2x", *cp++);
				strcat(ttt,tt);
				longjmp(Env, 1);
			}
		}

		void
		boom()
		{
		    longjmp(Env, 1);
		}    

		/*
		*/

		if( items >2 )
		{
			device=(char *)SvPV(ST(2),n_a);
		} 

		rr = libnet_name2addr4(l, dst_ip, LIBNET_RESOLVE);
		if (rr == -1) croak("bad dst ip address\n");

		l = libnet_init(LIBNET_LINK, device, errbuf);
		if (!l) croak("libnet_init() failed: %s", errbuf);

	       	/* in case an IP address has been passed as device name */
		device = libnet_getdevice(l);

		/* according to documentation, "can be null without error" after previous call */
		if (!device)
			device = pcap_lookupdev(errbuf);
		if (!device)
			croak("can't obtain the device name, pcap_lookupdev(): %s", errbuf);

		if(!(src_ip = libnet_get_ipaddr4(l)))
			croak("libnet_get_ipaddr4 failed: %s", libnet_geterror(l));
		if (!(src_mac = libnet_get_hwaddr(l)))
			croak("libnet_get_hwaddr failed: %s", libnet_geterror(l));

		ptag = libnet_autobuild_arp(ARPOP_REQUEST, src_mac->ether_addr_octet, (u_int8_t*) &src_ip, enet_dst, (u_int8_t*) &rr, l);
		if (ptag == -1) croak("building ARP packet failed: %s", libnet_geterror(l));

		ptag = libnet_autobuild_ethernet(enet_dst, ETHERTYPE_ARP, l);
		if (ptag == -1) croak("building ethernet packet failed: %s", libnet_geterror(l));

		if(!(handle = pcap_open_live(device,100,1,10, errbuf)))
		{
			croak("pcap_open_live failed\n");
		}

		if(pcap_compile(handle,&filter,filter_app,0,-1) == -1)
		{
			croak("pcap_compile failed\n");
		}

		if(pcap_setfilter(handle,&filter) == -1)
		{
			croak("pcap_setfilter failed\n");
		}

		alarm(timeout);
		signal(SIGALRM, boom);

		packet_size = libnet_getpacket_size(l);
		i = libnet_write(l);
		if (i == -1)
			croak("libnet_write(): %s", libnet_geterror(l));

		if (setjmp(Env) == 0) {
		    pcap_loop(handle,0, (pcap_handler)handlepacket, NULL);
		} 

		if (i != packet_size)
			croak("failed, sent only %d bytes\n",i);

		libnet_close_link(l);
		libnet_destroy(l); 
		pcap_close(handle);

		RETVAL=newSVpv(ttt,0);

		OUTPUT:
			RETVAL


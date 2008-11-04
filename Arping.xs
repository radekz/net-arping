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

#ifndef DEBUG
#ifdef DEBUG_ARPING
#	define DEBUG(msg) fprintf(stderr, msg);
#else
#	define DEBUG(msg) ;
#endif
#endif

MODULE = Net::Arping		PACKAGE = Net::Arping

PROTOTYPES: ENABLE

char *
send_arp(dst_ip, timeout=1, interface=NULL) 
		char *dst_ip
		int  timeout
		char *interface
	CODE:
		char *device;
		libnet_t *l;
		u_int32_t rr, src_ip; 
		char errbuf[ LIBNET_ERRBUF_SIZE > PCAP_ERRBUF_SIZE ? LIBNET_ERRBUF_SIZE : PCAP_ERRBUF_SIZE ];
		struct libnet_ether_addr *src_mac;
		libnet_ptag_t ptag;

		char filter_app[35];
		struct bpf_program filter;
		pcap_t *handle;

		u_char enet_dst[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; 

		char result[16] = "";

		/* leaks file handles if interface==NULL;
		 * see http://cvs.pld-linux.org/SOURCES/libnet-leaking-fd.patch */
		l = libnet_init(LIBNET_LINK, interface, errbuf);
		if (!l) croak("libnet_init() failed: %s", errbuf);

		/* in case an IP address has been passed as device name */
		device = libnet_getdevice(l);

		/* according to documentation, "can be null without error" after previous call */
		if (!device)
			device = pcap_lookupdev(errbuf);
		if (!device)
			croak("can't obtain the device name, pcap_lookupdev(): %s", errbuf);

		rr = libnet_name2addr4(l, dst_ip, LIBNET_RESOLVE);
		if (rr == -1) croak("bad dst ip address\n");
		snprintf(filter_app, sizeof(filter_app), "arp [7]==%d and src ", ARPOP_REPLY);
		strncat(filter_app, libnet_addr2name4(rr, LIBNET_DONT_RESOLVE), sizeof(filter_app)-strlen(filter_app));

		src_ip = libnet_get_ipaddr4(l);
		if (! src_ip ) croak("libnet_get_ipaddr4 failed: %s", libnet_geterror(l));
		src_mac = libnet_get_hwaddr(l);
		if (! src_mac) croak("libnet_get_hwaddr failed: %s", libnet_geterror(l));

		ptag = libnet_autobuild_arp(ARPOP_REQUEST, src_mac->ether_addr_octet, (u_int8_t*) &src_ip, enet_dst, (u_int8_t*) &rr, l);
		if (ptag == -1) croak("building ARP packet failed: %s", libnet_geterror(l));

		ptag = libnet_autobuild_ethernet(enet_dst, ETHERTYPE_ARP, l);
		if (ptag == -1) croak("building ethernet packet failed: %s", libnet_geterror(l));

		handle = pcap_open_live(device, 200, 0, timeout*1000, errbuf);
		if (! handle) croak("pcap_open_live failed\n");

		if ( pcap_setnonblock(handle, 1, errbuf) == -1 )
			croak("pcap_setnonblock() failed: %s", errbuf);

		if ( pcap_compile(handle, &filter, filter_app, 0, -1) == -1 )
			croak("pcap_compile failed\n");

		if ( pcap_setfilter(handle, &filter) == -1 )
			croak("pcap_setfilter failed\n");

		pcap_freecode(&filter);

		{
			int packet_size = libnet_getpacket_size(l);
			int i = libnet_write(l);
			if (i == -1)
				croak("libnet_write(): %s", libnet_geterror(l));
			if (i != packet_size)
				croak("failed, sent only %d bytes\n", i);
		}

		{
			struct pcap_pkthdr *h;
			const u_char *packet;
			int nap_counter = 0,
			    timer = timeout;

			while (timer >= 0) {
				int res = pcap_next_ex( handle, &h, &packet );
				//fprintf(stderr, "res=%d\n", res);
				if ( res == 0 ) {                               // no packets ready for read
					if ( nap_counter++ < 2 ) {                  // try nanosleep before sleep()
						struct timespec nap = { 0, 35000 };     // sleep 2x35ms
						//fprintf(stderr, "nanosleep\n");
						nanosleep(&nap, NULL);
					}
					else if ( timer ) {                         // timeout not exceeded yet
						//fprintf(stderr, "sleep\n");
						sleep(1);
						--timer;
					}
					else
						break;                                  // end loop: timeout
				}
				else if ( res == 1 ) {                          // read OK; handle the packet
					struct ethhdr *eth = (struct ethhdr*)packet;
					struct arphdr *harp = (struct arphdr*)((char*)eth + sizeof(struct libnet_ethernet_hdr));
					unsigned char *cp = (u_char*)harp + sizeof(struct arphdr);

					if (   
						   htons(harp->ar_pro) == ETH_P_IP 
						&& htons(harp->ar_hrd) == ARPHRD_ETHER
					   )
					{
						char tt[4];
						unsigned int i;
						result[0] = '\0';

						for (i=0; i<harp->ar_hln-1; i++) {
							snprintf(tt, 4, "%.2x:", *cp++);
							strcat(result, tt);
						}
						snprintf(tt, 3, "%.2x", *cp);
						strcat(result, tt);
						break;                                  // end loop: OK
					}
				}
				else
					break;                                      // end loop: read error
			}
		}

		pcap_close(handle);
		libnet_close_link(l);
		libnet_destroy(l); 

		RETVAL = ( result ? result : "0" );  // ARGH!

		OUTPUT:
			RETVAL

# vim: ts=4 sw=4 noet si

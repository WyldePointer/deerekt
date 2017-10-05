/*
 * Copyright (c) 2017, Sohrab Monfared <sohrab.monfared@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    * Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *    * Neither the name of the <organization> nor the
 *      names of its contributors may be used to endorse or promote products
 *      derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>

void
deerekt_print_dns_lookup(const u_char *query)
{

  unsigned int len = 0;
  unsigned int i=0;
  unsigned j=0;

  len = query[0];

  while (1) {

    j = 0;

    while (j++ < len) {
      putchar(query[i+j]); 
    }

    len = query[i+j];

    i += j;

    if (query[i]) {

      putchar('.');

    } else {

      break;

    }

  }

  switch (query[i+2]) {

    /* RFC 1035 */
    case 1:   puts(" A ");          break;
    case 2:   puts(" NS ");         break;
    case 5:   puts(" CNAME ");      break;
    case 6:   puts(" SOA ");        break;
    case 12:  puts(" PTR ");        break;
    case 15:  puts(" MX ");         break;
    case 16:  puts(" TXT ");        break;

    case 28:  puts(" AAAA ");       break; /* RFC 3596 */
    case 43:  puts(" DS ");         break; /* RFC 3658 */
    case 46:  puts(" RRSIG ");      break; /* RFC 3755 */
    case 48:  puts(" DNSKEY ");     break; /* RFC 3755 */
    case 50:  puts(" NSEC3 ");      break; /* RFC 5155 */
    case 51:  puts(" NSEC3PARAM "); break; /* RFC 5155 */
    case 99:  puts(" SPF ");        break; /* RFC 4408 */
    case 250: puts(" TSIG ");       break; /* RFC 2845, RFC 3645 */

    default:
      printf(" %d \n", query[i+2]);
  }

}

void
deerekt_parse_packet(u_char *args, const struct pcap_pkthdr* header,
  const u_char* packet)
{

  struct ip *ip = NULL;
  unsigned int ip_header_length = 0;
  unsigned int caplen = header->caplen;

  if (caplen < sizeof(struct ether_header)) {
    fprintf(stderr, "%d Incomplete Ethernet header.\n", (int)time(NULL));
    return;
  }

  /* Skip over the Ethernet header. */
  packet += sizeof(struct ether_header);
  caplen -= sizeof(struct ether_header);

  if (caplen < sizeof(struct ip)) {
    fprintf(stderr, "%d Incomplete IP header.\n", (int)time(NULL));
    return;
  }

  ip = (struct ip*) packet;

  ip_header_length = ip->ip_hl * 4;

  if (caplen < ip_header_length) {
    fprintf(stderr, "%d IP header without proper options.\n", (int)time(NULL));
    return;
  }

  /* Skip over the IP header. */
  packet += ip_header_length;
  caplen -= ip_header_length;

  if (caplen < 8) {
    fprintf(stderr, "%d Incomplete UDP header.\n", (int)time(NULL));
    return;
  }

  /* QR(first bit of flags) is 0 in case of DNS query. */
  if ( ! ((uint8_t)*(packet+10) & 128) ) {
    printf("%d ", (int)time(NULL));
    deerekt_print_dns_lookup((packet)+20); /* 8(UDP) + 12(DNS) */
  }

}

int main(int argc, char *argv[]) {

  pcap_t *handle = NULL;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program filter;
  bpf_u_int32 ip = 0;
  bpf_u_int32 netmask = 0;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <device>\n", argv[0]);
    return 1;
  }

  if (pcap_lookupnet(argv[1], &ip, &netmask, errbuf) == -1) {
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    ip = 0;
    netmask = 0;
  }

  handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

  if (handle == NULL) {
    fprintf(stderr, "Failed to open %s: %s\n", argv[1], errbuf);
    return 2;
  }

  if (pcap_compile(handle, &filter, "udp port 53", 0, ip) == -1) {
    fprintf(stderr, "%s\n", pcap_geterr(handle));
    return 3;
  }

  if (pcap_setfilter(handle, &filter) == -1) {
    fprintf(stderr, "%s\n", pcap_geterr(handle)); 
    return 4;
  }

  pcap_loop(handle, 0, deerekt_parse_packet, NULL);

  return 0;
}

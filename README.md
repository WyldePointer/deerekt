A utility for logging your outgoing DNS requests.

## Output
```
1507213825 openbsd.org A
1507213835 freebsd.org A
1507215841 mirror.yandex.ru A
1507215841 mirror.yandex.ru AAAA
1507215842 183.204.180.213.in-addr.arpa PTR
```

## Dependencies
 - `libpcap`

## Compile
`$ cc -o deerekt -lpcap -pedantic -std=c89 -Wall -D_DEFAULT_SOURCE main.c` 

## Running
`# ./deerekt eth0`

## Supported records
 - A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, DS, RRSIG, DNSKEY, NSEC3, NSEC3PARAM,
 SPF, TSIG.

#### TODO
 - Millisecond accuracy.
 - Redis backend.
 - JSON formatting.
 - Verbose option.
 - Use cases.
 - Testing on OSX and other *NIXs.

#### Currently tested on
 - Debian 9 / gcc 6.3.0 / libpcap 1.8.1-3

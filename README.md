The packet sniffer to capture only ip and mac address.
==========

[![License](http://img.shields.io/badge/license-BSD3-brightgreen.svg)](https://tldrlegal.com/license/bsd-3-clause-license-%28revised%29)

The packet sniffer to capture only ip and mac address.
This simple program purpose is understanding DSR(Direct Server Return).

## Dependencies
* gcc
* libpcap

## Compatibility
I have tested in linux but other OS is not tested.

## Installation

1. Clone the git repository.

  ```
  shell> git clone git://github.com/vozlt/sniff-ipmac.git
  ```

2. Compile
  ```
  shell> make
  ```

  ```
  gcc -Wall   -c ipmac.c -o ipmac.o
  gcc -o ipmac ipmac.o -lpcap
  ```

## Usage
```
USAGE   :
       ipmac [OPTION]... [EXPRESSION]

OPTIONS :
       -c [loop counter] (default : 0)
       -i [interface] (default : eth0)
       -v verbose print
       -n no ansi color

       Single Option :
       -m [HOST] (find mac address)
EXAMPLE:
       ipmac "ip"
       ipmac -c 5 "host 10.10.10.10 and port http"
       ipmac -v -c 5 "host 10.10.10.10 and port http"
       ipmac -m 192.168.0.1
```

## Running

### Capturing ip & mac

```
shell> ./ipmac -c 8 "ip"
```

```
# interface: eth0

SOURCE                                     DESTINATION
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
10.10.10.18:22    04:01:11:76:6a:01 ~> 10.10.10.66:40572 00:00:5e:00:01:64
```

### Capturing ip & mac & verbose

```
shell> ./ipmac -c 8 "port 80"
```

```
# Interface: eth0



+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Ethernet Header: 14byte                                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| - Source MAC Address      : 04:01:11:76:6a:01                 |
| - Destination MAC Address : 00:00:5e:00:01:64                 |
| - Ether Type              : 0x800                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| IPv4 Header: 20byte + Options(If exists max is 40byte)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| - Header Length    : 5                                        |
| - Version          : 4                                        |
| - Service Type     : 0                                        |
| - Total Length     : 1500                                     |
| - Ident            : 35117                                    |
| - Fragment Offset  : 16384                                    |
| - TTL              : 64                                       |
| - Protocol         : 6                                        |
| - Checksum         : 52217                                    |
| - Src Address      : 10.10.10.18                              |
| - Dst Address      : 10.10.10.66                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| TCP Header: 20byte + Options(If exists max is 40byte)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| - Src Port         : 80                                       |
| - Dst Port         : 33746                                    |
| - Seq Number       : 1947323077                               |
| - Ack number       : 1352167591                               |
| - Data Offset      : 5                                        |
| - Flags Urg        : 0x00                                     |
| - Flags Ack        : 0x01                                     |
| - Flags Psh        : 0x00                                     |
| - Flags Rst        : 0x00                                     |
| - Flags Syn        : 0x00                                     |
| - Flags Fin        : 0x00                                     |
| - Window           : 9216                                     |
| - Checksum         : 58819                                    |
| - Urgent Pointer   : 0                                        |
| - Data Length      : 1460                                     |
|   HTTP/1.1 200 OK..Server: nginx..Date: Fri, 20 Mar 2015 0    |
|   7:01:09 GMT..Content-Type: text/html; charset=utf-8..Tra    |
|   nsfer-Encoding: chunked..Connection: keep-alive..Keep-Al    |
|   ive: timeout=10..Vary: Accept-Encoding..Content-Encoding    |
|   : gzip....748.....                                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

00000 48 54 54 50 2f 31 2e 31 20 32 30 30 20 4f 4b 0d 0a 53 65 72 HTTP/1.1 200 OK..Ser
00020 76 65 72 3a 20 6e 67 69 6e 78 0d 0a 44 61 74 65 3a 20 46 72 ver: nginx..Date: Fr
00040 69 2c 20 32 30 20 4d 61 72 20 32 30 31 35 20 30 37 3a 30 31 i, 20 Mar 2015 07:01
00060 3a 30 39 20 47 4d 54 0d 0a 43 6f 6e 74 65 6e 74 2d 54 79 70 :09 GMT..Content-Typ
00080 65 3a 20 74 65 78 74 2f 68 74 6d 6c 3b 20 63 68 61 72 73 65 e: text/html; charse
00100 74 3d 75 74 66 2d 38 0d 0a 54 72 61 6e 73 66 65 72 2d 45 6e t=utf-8..Transfer-En
00120 63 6f 64 69 6e 67 3a 20 63 68 75 6e 6b 65 64 0d 0a 43 6f 6e coding: chunked..Con
00140 6e 65 63 74 69 6f 6e 3a 20 6b 65 65 70 2d 61 6c 69 76 65 0d nection: keep-alive.
00160 0a 4b 65 65 70 2d 41 6c 69 76 65 3a 20 74 69 6d 65 6f 75 74 .Keep-Alive: timeout
00180 3d 31 30 0d 0a 56 61 72 79 3a 20 41 63 63 65 70 74 2d 45 6e =10..Vary: Accept-En
00200 63 6f 64 69 6e 67 0d 0a 43 6f 6e 74 65 6e 74 2d 45 6e 63 6f coding..Content-Enco
00220 64 69 6e 67 3a 20 67 7a 69 70 0d 0a 0d 0a 37 34 38 0d 0a 1f ding: gzip....748...
00240 8b 08                                                       ..
.
.
.
.
```

### Finding mac address

```
shell> ./ipmac -m 10.10.10.55
```

```
10.10.10.55's mac address is 04:01:2c:75:ab:01
```

## Author
YoungJoo.Kim(김영주) [<vozlt@vozlt.com>]

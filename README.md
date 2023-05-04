# Project 2 - ZETA: Network sniffer

## Zadání:
- Navrhněte a implementujte síťový analyzátor, který bude schopen zachytit a filtrovat pakety na konkrétním síťovém rozhrání
- Vytvořte dokumentaci k projektu.

## Úvod:
Program implementovaný v jazyce C, který zachycuje a analyzuje síťové pakety s využitím knihovny libpcap. Tato knihovna nabízí funkce pro zachycení síťového provozu a analýzu packetů. Celá implementace se nachází v souboru `ipk-sniffer.c`.

## Implementace ipk-sniffer.c:
Na záčátku ve funkci `main()` se použije funkce `pcap_findalldevs()`, která načte všechny dostupné rozhrání a vrátí ukazatel na první rozhrání v seznamě. Náseledně se zkontroluje zda je počet argumentů větší jak dva (pokud je dán jeden argument jsou vytisknuté dostupné rozhraní pomocí funkce `print_interface()`, která na konci uvolní seznam alokovaných zařízení pomocí funkce `pcap_freealldevs()`) a zahájí se cyklus na kontrolu argumentů a nastavení vlajek přítomnosti protokolů. Tato kontrola probíhá pomocí funkce `getopt()` z knihovny `getopt.h`, která postupně parsuje argumenty. V rámci kontroli `inteface` se kontroluje zda se za argumentem nachází název a ne další argument.Tato kontrola podporuje krátké (např. `-t`) a dlouhé (`--tcp`) typy argumentů. V případě pokud nebyl zadán argument `.i`, tak se vypíší dostupné rozhraní pomocí funkce `print_interface()`. Následeně proběhne kontrola pomocí řady podmínek zda byly zadáný nějaké specifické typy paketů, které se mají odchytávat. Tyto argumenty se pomocí funkce `strcat()` spojí do jednoho řetězce a na konci se odstraní nadbytečné slovo `or`. Poté získáme masku a IP adresu sítě pomocí funkce `pcap_lookupnet()` a dále použijeme funkci `pcap_open_live()`, která otevře rozhraní a vrátí popisovač. Pomocí funkce `pcap_compile()` zkompilujeme filtry a pomocí funkce `pcap_setfilter()` tyto filtry nastavíme. Pokud všechny předchoží funkce proběhly bez problému vykonáme funkci `pcap_loop()`, která zpracovává pakety ze živého vysílaní podle nastaveného filtru. Funkci lze předat počet, který má zachytit, který bereme z argumentu `-n` (defaultě je nastavený na 1). Pro zpracování jednotlivých odchycených paketů je této funcki předávána funkce `process_packet()`. Na konci je zařízení uzavřeno pomoc `pcap_close()` a program úspěšně ukončen.
### Implementace funkce process_packet():
V této funkci se vypíše čas, kdy byl paket zachycený pomocí funkce `print_time()`. Jsou vytvořeny struktury pro IP hlavičku a pro jednotlivé pakety protokolů, které obsahují potřebné informace. Pomocí proměnné `ehternet_header`, která se nachází v struktuře `ether_header` se zkontroluje zda se jedná o IPv4, IPv6 nebo ARP. Uvnitř podmínky pro IPv4 se nachází switch, který rozhoduje, ke kterému protokolu paket patří. Vypíší se potřebné informace o paketech a těmi jsou: zdrojová a cílová MAC adresa, délka paketu, zdrojová a cílová IP adresa a zdrojový a cílový port. Pro výpis paketů se používá funkce `print_packet()`. IPv6 funguje podobný způsobem akorát na principu podmínek namísto switche a navíc používá funcki `print_ipv6` pro výpis IPv6 adresy. Porty jsou vypisovány pouze u protokolů TCP a UDP. 

## Testy:
### TCP
### Wireshark:
`telnet google.com`
`./ipk-sniffer -i enp0s3 -p 23 --tcp -n 2`
```sh
# Packet 4 from /var/tmp/wireshark_enp0s3GrexnE.pcapng
- 5
- 2023-04-17 15:39:15,441880221
- 0.000478251
- 10.0.2.15
- 142.251.36.142
- TCP
- 74
- 46696 → 23 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=111514150 TSecr=0 WS=128

0000   52 54 00 12 35 02 08 00 27 78 63 87 08 00 45 10   RT..5...'xc...E.
0010   00 3c 50 27 40 00 40 06 2a ed 0a 00 02 0f 8e fb   .<P'@.@.*.......
0020   24 8e b6 68 00 17 27 c1 aa 7e 00 00 00 00 a0 02   $..h..'..~......
0030   fa f0 bf c6 00 00 02 04 05 b4 04 02 08 0a 06 a5   ................
0040   92 26 00 00 00 00 01 03 03 07                     .&........
----
# Packet 5 from /var/tmp/wireshark_enp0s3GrexnE.pcapng
- 6
- 2023-04-17 15:39:16,463080851
- 1.021200630
- 10.0.2.15
- 142.251.36.142
- TCP
- 74
- [TCP Retransmission] [TCP Port numbers reused] 46696 → 23 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=111515171 TSecr=0 WS=128

0000   52 54 00 12 35 02 08 00 27 78 63 87 08 00 45 10   RT..5...'xc...E.
0010   00 3c 50 28 40 00 40 06 2a ec 0a 00 02 0f 8e fb   .<P(@.@.*.......
0020   24 8e b6 68 00 17 27 c1 aa 7e 00 00 00 00 a0 02   $..h..'..~......
0030   fa f0 bf c6 00 00 02 04 05 b4 04 02 08 0a 06 a5   ................
0040   96 23 00 00 00 00 01 03 03 07                     .#........
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 -p 23 --tcp -n 2
timestamp: 2023-04-17T15:39:16.463116+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 74 bytes
src IP: 10.0.2.15
dst IP: 142.251.36.142
src port: 46696
dst port: 23

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 00 45 10    RT..5...'xc...E.
0x0010   00 3c 50 27 40 00 40 06  2a ed 0a 00 02 0f 8e fb    .<P'@.@.*.......
0x0020   24 8e b6 68 00 17 27 c1  aa 7e 00 00 00 00 a0 02    $..h..'..~......
0x0030   fa f0 bf c6 00 00 02 04  05 b4 04 02 08 0a 06 a5    ................
0x0040   92 26 00 00 00 00 01 03  03 07                      .&........

timestamp: 2023-04-17T15:39:16.463180+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 74 bytes
src IP: 10.0.2.15
dst IP: 142.251.36.142
src port: 46696
dst port: 23

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 00 45 10    RT..5...'xc...E.
0x0010   00 3c 50 28 40 00 40 06  2a ec 0a 00 02 0f 8e fb    .<P(@.@.*.......
0x0020   24 8e b6 68 00 17 27 c1  aa 7e 00 00 00 00 a0 02    $..h..'..~......
0x0030   fa f0 bf c6 00 00 02 04  05 b4 04 02 08 0a 06 a5    ................
0x0040   96 23 00 00 00 00 01 03  03 07                      .#........
```
### UDP
### Wireshark
`telnet google.com`
`./ipk-sniffer -i enp0s3 --udp`
```sh
# Packet 6 from /var/tmp/wireshark_enp0s3ko0EmK.pcapng
- 1
- 2023-04-17 15:34:32,483286890
- 0.000000000
- 10.0.2.15
- 192.168.0.1
- DNS
- 70
- Standard query 0xaf09 AAAA google.com
0000   52 54 00 12 35 02 08 00 27 78 63 87 08 00 45 00   RT..5...'xc...E.
0010   00 38 7d 22 00 00 40 11 30 db 0a 00 02 0f c0 a8   .8}"..@.0.......
0020   00 01 a6 f3 00 35 00 24 cc ed af 09 01 00 00 01   .....5.$........
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 1c 00 01                                 m.....
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 --udp
timestamp: 2023-04-17T15:34:33.070745+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 70 bytes
src IP: 10.0.2.15
dst IP: 192.168.0.1

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 00 45 00    RT..5...'xc...E.
0x0010   00 38 7d 22 00 00 40 11  30 db 0a 00 02 0f c0 a8    .8}"..@.0.......
0x0020   00 01 a6 f3 00 35 00 24  cc ed af 09 01 00 00 01    .....5.$........
0x0030   00 00 00 00 00 00 06 67  6f 6f 67 6c 65 03 63 6f    .......google.co
0x0040   6d 00 00 1c 00 01                                   m.....
```
### ICMP4 a ICMP6 
### Wireshark:
`ping6 ff02::1%enp0s3`
`./ipk-sniffer -i enp0s3 --icmp4 --icmp6`
```

# Packet 0 from /var/tmp/wireshark_enp0s3RpsF3h.pcapng
- 1
- 2023-04-17 15:43:21,629182453
- 0.000000000
- fe80::cee0:4ddc:f719:6824
- ff02::1
- ICMPv6
- 118
- Echo (ping) request id=0x0003, seq=1, hop limit=1 (multicast)

0000   33 33 00 00 00 01 08 00 27 78 63 87 86 dd 60 08   33......'xc...`.
0010   0f d3 00 40 3a 01 fe 80 00 00 00 00 00 00 ce e0   ...@:...........
0020   4d dc f7 19 68 24 ff 02 00 00 00 00 00 00 00 00   M...h$..........
0030   00 00 00 00 00 01 80 00 70 e3 00 03 00 01 f9 4c   ........p......L
0040   3d 64 00 00 00 00 96 99 09 00 00 00 00 00 10 11   =d..............
0050   12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21   .............. !
0060   22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31   "#$%&'()*+,-./01
0070   32 33 34 35 36 37                                 234567
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 --icmp4 --icmp6
timestamp: 2023-04-17T15:43:22.607887+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 33:33:00:00:00:01
frame length: 118 bytes
fe80:0000:0000:0000:cee0:4ddc:f719:6824 > ff02:0000:0000:0000:0000:0000:0000:0001
0x0000   33 33 00 00 00 01 08 00  27 78 63 87 86 dd 60 08    33......'xc...`.
0x0010   0f d3 00 40 3a 01 fe 80  00 00 00 00 00 00 ce e0    ...@:...........
0x0020   4d dc f7 19 68 24 ff 02  00 00 00 00 00 00 00 00    M...h$..........
0x0030   00 00 00 00 00 01 80 00  70 e3 00 03 00 01 f9 4c    ........p......L
0x0040   3d 64 00 00 00 00 96 99  09 00 00 00 00 00 10 11    =d..............
0x0050   12 13 14 15 16 17 18 19  1a 1b 1c 1d 1e 1f 20 21    .............. !
0x0060   22 23 24 25 26 27 28 29  2a 2b 2c 2d 2e 2f 30 31    "#$%&'()*+,-./01
0x0070   32 33 34 35 36 37                                   234567
```
### ARP 
### Wireshark:
`telnet google.com`
`./ipk-sniffer -i enp0s3 --arp`
```
# Packet 4 from /var/tmp/wireshark_enp0s3NfDLUw.pcapng
- 5
- 2023-04-17 15:49:31,438754053
- 5.055423427
- PcsCompu_78:63:87
- RealtekU_12:35:02
- ARP
- 42
- Who has 10.0.2.2? Tell 10.0.2.15
0000   52 54 00 12 35 02 08 00 27 78 63 87 08 06 00 01   RT..5...'xc.....
0010   08 00 06 04 00 01 08 00 27 78 63 87 0a 00 02 0f   ........'xc.....
0020   00 00 00 00 00 00 0a 00 02 02                     ..........
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 --arp
timestamp: 2023-04-17T15:49:31.631364+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 42 bytes
src IP: 10.0.2.15
dst IP: 10.0.2.2

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 06 00 01    RT..5...'xc.....
0x0010   08 00 06 04 00 01 08 00  27 78 63 87 0a 00 02 0f    ........'xc.....
0x0020   00 00 00 00 00 00 0a 00  02 02                      ..........
```
## ARP 
`sudo tcpreplay -t -i enp0s3 arp_pcap.pcapng.cap`
`./ipk-sniffer -i enp0s3 --arp`
### Wireshark:
```
# Packet 9 from /var/tmp/wireshark_enp0s3DstELy.pcapng
- 10
- 2023-04-17 16:06:52,312568229
- 0.000002757
- c4:01:32:58:00:00
- c4:02:32:6b:00:00
- ARP
- 60
- Who has 10.0.0.2? Tell 10.0.0.1

0000   c4 02 32 6b 00 00 c4 01 32 58 00 00 08 06 00 01   ..2k....2X......
0010   08 00 06 04 00 01 c4 01 32 58 00 00 0a 00 00 01   ........2X......
0020   c4 02 32 6b 00 00 0a 00 00 02 00 00 00 00 00 00   ..2k............
0030   00 00 00 00 00 00 00 00 00 00 00 00               ............
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 --arp
timestamp: 2023-04-17T16:06:52.719033+02:00
src MAC: c4:01:32:58:00:00
dst MAC: c4:02:32:6b:00:00
frame length: 60 bytes
src IP: 10.0.0.1
dst IP: 10.0.0.2

0x0000   c4 02 32 6b 00 00 c4 01  32 58 00 00 08 06 00 01    ..2k....2X......
0x0010   08 00 06 04 00 01 c4 01  32 58 00 00 0a 00 00 01    ........2X......
0x0020   c4 02 32 6b 00 00 0a 00  00 02 00 00 00 00 00 00    ..2k............
0x0030   00 00 00 00 00 00 00 00  00 00 00 00                ............
```
## IGMP 
`sudo tcpreplay -t -i enp0s3 IGMP_V1.cap`
`./ipk-sniffer -i enp0s3 --igmp -n 2`
### Wireshark:
```
# Packet 0 from /var/tmp/wireshark_enp0s3DigROG.pcapng
- 1
- 2023-04-17 16:16:33,516224430
- 0.000000000
- 10.0.200.151
- 224.0.0.1
- IGMPv1
- 60
- Membership Query

0000   01 00 5e 00 00 01 5c d9 98 f9 1c 18 08 00 46 00   ..^...\.......F.
0010   00 20 00 02 00 00 01 02 72 3d 0a 00 c8 97 e0 00   . ......r=......
0020   00 01 94 04 00 00 11 00 ee ff 00 00 00 00 00 00   ................
0030   00 00 00 00 00 00 00 00 00 00 00 00               ............
----
# Packet 1 from /var/tmp/wireshark_enp0s3DigROG.pcapng
- 2
- 2023-04-17 16:16:33,516243697
- 0.000019267
- 10.0.200.163
- 224.0.0.252
- IGMPv1
- 60
- Membership Report

0000   01 00 5e 00 00 fc 78 2b cb 99 fb 5b 08 00 46 00   ..^...x+...[..F.
0010   00 20 53 ab 00 00 01 02 1d 8d 0a 00 c8 a3 e0 00   . S.............
0020   00 fc 94 04 00 00 12 00 0d 03 e0 00 00 fc 00 00   ................
0030   00 00 00 00 00 00 00 00 00 00 00 00               ............
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 --igmp -n 2
timestamp: 2023-04-17T16:16:34.287936+02:00
src MAC: 5c:d9:98:f9:1c:18
dst MAC: 01:00:5e:00:00:01
frame length: 60 bytes
src IP: 10.0.200.151
dst IP: 224.0.0.1

0x0000   01 00 5e 00 00 01 5c d9  98 f9 1c 18 08 00 46 00    ..^...\.......F.
0x0010   00 20 00 02 00 00 01 02  72 3d 0a 00 c8 97 e0 00    . ......r=......
0x0020   00 01 94 04 00 00 11 00  ee ff 00 00 00 00 00 00    ................
0x0030   00 00 00 00 00 00 00 00  00 00 00 00                ............

timestamp: 2023-04-17T16:16:34.288006+02:00
src MAC: 78:2b:cb:99:fb:5b
dst MAC: 01:00:5e:00:00:fc
frame length: 60 bytes
src IP: 10.0.200.163
dst IP: 224.0.0.252

0x0000   01 00 5e 00 00 fc 78 2b  cb 99 fb 5b 08 00 46 00    ..^...x+...[..F.
0x0010   00 20 53 ab 00 00 01 02  1d 8d 0a 00 c8 a3 e0 00    . S.............
0x0020   00 fc 94 04 00 00 12 00  0d 03 e0 00 00 fc 00 00    ................
0x0030   00 00 00 00 00 00 00 00  00 00 00 00                ............
```
## Pouze interface
`sudo ./ipk-sniffer -i enp0s3`
`./ipk-sniffer -i enp0s3`
### Wireshark:
```
# Packet 2 from /var/tmp/wireshark_enp0s3ZnKH7J.pcapng
- 3
- 2023-04-17 16:31:12,889991214
- 0.842270722
- 10.0.2.15
- 142.251.36.142
- TCP
- 74
- 43500 → 23 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=114631598 TSecr=0 WS=128¨

0000   52 54 00 12 35 02 08 00 27 78 63 87 08 00 45 10   RT..5...'xc...E.
0010   00 3c fc 98 40 00 40 06 7e 7b 0a 00 02 0f 8e fb   .<..@.@.~{......
0020   24 8e a9 ec 00 17 eb c3 c1 6d 00 00 00 00 a0 02   $........m......
0030   fa f0 bf c6 00 00 02 04 05 b4 04 02 08 0a 06 d5   ................
0040   23 ae 00 00 00 00 01 03 03 07                     #.........
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3
timestamp: 2023-04-17T16:31:13.263342+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 74 bytes
src IP: 10.0.2.15
dst IP: 142.251.36.142

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 00 45 10    RT..5...'xc...E.
0x0010   00 3c fc 98 40 00 40 06  7e 7b 0a 00 02 0f 8e fb    .<..@.@.~{......
0x0020   24 8e a9 ec 00 17 eb c3  c1 6d 00 00 00 00 a0 02    $........m......
0x0030   fa f0 bf c6 00 00 02 04  05 b4 04 02 08 0a 06 d5    ................
0x0040   23 ae 00 00 00 00 01 03  03 07                      #.........
```
## Bez interface
`./ipk-sniffer -i`
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i
Name: enp0s3   Description: (null) 
Name: any   Description: Pseudo-device that captures on all interfaces 
Name: lo   Description: (null) 
Name: bluetooth-monitor   Description: Bluetooth Linux Monitor 
Name: usbmon1   Description: Raw USB traffic, bus number 1 
Name: usbmon0   Description: Raw USB traffic, all USB buses 
Name: nflog   Description: Linux netfilter log (NFLOG) interface 
```
## Mnoho argumentů
`./ipk-sniffer -i enp0s3 -p 22 --tcp --udp --icmp4 --icmp6 --arp --igmp`
### Wireshark:
```
# Packet 7 from /var/tmp/wireshark_enp0s3kA8aTA.pcapng
- 8
- 2023-04-17 16:38:29,294826083
- 2.239930406
- PcsCompu_78:63:87
- RealtekU_12:35:02
- ARP
- 42
- Who has 10.0.2.2? Tell 10.0.2.15

0000   52 54 00 12 35 02 08 00 27 78 63 87 08 06 00 01   RT..5...'xc.....
0010   08 00 06 04 00 01 08 00 27 78 63 87 0a 00 02 0f   ........'xc.....
0020   00 00 00 00 00 00 0a 00 02 02                     ..........
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer -i enp0s3 -p 22 --tcp --udp --icmp4 --icmp6 --arp --igmp
timestamp: 2023-04-17T16:38:30.127300+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 42 bytes
src IP: 10.0.2.15
dst IP: 10.0.2.2

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 06 00 01    RT..5...'xc.....
0x0010   08 00 06 04 00 01 08 00  27 78 63 87 0a 00 02 0f    ........'xc.....
0x0020   00 00 00 00 00 00 0a 00  02 02                      ..........
```
## --interface TCP
`./ipk-sniffer --interface enp0s3 --tcp`
`telnet google.com`
### Wireshark:
```
# Packet 4 from /var/tmp/wireshark_enp0s3S0thFe.pcapng
- 5
- 2023-04-17 16:59:41,605866232
- 0.000430899
- 10.0.2.15
- 142.251.36.142
- TCP
- 74
- 40334 → 23 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM=1 TSval=116340314 TSecr=0 WS=128

0000   52 54 00 12 35 02 08 00 27 78 63 87 08 00 45 10   RT..5...'xc...E.
0010   00 3c 8f 65 40 00 40 06 eb ae 0a 00 02 0f 8e fb   .<.e@.@.........
0020   24 8e 9d 8e 00 17 3f 05 c7 88 00 00 00 00 a0 02   $.....?.........
0030   fa f0 bf c6 00 00 02 04 05 b4 04 02 08 0a 06 ef   ................
0040   36 5a 00 00 00 00 01 03 03 07                     6Z........
```
### My output:
```
[michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer --interface enp0s3 --tcp
timestamp: 2023-04-17T16:59:42.575838+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 74 bytes
src IP: 10.0.2.15
dst IP: 142.251.36.142

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 00 45 10    RT..5...'xc...E.
0x0010   00 3c 8f 65 40 00 40 06  eb ae 0a 00 02 0f 8e fb    .<.e@.@.........
0x0020   24 8e 9d 8e 00 17 3f 05  c7 88 00 00 00 00 a0 02    $.....?.........
0x0030   fa f0 bf c6 00 00 02 04  05 b4 04 02 08 0a 06 ef    ................
0x0040   36 5a 00 00 00 00 01 03  03 07                      6Z........
```
## -t -u --arp UCP
`telnet google.com`
`./ipk-sniffer --interface enp0s3 -t -u --arp`
### Wireshark:
```
# Packet 0 from /var/tmp/wireshark_enp0s3oJm9KX.pcapng
- 1
- 2023-04-17 17:04:10,890424006
- 0.000000000
- 10.0.2.15
- 192.168.0.1
- DNS
- 70
- Standard query 0x4798 AAAA google.com
- 
0000   52 54 00 12 35 02 08 00 27 78 63 87 08 00 45 00   RT..5...'xc...E.
0010   00 38 bb 50 00 00 40 11 f2 ac 0a 00 02 0f c0 a8   .8.P..@.........
0020   00 01 db 62 00 35 00 24 cc ed 47 98 01 00 00 01   ...b.5.$..G.....
0030   00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co
0040   6d 00 00 1c 00 01                                 m.....
```
### My output:
```
michal@fedora ipk-sniffer]$ sudo ./ipk-sniffer --interface enp0s3 -t -u --arp
timestamp: 2023-04-17T17:04:11.055049+02:00
src MAC: 08:00:27:78:63:87
dst MAC: 52:54:00:12:35:02
frame length: 70 bytes
src IP: 10.0.2.15
dst IP: 192.168.0.1

0x0000   52 54 00 12 35 02 08 00  27 78 63 87 08 00 45 00    RT..5...'xc...E.
0x0010   00 38 bb 50 00 00 40 11  f2 ac 0a 00 02 0f c0 a8    .8.P..@.........
0x0020   00 01 db 62 00 35 00 24  cc ed 47 98 01 00 00 01    ...b.5.$..G.....
0x0030   00 00 00 00 00 00 06 67  6f 6f 67 6c 65 03 63 6f    .......google.co
0x0040   6d 00 00 1c 00 01                                   m.....
```
## Zdroje:
- Programming with pcap | TCPDUMP & LIBPCAP. Home | TCPDUMP & LIBPCAP [online]. Copyright © 1999 [cit. 17.04.2023]. Dostupné z: https://www.tcpdump.org/pcap.html
- Home | TCPDUMP & LIBPCAP [online]. Dostupné z: https://www.tcpdump.org/other/sniffex.c
- Nut/OS: ether_header Struct Reference. Embedded Ethernet [online]. Copyright © [cit. 17.04.2023]. Dostupné z: http://www.ethernut.de/api/structether__header.html
- Forbidden - Stack Exchange. Forbidden - Stack Exchange [online]. Dostupné z: https://stackoverflow.com/questions/3727421/expand-an-ipv6-address-so-i-can-print-it-to-stdout
- How to Code Raw Sockets in C on Linux - BinaryTides. BinaryTides - Coding, Software, Tech and Reviews [online]. Copyright © 2023 [cit. 17.04.2023]. Dostupné z: https://www.binarytides.com/raw-sockets-c-code-linux/
- Home | TCPDUMP & LIBPCAP [online]. Copyright © 1999 [cit. 17.04.2023]. Dostupné z: https://www.tcpdump.org/manpages/pcap_open_live.3pcap.html
- Forbidden - Stack Exchange. Forbidden - Stack Exchange [online]. Dostupné z: https://stackoverflow.com/questions/5177879/display-the-contents-of-the-packet-in-c
- Forbidden - Stack Exchange. Forbidden - Stack Exchange [online]. Dostupné z: https://stackoverflow.com/questions/42840636/difference-between-struct-ip-and-struct-iphdr
- Packet Captures - PacketLife.net. PacketLife.net [online]. Dostupné z: https://packetlife.net/captures/protocol/icmp/
- C++ hex dump. ProgramCreek.com [online]. Dostupné z: https://www.programcreek.com/cpp/?CodeExample=hex+dump



# pcap_explorel
pcap explorel can be run on linux plateform
This cpp program can be used to campare two pacp files based on ipv4 id.
ipv6 support is not added.
This program depends on libpcap library . so before compiling wire_read.cpp file please install libpcap library

Steps to install libpcap library on linux Ubuntu refrence http://www.linuxfromscratch.org/blfs/view/svn/basicnet/libpcap.html 

1) wget http://www.tcpdump.org/release/libpcap-1.7.4.tar.gz 

2) wget http://www.linuxfromscratch.org/patches/blfs/svn/libpcap-1.7.4-enable_bluetooth-1.patch 

3) tar xf libpcap-1.7.4.tar.gz 

4) cd libpcap-1.7.4 

5) patch -Np1 -i ../libpcap-1.7.4-enable_bluetooth-1.patch && 

6) ./configure --prefix=/usr && 

7) make 

8) make install 


There is already precompiled binary for ubuntu 3.2.0-40-generic with name suraj_wi_debug

If you want you can compile for your linux.
just we need to compile wire_read.cpp using g++.
so compilation steps-

1) copy wire_read.cpp in some folder

2) g++ wire_read.cpp  -lpcap -o pcap_exp


Now we can run pcap_exp binary . for ruuning we have to give location of two pcap file to compare.
It will compare first wireshark with second wireshark file
When the binary will start with these two files it will ask for some soure filter things...
if you want to skip just press enter.
Perpose of filter is that if we want to filter for some perticuler source ip address or destination ip address.
This will compare source file with with filter detail to destination pcap file.
if no filter is given It will compare source & destination pcap file by source pcap id.
once the comparision is done It will create two file found.txt & not_found.txt in same location with detail
of found & not found packet details

EXAMPLE WITH NO FILTER---
$ ./suraj_wi_debug client.pcapng modem.pcap 
The argument supplied is source file=client.pcapng dest file =modem.pcap

source wireshart file packet type=EN10MB

source wireshart more detail::Ethernet packet type

destination wireshart file packet type=RAW

destination wireshart more detail::raw IP type

Enter filter source ip . press enter for exit::  (<<<<here Enter is press to skip source ip as filter)

Invalid source ip

Enter filter enter destination ip . press enter for exit::  (<<<<here Enter is press to skip destination ip as filter)

Invalid destination ip

You havent entered any filter . Now comparision will on based on ipv4 id
~~source_pcap_file==    client.pcapng
~~dest_pcap_file==      modem.pcap


doing comparision . please wait!


packet found count =848

packet drop or not found count =2099

~~~~comparision done . please check file=found.txt for found & file=not_found.txt for Drop~~~

$ cat  found.txt
FOUND current count=1   ipv4 PACKid =0x6a3a     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=2   ipv4 PACKid =0x6a3b     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=3   ipv4 PACKid =0x6a3c     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=4   ipv4 PACKid =0x6a3d     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=5   ipv4 PACKid =0x6a3e     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=6   ipv4 PACKid =0x6a3f     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=7   ipv4 PACKid =0x6a40     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=8   ipv4 PACKid =0x6a41     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=9   ipv4 PACKid =0x6a42     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 
FOUND current count=10  ipv4 PACKid =0x6a43     source ip=172.17.213.13         destination ip  65.55.252.43    protocol 6 

$ cat  not_found.txt
NOT FOUND current count=1       ipv4 PACKid =0x2910     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=2       ipv4 PACKid =0x3a12     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=3       ipv4 PACKid =0x2a9c     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=4       ipv4 PACKid =0x3a13     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=5       ipv4 PACKid =0x6a33     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=6       ipv4 PACKid =0x6a2e     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=7       ipv4 PACKid =0xa0a3     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  
NOT FOUND current count=8       ipv4 PACKid =0x6a2e     source ip=172.17.213.13         destination ip   10.64.218.26   protocol 6  

EXAMPLE WITH FILTER---
$ ./suraj_wi_debug client.pcapng modem.pcap 
The argument supplied is source file=client.pcapng dest file =modem.pcap

source wireshart file packet type=EN10MB

source wireshart more detail::Ethernet packet type

destination wireshart file packet type=RAW

destination wireshart more detail::raw IP type

Enter filter source ip . press enter for exit::202.154.164.205

Enter '&&' for 'and condition' ,enter '||' for 'or condition'::||

Enter filter enter destination ip . press enter for exit::10.4.45.86

You have enter source ip=202.154.164.205 mutual condistion=|| destination ip=10.4.45.86 as filter . 
Now comparision will on based on ((source_ip=202.154.164.205 || dest_ip=10.4.45.86))
~~source_pcap_file==    client.pcapng
~~dest_pcap_file==      modem.pcap


         doing comparision . please wait!


packet found count =13

packet drop or not found count =266

~~~~comparision done . please check file=found.txt for found & file=not_found.txt for Drop~~~




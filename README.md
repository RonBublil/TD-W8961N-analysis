# TD-W8961N Analysis

Hey,
This repository focuses on reverse engineering the TP-Link TD-W8961N router. These notes summarize my findings after a week of analyzing the router.

## **HTTP**
First i logged into the router's Webserver hosted at `192.168.1.1` while looking at the same time in `WireShark` i could easlly change the wifi password using a simple curl command I've added the script here (https://github.com/RonBublil/TD-W8961N-analysis/blob/main/changePassScript.sh).

### nmap scanning
after a quick port scan i saw that port 80,23 and 443 which was a UPnP port 
i mentiond below about further exploration with `Telnet`,moreover ,with the other ports i didnt find any significant information to mention here.

## Denial Of Service Attack

while using nuclei for finding any network vulnerabilities i came across something odd which caused the router to crash repeatedly with a crash report which was shown in my uart terminal 

TLB refill exception occured!
EPC= 0x801DBAA8
SR= 0x10000003
CR= 0x40805008
$RA= 0x00000000
Bad Virtual Address = 0x00000000
UTLB_TLBL ..\core\sys_isr.c:336 sysreset()


	$r0= 0x00000000	$at= 0x80300000	$v0= 0x00000000	$v1= 0x00000001
	$a0= 0x00000001	$a1= 0x8050BA8C	$a2= 0x00000001	$a3= 0x802A1510
	$t0= 0x8001FF80	$t1= 0xFFFFFFFE	$t2= 0x00001A30	$t3= 0x00000000
	$t4= 0x00000002	$t5= 0x00000005	$t6= 0x00000010	$t7= 0x00000A12
	$s0= 0x8051AC90	$s1= 0x803A4000	$s2= 0x00000001	$s3= 0x802C9794
	$s4= 0x802C9790	$s5= 0x8000007C	$s6= 0x00000000	$s7= 0x00000000
	$t8= 0x00000000	$t9= 0x00000000	$k0= 0x00000000	$k1= 0x8000007C
	$gp= 0x802C305C	$sp= 0x8051AC90	$fp= 0x8051AC90	$ra= 0x800EBCA4
 
Looking at the stack pointers we can the the `ra` pointer which is the return address pointer is critical for exploitation because in case of a Buffer Stack Overflow we could manipulate the flow control of the system.nevertheless, the `ra` pointer is concerning because its return address is not `0x00000000` which is weird for me.

Trying to understand which of the nuclei packets caused the crash i ran nuclei with a `-rl 1` for sending 1 packet for each second and then sending those packets using a python script or bash script. which both failed for me to crash the router which mean that there is might a timing factor here that caused the reapeted crash.



## **Hardware**
![ethernet card](https://github.com/RonBublil/TD-W8961N-analysis/blob/main/images/card.jpg)
![ethernet cpu](https://github.com/RonBublil/TD-W8961N-analysis/blob/main/images/cpu.jpg)
![The PCB](https://github.com/RonBublil/TD-W8961N-analysis/blob/main/images/pcb.jpg)



Upon examining the PCB, I noticed four pins that could be a UART interface. After further investigation, I confirmed they were indeed UART pins. The baud rate is 115200. When I connected to the UART shell, it booted up a custom shell with limited commands.


![The UART](https://github.com/RonBublil/TD-W8961N-analysis/blob/main/images/uart.jpg)


Unfortunately, I didn't find anything immediately useful through this interface.


![The flash](https://github.com/RonBublil/TD-W8961N-analysis/blob/main/images/flash.jpg)



Next, I extracted the firmware using a SOIC-8 clip and the flashrom software. The chip used is an EN25Q1N.


I then ran binwalk on the firmware binary file.

### Firmware Analysis
![Block1](https://github.com/RonBublil/TD-W8961N-analysis/blob/main/images/whole.png)

## `binwalk` Output

The following table represents the analysis from `binwalk` on the firmware file.

| **DECIMAL** | **HEXADECIMAL** | **DESCRIPTION**                                                                                         |
|-------------|-----------------|---------------------------------------------------------------------------------------------------------|
| 40960       | 0xA000          | ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16 |
| 49172       | 0xC014          | ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 0, uncompressed size: 0, data offset from start of block: 16 |
| 49192       | 0xC028          | ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 16 |
| 129251      | 0x1F8E3         | ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16 |
| 129500      | 0x1F9DC         | ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16 |
| 150579      | 0x24C33         | LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 66696 bytes   |
| 183572      | 0x2CD14         | Unix path: /usr/share/tabset/vt100:\
| 184340      | 0x2D014         | ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 0, uncompressed size: 0, data offset from start of block: 16 |
| 184360      | 0x2D028         | ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 16 |
| 193538      | 0x2F402         | GIF image data, version "89a", 200 x 50                                                                  |
| 201730      | 0x31402         | GIF image data, version "89a", 560 x 50                                                                  |
| 318877      | 0x4DD9D         | Neighborly text, "neighbor of your ADSL Router that will forward the packet to the destination..."      |
| 415151      | 0x655AF         | Copyright string: "Copyright (c) 2001 - 2021 TP-Link Corporation Limited."                             |
| 452035      | 0x6E5C3         | Copyright string: "Copyright &copy; 2021 TP-Link Corporation Limited. All rights reserved."            |
| 828979      | 0xCA633         | LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 2732124 bytes |
| 2035732     | 0x1F1014        | ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 0, uncompressed size: 0, data offset from start of block: 16 |
| 2035752     | 0x1F1028        | ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 16 |



The `binwalk` tool was run on the `firmware.bin` file, which was extracted from a device using a Bus Pirate and a SOIC-8 clip. The output reveals several interesting findings, including configuration blocks, compressed data, and file systems. Below is a summary of the significant findings:

### Key Findings:
1. **Configuration Blocks:**
   Multiple ZyXEL `rom-0` configuration blocks were identified in the firmware, such as `dbgarea`, `spt.dat`, and `autoexec.net`. These blocks are significant as they may contain device-specific configurations or script files.
   
2. **Compressed Data:**
   There are multiple instances of LZMA compressed data found at different offsets (`0x24C33`, `0xCA633`). This compressed data could be critical as it may contain firmware-related files that can be extracted for further analysis.
   
3. **File System Information:**
   Various Unix paths, like `/usr/share/tabset/vt100`, were discovered, indicating the presence of files that might be important for the device's operation. These files could provide further insight into the firmware's functionality.

## Binwalk Output - Kernel Image and Other Findings

This `binwalk` output shows the findings after extracting the LZMA file that was in the offset `0xCA633`.

### Binwalk Output Table - Kernel Image

| DECIMAL   | HEXADECIMAL | DESCRIPTION                                                                 |
|-----------|-------------|-----------------------------------------------------------------------------|
| 1179588   | 0x11FFC4     | TP-Link firmware header, firmware version: -24640.27395.-4500, image version: "Co., Ltd.", product ID: 0x65737320, product version: 1349478766, kernel load address: 0x11F50, kernel entry point: 0xEFFFFFFF, kernel offset: 1693673252, kernel length: 4156967956, rootfs offset: 3556796160, rootfs length: 469800426, bootloader offset: 3573675958, bootloader length: 1106012034 |


As shown here the first thing i found was the firmware img which included all the offsets for the rootfs which is located in `3556796160` which obviously ment that a filesystem is somewhere in that img and I can mount it, the main problem was that as shown above the offset is located in `3556796160` was way much bigger than file offset itself `1179588`.
which ment for me that the rootfs offset was an internal offset because the img might be compressed.
I've tried almost every way of decompressing the img using `gzip`,`lmza`.. but none of the ways worked for me 




# Telnet Access and Findings

## Overview
During the security assessment of the router, an open Telnet service was discovered. This service allowed access using default credentials, providing a restricted shell environment identical to the one accessed via UART.

## Telnet Configuration
- **Service:** Telnet  
- **Default Username:** `admin`  
- **Default Password:** `admin`  

## Behavior
After successfully logging in with the default credentials, the following observations were made:

- **Restricted Shell:**  
  Logging in granted access to a restricted shell environment.  

- **Limited Command Set:**  
  Only a small set of predefined commands was accessible. Commands like `ls`, `cat`, and `sh` were not available.  

- **No Administrative Privileges:**  
  The restricted shell did not allow execution of administrative or advanced commands. This limited exploration and deeper analysis of the system.

---

### Summary
The restricted shell through Telnet mirrored the behavior of the UART interface, indicating similar constraints in both interfaces. This raises questions about the router's default configurations and potential vulnerabilities for exploitation.

## UART

Using `picocom` at a `115200` baudrate i could the whole boot process of the router and later on a terminal was coming up that required a password which was admin.
The shell itself is limited with certain commands:
```
Copyright (c) 2001 - 2021 TP-Link Corporation Limited.
TP-LINK> ?
Valid commands are:
sys             exit            ether           wan               
etherdbg        tcephydbg       ip              ip6               
bridge          dot1q           pktqos          qdma              
show            set             lan                               
TP-LINK> sys
adjtime         countrycode     edit            feature           
hostname        log             resetlog        stdio             
time            syslog          version         skutbldisp        
dftpinswitch    setdftpin       view            wdog              
rstbtndisable   romreset        infohide        upnp              
atsh            setsid          dumpsidlist     wificalcheckflag  
diag            routeip         bridge          save              
display         password        default         adminname         
modelcheck      multiuser       defaultTCrestorepswauthen         
hangdbg         ledtr68         pppnamelock     defaultpwdcheck   
fwuptimeout     autocwmpoui     sptromsize      compileid         
dhcpprobe       dhcpfor2ndusr   pvcconfigflag   pswconfirmflag    
fortr69flag     hiddenaclruleflawanmulticastconvcwmp              
socket          filter          ddns            cpu               
snmp                                                              
TP-LINK> ether
config          driver          portreverse                       
TP-LINK> wan
atm             node            hwsar           tdebug            
adsl            tsarm                                             
TP-LINK> etherdbg
miir            miiw                                              
TP-LINK> tcephydbg
ver             miir            miiw            config            
testmode        macreg          reset           swpatch           
regcheck        loopback        send            sendrandom        
ping            pingechocnt     forcelink       errmonitor        
TP-LINK> ip
address         alias           arp             dhcp              
dhcpoption      dhcpsvrfilter   dns             httpd             
icmp            ifconfig        ping            route             
status          udp             rip             tcp               
dhcpautocalc    mut             mldproxy        igmp              
igmpv3          igmpsnoop       mldsnoop                          
TP-LINK> ip6
enable          debug           ifconfig        neigh             
route           radvd           tcp             udp               
ping            rawsock         wan             lan               
mssadjust       6rd             pktqos          icmp6_msg_filter  
ingress_filter  mldproxy        igmp            igmpv3            
igmpsnoop       mldsnoop                                          
TP-LINK> bridge
TP-LINK> dot1q
active          pvid            vlan            disp              
TP-LINK> pktqos
active          set             disp            status            
clear                                                             
TP-LINK> qdma
show            dbglevel        pbus_test       clear             
TP-LINK> show
wan             lan             cpe             community         
channel         all                                               
TP-LINK> set
cpe             lan             community       baudrate          
reboot                                                            
TP-LINK> lan
index           active          ipaddr          rip               
multicast       filter          display         dhcp              
clear           save                                              
TP-LINK> ok


```
### Ghidra reversing

However, using xxd did not reveal any signs of a filesystem. I imported the chunks into Ghidra, where the best language configuration for my analysis was MIPS 32 little-endian.

In Ghidra, I still encountered many undefined functions and couldn't find any keys or significant information to include here.




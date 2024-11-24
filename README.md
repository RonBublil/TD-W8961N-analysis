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
```
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


          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

8051ac90: 80 3a 40 00 80 10 23 88 40 80 50 08 80 1d ba a8     .:@...#.@.P.....
8051aca0: 10 00 00 03 80 2c 97 94 80 01 ff fc 80 2c a4 a0     .....,.......,..
8051acb0: 2e 2e 5c 63 6f 72 65 5c 73 79 73 5f 69 73 72 2e     ..\core\sys_isr.
8051acc0: 63 3a 33 33 36 20 73 79 73 72 65 73 65 74 28 29     c:336 sysreset()
8051acd0: 0a 00 a4 a0 80 02 b0 43 80 51 ac e0 ff ff a5 03     .......C.Q......
8051ace0: 80 1d ba a8 ff ff a5 5e 80 1d ba a8 80 02 b5 6d     .......^.......m
8051acf0: 00 00 00 03 00 00 00 00 00 00 00 00 40 80 50 08     ............@.P.
8051ad00: 80 51 ad 30 80 02 a4 68 80 2c b0 80 00 00 00 00     .Q.0...h.,......
8051ad10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051ad20: 00 55 54 4c 42 5f 54 4c 42 4c 00 00 80 2e 47 b4     .UTLB_TLBL....G.
8051ad30: 80 51 af 08 80 02 03 a8 00 00 00 00 80 27 00 00     .Q...........'..
8051ad40: 00 01 80 14 80 2e 30 94 00 00 00 00 80 0c 86 04     ......0.........
8051ad50: 00 00 00 00 80 2c ee 50 00 00 00 00 01 01 01 01     .....,.P........
8051ad60: 00 00 00 72 00 00 00 74 80 1d 85 ec 80 55 6d 7c     ...r...t.....Um|
8051ad70: 19 99 99 99 7f 7f 7f 7f 80 2c b0 80 00 00 00 00     .........,......
8051ad80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051ad90: 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 00     ................
8051ada0: 80 02 01 20 80 1d 82 04 80 2c 30 5c 80 51 ad 38     ... .....,0\.Q.8
8051adb0: 80 51 af 08 80 0c 83 cb 10 00 00 03 80 1d ba a8     .Q..............
8051adc0: 40 80 50 08 00 00 00 00 80 55 6d 7e 80 0c ed 00     @.P......Um~....
8051add0: 80 2c b0 90 80 55 6d 9e 80 2e 30 94 80 2c c5 10     .,...Um...0..,..
8051ade0: 80 55 6c a7 80 55 6d b9 80 55 6d 56 80 55 6d b7     .Ul..Um..UmV.Um.
8051adf0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051ae00: 80 2c c5 10 80 2c c5 10 80 2c ee 40 80 0c cf bb     .,...,...,.@....
8051ae10: 01 ac 00 00 80 2c c5 10 80 2c ee 40 80 0c f5 af     .....,...,.@....
8051ae20: 00 00 01 ac 80 04 49 00 80 2c b1 04 80 55 6c 78     ......I..,...Ulx
8051ae30: 00 00 00 00 80 2c b0 90 80 2f c5 60 80 2c b0 90     .....,.../.`.,..
8051ae40: 00 00 00 00 80 0c 59 99 80 2c c2 d8 80 2c c5 10     ......Y..,...,..
8051ae50: 80 2c b0 90 80 0c 59 d1 80 2c b0 90 80 0c 5a 31     .,....Y..,....Z1
8051ae60: 80 51 ae 0c 80 27 93 34 80 2c b0 90 80 0c 5d b5     .Q...'.4.,....].
8051ae70: 80 3a ff 7c 80 46 de 00 00 00 00 00 00 00 00 01     .:.|.F..........
8051ae80: 80 55 6c 78 80 03 01 ac 10 00 00 01 80 3a 99 68     .Ulx.........:.h
8051ae90: 00 00 00 00 80 2c b0 fc 00 00 00 00 80 2c b1 7c     .....,.......,.|
8051aea0: 00 00 00 00 80 2c b0 90 00 00 00 01 80 1d 00 50     .....,.........P
8051aeb0: 80 2c c4 e0 00 00 00 00 80 2c b0 80 80 2c b0 80     .,.......,...,..
8051aec0: 80 51 ae dc 80 51 ae e0 80 51 ae d0 80 27 a0 c8     .Q...Q...Q...'..
8051aed0: 00 00 00 00 80 0d 76 ad ef ef ef ef 00 00 00 00     ......v.........
8051aee0: 00 00 00 00 ef ef ef ef ef ef ef ef 80 3a 99 68     .............:.h
8051aef0: 10 00 00 01 80 1d aa 1c 00 00 00 00 00 00 00 00     ................
8051af00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051af10: ef ef ef ef 80 51 af 28 80 35 81 40 14 eb b6 dc     .....Q.(.5.@....
8051af20: 33 4c 14 eb b6 dc 33 4c 80 51 af 38 80 35 81 40     3L....3L.Q.8.5.@
8051af30: 80 2e 72 68 80 2e 72 74 80 51 b3 40 80 35 81 40     ..rh..rt.Q.@.5.@
8051af40: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051af50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051af60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051af70: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051af80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051af90: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051afa0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051afb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051afc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051afd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051afe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051aff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b030: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b040: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b050: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b060: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b070: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8051b080: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................

 current task   = httpd
 dump task      = network
 tx_stack_ptr   = 0x80507928
 tx_stack_start = 0x80503A84
 tx_stack_end   = 0x80507A83
 tx_stack_size  = 0x00004000
 tx_run_count   = 0x00002449
          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

80507928: 00 00 00 00 80 50 7a 08 80 30 77 c4 80 3a 94 e0     .....Pz..0w..:..
80507938: 80 30 78 58 80 30 78 5c 80 30 78 48 80 30 78 60     .0xX.0x\.0xH.0x`
80507948: 80 3a 94 e0 10 00 00 01 00 00 00 b5 00 00 00 00     .:..............
80507958: 80 1d 66 ec 10 00 00 01 00 00 1c da 14 02 04 00     ..f.............
80507968: 40 06 00 00 00 00 03 e8 80 50 7a 30 80 04 60 39     @........Pz0..`9
80507978: 80 3c cf 78 00 00 00 00 80 50 79 98 80 07 66 14     .<.x.....Py...f.
80507988: 80 44 14 38 00 00 48 3c 80 44 14 38 00 00 14 38     .D.8..H<.D.8...8
80507998: 80 50 7a 28 80 02 27 04 80 31 a6 3c 00 00 00 02     .Pz(..'..1.<....
805079a8: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
805079b8: 00 00 00 00 80 04 20 0f 80 44 14 38 80 2c 9c 40     ...... ..D.8.,.@
805079c8: 00 00 00 0e 80 47 7b 00 00 00 00 00 80 50 79 ec     .....G{......Py.
805079d8: 00 60 00 00 80 3f 93 b0 00 00 00 a1 c0 a8 01 01     .`...?..........
805079e8: 10 00 00 01 80 3a 94 e0 00 00 00 00 00 00 00 00     .....:..........
805079f8: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
80507a08: 80 50 7a 20 80 1d ab 2c 80 31 a6 3c 00 00 00 00     .Pz ...,.1.<....
80507a18: 00 00 00 00 80 3f 6c 20 80 50 7a 28 80 1d 7b b0     .....?l .Pz(..{.
80507a28: 80 50 7a 30 80 10 33 94 80 50 7a 60 80 02 11 c0     .Pz0..3..Pz`....
80507a38: 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00 00     ....... ........
80507a48: 80 3a 94 e0 10 00 00 01 ef ef ef ef 00 00 00 00     .:..............
80507a58: 80 41 14 18 80 02 0e 18 80 50 7a 78 80 1d aa 1c     .A.......Pzx....
80507a68: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
80507a78: 00 00 00 00 00 00 00 00 ef ef ef ef 80 50 ba 8c     .............P..
80507a88: 80 35 81 40 ef ef ef ef ef ef ef ef ef ef ef ef     .5.@............


 current task   = httpd
 dump task      = DMT TASK
 tx_stack_ptr   = 0x804628C0
 tx_stack_start = 0x80460A10
 tx_stack_end   = 0x80462A0F
 tx_stack_size  = 0x00002000
 tx_run_count   = 0x00000049
          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

804628c0: 00 00 00 00 80 46 29 a0 80 30 77 c4 80 3a 8c b8     .....F)..0w..:..
804628d0: 80 30 78 58 80 30 78 5c 80 30 78 48 80 30 78 60     .0xX.0x\.0xH.0x`
804628e0: 80 3a 8c b8 10 00 00 01 34 bb ff ff cb 44 00 00     .:......4....D..
804628f0: 80 1d 66 ec 10 00 00 01 02 00 02 00 02 00 02 00     ..f.............
80462900: 02 00 02 00 02 00 02 00 02 00 02 00 02 00 02 00     ................
80462910: 02 00 02 00 02 00 02 00 02 00 02 00 02 00 02 00     ................
80462920: 02 00 02 00 02 00 02 00 02 00 02 00 02 00 02 00     ................
80462930: 80 46 29 78 80 16 f6 70 00 00 00 06 80 26 0b 1c     .F)x...p.....&..
80462940: 02 02 02 00 00 00 00 00 00 00 00 11 00 00 00 53     ...............S
80462950: 80 46 29 78 80 16 f6 80 80 46 29 a0 80 16 f8 58     .F)x.....F)....X
80462960: 00 00 00 06 80 26 0b 7a 00 00 00 11 80 2b 00 00     .....&.z.....+..
80462970: 00 00 00 05 00 00 00 14 80 46 29 a0 80 16 f8 c4     .........F).....
80462980: 10 00 00 01 80 3a 8c b8 80 30 1e d0 00 00 00 09     .....:...0......
80462990: 00 00 33 6d 00 00 00 00 00 00 00 00 00 00 00 00     ..3m............
804629a0: 80 46 29 b8 80 1d ab 2c 80 30 1f 0c 80 30 21 30     .F)....,.0...0!0
804629b0: 80 30 1e d0 80 25 c1 0d 80 46 29 c0 80 1d 7b b0     .0...%...F)...{.
804629c0: 80 46 29 c8 80 10 33 94 80 46 29 e8 80 15 95 2c     .F)...3..F)....,
804629d0: 80 3a 8c b8 10 00 00 01 00 00 00 00 00 00 00 00     .:..............
804629e0: 00 00 00 00 ef ef ef ef 80 46 2a 00 80 1d aa 1c     .........F*.....
804629f0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
80462a00: 00 00 00 00 00 00 00 00 ef ef ef ef ef ef ef ef     ................


 current task   = httpd
 dump task      = HPnetwork
 tx_stack_ptr   = 0x8050B948
 tx_stack_start = 0x80507A8C
 tx_stack_end   = 0x8050BA8B
 tx_stack_size  = 0x00004000
 tx_run_count   = 0x000008EB
          00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

8050b948: 00 00 00 00 80 50 ba 28 80 30 77 c4 80 3a 95 c8     .....P.(.0w..:..
8050b958: 80 30 78 58 80 30 78 5c 80 30 78 48 80 30 78 60     .0xX.0x\.0xH.0x`
8050b968: 80 3a 95 c8 10 00 00 01 00 00 00 00 00 00 00 00     .:..............
8050b978: 80 1d 66 ec 10 00 00 01 00 00 41 10 18 02 04 c0     ..f.......A.....
8050b988: 01 02 04 78 94 04 00 00 00 00 b9 b8 01 00 5e 00     ...x..........^.
8050b998: 00 fb 98 25 4a a4 4e 18 80 50 b9 b8 80 07 66 14     ...%J.N..P....f.
8050b9a8: 80 40 eb 78 80 48 48 3c 80 3e 48 9c 80 40 eb 78     .@.x.HH<.>H..@.x
8050b9b8: 80 50 ba 48 80 02 27 54 80 31 a6 3c 00 00 00 01     .P.H..'T.1.<....
8050b9c8: 00 00 00 00 00 00 00 00 80 2e 71 28 00 00 00 00     ..........q(....
8050b9d8: 00 00 00 00 00 00 00 00 80 50 b9 fc 80 50 b9 fe     .........P...P..
8050b9e8: 00 00 00 0e 80 27 46 20 80 31 ce 20 80 50 ba 0c     .....'F .1. .P..
8050b9f8: 80 3d 09 3c 80 3f c2 9c 80 50 ba 50 80 10 5c 33     .=.<.?...P.P..\3
8050ba08: 10 00 00 01 80 3a 95 c8 00 00 00 00 00 00 00 00     .....:..........
8050ba18: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8050ba28: 80 50 ba 40 80 1d ab 2c 80 31 a6 3c 00 00 00 00     .P.@...,.1.<....
8050ba38: 00 00 00 00 80 3f c2 9c 80 50 ba 48 80 1d 7b b0     .....?...P.H..{.
8050ba48: 80 50 ba 50 80 10 33 94 80 50 ba 68 80 03 83 e4     .P.P..3..P.h....
8050ba58: 80 3a 95 c8 10 00 00 01 80 3f c2 9c 80 40 eb 78     .:.......?...@.x
8050ba68: 80 50 ba 80 80 1d aa 1c 00 00 00 00 00 00 00 00     .P..............
8050ba78: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00     ................
8050ba88: ef ef ef ef 80 50 ca 94 80 35 81 40 ef ef ef ef     .....P...5.@....


```
 
Looking at the stack pointers we can the the `ra` pointer which is the return address pointer is critical for exploitation because in case of a Buffer Stack Overflow we could manipulate the flow control of the system.nevertheless, the `ra` pointer is concerning because its return address is not `0x00000000` which is weird for me.

Trying to understand which of the nuclei packets caused the crash i ran nuclei with a `-rl 1` for sending 1 packet for each second and then sending those packets using a python script or bash script. which both failed for me to crash the router which ment that there is might a timing factor here that caused the reapeted crash.
I am still trying to figure out what could cause the problem cause each time a diffrent packet makes the router crash.



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
```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
40960         0xA000          ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
49172         0xC014          ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
49192         0xC028          ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 16
129251        0x1F8E3         ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
129500        0x1F9DC         ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
150579        0x24C33         LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 66696 bytes
183572        0x2CD14         Unix path: /usr/share/tabset/vt100:\
184340        0x2D014         ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
184360        0x2D028         ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 16
193538        0x2F402         GIF image data, version "89a", 200 x 50
201730        0x31402         GIF image data, version "89a", 560 x 50
318877        0x4DD9D         Neighborly text, "neighbor of your ADSL Router that will forward the packet to the destination. On the LAN, the gateway </font>e destination. On the LAN, the gateway </font>"
415151        0x655AF         Copyright string: "Copyright (c) 2001 - 2021 TP-Link Corporation Limited."
452035        0x6E5C3         Copyright string: "Copyright &copy; 2021 TP-Link Corporation Limited. All rights reserved."
828979        0xCA633         LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 2732124 bytes
2035732       0x1F1014        ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
2035752       0x1F1028        ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 16

```



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

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1179588       0x11FFC4        TP-Link firmware header, firmware version: -24640.27395.-4500, image version: " Co., Ltd.", product ID: 0x65737320, product version: 1349478766, kernel load address: 0x11F50, kernel entry point: 0xEFFFFFFF, kernel offset: 1693673252, kernel length: 4156967956, rootfs offset: 3556796160, rootfs length: 469800426, bootloader offset: 3573675958, bootloader length: 1106012034
2129272       0x207D78        Neighborly text, "neighbor loss) fail"
2132364       0x20898C        ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 8313
2145880       0x20BE58        Neighborly text, "neighbordown: can't shutdown OSPF task completely"
2156458       0x20E7AA        ZyXEL rom-0 configuration block, name: "spt.dat", compressed size: 769, uncompressed size: 259, data offset from start of block: 28805
2221212       0x21E49C        HTML document footer
2221529       0x21E5D9        HTML document header
2225232       0x21F450        XML document, version: "1.0"
2257977       0x227439        Base64 standard index table
2270625       0x22A5A1        ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 131
2270737       0x22A611        Copyright string: "Copyright (c) 1994 - 2004 ZyXEL Communications Corp."
2270790       0x22A646        Copyright string: "Copyright (c) 2001 - 2006 TrendChip Technologies Corp."
2270845       0x22A67D        Copyright string: "Copyright (c) 2001 - 2006 "
2271239       0x22A807        ZyXEL rom-0 configuration block, name: "dbgarea", compressed size: 0, uncompressed size: 0, data offset from start of block: 16
2283162       0x22D69A        eCos RTOS string reference: "ecost"
2334548       0x239F54        AES S-Box
2334804       0x23A054        AES Inverse S-Box
2336716       0x23A7CC        SHA256 hash constants, big endian
2338780       0x23AFDC        Base64 standard index table
2339728       0x23B390        DES PC1 table
2339784       0x23B3C8        DES PC2 table
2339944       0x23B468        DES SP1, big endian
2340200       0x23B568        DES SP2, big endian
2380577       0x245321        ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 135
2398520       0x249938        ZyXEL rom-0 configuration block, name: "autoexec.net", compressed size: 25972, uncompressed size: 11886, data offset from start of block: 131
2439572       0x253994        Base64 standard index table
2471164       0x25B4FC        XML document, version: "1.0"
2475432       0x25C5A8        XML document, version: "1.0"
2476264       0x25C8E8        XML document, version: "1.0"
2481652       0x25DDF4        XML document, version: "1.0"
2485892       0x25EE84        XML document, version: "1.0"
2497516       0x261BEC        XML document, version: "1.0"
2503040       0x263180        XML document, version: "1.0"
2523847       0x2682C7        Copyright string: "copyright"
2533419       0x26A82B        Copyright string: "copyright" >"
2637604       0x283F24        CRC32 polynomial table, big endian
2731172       0x29ACA4        Copyright string: "Copyright (c) 1996-2010 Express Logic Inc. * ThreadX MIPS32_34Kx/Green Hills Version G5.4.5.0 SN: 3182-197-0401 *"

```


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
I did try to find any memory related commands or and network services related commands but most of the commands are for configs,however i didnt check every command and i might missed something there.

### Ghidra reversing
 I tried to reverse two main files in ghidra one of them was the img file i found at the second the lzma compressed file `tplink.img` and the second one was the whole binary i extracted from the chip `firmware.bin`

in both of them i didnt explore enough to find something relatable to here.

# Summery

Hope this blog will help others with their research for any new leads please contact my email,
Thank you.



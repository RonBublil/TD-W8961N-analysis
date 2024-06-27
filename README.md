#TD-W8961N Analysis

Hey,
This repository focuses on reverse engineering the TP-Link TD-W8961N router. These notes summarize my findings after a week of analyzing the router.

##**HTTP**
When I opened Wireshark, I first looked at the HTTP packets sent by the router's interface when I signed in to 192.168.1.1. I noticed that the packets didn't contain any CSRF tokens. This means that if a user is still logged into the interface, I could send the same packets and change the interface settings as I like.

I uploaded a script that automates this process, assuming the default username and password are both "admin." You can modify the script to suit your preferences. The script also includes the packet contents for reference.



##**Hardware**
![ethernet card](images/card.png)
![ethernet cpu](images/cpu.png)
![The PCB](images/pcb.png)

Upon examining the PCB, I noticed four pins that could be a UART interface. After further investigation, I confirmed they were indeed UART pins. The baud rate is 115200. When I connected to the UART shell, it booted up a custom shell with limited commands.
![The UART](images/uart.png)
Unfortunately, I didn't find anything immediately useful through this interface.

![ethernet flash](images/flash.png)
Next, I extracted the firmware using a SOIC-8 clip and the flashrom software. The chip used is an EN25Q1N.


I then ran binwalk on the firmware binary file.

As you can see, we found two LZMA data files at offsets 0x23A7CC. Running binwalk -E provided the same information in the entropy graph.

We also observed two sections of null bytes in the data. I split the data file into three chunks using dd.

However, using xxd did not reveal any signs of a filesystem. I imported the chunks into Ghidra, where the best language configuration for my analysis was MIPS 32 little-endian.

In Ghidra, I still encountered many undefined functions and couldn't find any keys or significant information to include here.




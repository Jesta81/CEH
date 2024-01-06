# IoT Hacking Methodology

Using the IoT hacking methodology, an attacker acquires information through techniques such as gathering information, identifying attack surface area, and vulnerability scanning, and uses it to hack the target device and network. This section will focus on the tools and techniques used by attackers to achieve their goal of hacking the target IoT device.

## What is IoT Device Hacking? 

The objective of IoT device hacking is to **compromise smart devices** like CCTV cameras, automobiles, printers, door locks, and washing machines to gain unauthorized access to network resources and IoT devices. 

## IoT Hacking Methodology

The following are the different phases in hacking an IoT device: 
> 1. ### Information Gathering
>
> - The first step in IoT device hacking is to **extract information** such as IP address, protocols used, open ports, device type, geo location of a device, manufacturing number, and manufacturing company of a device.  
>
> 2. ### Vulnerability Scanning
>
> - Vulnerability scanning helps an attacker to identify the IoT devices with **weak configurations** such as hidden exploits, firmware bugs, weak settings and passwords, and poorly encrypted communications. 
>
> 3. ### Launch Attacks
>
> - The vulnerabilities found are exploited further to **launch various attacks** such as DoS attacks, rolling code attacks, jamming signal attacks, Sybil attacks, MITM attacks, data and identity theft attacks. 
>
> 4. ### Gain Remote Access
>
> - Based on the vulnerabilities in an IoT device, the attacker may turn the device into a **backdoor to gain access** to an organization’s network without infecting any end system that is protected by IDS/IPS, firewall, antivirus software, etc. 
>
> 5. ### Maintain Access
>
> - Attackers remain **undetected by clearing the logs**, update the firmware and use **malicious programs** such as backdoors and Trojans to maintain access. 


## Information Gathering using Shodan

> - [Shodan](https://www.shodan.io) provides information about all the **internet-connected devices** such as routers, traffic lights, CCTV cameras, servers, and smart home devices. 
>
> - Attackers can utilize this tool to gather information such as **IP address, hostname, ISP, device’s location and the banner of the target IoT device**.
>
> - Attackers can gather information on a target device using filters given below:
>
>> 1. ### Search for webcams using geolocation:
>> - **webcamxp** country: "US" 
>> - Obtains all the webcamxp webcams present in US. 
>>
>> 2. ### Search using city: 
>> - **webcamxp city: "streetsboro"**
>> - Obtains existing webcamxp webcams in Streetsboro. 
>>
>> 3. Find webcams using longitude and latitude: 
>> - **webcamxp geo:" -50.81.201.80"** 
>> - Obtains a specific webcam present at the geolocation “-50.81,201.80” in the city Boston and country US. 


## Information Gathering using MultiPing

> - An attacker can use [MultiPing](https://multiping.com) to **find the IP address of any IoT device** in the target network. 
>
> - After obtaining the IP address of an IoT device, the attacker can perform further scanning to **identify vulnerabilities** in that device. 
>
> Steps to perform scanning to identify the IP address of any IoT device: 
>> 1. Open the MultiPing application and select File →Add Address Range
>>
>> 2. Select the router's gateway IP address from the Initial Address to add drop-down field. 
>>
>> 3. Set the Number of addresses to “255”, and click the OK button. 
>>
>> 4. MultiPing will cycle through every possible IP address in the range you have selected, and it begins testing every IP address that responds to its ping. 
>>
>> 5. Each row in the MultiPing Window is a device on the network. From the list, the attacker can identify the IP address of the target IoT device. 
>>
>> 6. To find the target device faster, set the ping interval to 1. 

![MultiPing](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/MultiPing.png) 


## Information Gathering using FCC ID Search 

[FCC ID Search](https://www.fcc.gov/oet/ea/fccid) helps in finding the details of devices and the certification granted to them. The search page has several fields that allow the information of devices to be accessed. All the devices are labeled with unique FCC IDs. FCC IDs consist of two elements, known as the grantee ID (initial three or five characters) and product ID (remaining characters). 

Using the FCC ID, the target device details can be gathered by following the steps given below:

> 1. Open the device and examine the attached label. 
> 2. The label has the FCC ID of the device. 
> 3. Now, go to the FCC ID search for on the official page. 
> 4. Enter the grantee code and product ID in the fields. 
> 5. After entering the details, click **“search”** – it displays details and a summary of the device with different frequencies. 

![FCC ID](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/FCC-Search.png) 

> 6. The basic details of the device can be obtained by clicking the **"Summary"** link, as shown in the below screenshot: 

![FCC Summary](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/FCC-Summary.png) 

> 7. Further details of the device can be found by clicking on the **“Detail”** link, such as Cover letter, External photos, Internal photos, Test report, User manual, etc. 

![FCC Detail](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/FCC-Detail.png) 

After obtaining the required information, the attacker can find underlying vulnerabilities in the target device and launch further attacks. 


## Discovering IoT Devices with Default Credentails using IoTSeeker 

> - Attackers use tools such as [IoTSeeker](https://github.com) to discover IoT devices that are using default credentials and are vulnerable to various **hijacking attacks**. 
>
> - IoTSeeker will scan a network for specific types of IoT devices to detect if they are using the default, **factory set credentials**. 
>
> - This tool helps organizations to scan their networks to detect IoT devices using the **factory setting**. 

For example, attackers run the following command to find devices with default credentials: 

**perl iotScanner.pl 1.1.1.1-1.1.4.254,2.1.1.1-2.2.3.254**

![IoTSeeker](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/IoTSeeker.png) 


## Vulnerability Scanning using Nmap

Attackers use vulnerability scanning tools such as Nmap to identify all the IoT devices connected to the network along with their open ports and services. 

1. To scan for a specific IP address. 
**nmap -n -Pn -sS -pT:0-65535 -v -A -oX "Name" "IP"**. 

2. To check for open TCP and UDP services and ports. 
**nmap -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX "Name" "IP"**. 

3. To identify the IPv6 capabilities of a device. 
**nmap -6 -n -Pn -sSU -pT:0-65535,U:0-65535 -v -A -oX "Name" "IP"**. 

![Nmap](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/nmap.png) 


## Vulnerability Scanning using Retina IoT (RIoT) Scanner 

[Retina IoT (RIoT) Scanner](https://beyondtrust.com) identifies at-risk IoT devices, such as IP cameras, DVRs, printers, and routers. 

This tool gives you an attacker’s view of all the IoT devices and their associated vulnerabilities. 

> ### Features
> 1. Identify vulnerable IoT devices. 
> 2. Check for default or hard-coded passwords. 
> 3. Perform external scans of up to 256 IP addresses. 
> 4. Generates reports of IoT vulnerabilites and their remediation. 

![RIoT](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/RIoT.png) 


## Sniffing using Foren6 

Attackers use tools like [Foren6](https://cetic.github.io) to **sniff the traffic** of IoT devices. 

Foren6 uses sniffers to **capture 6LoWPAN traffic** and renders the network state in a graphical user interface. 

Foren6 captures all **RPL-related information** and identifies abnormal behaviors. 

It combines multiple sniffers and **captures live packets** from deployed networks in a non-intrusive manner. 

![Foren6 Sniffing](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Foren6.png) 

![Foren6 dashbord](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Foren6-2.png) 


## Sniffing using Wireshark

Many IoT devices, such as security cameras, host a website for controlling or configuring the cameras from a remote location. These websites mostly implement the insecure HTTP protocol instead of HTTPS, and are vulnerable to various attacks. If the cameras are using default factory credentials, an attacker can easily intercept all the traffic flowing between the camera and web application and further gain access to the camera itself. Attackers can use tools such as Wireshark to intercept such traffic and decrypt the Wi-Fi key of the target network. 

Steps used by attackers to sniff **wireless traffic of a web camera:**  

1. Run Nmap to identify IoT devices using insecure HTTP ports. 

**nmap -p 80,81,8080,8081 <IP>**. 

2. Now, set up your wireless card in monitor mode and identify the channel used by the target router for broadcasting. For this, run **ifconfig** to identify your wireless card, here: **wlan0**. 

3. Run **Airmon-ng** to put the wireless card in monitor mode: 

**airmon-ng start wlan0**. 

4. Next, run **Airodump-ng** to scan all the nearby wireless networks: 

**airodump-ng start wlan0mon**. 

5. Now, discover the target wireless network and note down the corresponding channel to sniff the traffic using Wireshark. 

6. Next, set up your wireless card to listen to the traffic on the same channel. For example, if the target network’s channel is 11, run **Airmon-ng** to set your wireless card listening on **channel 11**: 

**airmon-ng start wlan0mon 11**. 

7. Launch **Wireshark** and double-click the interface that was kept in monitor mode, here wlan0mon, and start capturing the traffic. 

After sniffing the traffic, attackers can decrypt the WEP and WPA keys using Wireshark and can hack the target IoT device to steal sensitive information.

![Wireshark](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Wireshark.png) 


## Analyzing Spectrum and IoT Traffic 

### Analyzing Spectrum using Gqrx 

[Gqrx](https://gprx.dk) is an SDR implemented with the help of the GNU Radio and Qt GUI tool. **Attackers use hardware devices such as FunCube dongles, Airspy, HackRF, and RTL-SDR along with Gqrx SDR, to analyze the spectrum**. Attackers use Gqrx to observe the frequency bands of temperature/humidity sensors, light switches, car keys, M-bus transmitters, etc. Gqrx can also enable an attacker to listen to or eavesdrop on radio FM frequencies or any radio conversations. 

Steps to analyze the spectrum using Gqrx: 
> 1. The Gqrx and GNU Radio package consists of all Gqrx utilities. To install this package, use the command given below: 
>
> - **apt-get install gnuradio gqrx**. 
>
> - Attackers use hardware tools such as the **FunCube Dongle Pro+**, connecting it to the USB-2 port on a PC to analyze various frequency bands. 
>
> 2. Launch Gqrx using the following command: 
>
> - **gqrx**
>
> - This command opens the input/output configuration window. 
>
> 3. Click on the **Start/Stop** button to activate/deactivate Gqrx. 
>
> 4. Once Gqrx is activated, the central window displays frequencies and their noises can be heard via a headphone or speaker. 

![Gqrx](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Gqrx.png) 
![Gqrx](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Gqrx-2.png) 

By changing the FFT settings (located at the bottom right side), you can capture and analyze different frequencies in the vicinity. 


## Analyzing IoT Traffic using IoT Inspector 

Attackers use [IoT Inspector](https://www-iot-inspector.com) to **discover the target IoT devices**, and to record and analyze their network traffic to identify vulnerabilities. 

![IoT Inspector](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/IoT-Inspector.png) 


## Rolling Code Attack using RFCrack 

Attackers use the [RFCrack](https://github.com) tool to obtain the **rolling code** sent by the victim to **unlock the vehicle** and later use the same code for unlocking. 

RFCrack is used for **testing RF communications** between any physical device that communicates over sub **Ghz frequencies**. 

Some of the commands used by an attacker to perform rolling code attacks, are given below: 

1. Live Replay: 

**python RFCrack.py -i**

2. Rolling code: 

**python RFCrack.py -r -M MOD_2FSK -F 314350000**

3. Adjust RSSI range: 

**python RFCrack.py -r -U "-75" -L "-5" -M MOD_2FSK -F 314350000**

4. Jamming: 

**python RFCrack.py -j -F 314000000**

5. Scan common frequencies: 

**python RFCrack.py -k**

6. Scan with your list: 

**python RFCrack.py -k -f 433000000 314000000 39000000**

7. Incremental scan: 

**python RFCrack.py -b -v 5000000**

8. Send saved payload: 

**python RFCrack.py -s -u ./files/test.cap -F 315000000 -M MOD_ASK_OOK** 

![RFCrack Rolling-Code Attack](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/RFCrack.png) 


## Hacking Zigbee Devices with Attify Zigbee Framework

Most of the IoT devices use the ZigBee protocol for **short-range wireless communication**. 

Attackers find **vulnerabilities in ZigBee** based IoT and smart devices and exploit them using tools like the [Attify ZigBee Framework](https://www.attify.com). 

The ZigBee protocol makes use of **16 different channels** for all communications. 

Attackers use **Zbstumbler** from the Attify Zigbee framework to identify the channel used by the target device. 

An attacker can perform a replay attack by **capturing and replaying the same packets** to observe the behavior of the device. 

![Attify Zigbee Framework](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Attify.png) 


## BlueBorne Attack Using HackRF One 

IoT devices include some sort of wireless communication using **RF or ZigBee or LoRa**. 

Attackers use [HackRF One](https://greatscottgadgets.com) to perform attacks such as **BlueBorne or AirBorne** attacks such as **replay, fuzzing, and jamming**. 

HackRF One is an advanced hardware and software-defined radio with the range of **1MHz to 6GHz**. 

It transmits and receives radio waves in **half-duplex mode**, so it is easy for attackers to perform attacks using this device. 

It can sniff a wide range of wireless protocols ranging from **GSM to Z-wave**. 

![HackRF One](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/HackRF-One.png) 


## Replay Attack using HackRF One 

Attackers use online resources such as the **FCC database** to determine the frequency of the target device. 

Attackers also use tools such as **RTL-SDR** to determine the frequency of the target device in the vicinity. 

Once the frequency is determined, attackers use tools such as **HackRF One** to launch a replay attack on the target device. 

**Steps to perform a replay attack on the target IoT device:**

1. Record the device’s signal using the following command: 

**hackrf_transfer -r connector.raw -f [device frequency]** 
> - Here, -r -> used to record the signal, -f -> frequency of the device. 

![HackRF One record signal](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/HackRF-One-record.png) 

2. Replay the signal to the target using the following command: 

**hackrf_transfer -t connector.raw -f [device frequency]** 
> - Here, -t -> used to replay the signal. 

![HackRF One replay](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/HackRF-One-replay.png) 

After executing the attack successfully, the attacker can command and control the target IoT device to perform further attacks.  


## SDR-Based Attacks using RTL-SDR and GNU Radio 

### Hardware-based attack (RTL-SDR) 

Attackers use hardware tools such as **[RTL-SDR](https://www.rtl-sdr.com)** to perform SDR-based attacks on IoT devices. 

The attacker can use **RTL-STR** to capture the active radio signals in the vicinity. 

It captures frequencies ranging from 500 kHz up to 1.75 GHz based on the selected SDR models. 

![RTL-SDR](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/RTL-SDR.png) 

Attackers use an RTL-SDR radio scanner to perform the following activities: 
> 1. Receiving and decoding GPS signals
> 2. Analyzing spectrum
> 3. Listening to DAB broadcst radio
> 4. Listening to and decoding HD radio
> 5. Sniffing GSM signals
> 6. Listening to VHF amateur radio
> 7. Scanning trunked radio conversations
> 8. Scanning for cordless phones 

### Software-based attack (GNU Radio) 

Along with hardware tools, attackers can also assault SDR-based IoT devices using various software tools, such as GNU Radio. 

[GNU Radio](https://www.gnuradio.org) consists of several pre-defined programs and tools such as **uhd_ft, uhd_rx_cfile, and uhd_rx_nogui** to perform SDR-based attacks. 

GNU Radio consists of a number of pre-defined programs and tools, which can be used for a variety of tasks. If it is installed from Python, the source files can be found in **gr-utils/src/python and gr-uhd/apps**. 

**uhd_ft**
> -  A spectrum analyzer tool that can be connected to a UHD device to find the spectrum at a given frequency. 

**uhd_rx_cfile** 
> - Stores wave samples with the help of a UHD device; samples can be stored in a file and analyzed later using GNU Radio or similar tools such as Matlab or Octave. 

**uhd_rx_nogui** 
> - Used to obtain and listen to the incoming signals on the audio device. 

**uhd_siggen_gui** 
> - Used to create simple signals such as sine, square, or noise. 

**gr_plot** 
> - Used to present previously recorded samples saved in a file. 

![GNU-Radio](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/GNU-Radio.png) 


## Side-Channel Attack using ChipWhisperer 

[ChipWhisperer](https://newae.com) is an open-source toolchain mainly used for **embedded hardware** security research. 

Attackers use ChipWhisperer for performing **side-channel power analysis and glitching attacks**. 

Side-channel power analysis allows attackers to **extract cryptographic keys** from a system. 

Attackers use ChipWhisperer for breaking the implementation of complex algorithms like AES and triple DES by using **power analysis attacks**. 

![ChipWhisperer](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/ChipWhisperer.png) 


## Identifying IoT Communication Buses and Interfaces 

Attackers identify various **serial and parallel interfaces** such as UART, SPI, JTAG, and I2C to gain access to a shell, extract firmware, and so on. 

Attackers use tools such as **BUS Auditor, Damn Insecure and Vulnerable Application (DIVA)**, a PCB, and the EXPLIoT framework to identify interfaces. 

### UART

Listed below are the steps involved in Identifying UART on a PCB without the data of micro controllers:  

1. Connect the two channels CH0 and CH1 of BUS Auditor to the UART header. 
2. Connect both the DIVA IoT board and BUS Auditor to the computer. 
3. Run the following command in the EXPLIoT framework: 

**run busauditor.generic.uartscan -v 3.3 -p /dev/ttyACM0 -s 0 -e 1** 

> - voltage -> -v
> - dev/tty* port -> -p
> - starting channel -> -s
> - ending channel -> -e

![UART](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/UART.png) 


### JTAG

The Joint Test Action Group (JTAG) adapted as IEEE 1149.1 consists of four pins—Test Mode Select (TMS), Test Clock (TCK), Test Data In (TDI), and Test Data Out (TDO)—and one additional optional pin, Test Reset (TRST). 

Listed below are the steps involved in identifying JTAG: 

1. Connect the CH0 to CH8 channels of BUS Auditor to the JTAG header. 
2. Connect both the DIVA board and BUS Auditor to the computer. 
3. Run the following command in the EXPLIoT framework: 

**run busauditor.generic.jtagscan -v 3.3 -p /dev/ttyACM0 -s 0 -e 10** 

![JTAG](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/JTAG.png) 


### I2C

Inter-Integrated Circuit (I2C) uses serial data (SDA) to send and receive data and a serial clock (SCL). 

Listed below are the steps involved in identifying I2C: 

1. Connect the CH0 to CH8 channels of BUS Auditor to the header. 
2. Connect both the DIVA board and BUS Auditor to the computer. 
3. Run the following command in the EXPLIoT framework: 

**run busauditor.generic.i2scan -v 3.3 -p /dev/ttyACM0 -s 0 -e 10** 

![I2C Scan](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/I2C.png) 


## NAND Glitching

NAND glitching is the process of **gaining privileged root access** while booting a device, which can be performed by making a ground connection to the serial I/O pin of a flash memory chip. 

### Steps for Implementing NAND Glitching Process 

1. Execute the following command to initiate a reconnaissance process using an UART-USB converter: 

**minicom -D /dev/ttyUSB0 -w -C -D-link_startup.txt** 

The above command returns bootlogs that are communicated during device boot up, which helps the attacker in obtaining the actual memory chip loaded with the booting firmware. 

#### Glitching

2. The next step is to short the serial I/O pin of flash memory chip to ground to interrupt the ongoing booting process, which results in the loading of backup loader code. 

![glitching](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/glitching.png) 
![glitching](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/glitching-2.png) 

3. Run the **printenv** command to view the bootargs loaded during this process, which returns the following: 

**bootargs=noinitrd  console=ttyAM0,115200  rootfstype=ubifsubi.mtd=5  root=ubi0:rootfs  rw gpmi  badupdater** 

![glitching](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/glitching-3.png) 

4. Run the following command to load the environment variables into the device: 

**setenv bootargs 'noinitrd console=ttyAM0,115200 rootfstype=ubifsubi.mtd=5 root=ubi0:rootfs rw gpmi init=/bin/sh';** 

5. Run the following command on the UART console to gain root access: 

**nand read ${loadaddr} app-kernel 0x00400000 && bootm ${loadaddr}** 

Here, the **bootm** command helps in loading the backup privileged booting image from the flash memory. 

![glitching](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/glitching-4.png) 


## Gaining Remote Access using Telnet

Attackers perform **port scanning** to learn about **open ports** and services on the target IoT device. 

Many embedded system applications in IoT devices such as industrial control systems, routers, VoIP phones, and televisions implement remote access capabilities using Telnet. 

If an attacker identifies that the **Telnet port is open**, he/she can exploit this vulnerability to **gain remote access** to the device. 

Attackers use tools such as **Shodan and Censys** to gain remote access to the target device. 

![Shodan](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Shodan.png) 


## Maintain Access by Exploiting Firmware 

Attackers **exploit the firmware** installed on the IoT device to **maintain access** on the device. 

After gaining remote access, the attackers explore the file system to **access the firmware on the device**. 

Attackers use tools such as **[Firmware Mod Kit](https://code.google.com)** to reconstruct the malicious firmware from the legitimate firmware. 

The Firmware Mod Kit allows for easy **deconstruction and reconstruction** of firmware images for various embedded devices. 

Using Firmware Mod Kit, attackers can perform the following activities: 
1. Extract a firmware image into its component parts. 
2. User makes a desired modification to the firmware’s file system or web UI (webif). 
3. Rebuild firmware. 
4. Flash modified firmware onto the device and brick it. 

The core scripts to facilitate firmware operations are listed below. 

![Firmware Mod Kit](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Firmware-Mod-Kit.png) 

![Firmware Mod Kit](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Firmware-Mod-Kit-2.png) 

## Firmware Analysis and Reverse Engineering

Attackers perform firmware analysis to **identify the passwords, API tokens and endpoints**, vulnerable services running, backdoor accounts, configuration files in use, private keys, stored data, etc. 

Steps used by attackers to perform firmware analysis and reverse engineering: 

1. ### Obtain Firmware 

After gaining access to the target IoT device, extract the firmware from the device. 

2. ### Analyze Firmware

Run the following commands to analyze the firmware: 

Run the **"file"** command on the **".bin"** file. 

Run the **"cat"** command on the **.md5** file. 

Run the **"md5sum"** command on the **.bin** file. 

Run **"strings"** against the **.bin** file

**strings -n 10 xyz.bin > strings.out | less strings.out** 

3. ### Extract the Filesystem

Run binwalk for analyzing, reverse-engineering, and extracting data from the firmware image. 

**binwalk xyz.bin** 

binwalk will identify the type of file system in use. 

Extract the filesystem using **"dd"** 

**dd if=xyz.bin bs=1 skip=922460 count=2522318 of=xyz.squashfs** 

4. ### Mount the Filesystem

Create a mount directory. 

**sudo mount -t ext2 {filename} rootfs** 

5. ### Analyze the Filesystem Content. 

Check the following files and folders once the filesystem is mounted. 

**etc/passwd, etc/shadow, etc/ssl** 

**grep -rnw '/path/to/somewhere/' -e “pattern”** such as password, admin, and root. 

**find . -name '.conf'** and other file types such as **.pem, .crt, .cfg, .sh, and .bin**. 

6. ### Emulate Firmware for Dynamic Testing

Perform dynamic testing of the web interface of the device using emulation software such as QEMU or Firmware Analysis Toolkit. 

**Identifying the CPU architecture:** Use commands such as **file or readelf** to determine the CPU architecture. 

![Reverse engineering](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/RE.png) 

![Reverse engineering](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/RE-2.png) 


## IoT Hacking Tools: Information-Gathering Tools

Attackers use information-gathering tools such as Shodan and Censys to gather basic information about the target device and network. Using these tools, attackers obtain information such as live devices connected to the network, their make, open ports and services, their physical location, etc. 

1. ### Censys
> - [Censys](https://censys.io) allows an attacker to **continually monitor every reachable server** and device on the Internet. 

![Censys](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Censys.png) 

2. ### Thingful
> - [Thingful](https://www.thingful.net) is a search engine for the Internet of Things to find and **use open IoT data** from around the world. 

![Thingful](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Thingful.png) 


## IoT Hacking Tools: Sniffing Tools

System administrators use automated tools to monitor their network and devices connected to the network, but attackers misuse these tools to sniff network data. Listed below are some of the tools that an attacker can use to sniff traffic generated by IoT devices. 

**[Suphacap](https://www.suphammer.net)**, a Z-Wave sniffer, is used to **sniff the traffic**, perform **real-time monitoring**, and capture packets from all Z-Wave networks. 

![Suphacap](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/Suphacap.png) 

Listed below are some of the additional tools used to sniff traffic generated by IoT devices:

> - [CloudShark](https://www.qacafe.com)
> - [Ubiqua Protocol Analyzer](https://www.ubilogix.com) 
> - [Perytons Protocol Analyzers](http://www.perytons.com) 
> - [tcpdump](https://www.tcpdump.org) 
> - [Open Sniffer](https://www.sewio.net) 


## IoT Hacking Tools: Vulnerability-Scanning Tools 

**[beSTORM](https://www.beyondsecurity.com)** is a **smart fuzzer** used to find **buffer overflow vulnerabilities** by automating and documenting the process of delivering corrupted input and watching for an unexpected response from the application. 

![beSTORM](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/beSTORM.png) 

Listed below are some of the additional vulnerability scanners for IoT devices:

> - [Metasploit Pro](https://www.rapid7.com) 
> - [IoTsploit](https://iotsploit.co) 
> - [IoTSeeker](https://information.rapid7.com) 
> - [Bitdefender Home Scanner](https://www.bitdefender.com) 
> - [IoT Inspector](https://www.iot-inspector.com)


## IoT Hacking Tools: Tools to Perform SDR-Based Attacks 

**[Universal Radio Hacker](https://github.com)** (URH) is software for **investigating unknown wireless protocols** used by various IoT devices. This tool allows attackers to perform the following activities: 

1. Identify hardware and interfaces for common SDRs. 
2. Perform demodulation of signals. 
3. Assign participants to keep an overview of data. 
4. Crack even sophisticated encodings like CC1101 data whitening. 
5. Assign labels to reveal the logic of the protocol. 
6. Perform automatic reverse engineering of protocol fields. 
7. Perform fuzzing component to find security leaks. 
8. Perform modulation to inject the data back into the system. 

![Universal Radio Hacker](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/URH.png) 

Listed below are some of the additional tools to perform SDR-based attacks: 
> - [BladeRF](https://www.nuand.com) 
> - [Rfcat](https://code.google.com)
> - [HackRF](https://greatscottgadgets.com)
> - [FunCube Dongle](https://www.funcubedongle.com)
> - [Gqrx](https://gqrx.dk) 


## Iot Hacking Tools

**[IoTVAS](https://firmalyzer.com)**  enables device vendors and security professionals to perform an **automated security assessment** on software that powers IoT devices (firmware) to **identify configuration and application vulnerabilities**. 

![IoTVAS](/IoT-and-OT-Hacking/IoT-Hacking-Methodology/images/IoTVAS.png) 

Listed below are some additional tools to perform IoT hacking: 

> - [Firmwalker](https://github.com) 
> - [rfcat-rolljam](https://github.com) 
> - [KillerBee](https://github.com) 
> - [GATTack.io](http://www.gattack.io) 
> - [JTAGULATOR](http://www/grandideastudio.com) 


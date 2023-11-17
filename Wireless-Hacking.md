# Hacking Wireless Networks #

## Wireless Concepts ##

1. Which of the following technologies is an air interface for 4G and 5G broadband wireless communications?


	1. DSSS
	2. [x] MIMO-OFDM
	3. FHSS
	4. OFDM


2. Which of the following terms describes the amount of information that may be broadcast over a connection?


	1. BSSID
	2. [x] Bandwidth
	3. ISM band
	4. Hotspot


3. Which of the following wireless standards uses modulation schemes such as GFSK, π/4-DPSK, and 8DPSK and a frequency of 2.4 GHz with data transfer rates in the range of 25–50 Mbps?


	1. [x] 802.15.1 (Bluetooth)
	2. 802.11a
	3. 802.11g
	4. 802.16 (WiMAX)


4. In LAN-to-LAN Wireless Network, the APs provide wireless connectivity to local computers, and computers on different networks that can be interconnected?


	False
	[x] True


5. Which of the following is used to connect wireless devices to a wireless/wired network?


	1. Hotspot
	2. Bandwidth
	3. [x] Access point (AP)
	4. Association


6. In which of the following processes do the station and access point use the same WEP key to provide authentication, which means that this key should be enabled and configured manually on both the access point and the client?


	1. WEP encryption
	2. [x] Shared key authentication process
	3. Open-system authentication process
	4. WPA encryption


7. Which of the following is considered as a token to identify a 802.11 (Wi-Fi) network (by default it is the part of the frame header sent over a wireless local area network (WLAN))?


	1. [x] SSID
	2. Association
	3. Access point
	4. Hotspot


8. Which of the following networks is used for very long-distance communication?


	1. Bluetooth
	2. ZigBee
	3. Wi-Fi
	4. [x] WiMax


9. Which of the following is considered as the method of transmitting radio signals by rapidly switching a carrier among many frequency channels?


	1. Multiple input, multiple output orthogonal frequency-division multiplexing (MIMO-OFDM)
	2. [x] Frequency-hopping Spread Spectrum (FHSS)
	3. Direct-sequence Spread Spectrum (DSSS)
	4. Orthogonal Frequency-division Multiplexing (OFDM)


10. Which of the following describes the amount of information that may be broadcasted over a connection?


	1. [x] Bandwidth
	2. Hotspot
	3. Association
	4. BSSID



## Wireless Hacking Methodology ##


1. In which of the following techniques does an attacker draw symbols in public places to advertise open Wi-Fi networks?


	1. Wardriving
	2. Warwalking
	3. [x] Warchalking 
	4. Warflying


2. Which of the following tools is designed to capture a WPA/WPA2 handshake and act as an ad-hoc AP?


	1. [x] Airbase-ng   **captures WPA/WPA2 handshake act as AP**

	2. Airolib-ng **stores pass lists**
	3. Airmon-ng     **managed to monitor mode**
	4. Airodump-ng    **capture packets**


3. Which of the following tools is used by an attacker to create rogue APs and perform sniffing and MITM attacks?


	1. Halberd   **Load Balance Detector**
	2. [x] MANA Toolkit     **Rogue AP**
	3. Skyhook    **GPS Mapping**
	4. Gobuster   **fuzzer**

4. Which of the following security standards contains the Dragonblood vulnerabilities that help attackers recover keys, downgrade security mechanisms, and launch various information-theft attacks?


	1. WPA
	2. WEP
	3. WPA2
	4. [x] WPA3


5. Which tool would be used to collect wireless packet data?


	1. John the Ripper
	2. Netcat
	3. [x] NetStumbler
	4. Nessus


6. There is a WEP encrypted wireless AP with no clients connected. In order to crack the WEP key, a fake authentication needs to be performed. Which of the following steps need to be performed by the attacker for generating fake authentication?


	1. Set the wireless interface to monitor mode
	2. [x] Ensure association of source MAC address with the AP
	3. Use cracking tools
	4. Capture the IVs


7. Andrew, a professional penetration tester, was hired by ABC Security, Inc., a small IT-based firm in the United States to conduct a test of the company’s wireless network. During the information-gathering process, Andrew discovers that the company is using the 802.11 g wireless standard. Using the NetSurveyor Wi-Fi network discovery tool, Andrew starts gathering information about wireless APs. After trying several times, he is not able to detect a single AP. What do you think is the reason behind this?


	1. [x] SSID broadcast feature must be disabled, so APs cannot be detected.
	2. Andrew must be doing something wrong, as there is no reason for him to not detect access points.
	3. NetSurveyor does not work against 802.11g.
	4. MAC address filtering feature must be disabled on APs or router.


8. Which of the following tools helps attackers identify networks by passively collecting packets and detecting standard named networks, hidden networks, and the presence of non-beaconing networks via data traffic?


	1. Netcraft   **OSINT**
	2. Robber    **DLL Hyjacking**
	3. L0phtCrack   **password cracking**
	4. [x] Kismet   **wireless packet capture**


10. Mark is working as a penetration tester in InfoSEC, Inc. One day, he notices that the traffic on the internal wireless router suddenly increases by more than 50%. He knows that the company is using a wireless 802.11 a/b/g/n/ac network. He decided to capture live packets and browse the traffic to investigate the issue to find out the actual cause. Which of the following tools should Mark use to monitor the wireless network?


	1. [x] CommView for Wi-Fi
	2. WiFiFoFum
	3. WiFish Finder
	4. BlueScan


11. Which of the following is a portable RFID cloning device that can be used by attackers to clone RFID tags?


	1. [x] iCopy-X
	2. KeyGrabber
	3. PCB-2040 Jammer
	4. Hardware Protocol Analyzer

	 Explanation:

    Hardware Protocol Analyzer: A hardware protocol analyzer is a device that interprets traffic passing over a network. It captures signals without altering the traffic segment.
    KeyGrabber: A KeyGrabber hardware keylogger is an electronic device capable of capturing keystrokes from a PS/2 or USB keyboard.
    **iCopy-X: iCopy-X is a portable RFID cloning device that can be used by attackers to clone RFID tags. It is an entirely stand-alone device with an integrated screen and buttons, providing the functionality of a Proxmark but without the need for an external computer.**
    PCB-2040 Jammer: An attacker can jam a wireless network using a Wi-Fi jammer. This device uses the same frequency band as a trusted network. It causes interference to legitimate signals and temporarily disrupts the network service.

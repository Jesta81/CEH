# Sniffing #

## Sniffing Concepts ##

1. In which of the following techniques does an attacker perform passive sniffing by installing malware on the victim’s machine and compromising it to install a sniffer?


	1. MAC flooding
	2. DNS poisoning
	3. Switch port stealing
	4. [x] Trojan horse


2. Which of the following protocols transmits email messages over the Internet in cleartext, allowing attackers to capture plaintext passwords?


	1. IMAP
	2. NNTP
	3. [x] SMTP
	4. FTP


3. In which of the following OSI layers do sniffers operate and perform an initial compromise?


	1. Transport layer
	2. Physical layer
	3. [x] Data link layer
	4. Network layer


4. Which of the following techniques is used by a third party to monitor telephone or Internet conversations with covert intentions?


	1. [x] Wiretapping
	2. ARP spoofing
	3. DNS spoofing
	4. VLAN hopping


5. What is the TCP/IP-based protocol used for exchanging management information between devices connected to a network?


	1. [x] SNMP
	2. IMAP
	3. NNTP
	4. POP


6. Which of the following protocols is used in the ARPA–Internet community to distribute, inquire into, retrieve, and post news articles through reliable stream-based transmission?


	1. FTP
	2. IMAP
	3. [x] NNTP
	4. POP


7. Which of the following protocols allows a user’s workstation to access mail from a mailbox server and send mail from the workstation to the mailbox server via SMTP?


	1. SMTP
	2. HTTP
	3. [x] POP
	4. FTP

8. Out of the following, which layer is responsible for encoding and decoding data packets into bits?


	1. Application layer
	2. Session layer
	3. Network layer
	4. [x] Data link layer


9. An attacker wants to monitor a target network traffic on one or more ports on the switch. In such a case, which of the following methods can he use?


	1. Lawful interception
	2. Wiretapping
	3. Active sniffing
	4. [x] Port mirroring

	 Explanation:

    The correct answer is (d). Switched port analyzer (SPAN) is a Cisco switch feature, also known as “port mirroring,” that monitors network traffic on one or more ports on the switch. It is a port that is configured to receive a copy of every packet that passes through a switch. It helps to analyze and debug data, identify errors, and investigate unauthorized network access on a network.


10. Sniffers work at which of the following open systems interconnect (OSI) layers?


	1. Application layer
	2. [x] Data link layer
	3. Presentation layer
	4. Transport layer


## Sniffing Techniques ##


1. Which of the following threats of ARP poisoning links multiple IP addresses with a single MAC address of a target host intended for different IP addresses and overloads it with a huge amount of traffic?


	1. [x] DoS attack
	2. Man-in-the-middle attack
	3. Session hijacking
	4. VoIP call tapping


2. Which of the following tools helps an attacker perform an ARP poisoning attack?


	1. Svmap
	2. Enyx
	3. [x] BetterCAP
	4. DNSRecon


3. Which of the following techniques is used by an attacker to connect a rogue switch to the network by tricking a legitimate switch and thereby creating a trunk link between them?


	1. Switch port stealing
	2. [x] Switch spoofing
	3. Double tagging
	4. IRDP spoofing


4. Which of the following techniques is also a type of network protocol for PNAC that is used to defend against MAC address spoofing and to enforce access control at the point where a user joins the network?


	1. Dynamic ARP inspection
	2. [x] IEEE 802.1X suites
	3. DHCP snooping binding table
	4. IP source guard


5. Which of the following security measures should be followed to defend against DNS spoofing?

1. Do not restrict DNS zone transfers to a limited set of IP addresses
2. Allow DNS requests being sent to external servers
3. Avoid using DNS non-existent domain (NXDOMAIN) rate limiting
4. [x] Restrict the DNS recusing service, either fully or partially, to authorized users


6. Which of the following techniques is used by attackers to compromise the security of network switches that connect network segments and force a switch to act as a hub to sniff the traffic easily?


	1. Switch spoofing
	2. [x] MAC flooding
	3. ARP spoofing
	4. Wiretapping


7. Which of the following IOS global commands verifies the DHCP snooping configuration?


	1. ip dhcp snooping trust
	2. no ip dhcp snooping information option
	3. [x] show ip dhcp snooping
	4. ip dhcp snooping


8. In one of the following techniques, an attacker must be connected to a LAN to sniff packets, and on successful sniffing, they can send a malicious reply to the sender before the actual DNS server. Which is this technique?


	1. DNS cache poisoning
	2. Proxy server DNS poisoning
	3. [x] Intranet DNS spoofing
	4. Internet DNS spoofing


9. Cyrus, a professional hacker, performed an ARP poisoning attack on a target network by using an automated tool. The tool used by Cyrus sends fake ARP messages to divert all communications between two machines so that all traffic is redirected through his machine.

	Which of the following tools did Cyrus employ in the above scenario?


	1. OpenVAS
	2. Nikto
	3. Nexpose
	4. [x] dsniff


10. Ross, an attacker, targeted an organization’s network to sniff the DNS traffic. For this purpose, he used a DNS poisoning tool that can create a list of fake DNS records and load it while running to redirect a target employee to a malicious website.

	Which of the following tools did Ross employ in the above scenario?


	1. Suricata
	2. DerpNSpoof
	3. Reaver
	4. WIBR+


11. A tester is attempting to capture and analyze the traffic on a given network and realizes that the network has several switches. What could be used to successfully sniff the traffic on this switched network? (Choose three.)


	1. Reverse smurf attack
	2. [x] Address resolution protocol (ARP) spoofing
	3. [x] MAC duplication
	4. [x] MAC flooding
	5. ARP broadcasting
	6. SYN flooding

	 Explanation:

    ARP spoofing is a technique by which an attacker sends (spoofed) ARP messages onto a local area network. In general, the aim is to associate the attacker’s MAC address with the IP address of another host, such as the default gateway, causing any traffic meant for that IP address to be sent to the attacker instead.
    MAC duplication is executed by an attacker by changing the MAC address of their host to match the MAC address of the target host on the network, making the switch forward the target packets to both the host on the network.
    MAC flooding is a technique employed to compromise the security of the network switches. Switches maintain a list (called a content addressable memory (CAM) table) that maps individual MAC addresses on the network to the physical ports on the switch.


12. What happens when a switch CAM table becomes full?


	1. The switch replaces outgoing frame switch factory default MAC address of FF:FF:FF:FF:FF:FF.
	2. The CAM overflow table will cause the switch to crash causing denial-of-service (DoS).
	3. Every packet is dropped and the switch sends out simple network management protocol (SNMP) alerts to the intrusion detection system (IDS) port.
	4. [x] The switch then acts as a hub by broadcasting packets to all machines on the network.


13. What method should be incorporated by a network administrator to prevent the organization’s network against ARP poisoning?


	1. Use SSL for secure traffic
	2. Use secure shell (SSH) encryption
	3. [x] Implement dynamic arp inspection (DAI) using the dynamic host configuration protocol (DHCP) snooping binding table
	4. Resolve all DNS queries to local DNS server


14. A network administrator wants to configure port security on a Cisco switch. Which of the following command helps the administrator to enable port security on an interface?


	1. switchport port-security aging type inactivity
	2. [x] switchport port-security
	3. switchport port-security aging time 2
	4. switchport port-security maximum 1


15. Out of the following options, identify the function of the following command performed on a Cisco switch. “switchport port-security mac-address sticky”


	1. Configures the secure MAC address aging time on the port
	2. Configures the switch port parameters to enable port security
	3. Configures the maximum number of secure MAC addresses for the port
	4. [x] Adds all secure MAC addresses that are dynamically learned to the running configuration


16. Which of the following is not a mitigation technique against MAC address spoofing?


	1. IP source guard
	2. DHCP snooping binding table
	3. Dynamic ARP inspection
	4. [x] DNS security (DNSSEC)

	 Explanation:

Following some of the techniques to defend against MAC address spoofing attacks:

    IP Source Guard: IP Source Guard is a security feature in switches that restricts the IP traffic on untrusted Layer 2 ports by filtering traffic based on the DHCP snooping binding database. It prevents spoofing attacks when the attacker tries to spoof or use the IP address of another host.
    DHCP Snooping Binding Table: The DHCP snooping process filters untrusted DHCP messages and helps to build and bind a DHCP binding table. This table contains the MAC address, IP address, lease time, binding type, VLAN number, and interface information to correspond with untrusted interfaces of a switch. It acts as a firewall between untrusted hosts and DHCP servers. It also helps in differentiating between trusted and untrusted interfaces.
    Dynamic ARP Inspection: The system checks the IP to MAC address binding for each ARP packet in a network. While performing a Dynamic ARP inspection, the system will automatically drop invalid IP to MAC address bindings.
    DNS Security (DNSSEC): Implement Domain Name System Security Extension (DNSSEC) to prevent DNS spoofing attacks.


17. Which of the following Cisco IOS global commands is used to enable or disable DHCP snooping on one or more VLANs?


	1. [x] ip dhcp snooping vlan 4,104
	2. no ip dhcp snooping information option
	3. switchport port-security mac-address sticky
	4. ip dhcp snooping

	 Explanation:

    Cisco OS Global Commands:
        ip dhcp snooping vlan 4,104
    Enable or disable DHCP snooping on one or more VLANs.
        ono ip dhcp snooping information option
    To disable the insertion and the removal of the option-82 field, use the no IP dhcp snooping information option in global configuration command. To configure an aggregation, switch to drop incoming DHCP snooping packets with option-82 information from an edge switch, use the no IP dhcp snooping information option allow-untrusted global configuration command.
        ip dhcp snooping
    Enable DHCP snooping option globally.
    Configuring Port Security on Cisco switch:
        switchport port-security mac-address sticky
    Enables sticky learning on the interface by entering only the mac-address sticky keywords. When sticky learning is enabled, the interface adds all secure MAC addresses that are dynamically learned to the running configuration and converts these addresses to sticky secure MAC addresses.


18. During the penetration testing, Marin identified a web application that could be exploited to gain the root shell on the remote machine. The only problem was that in order to do that he would have to know at least one username and password usable in the application. Unfortunately, guessing usernames and brute-forcing passwords did not work. Marin does not want to give up his attempts. Since this web application, was being used by almost all users in the company and was using http protocol, so he decided to use Cain & Abel tool in order to identify at least one username and password. After a few minutes, the first username and password popped-up and he successfully exploited the web application and the physical machine. What type of attack did he use in order to find the username and password to access the web application?


	1. TCP protocol hijacking
	2. [x] ARP spoofing
	3. UDP protocol hijacking
	4. DNS spoofing

	 Explanation:

    **ARP spoofing is the correct answer, and since there are no configuration or management options on switches it means that there is no ARP spoofing protection.**
    DNS spoofing is more complex and it is never the first option.
    TCP and UDP protocol hijacking does not make any sense here – after ARP spoofing all the traffic will be hijacked.


19. Which of the following is a network tool designed to take advantage of weaknesses in different network protocols such as DHCP?


	1. BCTextEncoder
	2. FileVault 2
	3. Secure Everything
	4. [x] Yersinia


20. Martin, a security professional, was tasked with enhancing the security of the switches connected to their organizational network. For this purpose, he applied MAC limiting feature on the switches. Now, Martin executed a command to verify if the MAC limiting process is perfectly implemented on each switch.

	Identify the command executed by Martin to verify MAC limiting process on a specific switch.


	1. ip dhcp snooping vlan number [number] | vlan {vlan range}]
	2. [x] show ethernet-switching table
	3. switchport port-security violation restrict
	4. switchport port-security aging time 2


## Sniffing Tools ##


1. Which of the following display filters in Wireshark is used by an attacker to perform filtering by multiple IP addresses?


	1. [x] ip.addr == 10.0.0.4 or ip.addr == 10.0.0.5
	2. ip.addr==192.168.1.100 && tcp.port=23
	3. ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip
	4. tcp.analysis. retransmission


2. Which of the following tools helps an attacker capture all the data transmitted over a network and perform expert analysis of each part of the target network?


	1. [x] OmniPeek
	2. DerpNSpoof
	3. ike-scan
	4. Spoof-Me-Now


3. Which of the following filters in Wireshark displays only the traffic in a LAN (192.168.x.x) between workstations and servers with no Internet?


	1. ip.addr==192.168.1.100 && tcp.port=23
	2. ip.addr == 10.0.0.4 or ip.addr == 10.0.0.5
	3. ip.src != xxx.xxx.xxx.xxx && ip.dst != xxx.xxx.xxx.xxx && sip
	4. [x] ip.src==192.168.0.0/16 and ip.dst==192.168.0.0/16


4. Karbon, a professional hacker, targeted an organization to bypass the network traffic. For this purpose, he used a network forensic analysis tool that can monitor and extract information from network traffic as well as capture application data contained in the network traffic.

	Which of the following tools did Karbon utilize in the above scenario?


	1. AnDOSid
	2. Akamai
	3. [x] Xplico
	4. Vindicate


	 Explanation:

    AnDOSid: AnDOSid allows the attacker to simulate a DoS attack (an HTTP POST flood attack to be precise) and DDoS attack on a web server from mobile phones.

    Xplico: The goal of Xplico is extract from an internet traffic capture the applications data contained. Xplico is an open source Network Forensic Analysis Tool (NFAT). Xplico is released under the GNU General Public License.
    Akamai: Akamai provides DDoS protection for enterprises regularly targeted by DDoS attacks. Akamai Kona Site Defender delivers multi-layered defense that effectively protects websites and web applications against the increasing threat, sophistication, and scale of DDoS attacks.
    Vindicate: Vindicate is an LLMNR/NBNS/mDNS spoofing detection toolkit for network administrators. Security professionals use this tool to detect name service spoofing.


5. Which of the following tools allows attackers to perform sniffing attempts on the target network?


	1. theHarvester
	2. Netcraft
	3. [x] RITA
	4. Sublist3r

## Sniffing Countermeasures ##


1. Which of the following countermeasures should be followed to defend against sniffing?


	1. Allow SSID broadcasting
	2. Use dynamic IP addresses and ARP tables
	3. [x] Use HTTPS to protect usernames and passwords
	4. Turn on network identification broadcasts


2. Which of the following protocols is not vulnerable to sniffing?


	1. Hypertext transfer protocol (HTTP)
	2. Telnet and Rlogin
	3. Post office protocol (POP)
	4. [x] Secure sockets layer (SSL)


3. A tester wants to securely encrypt the session to prevent the network against sniffing attack, which of the following protocols should he use as a replacement of Telnet?


	1. [x] SSH
	2. Intrusion prevention system (IPS)
	3. Public key infrastructure (PKI)
	4. Load balancing (LB)


4. Which of the following tool a tester can use to detect a system that runs in promiscuous mode, which in turns helps to detect sniffers installed on the network?


	1. shARP
	2. FaceNiff
	3. OmniPeek
	4. [x] Nmap

	 Explanation:

    Nmap: There are many tools, such as the Nmap that are available to use for the detection of promiscuous mode. Nmap’s NSE script allows you to check if a target on a local Ethernet has its network card in promiscuous mode. There is an NSE script for nmap called sniffer-detect.nse which does just that. NAST: - it detects other PC's in promiscuous mode by doing the ARP test.
    FaceNiff: FaceNiff is an Android app that can sniff and intercept web session profiles over the WiFi connected to the mobile. This app works on rooted android devices. The Wi-Fi connection should be over Open, WEP, WPA-PSK, or WPA2-PSK networks while sniffing the sessions.
    OmniPeek: OmniPeek network analyzer provides real-time visibility and expert analysis of each part of the target network. This tool will analyze, drill down, and fix performance bottlenecks across multiple network segments. Attackers can use this tool to analyze a network and inspect the packets in the network.
    shARP: An anti-ARP-spoofing application software that use active and passive scanning methods to detect and remove any ARP-spoofer from the network.


5. Which of the following practices helps security professionals defend the network against sniffing attacks?


	1. Never use POP2 or POP3 instead of POP
	2. Retrieve MAC addresses directly from OS instead of the NICs
	3. [x] Avoid accessing unsecured networks and open Wi-Fi networks
	4. Allow physical access to the network media


6. In one of the following techniques, a non-broadcast ARP is sent to all the nodes in a network, and a node running in the promiscuous mode broadcasts a ping message on the network with the local IP address but a different MAC address. Which is this technique?


	1. ARP poisoning
	2. ARP spoofing
	3. [x] ARP method
	4. Ping method

	 Explanation:

    ARP Spoofing: ARP spoofing is a method of attacking an Ethernet LAN. When a legitimate user initiates a session with another user in the same layer 2 broadcast domain, the switch broadcasts an ARP request using the recipient's IP address, while the sender waits for the recipient to respond with a MAC address.
    ARP Poisoning: With the help of ARP poisoning, an attacker can use fake ARP messages to divert all communications between two machines so that all traffic redirects via the attacker’s PC.
    ARP Method: This technique sends a non-broadcast ARP to all the nodes in the network. The node that runs in promiscuous mode on the network will cache the local ARP address. Then, it will broadcast a ping message on the network with the local IP address but a different MAC address. In this case, only the node that has the MAC address (cached earlier) will be able to respond to your broadcast ping request.
    Ping Method: To detect a sniffer on a network, identify the system on the network running in promiscuous mode. The ping method is useful in detecting a system that runs in promiscuous mode, which in turn helps to detect sniffers installed on the network.
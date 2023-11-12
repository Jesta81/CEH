1. Jamie needs to keep data safe in a large datacenter, which is in desperate need of a firewall replacement for the end of life firewall. The director has asked Jamie to select and deploy an appropriate firewall for the existing datacenter. The director indicates that the amount of throughput will increase over the next few years and this firewall will need to keep up with the demand while other security systems do their part with the passing data. What firewall will Jamie use to meet the requirements?


1. Application-level proxy firewall because unlike the old packet filtering firewall technology, it can adjust speed based on applications.

2. [x] Packet filtering firewall because it will best keep the increased traffic moving at an acceptable level.

3. Packet filtering firewall because layer 7 inspections use less overhead, allowing more packets to be inspected per second than other firewall types.

4. Application-level proxy firewall because the connection between internal and external systems are inspected but not broken; data moves more rapidly.

Explanation:

    Performance is the key focus of the question; therefore, the test taker will have to focus on the real need of the most enterprise businesses and not get distracted by other slower firewall types. Packet filtering firewall may seem old school to less experienced test takers and they may immediately choose other options.
     Packet filtering firewalls are best performing of the choices.

2. Jamie has purchased and deployed an application firewall to protect his company infrastructure which includes various email servers, file server shares, and applications. Also, all the systems in his company share the same onsite physical datacenter. Jamie has positioned the newly purchased firewall nearest to the application systems so as to protect the applications from attackers. This positioning does not protect the complete network.

What can be done to address the security issues by this deployment for Jamie?


1. Jamie will need to replace the application firewall with a packet filtering firewall at the network edge.

2. [x] Jamie will need to add at least one additional firewall at the network edge.

3. Jamie will need to add at least three additional firewalls at the DMZ, internet, and intranet.

4. Jamie will need to add at least three additional firewalls at the untrusted network, router side, and application side.

 Explanation:

    The test taker needs to understand that only the application server is being protected while the rest of the traffic is allowed to enter the network without a firewall. The test taker will have to understand that adding an additional firewall is better than having only the perimeter firewall. The test taker will also have to understand that placing three firewalls might be better; however, there is not enough detail to know where the router is in the scenario. They might choose this distractor because it has more firewalls.

3. When analyzing the IDS logs, the system administrator noticed an alert was logged when the external router was accessed from the administrator’s computer to update the router configuration. What type of an alert is this?


1. True-negative
2. [x] False-positive
3. True-positive
4. False-negative

Explanation:

    In a false-positive alarm an IDS raises an alarm on a nonmalicious event. As false-positive alarm triggers during unjustified alerts, they cause chaos in the organization. They nullify the urgency and the value of the real alerts, leading to ignoring the actual alarm situation.
    Causes of false-positive alarm:

    A network traffic false alarm: A network traffic false alarm triggers when a nonmalicious traffic event occurs. A great example of this would be an IDS triggers an alarm when the packets do not reach the destination due to network device failure.
    A network device alarm: An IDS triggers a network device alarm when the device generates unknown or odd packets, for example, load balancer.
    An Alarm caused by an incorrect software script: If poorly written software generates odd or unknown packets, IDS will trigger a false-positive alarm. 


4. Which of the following methods detects an intrusion based on the fixed behavioral characteristics of the users and components of a computer system?


1. Signature recognition
2. Protocol anomaly detection
3. Bastion host
4. [x] Anomaly detection

 Explanation:

    Signature Recognition: Signature recognition, also known as misuse detection, tries to identify events that indicate an abuse of a system or network resource
    Protocol Anomaly Detection: In this type of detection, models are built to explore anomalies in the way in which vendors deploy the TCP/IP specification
    Anomaly Detection: It detects the intrusion based on the fixed behavioral characteristics of the users and components in a computer system
    Bastion Host: The bastion host is designed for defending the network against attacks. It acts as a mediator between inside and outside networks. A bastion host is a computer system designed and configured to protect network resources from attacks. Traffic entering or leaving the network passes through the firewall

5. The general indicators of which of the following types of intrusions are repeated login attempts from remote hosts, a sudden influx of log data, and a sudden increase in bandwidth consumption?


1. Signature recognition
2. File-system intrusion
3. [x] Network intrusion
4. System intrusion

Explanation:

    File System Intrusions: By observing system files, the presence of an intrusion can be identified. System files record the activities of the system.
        If you find new, unknown files/programs on your system. Unexplained modifications in file size are also an indication of an attack.
        You can identify unfamiliar file names in directories, including executable files with strange extensions and double extensions.
        Missing files are also a sign of a probable intrusion/attack
    Network Intrusions: general indications of network intrusions include
        A sudden increase in bandwidth consumption.
        Repeated probes of the available services on your machines.
        Connection requests from IPs other than those in the network range, which imply that an unauthenticated user (intruder) is attempting to connect to the network
        Repeated login attempts from remote hosts
        A sudden influx of log data, which could indicate attempts at DoS attacks, bandwidth consumption, and DDoS attacks
    System Intrusions: General indications of system intrusions include:
        Sudden changes in logs such as short or incomplete logs.
        Unusually slow system performance.
        Missing logs or logs with incorrect permissions or ownership
        Unusual graphic displays or text messages
        Gaps in system accounting
    Signature recognition: It is an IDS intrusion detection method, also known as misuse detection, tries to identify events that indicate an abuse of a system or network resource


5. Which of the following types of firewall inspects only header information in network traffic?


1. Circuit-level gateway
2. [x] Packet filter
3. Stateful inspection
4. Application-level gateway

 Explanation:

    Stateful inspection firewall filter packets at the network layer to determine whether session packets are legitimate, and they overcome the limitation of packet firewalls that can only filter on IP address, port, and protocol, and so on by performing deep packet inspection. Circuit-level gateway forwards data between networks without verifying it, and blocks incoming packets into the host, but allows the traffic to pass through itself. Application-level gateway inspects, finds, and verifies malicious traffic missed by stateful inspection firewalls, decides whether to allow access, and improves the overall security of the application layer.


6. Which of the statements concerning proxy firewalls is correct?


1. Proxy firewalls block network packets from passing to and from a protected network

2. Firewall proxy servers decentralize all activity for an application

3. [x]Computers establish a connection with a proxy firewall that initiates a new network connection for the client

4. Proxy firewalls increase the speed and functionality of a network


7. Which of the following is a hardware requirement that either an IDS/IPS system or a proxy server must have in order to properly function?


1. Fast network interface cards
2. Similar RAM requirements
3. [x]They must be dual-homed
4. Fast processor to help with network traffic analysis



8. While conducting a penetration test, the tester determines that there is a firewall between the tester’s machine and the target machine. The firewall is only monitoring TCP handshaking of packets at the session layer of the OSI model. Which type of firewall is the tester trying to traverse?


1. [x] Circuit-level gateway firewall
2. Stateful multilayer inspection firewall
3. Packet filtering firewall
4. Application-level firewall

 Explanation:

    Packet filtering firewall: A packet filtering firewall investigates each individual packet passing through it and makes a decision whether to pass the packet or drop it. It works at the Internet protocol (IP) layer of the TCP/IP model. Packet filter–based firewalls concentrate on individual packets, analyze their header information, and determine which way they need to be directed.
    Application-level firewall: Application-based proxy firewalls concentrate on the application layer rather than just the packets. The need for application-level firewall arises when huge amount of voice, video, and collaborative traffic are accessed at data-link layer and network layer utilized for unauthorized access to internal and external networks.
    Stateful multilayer inspection firewall: They filter packets at the network layer, to determine whether session packets are legitimate, and evaluate the contents of packets at the application layer.
    With the use of stateful packet filtering, you can overcome the limitation of packet firewalls that can only filter on IP address, port, protocol, and so on. This multilayer firewall can perform deep packet inspection.



9. A circuit-level gateway works at which of the following layers of the OSI model?


1. Layer 2 – Data Link
2. Layer 3 – Network
3. [x] Layer 5 – Session
4. Layer 4 – Transport




10. At which two traffic layers do most commercial IDSes generate signatures? (Select Two)


1. [x] Transport layer
2. [x] Network layer
3. Session layer
4. Application layer

 Explanation:

    According to New 'semantics-aware' IDS reduces false positives (https://searchsecurity.techtarget.com/news/1113940/New-semantics-aware-IDS-reduces-false-positives), https://www.sanfoundry.com/computer-networks-questions-answers-entrance-exams/, and https://searchsecurity.techtarget.com/quiz/Quiz-IDS-IPS, the most commercial IDSes generate signatures at the network and transport layers.



11. Which type of intrusion detection system can monitor and alert on attacks, but cannot stop them?


1. Intuitive
2. [x] Passive
3. Detective
4. Reactive



12. Jamie needs to keep data safe in a large datacenter, which is in desperate need of a firewall replacement for the end of life firewall. The director has asked Jamie to select and deploy an appropriate firewall for the existing datacenter. The director indicates that the amount of throughput will increase over the next few years and this firewall will need to keep up with the demand while other security systems do their part with the passing data. What firewall will Jamie use to meet the requirements?


1. Application-level proxy firewall because the connection between internal and external systems are inspected but not broken; data moves more rapidly

2. [x] Packet filtering firewall because it will best keep the increased traffic moving at an acceptable level

3. Application-level proxy firewall because unlike the old packet filtering firewall technology, it can adjust speed based on applications

4. Packet filtering firewall because layer 7 inspections use less overhead, allowing more packets to be inspected per second than other firewall types




13. Jamie was asked by their director to make new additions to the firewall in order to allow traffic for a new software package. After the firewall changes, Jamie receives calls from users that they cannot access other services, such as email and file shares, that they were able to access earlier.

What was the problem in the latest changes that is denying existing users from accessing network resources?


1. Jamie needs to restart the firewall to make the changes effective

2. Jamie should exit privileged mode to allow the settings to be effective

3. Jamie needs to have the users restart their computers in order to make settings effective

4. Jamie’s additional entries were processed first

 Explanation:

    Jamie has typed the new changes at the top of the existing access control list and included an explicit deny statement (deny any any) at the end of their new entries. Since the firewall interprets each new line in order, when the firewall reaches the end of the new entries at the top, it stops allowing all traffic. Jamie should have added the new additions at the bottom just before the existing deny any any instead of adding an additional deny any any. The test taker needs to know that what is meant by processed first is that there was an accidental additional deny any any added just below the new lines but just above the original previously existing entries.




14. When analyzing the IDS logs, the system administrator notices connections from outside of the LAN have been sending packets where the source IP address and destination IP address are the same. However, no alerts have been sent via email or logged in the IDS. Which type of an alert is this?


1. True negative

2. False positive

3. [x] False negative

4. True positive


 Explanation:

    False Positive (No attack - Alert): A false positive occurs if an event triggers an alarm when no actual attack is in progress. A false positive occurs when an IDS treats regular system activity as an attack. False positives tend to make users insensitive to alarms and reduce their reactions to actual intrusion events. While testing the configuration of an IDS, administrators use false positives to determine if the IDS can distinguish between false positives and real attacks or not.
    False Negative (Attack - No Alert): A false negative is a condition occurred when an IDS fails to react to an actual attack event. This event is the most dangerous failure since the purpose of an IDS is to detect and respond to attacks.
    True Positive (Attack - Alert): A true positive is a condition occurring when an event triggers an alarm and causes the IDS to react as if a real attack is in progress. The event may be an actual attack, in which case an attacker is making an attempt to compromise the network, or it may be a drill, in which case security personnel are using hacker tools to conduct tests of a network segment.
    True Negative (No attack - No Alert): A true negative is a condition occurred when an IDS identifies an activity as acceptable behavior and the activity is acceptable. A true negative is successfully ignoring the acceptable behavior. It is not harmful as the IDS is performing as expected.



15. When analyzing the IDS logs, the system administrator noticed an alert was logged when the external router was accessed from the administrator’s computer to update the router configuration. What type of an alert is this?


1. False-negative
2. True-negative
3. True-positive
4. [x] False-positive



16. A network administrator received an administrative alert at 3:00 a.m. from the intrusion detection system. The alert was generated because a large number of packets were coming into the network over ports 20 and 21. During analysis, there were no signs of attack on the FTP servers. How should the administrator understand this situation?


1. False negatives
2. True negatives
3. True positives
4. [x] False positives


17. Which of the following methods detects an intrusion based on the fixed behavioral characteristics of the users and components of a computer system?


1. Signature recognition
2. Protocol anomaly detection
3. Bastion host
4. [x] Anomaly detection


18. The general indicators of which of the following types of intrusions are repeated login attempts from remote hosts, a sudden influx of log data, and a sudden increase in bandwidth consumption?


1. File-system intrusion
2. System intrusion
3. Signature recognition
4. [x] Network intrusion


18. Which of the following elements in the firewall architecture is a computer system designed and configured to protect network resources from attacks and acts as a mediator between inside and outside networks?


1. Screened subnet
2. [x] Bastion host
3. Multi-homed firewall
4. Demilitarized zone



19. Which of the following attributes in a packet can be used to check whether the packet originated from an unreliable zone?


1. [x] Interface
2. Direction
3. Source IP address
4. TCP flag bits


20. Which of the following intrusion detection technique involves first creating models of possible intrusions and then comparing these models with incoming events to make a detection decision?


1. Obfuscating
2. Protocol Anomaly Detection
3. Anomaly Detection
4. [x] Signature Recognition


21. Which of the statements concerning proxy firewalls is correct?


1. [x] Computers establish a connection with a proxy firewall that initiates a new network connection for the client

2. Proxy firewalls block network packets from passing to and from a protected network

3. Firewall proxy servers decentralize all activity for an application

4. Proxy firewalls increase the speed and functionality of a network



22. Which solution can be used to emulate computer services, such as mail and ftp, and to capture information related to logins or actions?


1. Intrusion detection system (IDS)
2. Firewall
3. DeMilitarized zone (DMZ)
4. [x] Honeypot


23. Sean who works as a network administrator has just deployed an IDS in his organization’s network. Sean deployed an IDS that generates four types of alerts that include: true positive, false positive, false negative, and true negative.

In which of the following conditions does the IDS generate a true positive alert?

1. A true positive is a condition occurring when an IDS fails to react to an actual attack event

2. A true positive is a condition occurring when an event triggers an alarm when no actual attack is in progress

3. A true positive is a condition occurring when an IDS identifies an activity as acceptable behavior and the activity is acceptable

4. [x] A true positive is a condition occurring when an event triggers an alarm and causes the IDS to react as if a real attack is in progress


24. Which of the following indicator identifies a network intrusion?


1. Sudden decrease in bandwidth consumption is an indication of intrusion
2. Connection requests from IPs from those systems within the network range
3. [x] Repeated probes of the available services on your machines
4. Rare login attempts from remote hosts

 Explanation:

    Network Intrusions: General indications of network intrusions include:

    Sudden increase in bandwidth consumption is an indication of intrusion
    Repeated probes of the available services on your machines
    Connection requests from IPs other than those in the network range, indicating that an unauthenticated user (intruder) is attempting to connect to the network
    Repeated login attempts from remote hosts
    A sudden influx of log data could indicate attempts at Denial-of-Service attacks, bandwidth consumption, and distributed Denial-of-Service attacks



25. Which of the following is a hardware requirement that either an IDS/IPS system or a proxy server must have in order to properly function?


1. Fast processor to help with network traffic analysis
2. Fast network interface cards
3. [x] They must be dual-homed
4. Similar RAM requirements


26. An advantage of an application-level firewall is the ability to


1. Retain state information for each packet
2. Monitor TCP handshaking
3. Filter packets at the network level
4. [x] Filter specific commands, such as http:post


27. Which of the following is an IDS evasion technique used by an attacker to confuse the IDS by forcing it to read invalid packets as well as blindly trust and accept a packet that an end system rejects?


1. Obfuscation
2. Fragmentation attack
3. Invalid RST packets
4. [x] Insertion attack

 Explanation:

    Invalid RST Packets: The TCP uses 16-bit checksums for error checking of the header and data and to ensure that communication is reliable. It adds a checksum to every transmitted segment that is checked at the receiving end. When a checksum differs from the checksum expected by the receiving host, the TCP drops the packet at the receiver's end. The TCP also uses an RST packet to end two-way communications. Attackers can use this feature to elude detection by sending RST packets with an invalid checksum.
    Fragmentation attack: Fragmentation can be used as an attack vector when fragmentation timeouts vary between the IDS and the host. Through the process of fragmenting and reassembling, attackers can send malicious packets over the network to exploit and attack systems.
    Obfuscating: It is an IDS evasion technique used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS. An attacker manipulates the path referenced in the signature to fool the HIDS. Using Unicode characters, an attacker can encode attack packets that the IDS would not recognize but which an IIS web server can decode
    Insertion Attack: Insertion is the process by which the attacker confuses the IDS by forcing it to read invalid packets (i.e., the system may not accept the packet addressed to it). An IDS blindly trusts and accepts a packet that an end system rejects. If a packet is malformed or if it does not reach its actual destination, the packet is invalid. If the IDS reads an invalid packet, it gets confused. An attacker exploits this condition and inserts data into the IDS



28. One of the following is an IDS evasion technique used by an attacker to send a huge amount of unnecessary traffic to produce noise or fake traffic. If the IDS does not analyze the noise traffic, the true attack traffic goes undetected. Which is this IDS evasion technique?


1. Denial-of-service attack
2. Encryption
3. [x] Flooding
4. Overlapping fragments

 Explanation:

    Encryption: Network-based intrusion detection analyzes traffic in the network from the source to the destination. If an attacker succeeds in establishing an encrypted session with his/her target host using a secure shell (SSH), secure socket layer (SSL), or virtual private network (VPN) tunnel, the IDS will not analyze the packets going through these encrypted communications. Thus, an attacker sends malicious traffic using such secure channels, thereby evading IDS security.
    Overlapping Fragments: Attackers use overlapping fragments to evade IDS. In this technique, attackers generate a series of tiny fragments with overlapping TCP sequence numbers.
    Flooding: To bypass IDS security, attackers flood IDS resources with noise or fake traffic to exhaust them with having to analyze flooded traffic. Once such attacks succeed, attackers send malicious traffic toward the target system behind the IDS, which offers little or no intervention. Thus, true attack traffic might go undetected
    Denial-of-Service Attack (DoS): The attacker identifies a point of network processing that requires the allocation of a resource, causing a condition to occur in which all of that resource is consumed. The resources affected by the attacker are CPU cycles, memory, disk space, and network bandwidth. Attackers monitor and attack the CPU capabilities of the IDS. This is because the IDS needs half of a CPU cycle to read the packets, detect the purpose of their existence, and then compare them with some location in the saved network state. An attacker can verify the most computationally expensive network processing operations and then compel the IDS to spend all its time in carrying out useless work.



29. In which of the following IDS evasion techniques does an attacker use an existing buffer-overflow exploit and set the “return” memory address on the overflowed stack to the entrance point of the decryption code?


1. Invalid RST packets
2. [x] Polymorphic shellcode
3. Overlapping fragments
4. Urgency flag


30. Which of the following techniques is used by an attacker to exploit a host computer and results in the IDS discarding packets while the host that must receive the packets accepts them?


1. Obfuscation
2. [x] Evasion
3. Session splicing
4. Fragmentation attack



31. In which of the following IDS evasion techniques does an attacker split the attack traffic into an excessive number of packets such that no single packet triggers the IDS?


1. [x] Session splicing
2. Evasion
3. Insertion attack
4. Denial-of-service attack (DoS)


32. The use of alert thresholding in an IDS can reduce the volume of repeated alerts, but introduces which of the following vulnerabilities?


1. Thresholding interferes with the IDS’ ability to reassemble fragmented packets

2. [x] An attacker, working slowly enough, can evade detection by the IDS

3. The IDS will not distinguish among packets originating from different sources

4. Network packets are dropped if the volume exceeds the threshold


33. Which evasion technique is used by attackers to encode the attack packet payload in such a way that the destination host can only decode the packet but not the IDS?


1. Fragmentation attack
2. Session splicing
3. [x] Obfuscation
4. Unicode evasion


34. How many bit checksum is used by the TCP protocol for error checking of the header and data and to ensure that communication is reliable?


1. 13-bit
2. 14-bit
3. 15-bit
4. [x] 16-bit

 Explanation:

    The TCP protocol uses 16-bit checksums for error checking of the header and data and to ensure that communication is reliable. It adds a checksum to every transmitted segment that is checked at the receiving end.



35. An attacker hides the shellcode by encrypting it with an unknown encryption algorithm and by including the decryption code as part of the attack packet. He encodes the payload and then places a decoder before the payload. Identify the type of attack executed by attacker.


1. Preconnection SYN
2. Postconnection SYN
3. ASCII shellcode
4. [x] Polymorphic shellcode



36. Which network-level evasion method is used to bypass IDS where an attacker splits the attack traffic in too many packets so that no single packet triggers the IDS?


1. Fragmentation attack
2. [x] Session splicing
3. Unicode evasion
4. Overlapping fragments

 Explanation:

    Session splicing is an IDS evasion technique that exploits how some IDSs do not reconstruct sessions before pattern-matching the data. It is a network-level evasion method used to bypass IDS where an attacker splits the attack traffic in too many packets such that no single packet triggers the IDS. The attacker divides the data into the packets into small portions of bytes and while delivering the data evades the string match. Attackers use this technique to deliver the data into several small-sized packets. Overlapping fragments and fragmentation attack evade IDS by using fragments of packet, whereas in unicode evasion is done by exploiting unicode characters.



37. Which of the following is a technique used by an attacker masquerading as a trusted host to conceal their identity for hijacking browsers or gaining unauthorized access to a network?


1. Firewalking
2. [x] IP address spoofing
3. Port scanning
4. Banner grabbing


38. Which of the following techniques routes all traffic through an encrypted tunnel directly from a laptop to secure and harden servers and networks?


1. Source routing
2. ACK tunneling method
3. Tiny fragments
4. [x] Anonymizer

 Explanation:

    Source Routing: Using this technique, the sender of the packet designates the route (partially or entirely) that a packet should take through the network such that the designated route should bypass the firewall node. Thus, the attacker can evade firewall restrictions
    Tiny Fragments: Attackers create tiny fragments of outgoing packets, forcing some of the TCP packet’s header information into the next fragment. The IDS filter rules that specify patterns will not match with the fragmented packets owing to the broken header information. The attack will succeed if the filtering router examines only the first fragment and allows all the other fragments to pass through
    ACK tunneling method: ACK tunneling allows tunneling a backdoor application with TCP packets with the ACK bit set. The ACK bit is used to acknowledge the receipt of a packet. Some firewalls do not check packets with the ACK bit set because ACK bits are supposed to be used in response to legitimate traffic
    Anonymizer: Anonymizer’s VPN routes all the traffic through an encrypted tunnel directly from your laptop to secure and harden servers and networks. It then masks the real IP address to ensure complete and continuous anonymity for all online activities.




39. Which of the following tools provides secure remote login capabilities using SSH TCP/IP tunneling to Windows workstations and servers by encrypting data during transmission?


1. zIPS
2. Suricata
3. [x] Bitvise
4. Snort

 Explanation:

    Snort: Snort is an open-source network intrusion detection system capable of performing real-time traffic analysis and packet logging on IP networks. It can perform protocol analysis and content searching/matching, and it is used to detect a variety of attacks and probes, such as buffer overflows, stealth port scans, CGI attacks, SMB probes, and OS fingerprinting attempts.
    Suricata: Suricata is a robust network threat detection engine capable of real-time intrusion detection (IDS), inline intrusion prevention (IPS), network security monitoring (NSM), and offline pcap processing. It.
    Bitvise: Bitvise SSH Server provides secure remote login capabilities to Windows workstations and servers by encrypting data during transmission. It is ideal for remote administration of Windows servers, for advanced users who wish to access their home machine from work or their work machine from home, and for a wide spectrum of advanced tasks, such as establishing a VPN using the SSH TCP/IP tunneling feature or providing a secure file depository using SFTP.
     zIPS: Zimperium’s zIPS™ is a mobile intrusion prevention system app that provides comprehensive protection for iOS and Android devices against mobile network, device, and application cyber-attacks.



40. Which of the following attack techniques is used by an attacker to exploit the vulnerabilities that occur while processing the input parameters of end users and the server responses in a web application?


1. MITM attack
2. Social engineering attack
3. Denial-of-service attack
4. [x] XSS attack

 Explanation:

    Social engineering Attack: Social engineering and data-driven attacks whereby the attacker sends malicious links and emails to employees inside the network.
    Denial of Service Attack: The attacker identifies a point of network processing that requires the allocation of a resource, causing a condition to occur in which all of that resource is consumed. The resources affected by the attacker are CPU cycles, memory, disk space, and network bandwidth. Attackers monitor and attack the CPU capabilities of the IDS.
    MITM Attack: In MITM attacks, attackers use DNS servers and routing techniques to bypass firewall restrictions. They may either take over the corporate DNS server or spoof DNS responses to perform the MITM firewall attack.
    XSS Attack: XSS attack exploits vulnerabilities that occur while processing the input parameters of end users and the server responses in a web application. Attackers take advantage of these vulnerabilities to inject malicious HTML code into the victim website to bypass the WAF.




41. Which of the following is a fingerprinting technique used by an attacker to detect the vendor of a firewall, firmware version, and services running on a system?


1. Port scanning
2. [x] Banner grabbing
3. Source routing
4. Firewalking


42. Firewalk has just completed the second phase (the scanning phase) and a technician receives the output shown below.

What conclusions can be drawn based on these scan results?

    TCP port 21—no response
    TCP port 22—no response
    TCP port 23—Time-to-live exceeded



1. The firewall itself is blocking ports 21 through 23 and a service is listening on port 23 of the target host.

2. The lack of response from ports 21 and 22 indicate that those services are not running on the destination server.

3. [x] The scan on port 23 passed through the filtering device. This indicates that port 23 was not blocked at the firewall.

4. The scan on port 23 was able to make a connection to the destination host prompting the firewall to respond with a TTL error.

 Explanation:

    Since the output shown to the technician containsTCP port 21—no response, TCP port 22—no response, and TCP port 23—Time-to-live exceeded, this means that the traffic through port 23 has passed through the firewall filtering which indicates that the firewall does not block port 23.



43. Check Point's FireWall-1 listens to which of the following TCP ports?


1. 1080
2. 1072
3. [x] 259
4. 1745

 Explanation:

    Some firewalls will uniquely identify themselves using simple port scans. For example, Check Point's FireWall-1 listens on TCP ports 256, 257, 258, and 259, and Microsoft's Proxy Server usually listens on TCP ports 1080 and 1745.


44. Which method of firewall identification has the following characteristics:

    uses TTL values to determine gateway ACL filters
    maps networks by analyzing IP packet response
    probes ACLs on packet filtering routers/firewalls using the same method as trace-routing
    sends TCP or UDP packets into the firewall with TTL value is one hop greater than the targeted firewall



1. Source routing
2. Port scanning
3. [x] Firewalking
4. Banner grabbing



45. Which of the following tools is used to execute commands of choice by tunneling them inside the payload of ICMP echo packets if ICMP is allowed through a firewall?


1. Anonymizer
2. HTTPTunnel
3. AckCmd
4. [x] Loki

 Explanation:

    Anonymizer: Anonymous web-surfing sites help to browse the Internet anonymously and unblock blocked sites.
    Loki ICMP tunneling is used to execute commands of choice by tunneling them inside the payload of ICMP echo packets.
    AckCmd (http://ntsecurity.nu) use ACK tunneling.
    HTTPTunnel uses technique of tunneling traffic across TCP port 80 to bypass firewall.



46. Which feature of Secure Pipes tool open application communication ports to remote servers without opening those ports to public networks?


1. [x] Local forwards
2. Remote backwards
3. SOCKS proxies
4. Remote forwards

 Explanation:

    Local forwards open application communication ports to remote servers without opening those ports to public networks. It brings the security of VPN communication to clients and servers on an ad hoc basis without the configuration and management hassle.



47. Which of the following is a hijacking technique where an attacker masquerades as a trusted host to conceal his identity, hijack browsers or websites, or gain unauthorized access to a network?


1. Firewalking
2. [x] IP address spoofing
3. Port scanning
4. Source routing


48. An organization’s web application firewall (WAF) allows specific queries and syntaxes that originate from their internal addresses. Jack, a professional hacker, exploited this functionality to send spoofed requests to trick the target WAF and server into believing that the request originated from their internal network. Jack also appended various extensions such as X-Originating-IP, X-Forwarded-For, X-Remote-IP, and X-Remote-Addr to the spoofed requests to bypass the target WAF.

Identify the technique employed by Jack to bypass the target WAF.


1. VLAN hopping
2. MAC spoofing
3. [x] HTTP header spoofing
4. ARP spoofing


49. In which of the following attacks does an attacker create a malicious link by developing a JavaScript-based blob with a compatible MIME that is set to automatically download the malware on the victim’s machine?


1. Pre-connection SYN
2. URL encoding
3. [x] HTML smuggling
4. Polymorphic shellcode



51. Which of the following practices helps security professionals in defending against HTML smuggling attacks?


1. Never block auto-execution of .js and .jse files

2. [x] Recommend user to access web browser activated with Microsoft Defender SmartScreen

3. Disable cloud delivery-based protection

4. Never verify the perimeter operation of security devices


52. Mark, a professional hacker, has targeted an organization’s employee to create a backdoor on his system. To achieve his goal, Mark exploited a standard service of Microsoft-based OS that distributes automatic updates to its global users. The administrators often disregard monitoring this service as it delivers continuous updates.

Which of the following features did Mark abuse in the above scenario?


1. ICMP protocol
2. SSH tunneling
3. HTTP tunneling
4. [x] Windows BITS


53. In which of the following techniques does an attacker use a combination of upper- and lower-case letters in an XSS payload to bypass the WAF?


1. [x] Using obfuscation to bypass the WAF
2. Using hex encoding to bypass the WAF
Using ASCII values to bypass the WAF
Using ICMP tunneling


54. Which of the following is a two-way HTTP tunneling software tool that allows HTTP, HTTPS, and SOCKS tunneling of any TCP communication between any client–server systems?


1. Secure Pipes
2. Bitvise
3. [x] Super network tunnel
4. Loki


 Explanation:

    Super network tunnel is two-way HTTP tunneling software that connects two computers utilizing HTTP-tunnel client and HTTP-tunnel server. It can bypass any firewall to surf the web, use IM applications, games, and so on. Super network tunnel integrates SocksCap function along with bidirectional HTTP tunneling and remote control to simplify the configuration.
    Bitvise and Secure Pipes are SSH tunneling tool and Loki is an ICMP tunneling tool.



55. In which of the following techniques do attackers first send payloads to the WAF connected to their local network to identify the payloads that can be used for evasion and then send those payloads to the target WAF for evasion?


1. [x] Fuzzing/brute-forcing
2. Runtime execution path profiling
3. Code emulation
4. Function testing


56. Identify the evasion technique used by attackers to bypass endpoint detection and response (EDR) to infect the devices with potential malware and establish command and control to maintain a foothold without being detected.


1. Website mirroring
2. [x] XLM weaponization
3. Dark web footprinting
4. Banner grabbing



56. Which of the following is a simple VLAN enumeration and hopping script that sniffs out CDP packets and extracts the VTP domain name, VLAN management address, native VLAN ID, and IOS version of Cisco devices?


1. [x] Frogger
2. Maltego
3. Nikto
4. got-responded



57. Which of the following tools allows attackers to place their device between a network switch and an authenticated device to ensure that the traffic flows through their device?


1. Dependency Walker
2. InSpectre
3. [x] nac_bypass_setup.sh
4. OmniPeek



58. Which of the following tools is used by attackers to bypass antivirus software by utilizing binary deconstruction, insertion of arbitrary assembly code, and reconstruction?


1. [x] Ghostwriting.sh
2. KFSensor
3. FaceNiff
4. Colasoft Packet Builder

Explanation:

    Ghostwriting.sh: Ghostwriting is used to bypass antivirus software by utilizing binary deconstruction, insertion of arbitrary assembly code, and reconstruction. It uses the built-in Metasploit tools to perform these actions. Ghostwriting.sh is a tool to automate this process.
    Colasoft Packet Builder: Colasoft Packet Builder is used to create custom network packets and fragmenting packets. Attackers use this tool to create custom malicious packets and fragment them such that firewalls cannot detect them.
    KFSensor: KFSensor is a host-based IDS that acts as a honeypot to attract and detect hackers and worms by simulating vulnerable system services and Trojans.
    FaceNiff: FaceNiff is an Android app that can sniff and intercept web session profiles over a Wi-Fi connection to a mobile.



59. Identify the technique in which attackers abuse Microsoft Excel macro sheets to bypass endpoint protection and execute a malicious payload on a target system.


1. Fuzzing/brute-forcing
2. Fast flux DNS method
3. [x] XLM weaponization
4. Password grabbing


60. Which of the following tools allows attackers to analyze the detection rate of a malicious file that is being propagated to bypass the antivirus solution?


1. Zsteg
2. BeRoot
3. Robber
4. [x] VirusTotal

 Explanation:

    Robber: Robber is an open-source tool that helps attackers to find executables prone to DLL Hijacking.
    BeRoot: BeRoot is a post-exploitation tool to check common misconfigurations to find a way to escalate privilege.
    VirusTotal: Attackers use VirusTotal to analyze the file and identify the detection rate.
    Zsteg : The zsteg tool is used to detect stegano-hidden data in PNG and BMP image files.



61. Which of the following tools allows attackers to create malicious payload or launcher to bypass endpoint protection?


1. Metagoofil
2. Sherlock
3. [x] Covenant C2 Framework
4. Octoparse


62. Identify the bypass technique in which attackers use hex-format encryption to ping different IP addresses for evading detection mechanisms.


1. [x] Passing encoded commands
2. Honey trap
3. Website defacement
4. Heuristic analysis


63. James, a professional hacker, was targeted to bypass endpoint security and gain access to the internal systems connected to a corporate network. For this purpose, he employed a technique through which malware is executed when a victim performs specific actions such as opening a particular window and clicking it; as a result, the malware gets activated after the system reboots.

Identify the technique employed by James to evade endpoint security.


1. IP address spoofing
2. Unicode evasion
3. [x] Timing-based evasion
4. Flooding


64. Which of the following techniques allows attackers to leverage trusted in-built utilities for the execution of malicious codes to evade EDR solutions?


1. Spawning using XMLDOM
2. Masking and filtering
3. Distortion techniques
4. [x] Signed binary proxy execution

 Explanation:

    Spawning using XMLDOM: Attackers can also implement process spawning through XMLDOM. This technique allows attackers to download and run a code inside an Office process.
    Signed Binary Proxy Execution: This technique allows attackers to leverage trusted in-built utilities for the execution of malicious codes to evade EDR solutions. Attackers use these legitimate or trusted utilities because they are signed with digital certificates and help in proxying the malicious code execution.
    Distortion Techniques: In this technique, the user implements a sequence of modifications to the cover to obtain a stego-object.
    Masking and Filtering: Masking and filtering techniques exploit the limitations of human vision, which is incapable of detecting slight changes in images.



65. Identify the evasion technique in which attackers perform DDL hijacking to place a malicious DLL with a legitimate name that the application is looking for in the same directory where the executable resides and then the malicious DLL gets executed along with the application to disable the endpoint security.


1. Fake security applications
2. Using blacklist detection
3. Overlapping fragments
4. Application whitelisting


66. Which of the following techniques helps an attacker circumvent blacklists and hide the C&C server behind the compromised systems operating as reverse proxies?


1. WHOIS lookup
2. Web application fuzz testing
3. Reverse DNS lookup
4. [x] Fast flux DNS method


67. Which of the following is a honeypot application that captures rootkits and other malicious malware that hijacks the read() system call?


1. Fake AP
2. [x] Sebek
3. Bait and switch
4. Tar pits


68. Which of the following techniques manipulates the TCP/IP stack and is effectively employed to slow down the spread of worms and backdoors?


1. Honeyd honeypot
2. Layer 2 tar pits
3. Layer 7 tar pits
4. [x] Layer 4 tar pits


69. In what way do the attackers identify the presence of layer 7 tar pits?


1. By looking at the IEEE standards for the current range of MAC addresses
2. [x] By looking at the latency of the response from the service
3. By looking at the responses with unique MAC address 0:0:f:ff:ff:ff
4. By analyzing the TCP window size


70. Which of the following methods is NOT a countermeasure to defend against IDS evasions?

1. Shut down switch ports associated with known attack hosts
2. Regularly update the antivirus signature database
3. [x] Never define the DNS server for client resolver in routers
4. Train users to identify attack patterns


71. Which of the following countermeasures can be employed to defend against firewall evasion?


1. Set the firewall rule set to accept all traffic
2. Never notify the security policy administrator about firewall changes
3. Do not specify the source and destination IP addresses or ports
4. [x] Disable all FTP connections to or from the network


72. Riya wants to defend against the polymorphic shellcode problem. What countermeasure should she take against this IDS evasion technique?


1. [x] Look for the nopopcode other than 0x90

2. Catalog and review all inbound and outbound traffic

3. Disable all FTP connections to or from the network
4. Configure a remote syslog server and apply strict measures to protect it from malicious users



72. Which of the following practices makes an organization’s network susceptible to IDS evasion attempts?


1. Perform an in-depth analysis of ambiguous network traffic for all possible threats

2. Look for the nop opcode other than 0x90 to defend against the polymorphic shellcode problem

3. [x] Allow malicious script injection in snort rules directory

4. Use TCP FIN or Reset (RST) packet to terminate malicious TCP sessions



73. Which of the following practices helps security professionals defend their organizational network against IDS evasion attempts?


1. Look for 0x90 other than nop opcode to defend against the polymorphic shellcode problem

2. Never use a traffic normalizer to remove potential ambiguity from the packet stream

3. Do not store the attack information for future analysis

4. [x] Ensure that the packets are arriving from a path secured with IDS



74. Which of the following practices helps security professionals defend their network against firewall bypass attempts?


1. By default, enable all FTP connections to or from the network

2. Never configure a remote syslog server

3. [x] Use HTTP Evader to run automated testing for suspected firewall evasions

4. The firewall should be configured such that the IP address of an intruder should not be filtered out
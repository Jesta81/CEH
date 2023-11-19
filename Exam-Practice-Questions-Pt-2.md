# CEH Practice Questions Part 2 #

1. 

	In which phase of a social engineering attack does an attacker indulges in dumpster diving?
	
	1. Selecting target
	2. Develop the relationship
	3. Research on target
	4. Exploit the relationship


2. Which of the following policies addresses the areas listed below:

    1. Issue identification (ID) cards and uniforms, along with other access control measures to the employees of a particular organization.
    2. Office security or personnel must escort visitors into visitor rooms or lounges.
    3. Restrict access to certain areas of an organization in order to prevent unauthorized users from compromising security of sensitive data.

		1. Special-access policies
		2. [x] Physical security policies
		3. Password security policies
		4. Defense strategy


3. Elijah, a malicious hacker, targeted an organization’s cloud environment and created oversized HTTP requests to trick the origin web server into responding with error content, which can be cached at the CDN servers. The error-based content that is cached in the CDN server is delivered to legitimate users, resulting in a DoS attack on the target cloud environment.

	Which of the following attacks did Elijah initiate in the above scenario?
	
	1. Cloudborne attack
	2. Wrapping attack
	3. [x] CPDoS attack
	4. Golden SAML attack


4. 

Kevin, a professional hacker, was hired to take control of the target organization’s Active Directory (AD) environment. For this purpose, Kevin configured a fake SMB server and initiated an MITM attack to steal valid users’ NTLM hashes and get authenticated by the domain controller. He used the same hashes to obtain admin privileges from the AD to control all the domain users.

	Which of the following attacks did Kevin launch in the above scenario?	

	1. PetitPotam hijacking
	2. Distribution attack
	3. MAC flooding
	4. XSS attack

5. Where should a web server be placed in a network in order to provide the most security?

	1. Inside an unsecured network
	2. Outside an unsecured network
	3. Inside DeMilitarized Zones (DMZ)
	4. Outside a secure network


6. Which of the following tools allows attackers to exploit a flaw in the BLE pairing process and quickly brute force a temporary key (TK)?

	1. Netcraft
	2. crackle
	3. Sublist3r
	4. Spokeo


7. A certificate authority (CA) generates a key pair that will be used for encryption and decryption of e-mails. The integrity of the encrypted e-mail is dependent on the security of which of the following?

	1. Public key
	2. Private key
	3. Modulus length
	4. E-mail server certificate


8. Clark, a professional hacker, has targeted Rick, a bank employee. Clark secretly installed a backdoor Trojan in Rick’s laptop to leverage it and access Rick’s files. After installing the Trojan, Clark obtained uninterrupted access to the target machine and used it for transferring and modifying files.

	Which of the following types of Trojans did Clark install in the above scenario?
	
	1. Win32/Simile
	2. Zmist
	3. Dharma
	4. [x] PoisonIvy




9. Which of the following is a published standard that provides an open framework for communicating the characteristics and impacts of IT vulnerabilities?
	
	1. [x] CVSS
	2. NIST
	3. OWASP
	4. IETF




10. Which of the following techniques is applied to routers for blocking spoofed traffic and preventing spoofed traffic from entering the Internet?
	
	1. [x] Ingress filtering
	2. Egress filtering
	3. Using random initial sequence numbers
	4. Using firewalls and filtering mechanisms




11. Which of the following is the regulation that specifies the requirements for establishing, implementing, maintaining, and continually improving an information security management system within the context of an organization? 

	1. The Federal Information Security Management Act (FISMA)
	2. [x] ISO/IEC 27001:2013
	3. The Digital Millennium Copyright Act (DMCA)
	4. Sarbanes Oxley Act (SOX)




12. Which of the following techniques is a black-box testing method that is used to identify coding errors and security loopholes in web applications and can prevent attacks such as buffer overflow, DoS, XSS, and SQL injection?

	1. Application whitelisting
	2. Application blacklisting
	3. Runtime application self-protection
	4. [x] Application fuzz testing




13. An attacker uses the following SQL query to perform an SQL injection attack

**SELECT * FROM users WHERE name = ‘’ OR ‘1’=‘1';**

	Identify the type of SQL injection attack performed.
		
		1. [x] Tautology
		2. Illegal/logically incorrect query
		3. UNION SQL injection
		4. End-of-line comment




14. An attacker is using DumpsterDiver, an automated tool, to identify potential secret leaks and hardcoded passwords in target cloud services.

	Which of the following flags is set by the attacker to analyze the files using rules specified in “rules.yaml”?
	
	1. -r, --remove
	2. [x] -a, --advance
	3. -s, --secret
	4. -o OUTFILE




15. Allen, a security professional in an organization, was suspicious about the activities in the network and decided to scan all the logs. In this process, he used a tool that automatically collects all the event logs from all the systems present in the network and transfers the real-time event logs from the network systems to the main dashboard.

	Which of the following tools did Allen employ in the above scenario?

	1. Intelius
	2. BinText
	3. [x] Splunk
	4. theHarvester




16. Which of the following indicators in the OSINT framework indicates a URL that contains the search term, where the URL itself must be edited manually?

	1. (T)
	2. (D)
	3. (R)
	4. [x] (M)




17. Which of the following protocols is widely used in network management systems to monitor network-attached devices such as routers, switches, firewalls, printers, and servers?

	1. NBNS
	2. SMTP
	3. [x] SNMP
	4. NFS	




18. Given below are the different phases involved in the web API hacking methodology.

    1. Detect security standards
    2. Identify the target
    3. Launch attacks
    4. Identify the attack surface

What is the correct sequence of phases followed in the web API hacking methodology?

**2,1,4,3**



19. Jim, a professional hacker, launched an APT attack on an organization. He was successful in entering the target network and extending access in the target network. He is now maintaining access with the use of customized malware and repackaging tools.

Which of the following phases of the APT lifecycle involves maintaining access to the target system, starting from evading endpoint security devices, until there is no further use of the data and assets?

	1. Preparation
	2. Cleanup
	3. Initial intrusion
	4. [x] Persistence


20. Which of the following layers in the IoT architecture is responsible for bridging the gap between two endpoints and performs functions such as message routing, message identification, and subscribing?
	
	1. Internet layer
	2. [x] Access gateway layer
	3. Middleware layer
	4. Edge technology layer


21. Which of the following is the entity in the NIST cloud deployment reference architecture that manages cloud services in terms of use, performance, and delivery and maintains the relationship between cloud providers and consumers?

	1. Cloud provider
	2. Cloud carrier
	3. Cloud auditor
	4. [x] Cloud broker


22. Through which of the following techniques can an attacker obtain a computer’s IP address, alter the packet headers, and send request packets to a target machine while pretending to be a legitimate host?

	1. IP address decoy
	2. Source port manipulation
	3. Packet fragmentation
	4. [x] IP address spoofing




23. Which of the following technologies is an advanced version of conventional cloud technology and is often used in solutions that require the processing of small and urgent operations within a timespan of milliseconds, where the gateway intelligence is performed within devices such as programmable automation controllers?

	1. [x] Edge computing
	2. Fog computing
	3. Serverless computing
	4. Docker networking




24. Which of the following techniques is used by an attacker to access all of an application’s functionalities and employs an intercepting proxy to monitor all requests and responses?

	1. [x] Web spidering/crawling
	2. Banner grabbing
	3. Attacker-directed spidering
	4. DNS interrogation




25. Which of the following viruses combines the approach of file infectors and boot record infectors and attempts to simultaneously attack both the boot sector and executable or program files?

	1. System or boot-sector viruses
	2. [x] Multipartite viruses
	3. Macro viruses
	4. Cluster viruses




26. Ray, a professional hacker, helps malicious attackers in finding vulnerabilities in the target organization. He also helps organizations by checking its limitations and suggesting best practices for making its IT infrastructure more secure.

What is the hacker class to which Ray belongs?

	1. Black hats
	2. White hats
	3. Suicide hackers
	4. [x] Gray hats




27. During a penetration test, Marin discovered a session token that had had the content: 20170801135433_Robert. Why is this session token weak, and what is the name used for this type of vulnerability?

	1. Unknown Session Token
	2. [x] Predictable Session Token
	3. Captured Session Token
	4. Date/Time Session Token



28. Which of the following hping command performs UDP scan on port 80?

	1. [x] hping3 -2 <IP Address> –p 80
	2. hping3 -1 <IP Address> –p 80
	3. hping3 –A <IP Address> –p 80
	4. hping3 –F –P –U <IP Address> –p 8




29. Ethan, a blackhat hacker, created a fake social media account impersonating an organization’s helpdesk account and started connecting with disgruntled individuals via social media posts. He started posting fake service links on social media. When victims click on the link, they are redirected to another site requesting them to provide their details.

	Which of the following types of attacks did Ethan perform in the above scenario?

	1. [x] Angler phishing
	2. Eavesdropping
	3. Dumpster diving
	4. Diversion theft




30. Which of the following attributes of the Findings element in a vulnerability scanning report contains the host’s name and address?

	1. OS
	2. [x] Node
	3. Date
	4. Services




31. In which of the following attacks do attackers send request packets to the target network while pretending to be a legitimate host to scan the hosts located behind the firewall?

	1. [x] MAC address spoofing
	2. Directory traversal
	3. Spimming
	4. Session hijacking



32. Which of the following scanning techniques used by attackers involves resetting the TCP connection between a client and server abruptly before the completion of the three-way handshake signals?

	1. TCP connect scan
	2. [x] Stealth scan
	3. Inverse TCP flag scan
	4. Xmas scan




33. Information gathered from social networking websites such as Facebook, Twitter, and LinkedIn can be used to launch which of the following types of attacks? 
	
	1. Smurf attack
	2. [x] Social engineering attack
	3. SQL injection attack
	4. Distributed denial of service attack


34. Which of the following attack techniques uses the cryptanalytic time-memory trade-off and requires less time than other techniques?

	1. [x] Rainbow table attack
	2. Distributed network attack
	3. Toggle-case attack
	4. PRINCE attack


35. Which of the following is a password cracking technique that tests all possible character combinations, including combinations of uppercase characters from A to Z, numbers from 0 to 9, and lowercase characters from a to z?

	1. Phishing attack
	2. Guessing
	3. [x] Brute-force attack
	4. Dictionary attack



36. Robert is a user with a privileged account and he is capable of connecting to the database. Rock wants to exploit Robert’s privilege account. How can he do that?

	1. [x] Access the database and perform malicious activities at the OS level
	2. Reject entries that contain binary data, escape sequences, and comment characters.
	3. Use the most restrictive SQL account types for applications.
	4. Design the code in such a way it traps and handles exceptions appropriately.



37. Billy, a software engineer, received a call from an unknown number claiming to be from the bank in which he has an account. The caller stated that Billy needs to verify his account because of a suspicious online transaction. Billy was suspicious of this request and did not provide any details.

	Which of the following types of attack was performed on Billy in the above scenario?
	
	1. [x] Impersonation
	2. Eavesdropping
	3. Shoulder surfing
	4. Dumpster diving


38. A hacker is attempting to see which protocols are supported by target machines or network. Which NMAP switch would the hacker use?
	1. [x] -sO
	2. -sT
	3. -sS
	4. -sU



39. In which of the following attacks does an attacker extract cryptographic secrets from a person by coercion or torture?

	1. [x] Rubber hose attack
	2. Brute-force attack
	3. Man-in-the-middle attack
	4. Hash collision attack



40. Which of the following Nmap commands is used by an attacker to perform an IP protocol ping scan on a target device?
	
	1. nmap –sn –PS <target IP address>
	2. nmap –sn –PA <target IP address>
	3. [x] nmap –sn –PO <target IP address>
	4. nmap –sn –PP <target IP address>



41. In a GNSS spoofing technique, attackers block and re-broadcast the original signals for masking the actual signal sent to the targeted receiver. In this manner, the attackers manipulate the original signal with false positioning data and delay timings. Identify this technique.

	1. [x] Meaconing method
	2. Cancellation methodology
	3. Drag-off strategy
	4. Interrupting the lock mechanism


42. Joe, a security professional in an organization, was instructed to simplify the decision-making capability of an organization for identified risks. In the process, he employed a method to scale risk by considering the probability, likelihood, and consequence or impact of the risk.

	What is the method employed by Joe for the representation of risk severity?
	
	1. Risk level
	2. Risk identification
	3. Risk treatment
	4. [x] Risk matrix



43. Which of the following is an open-source technology that provides PaaS through OS-level virtualization and delivers containerized software packages?

	1. Serverless computing
	2. Virtual machines
	3. [x] Docker
	4. Microservices



44. Which of the following is an HTTP header field used by an attacker to identify a client system's IP address that initiates a connection to a web server through an HTTP proxy?
	
	1. Referer
	2. User-Agent
	3. [x] X-Forwarded-For
	4. Proxy-Authorization 


45. Given below are the steps to exploit a system using the Metasploit framework.

    1. Verify exploit options
    2. Configure an active exploit
    3. Select a target
    4. Launch the exploit
    5. Select a payload

What is the correct sequence of steps through which a system can be exploited?

**3,1,2,5,4**


46. Which type of assessment tools are used to find and identify previously unknown vulnerabilities in a system?
	
	1. [x] Depth assessment tools
	2. Scope assessment tools
	3. Application-layer vulnerability assessment tools
	4. Active scanning tools



47. Which of the following cryptographic protocols allows two parties to establish a shared key over an insecure channel?
	
	1. DSA
	2. RSA
	3. [x] Diffie–Hellman
	4. YAK



48. Which of the following methods allows users to attain privileged control within Android’s subsystem, resulting in the exposure of sensitive data?

	1. OS data caching
	2. Simjacker
	3. Carrier-loaded software
	4. [x] Rooting



49. Teela, Inc. is running an application with debug enabled on one of its systems. Under which category of vulnerabilities can this flaw be classified?

	1. Design flaws
	2. Operating system flaws
	3. [x] Misconfiguration
	4. Unpatched servers



50. Which of the following scanning techniques is used by an attacker to check whether a machine is vulnerable to UPnP exploits?

	1. UDP scanning
	2. SCTP INIT scanning
	3. [x] SSDP scanning
	4. List scanning

51. Name an attack where the attacker connects to nearby devices and exploits the vulnerabilities of the Bluetooth protocol to compromise the device?

**BlueBorne attack**


52. Which of the following GNU radio tools is used to capture and listen to incoming signals on an audio device?
	
	1. uhd_rx_cfile
	2. uhd_siggen_gui
	3. [x] uhd_rx_nogui
	4. uhd_ft


53. An attacker sniffs encrypted traffic from the network and is subsequently able to decrypt it. Which cryptanalytic technique can the attacker use now in his attempt to discover the encryption key?

	1. Birthday attack
	2. Known plaintext attack
	3. Meet in the middle attack
	4. [x] Chosen ciphertext attack


54. Which of the following UDDI information structures takes the form of keyed metadata and represents unique concepts or constructs in UDDI?

	1. businessEntity
	2. businessService
	3. bindingTemplate
	4. [x] technicalModel



55. In which of the following malware components does an attacker embed notorious malware files that can perform the installation task covertly?

	1. Injector
	2. Obfuscator
	3. [x] Dropper
	4. Packer 



56. Which of the following master components in the Kubernetes cluster architecture scans newly generated pods and allocates a node to them?

	1. Kube-apiserver
	2. Etcd cluster
	3. [x] Kube-scheduler
	4. Kube-controller-manager


57. Which of the following MIBs manages the TCP/IP-based Internet using a simple architecture and system?

	1. WINS.MIB
	2. DHCP.MIB
	3. [x] MIB_II.MIB
	4. HOSTMIB.MIB



58. CenSys Solutions hired Clark, a security professional, to enhance the Internet security of the organization. To achieve the goal, Clark employed a tool that provides various Internet security services, including anti-fraud and anti-phishing services, application testing, and PCI scanning.

	What is the tool used by Clark to perform the above activities?
	
	1. Blisqy
	2. OmniPeek
	3. [x] Netcraft
	4. BTCrawler



59. Which of the following attacks involves unauthorized use of a victim’s computer to stealthily mine digital currency?

**Cloud cyptojacking**


60. In which of the following threat modelling steps does the administrator break down an application to obtain details about the trust boundaries, data flows, entry points, and exit points?

	1. Identify security objectives
	2. Identify threats
	3. Application overview
	4. [x] Decompose the application


61. Which of the following protocols uses AES-GCMP 256 for encryption and ECDH and ECDSA for key management?

	1. WPA
	2. WPA2
	3. WEP
	4. [x] WPA3


62. Which of the following types of antennas is useful for transmitting weak radio signals over very long distances – on the order of 10 miles?

	1. Omnidirectional
	2. [x] Parabolic grid
	3. Unidirectional
	4. Bidirectional


63. Which of the following techniques is used to detect rogue APs?

	1. [x] RF scanning
	2. Passphrases
	3. AES/CCMP encryption
	4. Non-discoverable mode


64. Identify the attack in which an attacker captures the data from an employee’s entry tag and copies it to another tag using a new chip to make unauthorized entry into the targeted organization’s premises.

	1. Key reinstallation attack
	2. [x] RFID cloning attack
	3. Bluejacking
	4. DNS rebinding attack



65. Which of the following technique allows an attacker to see past versions and pages of the target website?

	1. Run the Web Data Extractor tool
	2. [x] Go to Archive.org to see past versions of the company website
	3. Recover cached pages of the website from Google search engine cache
	4. Use SmartWhois to recover the old pages of the website


66. Which of the following attacks helps an attacker bypass a same-origin policy’s security constraints, allowing a malicious web page to communicate or make arbitrary requests to local domains?

	1. MarioNet attack
	2. Watering hole attack
	3. Clickjacking attack
	4. [x] DNS rebinding attack


67. In which of the following attack techniques does an attacker exploit an NFC-enabled Android device by establishing a remote connection with the target mobile device and taking full control of the device?

	1. Advanced SMS phishing
	2. Hooking
	3. Spearphone attack
	4. [x] Tap ’n Ghost attack
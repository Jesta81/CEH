# IoT Attacks 

Attackers implement various techniques to launch attacks on target IoT devices or networks. This section discusses the top IoT threats in relation to the basic types of IoT attack vectors and techniques, including distributed denial-of-service (DDoS) attacks, attacks on HVAC systems, rolling code attacks, BlueBorne attacks, and jamming attacks. 


## IoT Security Problems 

Potential vulnerabilities in the IoT system can result in major problems for organizations. Most IoT devices come with security issues such as the absence of a proper authentication mechanism or the use of default credentials, absence of a lock-out mechanism, absence of a strong encryption scheme, absence of proper key management systems, and improper physical security. 

![IoT Security Problems](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-security-problems.png) 

> 1. ### Application 
> - Validation of the inputted string, AuthN, AuthZ, no automatic security updates, default passwords. 
>
> 2. ### Network 
> - Firewall, improper communications encryption, services, lack of automatic updates. 
>
> 3. ### Mobile 
> - Insecure API, lack of communication channels encryption, authentication, lack of storage security. 
>
> 4. ### Cloud 
> - Improper authentication, no encryption for storage and communications, insecure web interface. 
>
> 5. ### IoT
> - **Application + Network + Mobile + Cloud = IoT**. 


## OWASP Top 10 IoT Threats 

![OWASP IoT Top 10 Threats](/IoT-and-OT-Hacking/IoT-Attacks/images/owasp-IoT.png) 

> 1. ### Weak, Guessable, or Hardcoded Passwords 
> - Using weak, guessable, or hardcoded passwords allows publicly available or unchangeable credentials to be determined via brute forcing. 
> - This also includes backdoors in the firmware or client software that lead to unauthorized access to the deployed devices. 
>
> 2. ### Insecure Network Services 
> - Insecure network services are prone to various attacks like buffer overflow attacks, which cause a denial-of-service scenario, thus leaving the device inaccessible to the user. 
> - An attacker uses various automated tools such as port scanners and fuzzers to detect the open ports and exploit them to gain unauthorized access to services. 
> - These insecure network services that are open to the Internet may compromise the confidentiality, authenticity, integrity, or availability of information and also allow remote access to critical information. 
>
> 3. ### Insecure Ecosystem Interfaces 
> - Insecure ecosystem interfaces such as web, backend API, mobile, and cloud interfaces outside the device lead to compromised security of the device and its components. 
> - Common vulnerabilities in such interfaces include lack of authentication/authorization, lack of encryption or weak encryption, and lack of input/output filtering. 
>
> 4. ### Lack of Secure Update Mechanisms 
> - Lack of secure update mechanisms, such as a lack of firmware validation on the device, lack of secure delivery, lack of anti-rollback mechanisms, or lack of notifications of security changes, may be exploited to perform various attacks. 
>
> 5. ### Use of Insecure or Outdated Components 
> - Use of outdated or older versions of software components or libraries, such as insecure customization of OS platforms or use of third-party hardware or software components from a compromised supply chain, may allow the devices themselves to be compromised. 
>
> 6. ### Insufficient Privacy Protection 
> - Insufficient privacy protection allows the user’s personal information stored on the devices or ecosystem to be compromised. 
>
> 7. ### Insecure Data Transfer and Storage 
> - Lack of encryption and access control of data that is in transit or at rest may result in leakage of sensitive information to malicious users. 
>
> 8. ### Lack of Device Management 
> - Lack of appropriate security support through device management on devices deployed in production, including asset management, update management, secure decommissioning, system monitoring, and response capabilities, may open the door to various attacks. 
>
> 9. ### Insecure Default Settings 
> - Insecure or insufficient device settings restrict the operators from modifying configurations to make the device more secure. 
>
> 10. ### Lack of Physical Hardening 
> - Lack of physical hardening measures allows potential attackers to acquire sensitive information that helps them in performing a remote attack or obtaining local control of the device. 


## OWASP IoT Attack Surface Areas 

![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-1.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-2.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-3.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-4.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-5.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-6.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-7.png) 
![IoT Attack Surface](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Attack-Surface-8.png) 


## IoT Vulnerabilities 

![IoT Vulnerabilities](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Vulns-1.png) 
![IoT Vulnerabilities](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Vulns-2.png) 
![IoT Vulnerabilities](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Vulns-3.png) 
![IoT Vulnerabilities](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Vulns-4.png) 


## IoT Threats

> - IoT devices have very **few security protection mechanisms** against various emerging threats. 
> - These devices can be infected by malware or malicious code at an alarming rate. 
> - Attackers often exploit these **poorly protected devices** on the Internet to cause physical damage to the network, to wiretap the communication, and also to **launch disruptive attacks** such as DDoS. 

![IoT Threats](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-Threats.png) 

Listed below are some types of IoT attack: 

>> 1. ### DDos Attack: 
>> - An attacker converts the devices into an army of botnets to target a specific system or server, making it unavailable to provide services. 
>>
>> 2. ### Attack on HVAC Systems: 
>> - HVAC system vulnerabilities are exploited by attackers to steal confidential information such as user credentials and to perform further attacks on the target network. 
>>
>> 3. ### Rolling Code Attack: 
>> - An attacker jams and sniffs the signal to obtain the code transferred to a vehicle’s receiver; the attacker then uses it to unlock and steal the vehicle. 
>>
>> 4. ### BlueBourne Attack: 
>> - Attackers connect to nearby devices and exploit the vulnerabilities of the Bluetooth protocol to compromise the device. 
>>
>> 5. ### Jamming Attack: 
>> - An attacker jams the signal between the sender and the receiver with malicious traffic that makes the two endpoints unable to communicate with each other. 
>>
>> 6. ### Remote Access using Backdoor: 
>> - Attackers exploit vulnerabilities in the IoT device to turn it into a backdoor and gain access to an organization’s network. 
>>
>> 7. ### Remote Access using Telnet: 
>> - Attackers exploit an open telnet port to obtain information that is shared between the connected devices, including their software and hardware models. 
>>
>> 8. ### Sybil Attack: 
>> - An attacker uses multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks. 
>>
>> 9. ### Exploit Kits: 
>> - A malicious script is used by the attackers to exploit poorly patched vulnerabilities in an IoT device. 
>>
>> 10. ### Man in The Middle Attack: 
>> - An attacker pretends to be a legitimate sender who intercepts all the communication between the sender and receiver and hijacks the communication. 
>>
>> 11. ### Replay Attack: 
>> - Attackers intercept legitimate messages from valid communication and continuously send the intercepted message to the target device to perform a denial-of-service attack or crash the target device. 
>>
>> 12. ### Forged Malicious Device: 
>> - Attackers replace authentic IoT devices with malicious devices if they have physical access to the network. 
>>
>> 13. ### Side-Channel Attack: 
>> - Attackers perform side-channel attacks by extracting information about encryption keys by observing the emission of signals, i.e., “side channels”, from IoT devices. 
>>
>> 14. ### Ransomeware Attack: 
>> - Ransomware is a type of malware that uses encryption to block a user’s access to his/her device either by locking the screen or by locking the user’s files. 
>>
>> 15. ### Client Impersonation: 
>> - An attacker masquerades as a legitimate smart device/server using a malicious device and compromises an IoT client device by impersonating it, to perform unauthorized activities or access sensitive information on behalf of the legitimate client. 
>>
>> 16. ### SQL Injection Attack: 
>> - Attackers perform SQL injection attacks by exploiting vulnerabilities in the mobile or web applications used to control the IoT devices, to gain access to the devices and perform further attacks on them. 
>>
>> 17. ### SDR-Based Attack: 
>> - Using a software-based radio communication system, an attacker can examine the communication signals passing through the IoT network and can send spam messages to the interconnected devices. 
>>
>> 18. ### Fault Injection Attack: 
>> - A fault injection attack occurs when an attacker tries to introduce fault behavior in an IoT device, with the goal of exploiting these faults to compromise the security of that device. 
>>
>> 19. ### Network Pivoting: 
>> - An attacker uses a malicious smart device to connect and gain access to a closed server, and then uses that connection to pivot other devices and network connections to the server to steal sensitive information. 
>>
>> 20. ### DNS Rebinding Attack: 
>> - DNS rebinding is a process of obtaining access to a victim’s router using a malicious JavaScript code injected on a web page. 


## Hacking IoT Devices: General Scenario

The IoT includes different technologies such as embedded sensors, microprocessors, and power management devices. Security consideration changes from device to device and application to application. The greater the amount of confidential data we send across the network, the greater the risk of data theft, data manipulation, data tampering, and attacks on routers and servers. 

Improper security infrastructure might lead to the following unwanted scenarios: 

> - An eavesdropper intercepts communication between two endpoints and discovers the confidential information that is sent across. He/she can misuse that information for his/her own benefit. 
>
> - A fake server can be used to send unwanted commands to trigger unplanned events. For example, some physical resources (water, coal, oil, electricity) could be sent to an unknown and unplanned destination, etc. 
>
> - A fake device can inject a malicious script into the system to make it work as instructed by the device. This may cause the system to behave inappropriately and dangerously. 

![Hacking-IoT General Scenario](/IoT-and-OT-Hacking/IoT-Attacks/images/General-IoT-device-hacking.png) 


## IoT DDoS Attack

> - Attacker initiates the attack by **exploiting the vulnerabilities** in the devices and installing a **malicious software** in their operating systems. 
>
> - Multiple infected IoT devices are referred to as an **Army of Botnets**. 
>
> - The target is attacked with a **large volume of requests** from multiple IoT devices present in different locations.

Given below are the steps followed by an attacker to perform a DDoS attack on IoT devices: 

1. Attacker gains remote access to vulnerable devices. 
2. After gaining access, they inject malware into the IoT devices to turn them into botnets. 
3. Attacker uses a coomand and control center to instruct botnets and to send multiple requests to the target server, resulting in a DDoS attack. 
4. Target server goes offline and becomes unavailable to process any further requests.  

![IoT DDoS](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-DDoS.png) 


## Exploit HVAC 

Steps followed by an attacker to exploit HVAC systems: 

1. Attacker uses [Shodan](https://www.shodan.io) and searches for vulnerable industrial control systems (ICSs). 

2. Based on the vulnerable ICSs found, the attacker then searches for default user credentials using online tools such as [defpass](https://www.defpass.com). 

3. Attacker uses default user credentials to attempt to access the ICS. 

4. After gaining access to the ICS, the attacker attempts to gain access to the HVAC system remotely through the ICS. 

5. After gaining access to the HVAC system, an attacker can control the temperature from the HVAC or carry out other attacks on the local network. 

![IoT HVAC Exploit](/IoT-and-OT-Hacking/IoT-Attacks/images/IoT-HVAC-Exploit.png) 


## Rolling Code Attack 

For example, given below are the steps followed by an attacker to perform a rolling-code attack: 

1. Victim presses car remote button and tries to unlock the car. 

2. Attacker uses a jammer that jams the car’s reception of the rolling code sent by the victim and simultaneously sniffs the first code. 

3. The car does not unlock; victim tries again by sending a second code. 

4. Attacker sniffs the second code. 

5. On the second attempt by the victim, the attacker forwards the first code, which unlocks the car. 

6. The recorded second code is used later by the attacker to unlock and steal the vehicle. 

Attackers can make use of tools such as rfcat-rolljam and RFCrack to perform this attack. 

![Rolling-Code-Attack](/IoT-and-OT-Hacking/IoT-Attacks/images/Rolling-Code-Attack.png) 


## BlueBorne Attack

Steps to perform BlueBorne attack: 

1. Attacker discovers active Bluetooth-enabled devices around them; all Bluetooth-enabled devices can be located even if they are not in discoverable mode. 

2. After locating any nearby device, the attacker obtains the MAC address of the device. 

3. Now, the attacker sends continuous probes to the target device to determine the OS. 

4. After identifying the OS, the attacker exploits the vulnerabilities in the Bluetooth protocol to gain access to the target device. 

5. Now the attacker can perform remote code execution or a man-in-the-middle attack and take full control of the device. 

![BlueBorne Attack](/IoT-and-OT-Hacking/IoT-Attacks/images/BlueBorne-Attack.png) 


## Jamming Attack

1. amming is a type of attack in which the communications between wireless IoT devices are jammed so that they can be compromised. 

2. An attacker transmits radio signals randomly with the same frequency as the sensor nodes for communication. 

3. As a result, the network gets jammed, which disables the endpoints from sending or receiving any messages. 

![Jamming Attack](/IoT-and-OT-Hacking/IoT-Attacks/images/Jamming-Attack.png) 


## Hacking Smart Grid/Industrial Devices: Remote Access using Backdoor 

> - The attacker gathers basic information about the target organization using various **social engineering techniques**. 
>
> - The attacker sends **phishing emails** to the employees with **malicious attachments**. 
>
> - When an employee **opens the email and clicks on the attachment**, a backdoor is automatically installed on the target system. 
>
> - Using the **backdoor**, the attacker gains access to the **private network** of the organization. 

![Remote Access Backdoor](/IoT-and-OT-Hacking/IoT-Attacks/images/backdoor.png) 


## SDR-Based Attacks on IoT 

The attacker uses software defined radio (SDR) **to examine the communication signals in the IoT networkand sends spam content** or texts to the interconnected devices. 

This software-based radio system can also **change the transmission and reception of signals** between the devices, based on their software implementations. 

Types of SDR-based attacks performed by attackers to break into an IoT environment:

> 1. ### Replay Attack 
> - This is the major attack described in IoT threats, in which attackers can capture the command sequence from connected devices and use it for later retransmission. 
> - An attacker can perform the below steps to launch a replay attack: 
>> 1. Attacker targets the **specified frequency** that is required to share information between devices. 
>> 2. After obtaining the frequency, the attacker can capture the original data when the commands are initiated by the connected devices. 
>> 3. Once the original data is collected, the attacker uses free tools such as URH (Universal Radio Hacker) to segregate the command sequence. 
>> 4. Attacker then injects the segregated command sequence on the same frequency into the IoT network, which replays the commands or captured signals of the devices. 
>
> 2. ### Cryptanalysis Attack 
> - A cryptanalysis attack is another type of substantial attack on IoT devices. 
> - In this attack, the procedure used by the attacker is the same as in a replay attack except for one additional step, i.e., reverse-engineering the protocol to obtain the original signal. 
> - To accomplish this task, the attacker must be skilled in cryptography, communication theory, and modulation scheme (to remove noises from the signal). 
> - This attack is practically not as easy as a replay attack to launch, yet the attacker can try to breach security using various tools and procedures. 
>
> 3. ### Reconnaissance Attack
> - This is an addition to a cryptanalysis attack. 
> - In this attack, information can be obtained from the device’s specifications. 
> - All IoT devices that run through RF signals must be certified by their country’s authority, and then they officially disclose an analysis report of the device. 
> - Designers often prevent this kind of analysis by obscuring any identification marks from the chipset. 
> - Therefore, the attacker makes use of multimeters to investigate the chipset and mark out some identifications, such as ground pins, to discover the product ID and compare it with the published report. 

![SDR IoT Attacks](/IoT-and-OT-Hacking/IoT-Attacks/images/SDR-Attacks.png) 


## Identifying and Accessing Local IoT Devices 

An attacker gains access over local IoT devices when a user from the network visits a malicious page, i.e., created and distributed by an attacker in the form of an advertisement or any attractive means. Once the victim visits the harmful website, a malicious JavaScript code inside the page begins the process. 

Attackers generally implement two methods to take control of local IoT devices, as discussed below:

> 1. ### Discovering or Identifying the Local IoT Devices

![Discovering IoT Devices](/IoT-and-OT-Hacking/IoT-Attacks/images/Discover-IoT-devices.png) 

> - The first attempt the attacker makes is to identify target devices, then obtain information about all the connected devices. To do this, the attacker follows the steps given below: 
>> 1. Attacker obtains local IP Address (using the malicious code). 
>> 2. Attacker requests all the available devices in the network. 
>> 3. Active devices respond with reset packet and request for inactive devices would return timeout. 
>> 4. Attacker detects all available devices based on their responses. 

> 2. ### Accessing the Local IoT Devices using DNS Rebinding 

![Accessing IoT Devices](/IoT-and-OT-Hacking/IoT-Attacks/images/Accessing-IoT-devices.png) 

> - DNS rebinding is a process of gaining access over the victim’s router using a malicious JavaScript code injected on a web page. After this, an attacker can assault any device activated using the default password. After identifying all the connected devices and their information in the network, the attacker exploits further to gain complete access to the local interconnected devices. Now that the attacker has the information on IoT devices in the network, he/she follows the steps given below: 
>> 1. Checks if the malicious code is performing DNS rebinding in all discovered devices, using DNS rebinding tools such as **Jaqen**. 
>> 2. Once the DNS rebinding is successfully implemented, the attacker can command and control the local IoT devices. 
>> 3. The attacker can further extract private information, such as the UIDs and BSSIDs of local access points that are useful in finding the geo-location of the target devices. 
> - After successfully launching this attack, the attacker could bypass the security and gain access to applications running on the local IoT devices. Further, the attacker can launch random audio or video files on different browsers of the devices. 


## Fault Injection Attacks 
>
> 1. Fault injection attacks, also known as **Perturbation attacks**, occur when a perpetrator injects any faulty or malicious program into the system to compromise the system security. 
> 2. Fault injection attacks can be both invasive and non-invasive in nature. 
>
> ### Types of Fault Injection Attacks
>
>> 1. #### Optical, Electro Magnetic Fault Injection (EMFI), Body Bias Injection (BBI). 
>> - Attackers inject faults into the device by using projecting lasers and electromagnetic pulses. 
>>
>> 2. #### Power/Clock/Reset Glitching 
>> - These types of attacks occur when faults or glitches are injected into the power supply that can be used for remote execution, also causing the skipping of key instructions. Faults can also be injected into the clock network used for delivering a synchronized signal across the chip. 
>>
>> 3. #### Frequency/Voltage Tampering 
>> - In these attacks, the attackers try to tamper with the operating conditions of a chip, and they can also modify the level of the power supply and alter the clock frequency of the chip. The intention of the attackers is to introduce fault behavior into the chip to compromise the device security. 
>>
>> 4. #### Temperature Attacks 
>> - Attackers alter the temperature for operating the chip, thereby changing the whole operating environment. This attack can be operated in non-nominal conditions. 
>
> After injecting faults using various techniques, now attackers can exploit the fault behavior of the device to perform various attacks to steal sensitive information or interrupt the normal operation of the device. 

![Fault Injection Attacks](/IoT-and-OT-Hacking/IoT-Attacks/images/Fault-Injection.png) 

## Sybil Attack
>
> 1. Vehicular communications play an important role in safe transportation by exchanging important safety messages and traffic updates, but even vehicular ad-hoc networks (VANETs) are not safe from the attackers’ reach. 
> 2. An attacker uses multiple forged identities to create a strong illusion of traffic congestion, affecting communication between neighboring nodes and networks. 
> 3. Sybil attacks in VANETs, which have a great impact on a network’s performance, are regarded as the most serious attacks. 
> 4. This type of attack impairs the potential applications in VANETs by creating a strong illusion of traffic congestion. 
> 5. To perform this type of attack, a vehicle is declared to be present in different locations at the same time. 

## Exploit Kits
> 
> - The attacker uses **malicious script** to exploit poorly patched vulnerabilities in an IoT device. 

## Man in The Middle Attack 
> 
> - The attacker **pretends to be a legitimate sender** who intercepts all the communication between the sender and receiver, and hijacks the communication. 

## Replay Attack
>
> - The attacker **intercepts legitimate messages** from a valid communication and continuously sends the intercepted message to the target device to perform a denial-of-service attack or crash the target device.  

## Forged Malicious Device 
> 
> - The attacker **replaces authentic IoT devices** with malicious devices, if they have physical access to the network. 

## Side-Channel Attack 
>
> - The attacker **extracts information about encryption keys** by observing the emission of signals i.e. "side channels" from IoT devices. 

## Ransomware Attack
>
> - Ransomware is a type of malware that **uses encryption to block the user’s access** to his/her device either by locking the screen or by locking the user’s files. 


## IoT Attacks in Different Sectors 

IoT technology is making progress in every sector of society, including industry, healthcare,
agriculture, smart cities, security, transportation, etc. However, due to the implementation of a decentralized approach in IoT technology, organizations focus less on the security of the devices. Therefore, rather than segmenting the IoT technology into different parts, suppliers focus more on spotting the vulnerabilities and exploiting them. 

These vulnerabilities present in IoT devices can be exploited by attackers to launch various types of attacks, such as DoS attacks, jamming attacks, MITM attacks, and Sybil attacks, and gather data, which results in loss of privacy and confidentiality. 

Different IoT sectors and their associated attacks are listed below: 

![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-1.png) 
![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-2.png)
![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-3.png) 
![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-4.png) 
![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-5.png) 
![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-6.png) 
![IoT Sectors](/IoT-and-OT-Hacking/IoT-Attacks/images/sectors-7.png) 


## Case Study: Enemybot

Enemybot is a **Mirai-based botnet malware** discovered in early 2022. It has been proliferating by **exploiting weaknesses in IoT and other routing devices**. 

Once a weakly configured device is identified and infected, Enemybot adds that infected IoT device to its botnet fleet. 

Enemybot **uses sophisticated string obfuscation methods** to bypass security solutions and maintains a persistent connection with the C2 server located in the Tor network. 

Below are the 5 steps of Enemybot. 

1. ### Creating Exploits 
>> 1. Enemybot borrows some modules such as **scanner and bot killer** from Mirai’s source code. 
>> 2. These modules are modified to identify vulnerable devices or processes to spread infection. 

2. ### Disabling other Malware on the Target 
>> 1. Enemybot targets multiple architectures to spread its infection. Apart from IoT devices, the malware can also infect desktop architectures such as i586, arm, arm5, arm64, arm7, Darwin, bsd, i686, m68k, mips, mpsl, ppc-440fp, sh4, spc, ppc, x64, and x86. 
>> 2. Using the **bot killer module**, the malware detects active processes triggered from specific paths or memory of the device and kills them immediately. Enemybot improves Mirai’s source code with additional keywords to detect and terminate any rival malware active on the same device. 

![Enemybot Code](/IoT-and-OT-Hacking/IoT-Attacks/images/Enemybot-Code.png) 

3. ### Gaining Access 
>> 1. After updating Mirai’s source code with suitable functions, Enemybot initiates a brute-force attack through a list of hard-coded username and password combinations to gain access to the devices configured with weak or default credentials. The malware can also infect weakly configured Android devices running on the Android Debug Bridge port (5555) through shell commands. 

4. ### Launching Attack
>> 1. Exploiting the above vulnerabilities, the threat group can launch attacks beyond DDoS, such as crypto-mining attacks. Once the exploitation is successful, a shell command is executed on the device to download another shellcode from a URL, which is dynamically updated by the remote server (C2) using the **LDSERVER command**. This command can also assist the threat group in updating the URL even if the download server is unavailable. 
>> 2. Then, the shell script **update.sh** downloads and executes the actual malware’s (Enemybot) binaries on the targeted architecture. 

5. ### Persistence 
>> 1. The malware can obfuscate its strings using several techniques such as **XOR encoding** with several byte keys, **single-byte XOR operation with 0x22**, encryption of commands with substitution ciphers, and encoding of strings by appending the value three to every character. 
>> 2. Using these obfuscation methods, Enemybot can hide its presence from analysts and other malware running on the same device. 

![Enemybot Commands](/IoT-and-OT-Hacking/IoT-Attacks/images/Enemybot-Commands.png) 


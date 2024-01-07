# OT Attacks

With evolving security threats and security posture of organizations using OT, organizations need to attach the utmost importance to OT security and adopt appropriate strategies to address security issues due to OT/IT convergence. This section discusses various OT threats and attacks such as hacking industrial networks, HMI attacks, side-channel attacks, hacking PLCs, hacking industrial machines via RF remote controllers, etc. 


## OT Vulnerabilities 

OT systems are becoming highly interconnected with IT networks. 

With increased integration and OT/IT convergence, the attack surface areas of OT systems have also increased. 

IT networks and systems experience frequent cyber-attacks; therefore, OT systems and networks may be compromised through IT networks. 

Vulnerabilities that exist in IT networks can be exploited by attackers to initiate various attacks on OT networks. 

![OT Vulnerabilities](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/OT-Vulnerabilites.png) 

Discussed below are some common OT vulnerabilities: 

> 1. ### Publicly Accessible OT Systems
>
> - OT systems are directly connected to the Internet so that third-party vendors can remotely perform maintenance and diagnostics. 
>
> - OT systesm are not protected using modern security controls. 
>
> - Ability to perform password brute-forcing or probe OT systems to disable to disrupt their functions. 
>
> 2. ### Insecure Remote Connections 
>
> - Corporate networks use jump boxes to establish remote connectivity with the OT network. 
>
> - Ability to exploit vulnerabilities in jump boxes to gain remote access to the OT systems. 
>
> 3. ### Missing Security Updates 
>
> - Outdated software versions lead to increased risks and pave the way for attackers to compromise the OT systems. 
>
> 4. ### Weak Passwords 
>
> - Operators and administrators use default usernames and passwords for OT systems, which are easily guessable. 
>
> - Ability to gain access to the OT systems, if the default vendor credentials of embedded devices and management interfaces are not changed. 
>
> 5. ### Insecure Firewall Configuration 
>
> - Misconfigured access rules allow unnecessary access between corporate IT and OT networks. 
>
> - Support teams allow excessive access permissions to the management interfaces on the firewalls. 
>
> - Insecure firewalls propagate security threats to the OT network, which makes them vulnerable to attacks. 
>
> 6. ### OT Systems Placed within the Corporate IT Network 
>
> - Corporate systems are interconnected with the OT network for accessing operational data or exporting data to third-party management systems. 
>
> - OT systems such as control stations and reporting servers are placed within the IT network. 
>
> - Ability to use compromised IT system to gain access to the OT network. 
>
> 7. ### Insufficient Security for Corporate IT Network from OT Systems 
>
> - Attacks also originate from OT systems, as they use outdated legacy software and are accessed from remote locations. 
>
> - Ability to gain unauthorized access to corporate IT systems through insecure OT devices. 
>
> 8. ### Lack of Segmentation within OT Networks 
>
> - Several OT networks have a flat and unsegmented configuration, which assumes all systems have equal importance and functions. 
>
> - Compromise of a single device may expose the entire OT network. 
>
> 9. ### Lack of Encryption and Authentication for Wireless OT Networks 
>
> - Wireless equipment in OT networks uses insecure and outdated security protocols. 
>
> - Ability to perform sniffing and authentication bypass attacks. 
>
> 10. ### Unrestricted Outbound Internet Access from OT Networks 
>
> - OT networks allow direct outbound network connections to support patching and maintenance activities from a remote location. 
>
> - Direct outbound Internet connectivity to insecure and unpatched OT devices increases the risk of malware attacks. 
>
> - Susceptibility to malware and command-and-control attacks. 


## MITRE ATT&CK for ICS 

[MITRE ATT&CK for ICS](https://collaborate.mitre.org) can be used as a knowledge base by ICS security teams or vendors to understand an attacker’s actions against OT systems and to develop a defense system to prevent them. It also helps security teams illustrate and characterize the behavior of an attacker after any compromise. 

![mitre-ICS](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/mitre-ICS.png) 
![mitre-ICS](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/mitre-ICS-2.png) 

### Initial Access 

It refers to the methods or techniques that an attacker can employ to establish initial access within the targeted ICS environment. An attacker can compromise different OT assets, websites, IT resources, and other external services to gain access to the ICS environment. Listed below are some of the techniques used by an attacker to gain initial access: 

> 1. #### Drive-by compromise: 
>
> - An attacker can gain access to the OT system by exploiting the target user’s web browser by tricking them into visiting a compromised website during a normal browsing session. 
>
> 2. #### Exploiting a public-facing software application: 
>
> - An attacker exploits the known vulnerabilities of an Internet-facing application to gain access to an OT network. Such applications can be used for remote monitoring and management. 
>
> 3. #### Exploiting remote services: 
>
> - An attacker can manipulate known vulnerabilities of an application by leveraging error messages generated by the OS, program, or the kernel to perform further attacks on the remote services. 
>
>> Listed below are some of the additional techniques used by attackers to gain initial access to an ICS environment: 
>>
>> 1. #### External remote services 
>> 2. #### Internet-accessible devices
>> 3. #### Remote services
>> 4. #### Replication through removable media
>> 5. #### Rogue master
>> 6. #### Spear-phishing attachment
>> 7. #### Supply-chain compromise
>> 8. #### Transient cyber assets
>> 9. #### Wireless compromise

### Execution 

Execution refers to an attacker’s attempt to execute malicious code, manipulate data, or
perform other system functions through illegitimate approaches. Attackers use different techniques to run malicious code within a device or asset in an ICT environment. Some of the techniques associated with this stage are as follows: 

> 1. #### Changing the operating mode: 
>
> - An attacker gains additional access to various OT functionalities by manipulating the operating modes of a controller within the infrastructure, e.g., program download. 
>
> 2. #### Command-line interface (CLI): 
>
> - An attacker uses the CLI to run various malicious commands and communicate with an OT system. It allows them to install and run different malicious programs and perform malicious operations without being detected. 
>
> 3. #### Execution through APIs: 
>
> - Attackers inject code into APIs to perform specific functions in a system after being called by the associated software. 
>> Listed below are some of the additional techniques used by attackers at the execution stage: 
>>
>> 1. #### Graphical user interface (GUI) 
>> 2. #### Hooking
>> 3. #### Modify controller tasking
>> 4. #### Native API
>> 5. #### Scripting
>> 6. #### User execution

### Persistence

Attackers employ persistence procedures to retain access within the ICS environment, even if the compromised device is restarted or the communication is interrupted. The following are some of the techniques that can be used by an attacker at this stage. 

> 1. #### Modifying a Program: 
> 
> - An attacker abuses a controller in an OT system by changing or attaching a program to it. It allows changing the behavior of how the controller communicates with other devices or processes within that environment. 
>
> 2. #### Module firmware: 
>
> - A malicious firmware can be inserted into the hardware devices by an attacker to maintain accessibility on the other devices or systems and hold footprints for long-term attacks. 
>
> 3. #### Project file infection: 
>
> - Attackers use malicious code to infect file dependencies such as objects or variables required for the functioning of programmable logic controllers (PLCs). Attackers often attempt to abuse the default functions of PLC. 
>> Listed below are some additional techniques used by attackers to maintain persistence: 
>>
>> 1. #### System firmware
>> 2. #### Valid Accounts

### Privilege Escalation 

Privilege escalation allows an attacker to achieve higher-level access and authorizations to perform further malicious activities on an ICS system or network. Some of the techniques that can be used by an attacker to escalate privileges are as follows. 

> 1. #### Exploiting software: 
>
> - Attackers can take advantage of known software vulnerabilities by abusing any programming errors to elevate privileges. 
>
> 2. #### Hooking: 
>
> - It allows attackers to hook into the APIs of different processes for redirecting and calling them to elevate privileges. 

### Evasion 

Attackers use this tactic to evade conventional defense mechanisms throughout their operations. Some of the techniques used to evade detection are as follows. 

> 1. #### Removing the indicators: 
>
> - Potential attack indicators are removed from a host to avoid detection and cover the attack footprints. 
>
> 2. #### Rootkits: 
>
> - An attacker can install rootkits to avoid detection by hiding different services, connections, and other system drivers. 
>
> 3. #### Changing the operator mode: 
>
> - The attackers can modify a controller’s operating mode to access and control different system functionalities. 
>> Some of the additional techniques for evasion are listed below: 
>>
>> 1. #### Exploitation of software vulnerabilites
>> 2. Masquerading
>> 3. Spoofed reporting messages

### Discovery

Discovery is the process of gaining information about an ICS environment to assess and identify target assets. The following are some of the techniques that can be used to gain information about the ICS environment. 

> 1. #### Enumerating the network connection: 
>
> - Attackers can gain information about the communication patterns of different network devices. 
>
> 2. #### Network Sniffing: 
>
> - An attacker can capture or monitor network information such as the protocol used, destination and source addresses, and other important information. 
>
> 3. #### Identifying remote systems: 
>
> - An attacker finds the details of other systems on the network through their hostnames, IP addresses, or other details to perform malicious activities. 
>
>> Some of the additional techniques that can be used by an attacker for discovery are listed below: 
>>
>> 1. #### Remote system information discovery
>> 2. #### Wireless sniffing

### Lateral Movement

Attackers attempt to make additional movements across the target ICS environment by leveraging the existing access. Some of the techniques used by attackers for lateral movement are as follows. 

> 1. #### Default credentials: 
>
> - An attacker can leverage the in-built credentials of the control systems to perform administrative tasks. 
>
> 2. #### Program download: 
>
> - An attacker can transmit a user program within a controller by executing a program download. 
>
> 3. #### Remote services: 
>
> - An attacker can abuse the remote services to make lateral movements within the network assets and components. 
>
>> Some of the additional techniques for lateral movement are listed below: 
>>
>> 1. #### Exploiting the remote services
>> 2. #### Lateral tool transfer
>> 3. #### Valid Accounts

### Collection

Collection refers to various methods that an attacker uses to gather information and gain knowledge regarding the data and domains of the ICS infrastructure. An attacker can use the following techniques to gather information. 

> 1. #### Automated collection: 
>
> - An attacker can use various tools or scripts to collect the information of an ICS environment automatically. 
>
> 2. #### Information repositories: 
>
> - Attackers can gain sensitive information such as layouts of a control system and specifications by targeting the information repositories. 
>
> 3. #### I/O image: 
>
> - The attackers can access the memory by obtaining the I/O image of a PLC for performing further malicious activities. 
>
>> Some of the additional techniques for collecting data are listed below: 
>> 1. #### Detecting the operating mode
>> 2. #### MiTM attack
>> 3. #### Monitoring the process state
>> 4. #### Point and tag identification
>> 5. #### Program upload
>> 6. #### Screen capture
>> 7. #### Wireless sniffing

### Command and Control (C2) 

An attacker attempts to deactivate, control, or exploit the physical control processes within the target ICS environment using command and control. Some of the techniques used for command and control are as follows. 

> 1. #### Frequently used ports: 
>
> - An attacker can use popular ports such as 80 and 443 to communicate and evade the conventional detection mechanisms. 
>
> 2. #### Connection Proxy: 
>
> - Attackers can control the traffic of the target network across the ICS environment using a connection proxy. 
>
> 3. #### Standard application-layer protocol: 
>
> - Attackers can use different application-layer protocols such as HTTPS, Telnet, and Remote Desktop Protocol (RDP) to hide their actions and establish control over the systems. 

### Inhibit Response Function 

The inhibition of response function refers to the different ways an attacker attempts to thwart reactions against any security event such as hazard or failure. Some of the techniques associated with this tactic are as follows. 

> 1. #### Activate firmware update mode: 
>
> - An attacker can activate the firmware update mode and thwart normal response functionalities during a security event. 
>
> 2. #### Block command messages: 
>
> - An attacker can block various commands or instruction messages before they reach the control systems. 
>
> 3. #### Block reporting messages: 
>
> - An attacker can stop or disrupt the reporting messages from the industrial systems and prevent them from reaching their destination, allowing the attacker to hide their activities. 
>
>> Some of the additional techniques for inhibiting response functions are listed below. 
>>
>> 1. #### Alarm Suppression
>> 2. #### Blocking serial COM
>> 3. #### Data destruction
>> 4. #### Denial of Service (DoS) 
>> 5. #### Device restart/shutdown
>> 6. #### Control I/O image
>> 7. #### Changing alarm settings
>> 8. #### Rootkit
>> 9. #### Service Stop
>> 10. #### System firmware

### Impair Process Control 

Attackers use this tactic to disable, exploit, or control the physical control processes in the target environment. Some of the techniques used for this tactic are as follows. 

> 1. #### I/O brute-forcing: 
>
> - Attackers can brute-force the I/O addresses to control a process functionality without targeting a particular interface. 
>
> 2. #### Alter the parameters: 
>
> - An attacker can manipulate the control systems by altering their instruction parameters through appropriate programming. 
>
> 3. #### Module firmware: 
>
> - An attacker can re-program a device by injecting malicious firmware into it and thereby prepare it to perform other malicious tasks. 
>
>> Some additional techniques associated with impairing process control are listed below. 
>>
>> 1. #### Spoofed reporting messages
>> 2. #### Unauthorized command messages 

### Impact 

Impact refers to the techniques used by an attacker to damage, disrupt, or gain control of the data and systems of the targeted ICS environment and its surroundings. Some of the techniques used for this tactic are as follows. 

> 1. #### Damage to property: 
> 
> - An attacker can cause heavy damage to the property and its surrounding environments by performing various attacks on the ICS. 
>
> 2. #### Loss of availability: 
>
> - Attackers can disrupt or hamper the industrial processes to make them unresponsive to the associated connections. 
>
> 3. #### Denial of control: 
>
> - An attacker can manipulate the controls to disrupt the communications between the operators and the process controls. 
>
>> Some of the additional techniques that can be used by the attackers are listed below. 
>>
>> 1. #### Denial of view
>> 2. #### Loss of control
>> 3. #### Loss of productivity and revenue
>> 4. #### Loss of protection
>> 5. #### Loss of safety
>> 6. #### Loss of view
>> 7. #### Manipulation of control
>> 8. #### Manipulation of view
>> 9. #### Theft of operational information


## OT Threats

With the convergence of OT and IT, OT systems are being used for purposes for which they were not originally designed. OT systems are being **integrated and interconnected with IT networks and are being exposed to the Internet**, which is global. Most OT systems use **legacy and outdated software with no security in place**, leaving a potential gateway for cybercriminals to gain access to corporate IT networks and OT infrastructure. In addition, **OT networks connect all machines and production infrastructure**, leading to complex and sophisticated cyber-attacks that cause even physical damage. 

![OT Threats](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/OT-Threats.png) 

Discussed below are some of the important threats faced by OT networks. 

> 1. ### Maintenance and Administrative Threat: 
>
> - Attackers exploit zero-day vulnerabilities to target the maintenance and administration of the OT network. 
>
> - By exploiting these vulnerabilities, attackers inject and spread malware to IT systems and target connected industrial control systems such as SCADA and PLC. 
>
> 2. ### Data Leakage: 
>
> - Attackers may exploit IT systems connected to the OT network to gain access to the IT/OT gateway and steal operationally significant data such as configuration files. 
> 
> 3. ### Protocol Abuse: 
>
> - Owing to compatibility issues, many **OT systems use outdated legacy protocols and interfaces such as Modbus and CAN bus**. 
>
> - **Attackers exploit these protocols and interfaces to perform various attacks on OT systems**. For example, attackers may **abuse emergency stop (e-stop)**, which is a safety mechanism used to shut down the machinery in emergencies to execute single-packet attacks. 
>
> 4. ### Potential Destruction of ICS Resources: 
>
> - Attackers exploit vulnerabilities in the OT systems to disrupt or degrade the functionality of the OT infrastructure, leading to life-and safety-critical issues. 
>
> 5. ### Reconnaissance Attacks: 
>
> - OT systems allow remote communication with minimal or no encryption or authentication mechanisms. 
>
> - Attackers can perform initial reconnaissance and scanning on the target OT infrastructure to gather information necessary for later stages of the attack. 
>
> 6. ### Denial-of-Service Attacks: 
>
> - Attackers exploit communication protocols such as Common Industrial Protocol (CIP) to perform DoS attacks on the target OT systems. 
>
> - For example, an attacker may send a malicious CIP connection request to a target device; once a connection is established, he/she may send a fake IP configuration to the device; if the device accepts the configuration, loss of communication may occur between the device and other connected systems. 
>
> 7. ### HMI-Based Attacks: 
>
> - Human–Machine Interfaces (HMIs) are often called Hacker–Machine Interfaces. 
> 
> - Even with the advancement and automation of OT, human interaction and control over the operational process remain challenges due to the underlying vulnerabilities. 
>
> - The lack of global standards for developing HMI software without any defense-in-depth security measures leads to many security problems. 
>
> - Attackers exploit these vulnerabilities to perform various attacks such as memory corruption, code injection, privilege escalation, etc. on target OT systems. 
>
> 8. ### Exploiting Enterpise-Specific Systems and Tools: 
>
> - Attackers may target ICS devices such as Safety Instrumented Systems (SIS) to inject malware by exploiting underlying protocols to detect hardware and systems used in communications, and further disrupt or damage their services. 
>
> 9. ### Spear Phishing: 
>
> - Attackers send fake emails containing malicious links or attachments, seemingly originated from legitimate or well-known sources, to the victim. 
>
> - When the victim clicks on the link or downloads the attachment, it injects malware, starts damaging the resources, and spreads itself to other systems. 
>
> - For example, an attacker sends a fraudulent email with a malicious attachment to a victim system that maintains the sales software of the operational plant. 
> 
> - When the victim downloads the attachment, the malware is injected into the sales software, propagates itself to other networked systems, and finally damages industrial automation components. 
>
> 10. ### Malware Attacks: 
>
> - Attackers are reusing legacy malware packages that were previously used to exploit IT systems for exploiting OT systems. 
>
> - They perform reconnaissance attacks to identify vulnerabilities in newly connected OT systems. 
>
> - Once they detect vulnerabilities, they reuse the older malware versions to perform various attacks on the OT systems. 
>
> - In some scenarios, attackers also develop malware targeting OT systems, such as ICS/SCADA. 
>
> 11. ### Exploiting Unpatched Vulnerabilites: 
>
> - Attackers exploit unpatched vulnerabilities in ICS products, firmware, and other software used in OT networks. 
>
> - ICS vendors develop products that are reliable and provide high-speed, real-time performance with no built-in security features. 
>
> - In addition, these vendors cannot develop patches for the identified vulnerabilities with the same speed as IT vendors. 
>
> - For these reasons, attackers target and exploit ICS vulnerabilities to perform various attacks on OT networks. 
>
> 12. ### Side-Channel Attacks: 
>
> - Attackers perform side-channel attacks to retrieve critical information from an OT system by observing its physical implementation. 
>
> - Attackers use various techniques, such as timing analysis and power analysis, to perform side-channel attacks. 
>
> 13. ### Buffer Overflow Attack: 
>
> - The attacker exploits various buffer overflow vulnerabilities that exist in ICS software, such as HMI web interface, ICS web client, communications interfaces, etc., to inject malicious data and commands to modify the normal behavior and operation of the systems. 
>
> 14. ### Exploiting RF Remote Controllers: 
>
> - OT networks use RF technology to control various industrial operations remotely. 
>
> - RF communication protocols lack in-built security for remote communication. 
>
> - Vulnerabilities in these protocols can be exploited by the attackers to perform various attacks on industrial machines that lead to production sabotage, system control, and unauthorized access. 


## HMI-based Attacks: 

Attackers often try to compromise an HMI system as it is the core hub that **controls critical infrastructure**. 

If attackers gain access over HMI systems, they can cause **physical damage to the SCADA devices** or collect sensitive information related to the critical architecture that can be used later to perform malicious activities. 

Using this information, attackers can **disable alert notifications of incoming threats to SCADA systems**. 

Discussed below are various **SCADA vulnerabilities exploited by attackers to perform HMI-based attacks** on industrial control systems. 

![HMI Attacks](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/HMI-Attacks.png) 

1. ### Memory Corruption: 
> - The vulnerabilities in this category are code security issues that include out-of-bound read/write vulnerabilities and heap-and stack-based buffer overflow. 
> 
> - In an HMI, memory corruptions take place when the memory contents are altered due to errors residing in the code. 
> 
> - When these altered memory contents are used, the program crashes or performs unintended executions. 
>
> - Attackers can accomplish memory corruption tasks simply by overwriting the code to cause a buffer overflow. 
>
> - Sometimes, the unflushed stack can also allow attackers to use string manipulation to abuse the program. 

2. ### Credential Management: 
>
> - The vulnerabilities in this category include the use of hard-coded passwords, saving credentials in simple formats such as cleartext, and inappropriate credential protection. 
>
> - These vulnerabilities can be exploited by the attackers to gain admin access to the systems and alter system databases or other settings. 

3. ### Lack of Authorization/Authentication and Insecure Defaults: 
>
> - The vulnerabilities in this category include transmission of confidential information in cleartext, insecure defaults, missing encryption, and insecure ActiveX controls used for scripting. 
>
> - An authentic SCADA solution administrator can view and access the passwords of other users. 
> 
> - Attackers can exploit these vulnerabilities to gain illegal access over the target system, and further record or manipulate the information being transmitted or stored. 

4. ### Code Injection: 
>
> - The vulnerabilities in this category include common code injections such as SQL, OS, command, and some domain-specific injections. 
>
> - Gamma is one of the prominent domain-specific languages for human–machine interfaces (HMIs) that is prone to code injection attacks. 
>
> - This script is designed to develop fast phase UI and control applications. 
>
> - An evaluate, compile, and execute code at runtime (EvalExpression) vulnerability in Gamma can be exploited by attackers to send and execute controlled arbitrary scripts or commands on the target supervisory control and data acquisition (SCADA) system. 


## Side-Channel Attacks 

Attackers perform a side-channel attack by **monitoring its physical implementation** to obtain critical information from a target system. 

Attackers use two techniques, **namely timing analysis and power analysis**, to perform side-channel attacks on the target OT systems. 

The **timing-analysis attack** is based on the **amount of time taken by the device to execute different computations**. 

The **power analysis attack** is based on the **change in power consumption during a cryptographic operation**. 

ICS systems are often vulnerable to these two side-channel attacks. 

![Side-Channel Attack](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/Side-Channel-Attack.png) 

### Timing Analysis
>
> - Passwords are often transmitted through a serial channel. 
>
> - Attackers employ a loop strategy to recover these passwords. 
>
> - They use one character at a time to check whether the first character entered is correct; if so, the loop continues for consecutive characters. 
> 
> - If not, the loop terminates. 
>
> - Attackers check how much time the device is taking to finish one complete password authentication process, through which they can determine how many characters entered are correct. 
>
> - The timing-based attacks can be easily detected and blocked. 

### Power Analysis
>
> - Power-analysis attacks are difficult to detect; the attacked device can operate even after being infected. 
>
> - Therefore, attackers often prefer to perform a power-analysis attack rather than a timing-based one to recover the sensitive information. 
>
> - This attack is performed observing the change in power consumption of semiconductors during clock cycles. 
>
> - The oscilloscope observes the time slot between two pulses via the probe. 
>
> - The power profile formed by the signals can leave a clue as to in what way the data is being processed. 


## Hacking Programmable Logic Controllers (PLC) 

PLCs are susceptible to cyber-attacks as they are used for **controlling the physical processes of the critical infrastructures**. 

Attackers identify PLCs exposed to the Internet using online **tools such as Shodan**. 

Compromised PLCs can pose a serious security threat to organizations. 

Attackers can tamper with the integrity and availability of the PLC systems by **exploiting pin control operations** and can launch attacks such as payload sabotages and PLC rootkits. 

![PLC Rootkit Attack](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/PLC-Rootkit.png) 

**Steps used to perform a PLC rootkit attack**. 

> ### Step 1: 
>
> - Attacker gains authorized access to the PLC device by injecting a rootkit. 
>
> - Then, he performs a control-flow attack against the PLC runtime to guess the default password and gain root-level access to the PLC. 
>
> ### Step 2: 
>
> - Now, the attacker maps the input and output modules along with their locations in the memory to overwrite the input and output PLC parameters. 
>
> ### Step 3: 
>
> - After learning about the I/O pins and the PLC logic mapping, the attacker manipulates the I/O initialization sequence, thus taking complete control over the PLC operations. 

A PLC rootkit attack is also referred to as a **PLC ghost attack**. 

The CPU of the PLC operates in two modes, i.e., **programming mode and run mode**. 

In the programming mode, the PLC can **remotely download the code from any computer**, and the run mode is used for **executing the actual code**. 


## Hacking Industrial Systems through RF Remote Controllers 

Most industrial machines are **operated via remote controllers**. 

These remote controllers are used in various industries, such as **manufacturing, logistics, mining, and construction, for automation or to control machines**. 

Devices in a network use a transmitter (TX) and receiver (RX) to communicate with each other. 

While the transmitter (TX) passes radio commands (via buttons), the receiver (TX) reacts to the corresponding commands. 

Improper security implementations in devices operating via **remote controllers can pose severe security risks** to industrial systems. 

**Listed below are threats industrial systems often face via RF remote controllers**. 

1. ### Replay Attack
>
> - Attackers record the commands (RF packets) transmitted by an operator and replay them to the target system to gain basic control over the system. 

![Replay-Attack](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/Replay-Attack.png) 


2. ### Command Injection 
>
> - Being aware of RF protocols, attackers can alter RF packets or inject their own packets employing reverse-engineering techniques to gain complete access over the machine. 
>
> - Attackers capture and record commands, perform reverse engineering to derive other commands used to control the target device, and inject those commands to manipulate the normal operation of the target device. 

![Command Injection](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/command-injection.png) 


3. ### Abusing E-Stop 
>
> - Using the above information, the attacker can send multiple e-stop (emergency stop) commands to the target device to cause DoS. 

![E-Stop](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/E-Stop.png) 


4. ### Re-pairing with Malicious RF Controller 
>
> - An attacker can hijack the original remote controller and pair up with the machine using a malicious RF controller, disguised as a legitimate one. 
>
> - Attackers send malicious requests to pair with target RF controllers, capture the command sequence, hijack the legitimate controller, and use a malicious controller to perform various attacks on the target device. 

![Re-pairing attack](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/re-pairing-attack.png) 


5. ### Malicious Reprogramming Attack 
>
> - Attackers can inject malware into the firmware running on the remote controllers to maintain persistent and complete remote access over the target industrial system. 

![Reprogramming](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/Reprogramming.png) 


## OT Malware 

Attackers are developing malware targeting industrial systems. **OT malware** such as **Havex** and **Industroyer** have caused severe disruption to business processes on industrial networks. It can cause potential damage to the software and hardware that is used to operate critical infrastructure. In some scenarios, OT malware can also **propagate the infection and make the devices connected to the network inoperable**. **Industrial control systems are more susceptible to malware attacks as they are connected to a wider network**. In addition, OT solutions are often vulnerable to malware attacks as they use **proprietary systems and legacy technology** that are **not regularly updated and patched**. OT ransomware, once it has infected an industrial system, can destructively lock and encrypt the hard drive files, making the system inaccessible and unusable. 

**Discussed below are some popular examples of OT malware**. 

### PIPEDREAM 

[PIPEDREAM](https://thehackernews.com) is an attack framework designed with a set of **tools aimed at ICS/SCADA devices**. Attackers use this tool set to **scan, compromise, and control** the devices of an OT network. PIPEDREAM contains **five components: EvilScholar, BadOmen, DustTunnel, MouseHole, and LazyCargo**. The malware allows attackers to make lateral moves, escalate privileges, and disrupt critical functionalities. 

Additionally, attackers can leverage this malware to compromise **Windows** devices by exploiting **ASRock motherboard driver** vulnerabilities. Using **DustTunnel** and **LazyCargo**, attackers attempt to penetrate IT systems and pivot OT networks to perform malicious activities; for example, they may **upload malicious configurations, backup** or **restore device contents**, and **alter device parameters**. 

![PIPEDREAM](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/PIPEDREAM.png) 

Listed below are some additional examples of OT malware. 
1. CaddyWiper
2. EKANS
3. MegaCorex
4. Disruptionware
5. LockerGoga
6. Triton
7. Olympic Destroyer

## INDUSTROYER.V2 Malware 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind.png) 
![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-2.png) 
![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-3.png) 


[INDUSTROYER.V2](https://www.mandiant.com) is a reloaded **variant** of the **ICS malware Industroyer** that was discovered in late **2016**, when the malware was used to cause **power disruption in Ukraine**. INDUSTROYER.V2 was discovered in 2022 with some **additional custom pieces of code to target OT-based power grids in specific regions of Ukraine**. With self-contained executables and configuration files, the malware implements the communication **protocol IEC-104** on the target network to manipulate the remote terminal units (RTUs) over TCP connections. INDUSTROYER.V2 allows attackers to integrate a custom configuration that can **change the malware behavior according to the target device’s functionality**. **Protection relays** and **merging units** are the **main targets** to achieve the goal. 

### Stage 1: Leveraging Initial Resources: 

**INDUSTROYER.V2** contains the **payload 104.dll**, which is similar to that used by its earlier variant, Industroyer, for targeting ICS networks. The malware is equipped with highly configurable programs to attack the target OT network. The **payload configuration is saved in a string format** and **injected through the IEC-104 protocol**. The table below presents the configuration structure of the malware. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-4.png) 
![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-5.png) 


These **configuration files** are **stored** independently in the **.INI file**, which is likely a recompiled version available on online public platforms. The following screenshot displays a malware configuration sample. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-6.png) 

A **configuration entry** from the above sample can appear as follows. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-7.png) 


### Stage 2: Communicating with the Target Power Station: 

If **option 4 is enabled** in the configuration entry, the malware sends specific commands to **change the state of the target station’s Information Object Addresses (IOAs) to off**. The **IOA range** is determined by configuration **options #5 and #6**. The malware’s configuration entries contain a few options **enabled by default**, which include **file rename, process termination, and application service data unit (ASDU) entries**. The **ASDU entries** are utilized to create suitable ASDU telegrams to **communicate with the remote station**. The entry structure of ASDU is presented in the table given below. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-8.png) 

After **parsing the configuration entry**, the malware scans **all the active processes** to **determine and kill** any **hard-coded process** that is **alive**. Soon after the **hard-coded process** is **terminated**, the malware scans the **active processes** again and **kills the processes** that are included by the operator in the configuration. The malware can **rename the process** by **appending .MZ** to its **filename**, which can prevent auto-revival of the targeted process after system reboot. 

A **new thread** is generated for every setting that configures the **IEC-104 protocol** with the ICS system. The protocol employs **application protocol data unit (APDU) specifications**. The APDU frame may contain only an application protocol control information (APCI) frame of fixed length and the ASDU frame, along with an APCI header of variable length. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-9.png) 


### Stage 3: Launching an Actual Attack 

The malware initially **transmits messages** related to **control functions** within the **APCI frame**. The first **message TESTFR ACT** of the test frame is forwarded to the remote station for validating an established connection. If the **connection is valid**, the station responds with the **TESTFR CON message**. 

Then, INDUSTROYER.V2 creates a **data transfer channel** toward the remote station using **Start Data Transfer (STARTDT)**. Direct data transfer between the remote and control station is not possible, although an active connection is established. Thus, **INDUSTROYER.V2 forwards the STARTDT ACT message** to open a data transfer channel, and the **remote station responds with STARTDT CON** as acknowledgment. 

Upon activating data transmission, INDUSTROYER.V2 **utilizes the ASDU frame** for **initiating commands** to the **remote station**. The ASDU telegrams contain a set of functions that can **turn the target station’s Information Object Addresses (IOA) off or on**. 

Such commands are created either based on the configuration options or ASDU entries specified above. For instance, the first ASDU entry for the above-extracted configuration can be. 

**1104 0 0 0 1 1**. 

Considering configuration entries 15 and 16, INDUSTROYER.V2 generates an ASDU packet with the following characteristics. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-10.png) 

**The generated ASDU telegram can appear as shown in the screenshot given below**. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-11.png) 

The malware **crafts suitable telegrams** for each target **remote station** and sends them accordingly. The configuration settings in the malware may develop **additional ASDU telegrams to turn on or off the remote station’s IOA**. The communication sequence of ASDU messages is described below. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-12.png) 

The following screenshot displays the **communication sequence** between the target remote station and the malware via the **IEC-104 protocol**. The message sequence contains all the above-mentioned commands such as **TESTFR** and **STARTDT** as well as **other ASDU-generated messages**, which can be directed to the target remote station’s IOA. 

![INDUSTROYER.V2](/IoT-and-OT-Hacking/OT-Hacking/OT-Attacks/images/ind-13.png) 


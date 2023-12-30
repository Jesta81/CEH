# Mobile Platform Attack Vectors. 

## Vulnerable Areas in Mobile Business Environment. 
>
> - Smartphones offer broad internet and network connectivity via different channels, such as 3G/4G/5G, Bluetooth, Wi-Fi, and wired computer connections
>

>
> - Security threats may arise in different places along these channels during data transmission. 
>

![Mobile Devices](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/mobile-network.png) 

## OWASP Top 10 Mobile Risks - 2016. 

![OWASP Mobile Devices](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/owasp-mobile.png) 

### M1 - Improper Platform Usage. 
>
> - This category covers the misuse of a platform feature or the failure to use platform security controls. It includes Android intents, platform permissions, and the misuse of Touch ID, Keychain, or some other security control that is part of the mobile device’s OS. There are several ways in which mobile apps can be exposed to this risk. 
>

### M2 - Insecure Data Storage. 
>
> - Insecure data storage vulnerability arises when development teams assume that users and malware will not have access to a mobile device’s file system and subsequently to sensitive information in the device’s data stores. “Jailbreaking” or rooting a mobile device bypasses encryption protection mechanisms. OWASP recommends analyzing platforms’ data security application programming interfaces (APIs) and calling them appropriately. 
>

### M3 - Insecure Communication. 
>
> - This category covers poor handshaking, incorrect SSL versions, weak negotiation, cleartext communication of sensitive assets, and so on. Such flaws expose an individual user’s data and can lead to account theft. If the adversary intercepts an admin account, the entire site could be exposed. A poor Secure Socket Layer (SSL) setup can also facilitate phishing and man-in-the-middle (MITM) attacks. 
>

### M4 - Insecure Authentication. 
>
> This category captures notions of authenticating the end user or bad session management such as. 
>
>> - Failing to identify the user when it is required. 
>>
>> - Failure to maintain the user's identity when it is required. 
>>
>> - Weaknesses in session management. 
>

### M5 - Insufficient Cryptography. 
>
> - The code applies cryptography to a sensitive information asset. However, cryptography is insufficient in some ways. This category covers issues in which cryptography is attempted but not performed correctly. This vulnerability will result in the unauthorized retrieval of sensitive information from the mobile device. To exploit this weakness, an adversary must successfully convert encrypted code or sensitive data into its original unencrypted form due to weak encryption algorithms or flaws in the process of encryption. 
>

### M6 - Insecure Authorization
>
> - This category captures failures in authorization (e.g., authorization decisions on the client side and forced browsing). It is distinct from authentication issues (e.g., device enrolment and user identification). 
>

### M7 - Client Code Quality. 
>
> - This category covers “Security Decisions via Untrusted Inputs” and is one of the less frequently used categories. It is the catch-all for code-level implementation problems in the mobile client, which are distinct from server-side coding mistakes. It captures buffer overflows, format string vulnerabilities, and various other code-level mistakes where the solution is to rewrite some code that is running on the mobile device. Most exploitations that fall into this category result in foreign code execution or DoS on remote server endpoints (and not the mobile device itself). 
>

### M8 - Code Tampering. 
>
> - This category covers binary patching, local resource modification, method hooking, method swizzling, and dynamic memory modification. 
>

### M9 - Reverse Engineering. 
>
> - This category includes the analysis of the final core binary to determine its source code, libraries, algorithms, and other assets. Software such as IDA, Hopper, otool, and other binary inspection tools give the attacker insights into the inner workings of the application. Thus, he/she may exploit other nascent vulnerabilities in the application and uncover information about backend servers, cryptographic constants and ciphers, and intellectual property. 
>

### M10 - Extraneous Functionality. 
>
> - Often, developers include hidden backdoor functionality or other internal development security controls that are not intended to be released into a production environment. For example, a developer may accidentally include a password as a comment in a hybrid app. Another example involves the disabling of two-factor authentication during testing. 
>

## Anatomy of a Mobile Attack

![Anatomy of a Mobile Attack](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/mobile-attack-anatomy.png) 

## The Device
>
> ### Browser-based Attacks. 
>
>> #### Phishing. 
>> - Phishing emails or pop-ups redirect users to fake web pages that mimic trustworthy sites, asking them to submit their personal information such as username, password, credit card details, address, and mobile number. Mobile users are more likely to be victims of phishing sites because the devices are small in size and they display only short URLs, limited warning messages, scaled-down lock icons, and so on. 
>>
>> #### Framing. 
>> - Framing involves a web page integrated into another web page using the iFrame elements of HTML. An attacker exploits iFrame functionality used in the target website, embeds his/her malicious web page, and uses clickjacking to steal users’ sensitive information. 
>>
>> #### Clickjacking. 
>> - Clickjacking, also known as a user interface redress attack, is a malicious technique used to trick web users into clicking something different from what they think they are clicking. Consequently, attackers obtain sensitive information or take control of the device. 
>>
>> #### Man-in-the-Mobile. 
>> - An attacker implants malicious code into the victim’s mobile device to bypass password verification systems that send one-time passwords (OTPs) via SMS or voice calls. Thereafter, the malware relays the gathered information to the attacker. 
>>
>> #### Buffer Overflow. 
>> - Buffer overflow is an abnormality whereby a program, while writing data to a buffer, surfeits the intended limit and overwrites the adjacent memory. This results in erratic program behavior, including memory access errors, incorrect results, and mobile device crashes. 
>>
>> #### Data Caching. 
>> - Data caches in mobile devices store information that is often required by these devices to interact with web applications, thereby preserving scarce resources and resulting in better responses time for client applications. Attackers attempt to exploit these data caches to access the sensitive information stored in them. 
>

> ### Phone/SMS-based Attacks. 
>
> Phone/SMS-based methods of attack are as follows. 
>
>> #### Baseband Attacks. 
>> - Attackers exploit vulnerabilities in a phone’s GSM/3GPP baseband processor, which sends and receives radio signals to cell towers. 
>>
>> #### SMiShing. 
>> - SMS phishing (also known as SMiShing) is a type of phishing fraud in which an attacker uses SMS to send text messages containing deceptive links of malicious websites or telephone numbers to a victim. The attacker tricks the victim into clicking the link or calling the phone number and revealing his or her personal information such as social security number (SSN), credit card number, and online banking username and password. 
>

> ### Application-based Attacks
>
> Application-based methods of attack are as follows. 
>
>> #### Sensitive Data Storage. 
>> - Some apps installed and used by mobile users employ weak security in their database architecture, which makes them targets for attackers who seek to hack and steal the sensitive user information stored in them.
>>
>> #### No Encryption / Weak Encryption. 
>> -  Apps that transmit unencrypted or weakly encrypted data are susceptible to attacks such as session hijacking. 
>>
>> #### Improper SSL Validation. 
>> -  Security loopholes in an application’s SSL validation process may allow attackers to circumvent the data security. 
>>
>> #### Configuration Manipulation. 
>> - Apps may use external configuration files and libraries that can be exploited in a configuration manipulation attack. This includes gaining unauthorized access to administration interfaces and configuration stores as well as retrieval of clear text configuration data.
>>
>> #### Dynamic Runtime Injection. 
>> - Attackers manipulate and abuse the run time of an application to circumvent security locks and logic checks, access privileged parts of an app, and even steal data stored in memory. 
>>
>> #### Unintended Permissions. 
>> - Misconfigured apps can sometimes open doors to attackers by providing unintended permissions. 
>>
>> #### Escalated Privileges. 
>> - Attackers engage in privilege escalation attacks, which take advantage of design flaws, programming errors, bugs, or configuration oversights to gain access to resources that are usually protected from an application or user. 
>>
>> #### Other Methods. 
>> - Other application-based methods of attack include UI overlay/pin stealing, third-party code, intent hijacking, zip directory traversal, clipboard data, URL schemes, GPS spoofing, weak/no local authentication, integrity/tampering/repackaging, side-channel attack, app signing key unprotected, app transport security, XML specialization, and so on. 
>>
>

## The System. 
>
> OS-based methods of attack are as follows. 
>
>> ### No Passcode / Weak Passcode. 
>> - Many users choose not to set a passcode or use a weak PIN, passcode, or pattern lock, which an attacker can easily guess or crack to compromise sensitive data stored in the mobile device. 
>
>> ### iOS Jailbreaking. 
>> - Jailbreaking iOS is the process of removing the security mechanisms set by Apple to prevent malicious code from running on the device. It provides root access to the OS and removes sandbox restrictions. Thus, jailbreaking involves many security risks as well as other risks to iOS devices, including poor performance, malware infection, and so on. 
>
>> ### Android Rooting. 
>> - Rooting allows Android users to attain privileged control (known as “root access”) within Android’s subsystem. Like jailbreaking, rooting can result in the exposure of sensitive data stored in the mobile device.  
>
>> ### OS Data Caching. 
>> -  An OS cache stores used data/information in memory on a temporary basis in the hard disk. An attacker can dump this memory by rebooting the victim’s device with a malicious OS and extract sensitive data from the dumped memory.  
>
>> ### Passwords and Data Accessible. 
>> - iOS devices store encrypted passwords and data using cryptographic algorithms that have certain known vulnerabilities. Attackers exploit these vulnerabilities to decrypt the device’s Keychain, exposing user passwords, encryption keys, and other private data. 
>
>> ### Carrier-loaded Software. 
>> - Pre-installed software or apps on devices may contain vulnerabilities that an attacker can exploit to perform malicious activities such as deleting, modifying, or stealing data on the device, eavesdropping on calls, and so on.  
>
>> ### User-initiated Code. 
>> - User-initiated code is an activity that tricks the victim into installing malicious applications or clicking links that allow an attacker to install malicious code to exploit the user’s browser, cookies, and security permissions.  
>
>> ### Other OS-based methods. 
>> - Other OS-based methods of attack include no/weak encryption, confused deputy attack, TEE/secure enclave processor, side-channel leakage, multimedia/file format parsers, kernel driver vulnerabilities, resource DoS, GPS spoofing, device lockout, and so on. 
>

## The Network
> 
> Network-based methods of attack are as follows. 
>
>> ### Wi-Fi (weak encryption / no encryption). 
>> - Some applications fail to encrypt data or use weak algorithms to encrypt data for transmission across wireless networks. An attacker may intercept the data by eavesdropping on the wireless connection. Although many applications use SSL/TLS, which offers protection for data in transit, attacks against these algorithms can expose users’ sensitive information.  
>>
>> ### Rogue Access Points. 
>> - Attackers install an illicit wireless access point by physical means, which allows them to access a protected network by hijacking the connections of legitimate network users.  
>>
>> ### Packet Sniffing. 
>> - An attacker uses sniffing tools such as Wireshark and Capsa Network Analyzer to capture and analyze all the data packets in network traffic, which generally include sensitive data such as login credentials sent in clear text. 
>>
>> ### Man-in-the-Middle (MITM). 
>> - Attackers eavesdrop on existing network connections between two systems, intrude into these connections, and then read or modify the data or insert fraudulent data into the intercepted communication. 
>>
>> ### Session Hijacking. 
>> - Attackers steal valid session IDs and use them to gain unauthorized access to user and network information. 
>>
>> ### DNS Poisoning. 
>> - Attackers exploit network DNS servers, resulting in the substitution of false IP addresses at the DNS level. Thus, website users are directed to another website of the attacker’s choice. 
>>
>> ### SSLStrip. 
>> - SSLStrip is a type of MITM attack in which attackers exploit vulnerabilities in the SSL/TLS implementation on websites. It relies on the user validating the presence of the HTTPS connection. The attack invisibly downgrades connections to HTTP without encryption, which is difficult for users to detect in mobile browsers.  
>>
>> ### Fake SSL Certificates. 
>> - Fake SSL certificates represent another type of MITM attack in which an attacker issues a fake SSL certificate to intercept traffic on a supposedly secure HTTPS connection. 
>>
>> ### Other network-based methods. 
>> - BGP hijacking
>> - HTTP Proxies
>

## The Data Center / CLOUD. 
>
> Data centers have two primary points of entry. 
> - Web Server
> - Database
>
> ### Web-Server-Based attacks. 
>
> - Web-server-based vulnerabilities and attacks are of the following types. 
>>
>> #### Platform Vulnerabilities. 
>> - Attackers exploit vulnerabilities in the OS, server software such as IIS, or application modules running on the web server. Sometimes, attackers can expose vulnerabilities associated with the protocol or access controls by monitoring the communication established between a mobile device and a web server. 
>>
>> #### Server Misconfiguration. 
>> - A misconfigured web server may allow an attacker to gain unauthorized access to its resources. 
>>
>> #### Cross-site Scripting (XSS). 
>> - XSS attacks exploit vulnerabilities in dynamically generated web pages, which enable malicious attackers to inject client-side script into web pages viewed by other users. Such attacks occur when invalidated input data are included in dynamic content sent to the user’s web browser for rendering. Attackers inject malicious JavaScript, VBScript, ActiveX, HTML, or Flash for execution on a victim’s system by hiding it within legitimate requests. 
>>
>> #### Cross-Site Request Forgery (CSRF). 
>> - CSRF attacks exploit web page vulnerabilities that allow an attacker to force an unsuspecting user’s browser to send unintended malicious requests. The victim holds an active session with a trusted site and simultaneously visits a malicious site that injects an HTTP request for the trusted site into his/her session, compromising its integrity. 
>>
>> #### Weak Input Validation. 
>> -  Web services excessively trust the input from mobile applications, depending on the application to perform input validation. However, attackers can forge their own communication to the web server or circumvent the app’s logic checks, allowing them to take advantage of missing validation logic on the server to perform unauthorized actions. Attackers exploit input validation flaws so that they can perform cross-site scripting, buffer overflow, injection attacks, and so on, which lead to data theft and system malfunction. 
>>
>> #### Brute-Force Attacks. 
>> - Attackers adopt the trial-and-error approach to guess the valid input to a particular field. Applications that allow any number of input attempts are generally prone to brute-force attacks. 
>>
>> #### Other Web-Server vulnerabilities. 
>> - Other web-server-based vulnerabilities and attacks include cross-origin resource sharing, side-channel attack, hypervisor attack, VPN, and so on. 
>
>
> ### Database Attacks. 
>
> Database-based vulnerabilites and attacks are of the following types. 
>
>> #### SQL Injection. 
>> - SQL injection is a technique used to take advantage of nonvalidated input vulnerabilities to pass SQL commands through a web application for execution by a backend database. It is a basic attack used to gain unauthorized access to a database or to retrieve information directly from the database. 
>>
>> #### Privilege Escalation. 
>> - This occurs when an attack leverages some exploit to gain high-level access, resulting in the theft of sensitive data stored in the database. 
>>
>> #### Data Dumping. 
>> - An attacker causes the database to dump some or all of its data, thereby uncovering sensitive records. 
>>
>> #### OS Command Execution. 
>> - An attacker injects OS-level commands into a query, causing certain database systems to execute these commands on the server. Thus, the attacker can gain unrestricted/root-level system access. 
>


## Mobile Attack Vectors and Mobile Platform Vulnerabilites. 


![Mobile attack vectors](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/mobile-attack-vectors.png) 

>
> ### Mobile Attack Vectors
>
>> #### Malware. 
>> - Virus and rootkit
>> - Application modification
>> - OS modification

>> #### Data Exfiltration
>> - Extracted from data streams and email
>> - Print screen and screen scraping
>> - Copy to USB key and loss of backup

>> #### Data Tampering
>> - Modification by another application
>> - Undetected tamper attempts
>> - Jailbroken device

>> #### Data Loss
>> - Application vulnerabilities
>> - Unapproved physical access
>> - Loss of device
>

>
> ### Mobile Platform Vulnerabilities and Risks
>
>> #### Malicious Apps in Stores
>> 1. Malicious apps in stores
>> 2. Mobile malware
>> 3. App sandboxing vulnerabilities
>> 4. Weak device and app encryption
>> 5. OS and app update issues
>> 6. Jailbreaking and rooting
>> 7. Mobile application vulnerabilites
>> 8. Privacy issues (Geolocation)
>> 9. Weak data security
>> 10. Excessive permissions
>> 11. Weak comminication security
>> 12. Physical attacks
>> 13. Insufficient code obfuscation
>> 14. Insufficient transport layer security
>> 15. Insufficient session expiration
>

## Security Issues Arising from App Stores
>
> 1. Insufficient or no vetting of apps leads to malicious and fake apps entering the app marketplace. 
>
> 2. App Stores are common targets for attackers to distribute malware and malicious apps. 
>
> 3. Attackers can also social engineer users to download and run apps outside of official app stores. 
>
> 4. Malicious apps can damage other applications and data, and send your sensitive data to attackers. 
>

![App Store Issues](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/app-store-issues.png) 

## App Sandboxing Issues
>
> - Sandboxing helps protect systems and users by limiting the resources the app can access to the mobile platform; however, malicious applications may exploit vulnerabilities and bypass the sandbox. 
>

![App Sandboxing Issues](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/sandboxing-issues.png) 


## Mobile Spam
> 
> - Unsolicited text / email messages sent to mobile devices from known / unknown phone numbers and emails. 
>
> - Spam messages contain advertisements or malicious links that can trick users info revealing confidential information. 
>
> - Significant amount of bandwidth is wasted by spam messages. 
>
> - Spam attacks are performed for financial gain. 
>

![Spam Message](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/spam-message.png) 

## SMS Phishing Attack (SMiShing) (Targeted Attack Scan) 
>
> - Most consumers access the Internet through a mobile device. 
>
> - Easy to set up a mobile phishing campaign. 
>
> - Difficult to detect and stop before harm already caused. 
>
> - Mobile users are not conditioned to receiving spam text messags on their mobile phones. 
>
> - No mainstream mechanism for weeding out spam SMSs  
>
> - Few mobile anti-viruses check SMSs. 

![SMS Phishing](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/sms-phishing.png) 

## Pairing Mobile Devices on Open Bluetooth and Wi-Fi Connections. 
>
> - Mobile device on open connections (public Wi-Fi / unencrypted WiFi routers) allows attackers to eavesdrop and intercept data transmission using techniques such as. 
>> 1. Bluesnarfing (stealing information via Bluetooth). 
>>
>> 2. Bluebugging (gaining control over the device via Bluetooth). 
>

![Bluebugging](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/bluebugging.png) 

## Agent Smith Attack
>
> - An Agent smith attack is carried out by persuading the victim to install a malicious app designed and published by an attacker. 
>
> - The malicious app replaces legitimate apps, such as WhatsApp, SHAREit, and MX Player. 
>
> - The attacker produce a huge volume of advertisements on the victim's device through the infected app for financial gains. 

![Agent Smith](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/agent-smith.png) 


## Exploiting SS7 Vulnerability
>
> - Signaling System 7 (SS7) is a communication protocol that allows mobile users to exchange communication through another cellular network. 
>
> - SS7 is operated depending on mutual trust between operators without any authentication. 
> 
> - Attackers can exploit this vulnerability to perform a man-in-the-middle attack, impending the texts and calls between communicating devices. 


![SS7 Vulnerability](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/SS7-vulnerability.png) 


## Simjacker: SIM Card Attack
>
> - Simjacker is a vulnerability associated with a SIM card's S@T browser, a pre-installed software on SIM cards that is designed to provide a set of instructions. 
>
> - Attackers exploit Simjacker to perform various malicious activities, such as capturing the location of devices, monitoring calls, forcing device browsers to connect to malicious websites, and performing DoS attacks. 

![Simjacker Vulnerability](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/simjacker.png) 


## One-time passwords (OTP) Hijacking/Two-Factor Authentication Hijacking. 
>
> - Attackers hijack OTP's and redirect them to their personal devices using different techniques such as social engineering and SMS jacking. 
>
> - Attackers succed in OTP hijacking by initially stealing victim's PII data by bribing or tricking the mobile store sellers or exploiting the reuse of the same number for different customers. 
>
> - Attackers can also use SIM jacking attacks to infect the target device's SIM using malware, through which they can intercept and read OTPs.

![OTP Hijacking](/Hacking-Mobile-Platforms/Mobile-Platform-Attack-Vectors/images/OTP-hijacking.png) 


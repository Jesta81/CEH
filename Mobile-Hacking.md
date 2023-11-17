# Hacking Mobile Platforms #

## Mobile Platform Attack Vectors ##


1. Which of the following categories of mobile risk covers “Security Decisions via Untrusted Inputs” and is one of the less frequently used categories?


	1. Code tampering
	2. Insecure communication
	3. Improper platform usage
	4. [x] Client code quality


2. Which of the following browser-based attacks involves emails or pop-ups that redirect users to fake web pages that mimic trustworthy sites, demanding the users to submit personal information?


	1. Clickjacking
	2. Framing
	3. [x] Phishing
	4. Man-in-the-Mobile

	 Explanation:

    Framing: Framing involves a web page integrated into another web page using the iFrame elements of HTML. An attacker exploits iFrame functionality used in the target website
    Clickjacking: Clickjacking, also known as a user interface redress attack, is a malicious technique used to trick web users into clicking something different from what they think they are clicking
    Man-in-the-Mobile: An attacker implants malicious code into the victim’s mobile device to bypass password verification systems that send one-time passwords (OTPs) via SMS or voice calls. Thereafter, the malware relays the gathered information to the attacker.
    **Phishing: Phishing emails or pop-ups redirect users to fake web pages that mimic trustworthy sites, asking them to submit their personal information such as username, password, credit card details, address, and mobile number**


3. Which of the following is an attack technique used by an attacker to gain remote access to a target Bluetooth-enabled device, use its features without the victim’s knowledge or consent, and perform a backdoor attack before returning control to its owner?


	1. SMiShing
	2. Bluesnarfing
	3. [x] Bluebugging
	4. Agent Smith attack


4. Which of the following attacks is performed by attackers to eavesdrop on existing network connections between two systems, intrude, and then read or modify data?


	1. DNS poisoning
	2. Packet sniffing
	3. Fake SSL certificates
	4. [x] Man-in-the-middle


5. In which of the following attacks does an attacker adopt the trial-and-error approach to guess the valid input to a particular field?


	1. Cross-site request forgery attack
	2. Cross-site scripting attack
	3. Platform vulnerabilities
	4. [x] Brute-force attack


6. Which of the following is not an OWASP Top 10 Mobile Risk?


	1. Insecure cryptography
	2. Reverse engineering
	3. Insecure communication
	4. [x] Buffer overflow

	Explanation:

According to OWASP, following are the Top 10 Mobile Risks:

     Improper platform usage
    Insecure data storage
    Insecure communication
    Insecure authentication
    Insufficient cryptography
    Insecure authorization
    Client code quality
    Code tampering
    Reverse engineering
    Extraneous functionality


7. Which of the following attacks can be performed by spam messages?


	1. Wardriving attacks
	2. Bluebugging attacks
	3. Bluesnarfing attacks
	4. [x] Phishing attacks


8. Which of the following is not a mobile platform risk?


	1. [x] Sandboxing
	2. Malicious Apps in App Store
	3. Mobile Malware
	4. Jailbreaking and Rooting


9. In which of the following attacks does an attacker bribe or socially engineer telecom providers to obtain ownership of a target user’s SIM?


	1. Clickjacking
	2. [x] OTP hijacking
	3. Framing
	4. Camfecting attack


10. Given below are the various steps involved in an OTP hijacking attack.

    1. The attacker performs social engineering on the telecom operator.
    2. The attacker’s device receives the OTP.
    3. The telecom operator transfers the victim’s SIM control.
    4. The attacker logs in to the victim’s online accounts via the OTP.
    5. The attacker gains the target user’s PII.

Identify the correct sequence of steps involved in an OTP hijacking attack.

[x] **5,1,3,2,4**



## Hacking Android OS ##



1. Which of the following Java API framework blocks manages the data sharing between applications?


	1. Activity manager
	2. [x] Content providers
	3. Window manager
	4. Notification manager


2. Which of the following practices is NOT a countermeasure to protect an Android device and the data stored in it from malicious users?


	1. Keep the device updated with Google Android antivirus software
	2. [x] Disable two-step verification on the Android mobile device
	3. Customize the lock screen with user information
	4. Enable GPS on the Android device to track it when lost or stolen

3. Which of the following is a native library used in the Android OS architecture and is meant for rendering fonts?


	1. Libc
	2. Surface Manager
	3. Open Max AL
	4. [x] FreeType


4. Which of the following Android tools is used by attackers to listen to HTTP packets sent via a wireless (802.11) network connection and extract the session IDs from these packets to reuse them?


	1. KingoRoot
	2. Orbot Proxy
	3. LOIC
	4. [x] DroidSheep


5. Which of the following countermeasures helps in protecting an Android device from malicious users?


	1. Disable screen lock for the Android device
	2. Install apps that invade privacy
	3. [x] Do not directly download Android package (APK) files
	4. Never block ads displayed by apps


6. Which of the following is an option in Android OS that is used to store private primitive data in key–value pairs?


	1. SQLite databases
	2. External storage
	3. [x] Shared preferences
	4. Internal storage


7. Which of the following practices is NOT a countermeasure to protect an Android device and the data stored on it from malicious users?


	1. [x] Enable features such as SmartLock instead of passwords
	2. Never root the Android device
	3. Download apps only from official Android markets
	4. Enable the screen pinning option to securely access Android apps


8. Which of the following tools is used to root the Android OS?


	1. zANTI
	2. [x] TunesGo
	3. DroidSheep
	4. LOIC


9. Which of the following applications allows attackers to identify the target devices and block the access of Wi-Fi to the victim devices in a network?


	1. KingoRoot
	2. [x] NetCut
	3. DroidSheep
	4. Network Spoofer


10. Which of the following android applications allows you to find, lock or erase a lost or stolen device?


	1. Find My iPhone
	2. X-Ray
	3. Faceniff
	4. [x] Find My Device


11. Which of the following mobile applications is used to perform denial-of-service attacks?


	1. MTK droid
	2. DroidSheep
	3. Unrevoked
	4. [x] Low orbit ion cannon (LOIC)



## Hacking iOS ##


1. Which of the following practices is NOT a countermeasure to secure iOS devices?


	1. Set separate passcodes for applications containing sensitive data
	2. Install Vault apps to hide critical data stored on the iOS mobile device
	3. Do not jailbreak or root the device if used within enterprise environments
	4. [x] Enable JavaScript and add-ons from the web browser


2. Which of the following is an online tool that allows attackers to hack a device remotely in an invisible mode without jailbreaking the device and access SMSes, call logs, app chats, GPS, etc.?


	1. [x] Spyzie
	2. Apricot
	3. Hexxa Plus
	4. Cydia


3. Which of the following iOS applications allows you to find, lock or erase a lost or stolen device?


	1. [x] Find My iPhone
	2. X-Ray
	3. Find My Device
	4. Faceniff


4. Which of the following Jailbreaking techniques will make the mobile device jailbroken after each reboot?


	1. Tethered Jailbreaking
	2. [x] Untethered Jailbreaking
	3. Semi-Tethered Jailbreaking
	4. None of the Above


5. Which of the following tools is not used for iOS Jailbreaking?


	1. Apricot
	2. [x] Magisk Manager
	3. checkra1n
	4. Yuxigon


6. Which of the following processes is supposed to install a modified set of kernel patches that allows users to run third-party applications not signed by the OS vendor?


	1. Spear-Phishing
	2. [x] JailBreaking
	3. WarDriving
	4. Sandboxing


7. Which of the following statements is not true for securing iOS devices?


	1. [x] Disable Jailbreak detection
	2. Do not store sensitive data on client-side database
	3. Disable Javascript and add-ons from web browser
	4. Do not jailbreak or root your device if used within enterprise environments


8. Given below are the various steps associated with the method swizzling technique used by attackers to assess the security posture and identify the vulnerabilities of the target iOS application:

    1. Run the application on the device.
    2. Create a new method with customized functionalities.
    3. Swap the functionality of the method by providing the new method reference to the Objective-C runtime.
    4. Identify the existing method selector reference to be swapped.

Identify the correct sequence of steps involved in the method swizzling technique.

[x] 4,2,1,3


9. Chris, a professional hacker, was tasked with obtaining credentials and certificates from a target iOS device. For this purpose, Chris employed a tool to extract secrets such as passwords, certificates, and encryption keys from the target iOS device’s storage system.

Identify the tool used by Chris in the above scenario.


	1. ScanMyServer
	2. [x] Keychain Dumper
	3. N-Stalker X
	4. CORE Impact


10. Which of the following tools helps attackers perform method hooking on an iOS application at runtime and gain illegal access to the sensitive information stored on the device?


	1. iStumbler
	2. Kismet
	3. Aircrack-ng Suite
	4. [x] objection

	 Explanation:

    Aircrack-ng Suite: Aircrack-ng is a network software suite consisting of a detector, packet sniffer, WEP and WPA/WPA2 PSK cracker, and analysis tool for 802.11 wireless networks. This program runs under Linux and Windows.
    **objection: Attackers use the objection tool to perform method hooking on an iOS application at runtime. It is also incorporated with other features such as iOS application patching, SSL pinning bypass, iOS keychain dumping, and pasteboard monitoring. Attackers connect an iOS device to their workstation and install the objection tool, which includes the Frida feature.**
    Kismet: Kismet is an 802.11 Layer-2 wireless network detector, sniffer, and intrusion detection system. It identifies networks by passively collecting packets and detecting standard named networks. It detects hidden networks and the presence of non-beaconing networks via data traffic.
    iStumbler: It is a WarDriving tool enabling users to list all APs broadcasting beacon signals at their location. It helps users set up new APs by ensuring that no interfering APs exist. These tools verify the network setup, find locations with poor coverage in the WLAN, and detect other networks that may be causing interference.
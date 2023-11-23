# System Hacking #


## Gaining Access (Cracking Passwords and Vulnerability Exploitation) ##


1. Which of the following countermeasures should be followed to protect systems against password cracking?


	1. Always using system default passwords
	2. Imposing no restriction on the password change policy
	3. [x] Avoiding the use of passwords that can be found in a dictionary
	4. Using the same password during a password change


2. An attacker is exploiting a buffer overflow vulnerability identified on a target server. Which of the following steps allows the attacker to send a large amount of data to the target server so that it experiences buffer overflow and overwrites the EIP register?


	1. Spiking
	2. Generation of shellcode
	3. Overwriting of the EIP Register
	4. [x] Fuzzing


3. In which of the following password attacks does an attacker attempt every combination of characters until the password is found?


	1. [x] Brute-force attack
	2. Combinator attack
	3. Rule-based attack
	4. Dictionary attack


4. Ben is a disgruntled ex-employee of an organization and has knowledge of computers and hacking. He decided to hack the organization and disrupt its operations. In this process, he cracked the passwords of remote systems by recovering cleartext passwords from a password hash dump.

	Which of the following types of password attacks did Ben perform on the target organization?


		1. Non-electronic attack
		2. [x] Offline attack
		3. Passive online attack
		4. Active online attack

		 Explanation:

    Non-Electronic Attacks: This is, for most cases, the attacker’s first attempt at gaining target system passwords. Non-electronic or non-technical attacks do not require any technical knowledge about hacking or system exploitation. Techniques used to perform non-electronic attacks include shoulder surfing, social engineering, dumpster diving, etc.
    Passive Online Attacks: A passive attack is a type of system attack that does not lead to any changes in the system. In this attack, the attacker does not have to communicate with the system, but passively monitor or record the data passing over the communication channel, to and from the system.
    Offline Attacks: Offline attacks refer to password attacks in which an attacker tries to recover cleartext passwords from a password hash dump. Offline attacks are often time-consuming but have a high success rate, as the password hashes can be reversed owing to their small keyspace and short length. Attackers use pre-computed hashes from rainbow tables to perform offline and distributed network attacks.
    Active Online Attacks: This is one of the easiest ways to gain unauthorized administrator-level system access. Here, the attacker communicates with the target machine to gain password access. Techniques used to perform active online attacks include password guessing, dictionary and brute-forcing attacks, hash injection, LLMNR/NBT-NS poisoning, use of Trojans/spyware/keyloggers, internal monologue attacks, Markov-chain attacks, Kerberos password cracking, etc.


5. Jim, a professional hacker, targeted a person to steal their banking credentials. When the target user was performing an online transaction, Jim intercepted and acquired access to the communication channel between the target and the server to obtain the credentials.

	Which of the following types of attack did Jim perform in the above scenario?


	1. Fingerprint attack
	2. Dictionary attack
	3. Rainbow table attack
	4. [x] Man-in-the-middle attack


6. Gary, a professional hacker, is attempting to access an organization’s systems remotely. In this process, he used a tool to recover the passwords of the target system and gain unauthorized access to critical files and other system software.

	Which of the following tools did Gary use to crack the passwords of the target system?


	1. [x] Hashcat
	2. Dependency Walker
	3. BeRoot
	4. OllyDbg


7. Jake, a professional hacker, was hired to perform attacks on a target organization and disrupt its services. In this process, Jake decided to exploit a buffer overflow vulnerability and inject malicious code into the buffer to damage files. He started performing a stack-based buffer overflow to gain shell access to the target system.

	Which of the following types of registers in the stack-based buffer overflow stores the address of the next data element to be stored onto the stack?


	1. [x] ESP
	2. EDI
	3. EBP
	4. EIP


8. Jude, a security professional in an organization, decided to strengthen the security of the applications used by the organization. In this process, he used a buffer-overflow detection tool that recognizes buffer overflow vulnerabilities in the applications.

	Which of the following tools helps Jude detect buffer overflow vulnerabilities?


	1. Maltego
	2. Octoparse
	3. [x] Splint
	4. Infoga


9. Which of the following tool is used for cracking passwords?


	1. OpenVAS
	2. Havij
	3. [x] John the Ripper
	4. Nikto


10. What statement is true regarding LAN Manager (LM) hashes?


	1. LM hashes consist in 48 hexadecimal characters.
	2. [x] LM hashes limit the password length to a maximum of 14 characters.
	3. LM hashes are based on AES128 cryptographic standard.
	4. Uppercase characters in the password are converted to lowercase.


	 Explanation:

    LAN Manager uses a 14-byte password. If the password is less than 14 bytes, it is concatenated with zeros. After conversion to uppercase, it is split into two 7-byte halves. From each 7-byte half an 8-byte odd parity DES key is constructed. Each 8-byte DES key is used to encrypt a fixed value. The results of these encryptions are concatenated into a 16-byte value. The value obtained is the LAN Manager one-way hash for the password.
    LM hashes limit the length of the password to a maximum of 14 characters. What makes the LM hash vulnerable is that an attacker has to go through just 7 characters twice to retrieve passwords up to 14 characters in length. There is no salting (randomness) done. For instance, if the password is 7 characters or less, the second half will always be a constant (0xAAD3B435B51404EE). If it has over 7 characters such as 10, then it is split up into a password hash of seven variable characters and another password hash of three characters. The password hash of three variable characters can be easily cracked with password crackers such as LOphtCrack. It is easy for password crackers to detect if there is an 8-character when the LM password is used. The challenge response can then be brute-forced for the LM-hash. The number of possible combinations in the LM password is low compared to the Windows NT password.


11. John the Ripper is a technical assessment tool used to test the weakness of which of the following?


	1. Usernames
	2. File permissions
	3. Firewall rulesets
	4. [x] Passwords


12. A computer science student needs to fill some information into a password protected Adobe PDF job application that was received from a prospective employer. Instead of requesting the password, the student decides to write a script that pulls passwords from a list of commonly used passwords to try against the secured PDF until the correct password is found or the list is exhausted. Identify the type of password attack.


	1. Session hijacking
	2. Man-in-the-middle attack
	3. Brute-force attack
	4. [x] Dictionary attack


13. Which of the following vulnerability repositories is available online and allows attackers access to information about various software vulnerabilities?


	1. [x] https://vulners.com
	2. http://foofus.net
	3. http://project-rainbowcrack.com
	4. https://www.tarasco.org


14. Which of the following is a password cracking tool that allows attackers to reset the passwords of the Windows local administrator, domain administrator, and other user accounts?


	1. DeepSound
	2. Audio Spyware
	3. OmniHide Pro
	4. [x] Secure Shell Bruteforcer


15. Given below are the various steps involved in an exploit chaining attack.

    1. Gather exploits one after another.
    2. Gain access to root-level services.
    3. Combine all the exploits to compromise the system.
    4. Initiate reconnaissance.

Identify the correct sequence of steps involved in performing exploit chaining attacks.

**4,1,3,2**


16. Identify the PowerView command that retrieves information related to the current domain including domain controllers (DCs).


	1. [x] Get-NetDomain
	2. Get-DomainSID
	3. Get-NetGroup -UserName <"username">
	4. (Get-DomainPolicy)."SystemAccess"


17. Aster, a professional hacker, was tasked with identifying insecurities in an organizational network. For this purpose, Aster employed a toolset to perform security checks and find insecurities, which can be exploited to launch active attacks.

	Which of the following tools did Aster employ in the above scenario?


	1. FaceNiff
	2. xHelper
	3. [x] GhostPack Seatbelt
	4. X-Ray


18. Which of the following practices makes an organization’s network vulnerable to password cracking attacks?


	1. Enable account lockout with a certain number of attempts, counter time, and lockout duration.
	2. Perform a periodic audit of passwords in the organization.
	3. [x] Never perform continuous user behavior analysis and blind-spot analysis.
	4. Ensure that password database files are encrypted and accessible only by system administrators.


19. Which of the following practices helps security experts defend an organizational network against various password cracking attempts?


	1. Always use the same password during a password change.
	2. Use passwords that can be found in a dictionary.
	3. [x] Employ geo-lock accounts to restrict users from logging in from different locations.
	4. Disable information security auditing.


20. Which of the following practices helps security professionals defend against LLMNR/NBT-NS poisoning attacks on an organizational network?


	1. Allow changes to the DWORD registry
	2. [x] Implement SMB signing
	3. Enable LMBNR
	4. Enable NBT-NS


## Escalating Privileges ##

1. Which of the following is a shim that runs in the user mode and is used by attackers to bypass UAC and perform different attacks including the disabling of Windows Defender and backdoor installation?


	1. RedirectEXE
	2. Schtasks
	3. WinRM
	4. launchd


2. Ray, a professional hacker, was hired to gather sensitive information from an organization. In the attack process, he used a tool to determine which DLLs are executable requests without an absolute path and to place his malicious DLL high up the search path so that it gets invoked before the original DLL.

	Which of the following tools helps Ray perform the above task?


	1. BCTextEncoder
	2. VeraCrypt
	3. CrypTool
	4. [x] Robber


3. Richard, an attacker, is launching attacks on a target system to retrieve sensitive information from it. In this process, he used a privilege escalation technique to place an executable in a location such that the application will execute it instead of the legitimate executable.

	Which of the following techniques was employed by Richard to escalate privileges?


	1. Web shell
	2. Application shimming
	3. Kernel exploits
	4. [x] Path interception


4. Greg, a network administrator in an organization, was instructed to strengthen the organization’s network against attacks. In this process, he implemented some countermeasures to defend against privilege escalation.

	Which of the following countermeasures allows Greg to defend against privilege escalation?


	1. Run services as privileged accounts
	2. Allow interactive logon privileges
	3. [x] Run users and applications with the lowest privileges
	4. Increase the amount of code that runs with a particular privilege


5. A pen tester is using Metasploit to exploit an FTP server and pivot to a LAN. How will the pen tester pivot using Metasploit?


	1. Set the payload to propagate through the meterpreter.
	2. [x] Create a route statement in the meterpreter.
	3. Issue the pivot exploit and set the meterpreter.
	4. Reconfigure the network settings in the meterpreter.


6. What is the best defense against a privilege escalation vulnerability?


	1. Never perform debugging using bounds checkers and stress tests and increase the amount of code that runs with particular privilege.
	2. Review user roles and administrator privileges for maximum utilization of automation services.
	3. Never place executables in write-protected directories.
	4. [x] Run services with least privileged accounts and implement multifactor authentication and authorization.


7. Which of the following techniques allows attackers to inject malicious script on a web server to maintain persistent access and escalate privileges?


	1. Launch daemon
	2. Web shell
	3. Access token manipulation
	4. Scheduled task


8. Which of the following vulnerabilities is found in all the Intel processors and ARM processors deployed by Apple (and others) and leads to tricking a process to access out of bounds memory by exploiting CPU optimization mechanisms such as speculative execution?


	1. DLL hijacking
	2. Privilege escalation
	3. [x] Meltdown
	4. Dylib hijacking

	 Explanation:

    Privilege escalation: In a privilege escalation attack, attackers first gain access to the network using a non-admin user account, and then try to gain administrative privileges. Attackers take advantage of design flaws, programming errors, bugs, and configuration oversights in the OS and software application to gain administrative access to the network and its associated applications.
    Dylib hijacking: OS X similar to windows is vulnerable to dynamic library attacks. OS X provides several legitimate methods such as setting the DYLD_INSERT_LIBRARIES environment variable, which are user specific. These methods force the loader to load malicious libraries automatically into a target running process. OS X allows loading of weak dylibs (dynamic library) dynamically, which allows an attacker to place a malicious dylib in the specified location. In many cases, the loader searches for dynamic libraries in multiple paths. This helps an attacker to inject a malicious dylib in one of the primary directories and simply load the malicious dylib at runtime. Attackers can take advantage of such methods to perform various malicious activities such as stealthy persistence, run-time process injection, bypassing security software, bypassing Gatekeeper, etc.
    Meltdown: Meltdown vulnerability is found in all the Intel processors and ARM processors deployed by Apple. This vulnerability leads to tricking a process to access out of bounds memory by exploiting CPU optimization mechanisms such as speculative execution. For example, an attacker requests to access an illegal memory location. He/she sends a second request to conditionally read a valid memory location. In this case, the processor using speculative execution will complete evaluating the result for both requests before checking the first request. When the processor checks that the first request is invalid, it rejects both the requests after checking privileges. Even though the processor rejects both the requests, the result of both the requests remains in the cache memory. Now the attacker sends multiple valid requests to access out of bounds` memory locations.
    DLL hijacking: Most Windows applications do not use the fully qualified path when loading an external DLL library; instead, they first search the directory from which they have been loaded. Taking this as an advantage, if attackers can place a malicious DLL in the application directory, the application will execute the malicious DLL in place of the real DLL.


9. Don, a professional hacker, targeted a Windows-based system to implant a fake domain controller (DC). To achieve his goal, he modified the configuration settings of domain policies to perform unintended activities such as creating a new account, disabling or modifying internal tools, ingress tool transfer, unwanted service executions, and extracting passwords in plaintext.

	In which of the following paths did Don find the domain policies folder?


	1. C:\Windows\system32>nltest/domain_trusts
	2. [x] \<DOMAIN>\SYSVOL\<DOMAIN>\
	3. C:\Windows\System32\osk.exe
	4. C:\Windows\Panther\ UnattendGC\


10. Malcolm, a professional hacker, targeted a Windows-based system to gain backdoor access. For this purpose, he escalated privileges by replacing the Windows App switcher accessibility feature with cmd.exe to gain backdoor access when a key combination is pressed at the login screen.

	Identify the Windows accessibility feature exploited by Malcolm in the above scenario.


	1. C:\Windows\System32\osk.exe
	2. C:\Windows\System32\sethc.exe
	3. C:\Windows\System32\Magnify.exe
	4. [x] C:\Windows\System32\AtBroker.exe


11. Which of the following tools allows attackers to obtain detailed information about the kernel, which can be used to escalate privileges on the target system?


	1. CrackMapExec
	2. [x] linpostexp
	3. pwdump7
	4. clearev


12. Which of the following is a post-exploitation tool used to check for common misconfigurations and find a way to escalate privileges?


	1. [x] BeRoot
	2. L0phtCrack
	3. 3CCleaner
	4. rtgen


## Maintaining Access (Executing Applications and Hiding Files) ##


1. Which of the following types of spyware can record and monitor Internet activities, record software usage and timings, record an activity log and store it at one centralized location, and log users’ keystrokes?


	1. Desktop spyware
	2. Audio spyware
	3. GPS spyware
	4. Email spyware


2. Which of the following techniques is not a countermeasure to defend against spyware?


1. [x] Always use the administrative mode
2. Adjust the browser security settings to medium or higher for the Internet zone
3. Avoid using any computer system that is not entirely under the user’s control
4. Be cautious of pop-up windows or web pages; never click anywhere on these windows`


3. Which of the following best practices should be adopted to defend against spyware?


	1. Disable a firewall to enhance the security level of the computer
	2. [x] Read all disclosures before installing an application
	3. Always use the administrative mode
	4. Download open-source music files, screensavers, or emoticons


4. Which of the following best practices should be followed to defend against rootkits?


	1. Uninstall network and host-based firewalls
	2. [x] Adhere to the least privilege principle
	3. Reinstall OS/applications from a third-party or unknown source
	4. Login to an account with administrative privileges


5. In which of the following steganography attacks does an attacker perform probability analysis to test whether a given stego-object and original data are the same?


	1. Distinguishing statistical
	2. Known-cover
	3. [x] Chi-square
	4. Chosen-message


6. Harper, a security professional in an organization, was instructed to increase the security of the organization. In this process, he trained the employees on the best practices that they should employ to defend against keyloggers.

	Which of the following is NOT a countermeasure to defend against keyloggers?


	1. Recognize phishing emails and delete them
	2. [x] Never update and patch system software
	3. Install antivirus programs and keep the signatures up to date
	4. Use pop-up blockers and avoid opening junk emails


7. Identify the technique used by the attackers to execute malicious code remotely?


	1. Rootkits and steganography
	2. [x] Install malicious programs
	3. Modify or delete logs
	4. Sniffing network traffic


8. Which one of the following software program helps the attackers to gain unauthorized access to a remote system and perform malicious activities?


	1. Antivirus
	2. Keylogger
	3. Anti-spyware
	4. [x] Rootkit


9. Which of the following techniques refers to the art of hiding data “behind” other data without the target’s knowledge?


	1. Footprinting
	2. Enumeration
	3. Scanning
	4. [x] Steganography


10. Which of the following is sophisticated malware that targets Windows machines, spreads its infection from one machine to another, and is distributed via a fake malicious Telegram installer?


	1. PoisonIvy
	2. [x] Purple Fox rootkit
	3. Necurs
	4. njRAT

11. Which of the following countermeasures allows security experts to defend against rootkits?


	1. Skip reading the instructions in the end-user license agreement (EULA) before installing software.
	2. Use configuration management and vulnerability-scanning tools to verify the effective deployment of updates.
	3. Surf the Internet while logged into an administrator account.
	4. Disable write protection on the motherboard to prevent BIOS from being infected by a rootkit.


12. Which of the following tools helps attackers implement the overpass-the-hash (OPtH) attack on a target server?


	1. KFSensor
	2. got-responded
	3. [x] Mimikatz
	4. clearev


13. Which of the following is a form of malware that attackers use to inject false credentials into domain controllers (DCs) to create a backdoor password?


	1. [x] Skeleton key
	2. Spyware
	3. Keylogger
	4. NTFS data stream


14. Which of the following commands allows attacks to abuse Data Protection API (DPAPI) to obtain all the backup master keys from Windows domain controllers (DCs)?


1. Invoke-Mimikatz -command '"lsadump::dcsync /domain:<Target Domain> /user:<krbtgt>\<Any Domain User>"
2. lsadump::dcsync /domain:domain name /user:krbtgt
3. [x] lsadump::backupkeys /system:dc01.offense.local /export
4. mimikatz “lsadump::dcsync /domain:(domain name) /user:Administrator”


15. Which of the following file-system commands allows attackers to discover SUID-executable binaries?


	1. find / -name ".txt" -ls 2> /dev/null
	2. [x] find / -perm -3000 -ls 2> /dev/null
	3. chmod o-w file
	4. keytool -list -v -keystore keystore.jks


16. Which of the following commands allows an attacker to retrieve all the users who have shell access?


	1. /sbin/ifconfig -a
	2. [x] egrep -e '/bin/(ba)?sh' /etc/passwd
	3. ls -la /etc/cron.d
	4. cat /etc/redhat* /etc/debian* /etc/'release


17. Identify the sysinternals command that allows an attacker to retrieve a remote system’s network information.


	1. psexec -i -d -s c:\windows\regedit.exe
	2. psexec -i \\<RemoteSystem> -c file.exe
	3. [x] psexec -i \\<RemoteSystem> ipconfig /all
	4. psexec -i \\<RemoteSystem> cmd


18. Which of the following commands helps network administrators view details about a specific service?


	1. netsh firewall show config
	2. [x] sc queryex type=service state=all | find /i "Name of the service: myService"
	3. netsh firewall show state
	4. sc queryex type=service state=all


19. Which of the following measures makes an organizational network vulnerable to persistence attacks?


	1. Conduct security awareness campaigns/training on phishing attacks and password creation policies.
	2. Deploy a minimum privileges access model.
	3. Regularly change KRBTGT’s password and reset the service twice.
	4. [x] Never restrict credential overlap within systems to maximize lateral movement.


20. Which of the following practices helps security professionals defend a network against persistence attacks?


	1. Allow all the inbound traffic through Windows Firewall.
	2. Never deploy the Kerberos validation tool for verifying the legitimacy of individual tickets.
	3. Never restrict credential overlap within systems to maximize lateral movement.
	4. [x] Restrict domain users within a local administrator group across multiple systems.


## Clearing Logs ##

1. Which of the following commands is used by an attacker to delete only the history of the current shell and retain the command history of other shells?


	1. history –c
	2. [x] history -w
	3. export HISTSIZE=0
	4. [x] cat /dev/null > ~.bash_history && history –c && exit


2. Which of the following countermeasures allows a security professional to defend against techniques for covering tracks?


	1. Ensure that new events overwrite old entries in log files
	2. Periodically back up log files to alterable media
	3. Leave all unused open ports and services as they are
	4. [x] Activate the logging functionality on all critical systems


3. Identify the technique used by the attackers to wipe out the entries corresponding to their activities in the system log to remain undetected?


	1. [x] Clearing logs
	2. Escalating privileges
	3. Executing applications
	4. Gaining access


4. Which of the following techniques is used by the attackers to clear online tracks?


	1. Disable LAN manager
	2. Disable the user account
	3. Disable LMNR and NBT-NS services
	4. [x] Disable auditing


5. Which of the following is a sh-compatible shell that stores command history in a file?


	1. Zsh
	2. [x] BASH
	3. ksh
	4. Tcsh/Csh


6. Which of the following technique is used by the attacker to distribute the payload and to create covert channels?


	1. [x] TCP parameters
	2. Covering tracks
	3. Clear online tracks
	4. Performing steganalysis

	 Explanation:

    TCP Parameters: TCP parameters can be used by the attacker to distribute the payload and to create covert channels. Some of the TCP fields where data can be hidden are as follow:
        IP Identification field: This is an easy approach where a payload is transferred bitwise over an established session between two systems. Here, one character is encapsulated per packet.
        TCP acknowledgement number: This approach is quite difficult as it uses a bounce server that receives packets from the victim and sends it to an attacker. Here, one hidden character is relayed by the bounce server per packet.
        TCP initial sequence number: This method also does not require an established connection between two systems. Here, one hidden character is encapsulated per SYN request and Reset packets.
    Clear Online Tracks: Attackers clear online tracks maintained using web history, logs, cookies, cache, downloads, visited time, and others on the target computer, so that victims cannot notice what online activities attackers have performed.
    Covering Tracks: Covering tracks is one of the main stage during system hacking. In this stage, the attacker tries to hide and avoid being detected, or “traced out,” by covering all “tracks,” or logs, generated while gaining access to the target network or computer.
    Steganalysis: Steganalysis is the process of discovering the existence of the hidden information in a medium. Steganalysis is the reverse process of steganography. It is one of the attacks on information security in which attacker called a steganalyst tries to detect the hidden messages embedded in images, text, audio and video carrier mediums using steganography.


7. Which of the following registry entry you will delete to clear Most Recently Used (MRU) list?


	1. HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
	2. HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
	3. [x] HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
	4. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AppKey


8. Which of the following commands allows an attacker having administrator privileges to hide any file or folder in a Windows system?


	1. net user <UserName> /add
	2. net user <UserName> /active:no
	3. [x] attrib +h +s +r <FolderName>
	4. mkdir .HiddenMaliciousFiles


9. Carter, a professional hacker, infiltrated a target Windows system and wanted to maintain persistence without being traced. For this purpose, he executed a command to hide his account in the Windows system.

	Identify the command executed by Carter in the above scenario.


	1. [x] net user <UserName> /active:no
	2. touch MaliciousFile.txt
	3. net user <UserName> /active:yes
	4. net user <UserName> /add


10. Which of the following practices helps security experts defend against covering track attempts?


	1. Periodically back up log files to alterable media.
	2. [x] Use restricted ACLs to secure log files.
	3. Deactivate the logging functionality on all critical systems.
	4. Open all unused open ports and services.
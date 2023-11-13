1. In which of the following attacks does an attacker use techniques such as timing analysis and power analysis to obtain critical information from a target industrial system?


	1. [x] Side-channel attack
	2. Malware attack
	3. Protocol abuse
	4. Buffer overflow attack
<br>

2. Identify the technique in which an attacker can gain access to an OT system by exploiting the target user’s web browser after tricking them into visiting a compromised website during a normal browsing session.

	1. [x] Drive-by compromise
	2. Checking the filtering systems of target networks
	3. Shoulder surfing
	4. Launch daemon

<br>

3. Which of the following techniques allows an attacker to achieve higher-level access and authorizations to perform further malicious activities on an ICS system or network?


	1. Network address translation
	2. Activity profiling
	3. Obfuscating
	4. [x] Hooking

<br>

4. Smith, a professional hacker, was attempting to gain access to a target ICS network. To achieve his goal, he initiated reconnaissance to gather information about the devices in the network, their IP addresses, hostnames, and other details.

Which of the following techniques did Smith employ in the above scenario


	1. [x] Identifying remote systems
	2. Password guessing
	3. IP address decoy
	4. Hooking
<br>

5. Which of the following techniques allows attackers to perform additional movements across a target ICS environment by leveraging existing access?


	1. Cookie sniffing
	2. Drive-by downloads
	3. [x] Remote services
	4. Proxy server DNS poisoning

<br>

6. Identify the technique that allows an attacker to deactivate, control, or exploit the physical control processes within a target ICS environment using command and control.


	1. [x] Connection proxy
	2. Anti-disassembly
	3. Alternative trusted medium
	4. Impersonation 

<br>

7. Peter, a professional hacker, managed to gain unauthorized access to a target ICS network. He wanted to thwart reactions to any security event such as a hazard or failure. For this purpose, Peter employed a technique to block command messages to stop defense solutions from reacting to any security event.

Identify the technique employed by Peter in the above scenario.


	1. Command and control
	2. Persistence
	3. Evasion
	4. [x] Inhibit response function

<br>

8. In which of the following phases of MITRE ATT&CK for ICS does an attacker use various tactics such as I/O brute-forcing and parameter altering to disable, exploit, or control the physical control processes in the target environment?

	1. Lateral movement
	2. Privilege escalation
	3. Collection
	4. [x] Impair process control

<br>

9. Which of the following phases of MITRE ATT&CK for ICS involves the use of techniques by an attacker to damage, disrupt, or gain control of the data and systems of the targeted ICS environment and its surroundings?


	1. Impair process control
	2. [x] Impact
	3. Discovery
	4. Inhibit response function

<br>

10. Robert, a professional hacker, targeted an ICS network to cause power disruption in specific areas of a targeted region. To achieve his goal, he employed malware that has self-contained executables and configuration files and implements the communication protocol IEC-104 on the target network to manipulate the RTUs over TCP connections for disrupting the target OT-based power grids.

Identify the malware employed by Robert in the above scenario.


	1. eCh0raix
	2. [x] INDUSTROYER.V2
	3. Dharma
	4. Divergent
<br>


11. Which of the following online tools allows attackers to discover the default credentials of a device or product simply by entering the device name or manufacturer name?


	1. Netcraft
	2. Thingful
	3. [x] CRITIFENCE
	4. Censys

<br>

12. Which of the following Nmap commands helps attackers identify the HMI systems in a target OT network?


	1. nmap -Pn -sT -p 1911,4911 --script fox-info <Target IP>
	2. [x] nmap -Pn -sT -p 46824 <Target IP>
	3. nmap -Pn -sU -p 44818 --script enip-info <Target IP>
	4. nmap -Pn -sT -p 102 --script s7-info <Target IP>

<br>

13. Which of the following tools passively maps and visually displays an ICS/SCADA network topology while safely conducting device discovery, accounting, and reporting on these critical cyber-physical systems?

	1. SCADA Shutdown Tool
	2. [x] GRASSMARLIN
	3. Gqrx
	4. Shodan

<br>

14. Which of the following tools helps attackers scan and examine firmware binaries and images as well as retrieve information such as encryption types, sizes, partitions, and file systems?


	1. Fritzing
	2. [x] Binwalk
	3. Multimeter
	4. GDB

<br>

15. Which of the following commands helps attackers gather information and identify critical network activities of an ICS network?


	1. msfvenom -p windows/shell_reverse_tcp lhost=<Target IP Address> lport=444 -f exe > /home/attacker/Windows.exe
	2. run post/windows/gather/arp_scanner RHOSTS <target subnet range>
	3. Invoke-Mimikatz -command '"lsadump::dcsync /domain:<Target Domain> /user:<krbtgt>\<Any Domain User>"
	4. [x] python -m fuzzowski printer1 631 -f ipp -r get_printer_attribs --restart smartplug

<br>

16. Which of the following tools helps security professionals perform an automated security assessment of software to identify configuration and application vulnerabilities?


	1. LOIC
	2. Azure IoT Central
	3. [x] IoTVAS
	4. Gqrx
<br>
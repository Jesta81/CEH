# OT Concepts

Operational technology (OT) plays a major role in today’s modern society, as it drives a collection of devices designed to work together as an integrated or homogeneous system. For example, OT in telecommunications is used to transfer information from the electrical grid through wheeling power. The same telecommunications are also used for financial transactions between electrical producers and consumers. OT is a combination of hardware and software that is used to monitor, run, and control industrial process assets. Before learning how to hack OT, it is important to understand its basic concepts. This section discusses various important concepts related to OT. 


## What is OT? 

Operational Technology (OT) is the software and hardware designed to **detect or cause changes in industrial operations** through direct monitoring and/or controlling of industrial physical devices. 

OT consists of **Industrial Control Systems (ICS)** that include Supervisory Control and Data Acquisition (SCADA), Remote Terminal Units (RTU), Programmable Logic Controllers (PLC), Distributed Control System (DCS), etc., to monitor and control the industrial operations. 

![OT Network Devices](/IoT-and-OT-Hacking/OT-Hacking/images/OT-Devices.png) 

![OT Components](/IoT-and-OT-Hacking/OT-Hacking/images/OT-Components.png) 


## Essential Terminology 

1. ### Assets

OT systems consist of **physical assets** such as sensors and actuators, servers, workstations, network devices, and PLCs, and logical assets such as flow graphics, program logic, databases, firmware, and firewall rules. 

2. ### Zones and Conduits 

A **network segregation technique** used to isolate the networks and assets to impose and maintain strong access control mechanisms. 

3. ### Industrial Network

A network of **automated control systems** is known as an industrial network. 

4. ### Business Network

It comprises of a network of systems that offer information infrastructure to the business. 

5. ### Industrial Protocols 

Protocols used for **serial communication** and communication over standard Ethernet. Ex: S7, CDA, CIP, Modbus, etc. 

6. ### Network Perimeter 

It is the outermost boundary of a network zone i.e. **closed group of assets**. 

7. ### Electronic Security Perimeter 

It is referred to as the **boundary** between secure and insecure zones. 

8. ### Critical Infrastructure 

A collection of **physical or logical systems and assets** that the failure or destruction of which will severely impact the security, safety, economy, or public health. 


## IT/OT Convergence (IIOT)

IT/OT convergence is the integration of **IT computing systems and OT operation monitoring systems** to bridge the gap between IT/OT technologies for improving overall security, efficiency, and productivity. 

The IT/OT convergence can enable smart manufacturing known as **industry 4.0**, where IoT applications are used in industrial operations. 

Using this Internet of Things (IoT) for industrial operations such as monitoring supply chains, manufacturing and management systems is referred to as **Industrial Internet of Things (IIoT)**. 

### Benefits of merging OT with IT 
>
> #### Enhancing Decision Making: 
> - Decision making can be enhanced by integrating OT data into business intelligence solutions. 
>
> #### Enhancing Automation: 
> - Business flow and industrial control operations can be optimized by OT/IT merging; together they can improve the automation. 
>
> #### Expedite Business Output: 
> - IT/OT convergence can organize or streamline development projects to accelerate business output. 
>
> #### Minimizing Expenses: 
> - Reduces the technological and organizational overheads. 
>
> #### Mitigating Risks: 
> - Merging these two fields can improve overall productivity, security, and reliability, as well as ensuring scalability. 

![IIOT](/IoT-and-OT-Hacking/OT-Hacking/images/IIOT.png) 

## The Purdue Model

![Purdue Model](/IoT-and-OT-Hacking/OT-Hacking/images/Purdue-Model.png) 

The Purdue model is derived from the Purdue Enterprise Reference Architecture (PERA) model, which is a widely used conceptual model that describes the internal connections and dependencies of important components in ICS networks. The Purdue model is also known as the Industrial Automation and Control System reference model. 

**The Purdue model consists of three zones**. 

1. The Manufacturing zone (OT). 
2. The Enterprise zone (IT). 
3. The Industrial Demilitarized Zone (IDMZ). 

### Enterprise Zone (IT Systems) 

**The enterprise security zone is a part of IT, in which supply-chain management and scheduling are performed using business systems such as SAP and ERP. It also locates the data centers, users, and cloud access. The enterprise zone consists of two levels**. 

> #### Level 5 (Enterprise Network) 
>
> - This is a corporate level network where business operations such as B2B (business-to-business) and B2C (business-to-customer) services are performed. 
>
> - Internet connectivity and management can be handled at this level. 
>
> - The enterprise network systems also accumulate data from all the subsystems located at the individual plants to report the inventory and overall production status. 
>
> #### Level 4 (Business Logistics Systems) 
>
> - All the IT systems supporting the production process in the plant lie at this level. 
>
> - Managing schedules, planning, and other logistics of the manufacturing operations are performed here. 
>
> - Level 4 systems include application servers, file servers, database servers, supervising systems, email clients, etc. 

### Manufacturing Zone (OT Systems) 

**All the devices, networks, control, and monitoring systems reside in this zone. The manufacturing zone consists of four levels**. 

> #### Level 3 (Operational Systems/Site Operations) 
>
> - In this level, the production management, individual plant monitoring, and control functions are defined. 
>
> - Production workflows and output of the desired product are ensured at this level. 
>
> - Production management includes plant performance management systems, production scheduling, batch management, quality assurance, data historians, manufacturing execution/operation management systems (MES/MOMS), laboratories, and process optimization. 
>
> - Production details from lower levels are collected here and can then be transferred to higher levels or can be instructed by higher-level systems.
>
> #### Level 2 (Control Systems/Area Supervisory Controls) 
>
> - Supervising, monitoring, and controlling the physical process is carried out at this level. 
>
> - The control systems can be DCSs, SCADA software, Human–Machine Interfaces (HMIs), real-time software, and other supervisory control systems such as engineering works and PLC line control. 
>
> #### Level 1 (Basic Controls/Intelligent Devices) 
>
> - Analyzation and alteration of the physical process can be done at this level. 
>
> - The operations in basic control include “start motors,” “open valves,” “move actuators,” etc. 
>
> - Level 1 systems include analyzers, process sensors, and other instrumentation systems such as Intelligent Electronic Devices (IEDs), PLCs, RTUs, Proportional Integral Derivative (PID) controllers, Equipment Under Control (EUC), and Variable Frequency Drives (VFDs). 
>
> - PLC was used in level 2 with a supervisory functionality, but it is used as a control function in level 1. 
>
> #### Level 0 (Physical Process) 
>
> - In this level, the actual physical process is defined, and the product is manufactured. 
>
> - Higher levels control and monitor operations at this level; therefore, this layer is also referred to as Equipment Under Control (EUC). 
>
> - Level 0 systems include devices, sensors (e.g., speed, temperature, pressure), actuators, or other industrial equipment used to carry out the manufacturing or industrial operations. 
>
> - A minor error in any of the devices at this level can affect overall operations. 

### Industrial Demilitarized Zone (IDMZ) 
>
> - The demilitarized zone is a barrier between the manufacturing zone (OT systems) and enterprise zone (IT systems) that enables a secure network connection between the two systems. 
>
> - The zone is created to inspect overall architecture. 
>
> - If any errors or intrusions compromise the working systems, the IDMZ holds the error and allows production to be continued without interruption. IDMZ systems include Microsoft domain controllers, database replication servers, and proxy servers. 


## Challenges of OT

![Challenges of OT](/IoT-and-OT-Hacking/OT-Hacking/images/OT-Challenges.png) 

OT plays a vital role in several sectors of critical infrastructure, like **power plants, water utilities, and healthcare**. 

Absurdly, most OT systems run on old versions of software and use **obsolete hardware**, which makes them vulnerable to malicious exploits like **phishing, spying, ransomware attacks, etc**. 

These types of attacks can be devastating to products and services. 

To curb these vulnerabilities, the OT system must employ critical examination in key areas of vulnerability by using various security tools and tactics. 

Discussed below are some of the challenges and risks to OT that makes it vulnerable to many threats: 

> 1. ### Lack of visibility: 
>
> - Broader cybersecurity visibility in the OT network achieves greater security and so one can rapidly respond to any potential threats. 
>
> - However, most organizations do not have clear cybersecurity visibility, making it difficult for the security teams to detect unusual behaviors and signatures. 
>
> 2. ### Plain-text passwords: 
>
> - Most industrial site networks use either weak or plain-text passwords. 
>
> - Plain-text passwords lead to weak authentication, which in turn leaves the systems vulnerable to various cyber-reconnaissance attacks. 
>
> 3. ### Network complexity: 
>
> - Most OT network environments are complex due to comprising numerous devices, each of which has different security needs and requirements. 
>
> 4. ### Legacy technology: 
>
> - OT systems generally use older technologies without appropriate security measures like encryption and password protection, leaving them vulnerable to various attacks. 
>
> - Applying modern security practices is also a challenge. 
>
> 5. ### Lack of antivirus protection: 
>
> -  Industries using legacy technology and outdated systems are not provided with any antivirus protection, which can update signatures automatically, thus making them vulnerable to malware infections. 
>
> 6. ### Lack of skilled security professionals: 
>
> - The cybersecurity skills gap poses a great threat to organizations, as there is a lack of skilled security professionals to discover threats and implement new security controls and defenses in networks. 
>
> 7. ### Rapid pace of change: 
>
> - Maintaining the pace of change is the biggest challenge in the field of security, and slow digital transformation can also compromise OT systems. 
>
> 8. ### Outdated Systems: 
>
> - Most OT devices, such as PLCs, use outdated firmware, making them vulnerable to many modern cyberattacks. 
>
> 9. ### Haphazard modernization: 
>
> - As the demand for OT grows, it must stay up to date with the latest technologies. 
>
> - However, due to the use of legacy components in OT system upgrading and patching, updating the system can take several years, which can adversely affect several operations. 
>
> 10. ### Insecure connections: 
>
> - OT systems communicate over public Wi-Fi and unencrypted Wi-Fi connections in the IT network for transferring control data, making them susceptible to man-in-the-middle attacks. 
>
> 11. ### Usage of rogue devices: 
>
> - Many industrial sites have unknown or rogue devices connected to their networks, which are vulnerable to various attacks. 
>
> 12. ### Convergenge with IT: 
>
> - OT mostly connects with the corporate network; as a result, it is vulnerable to various malware attacks and malicious insiders. 
>
> - In addition, the OT systems are IT enabled, and the IT security team does not have much experience with the OT systems and protocols. 
>
> 13. ### Organizational challenges: 
>
> - Many organizations implement and maintain different security architectures that meet the needs of both IT and OT. 
>
> - This can create some flaws in security management, leaving ways for the attackers to intrude into the systems easily. 
>
> 14. ### Unique production networks/proprietary software: 
>
> - Industries follow unique hardware and software configurations that are dependent on industry standards and explicit operational demands. 
>
> - The use of proprietary software makes it difficult to update and patch firmware, as multiple vendors control it. 
>
> 15. ### Vulnerable communication protocols: 
>
> - OT uses communication protocols such as **Modbus and Profinet** for supervising, controlling, and connecting different mechanisms such as controllers, actuators, and sensors. 
>
> - These protocols lack in-built security features such as **authentication, detection of flaws, or detection of abnormal behavior**, making them vulnerable to various attacks. 
>
> 16. ### Remote management protocols: 
>
> - Industrial sites use remote management protocols such as **RDP, VNC, and SSH**. Once the attacker compromises and gains access to the OT network, he/she can perform further exploitation to understand and manipulate the configuration and working of the equipment. 


## Introduction to ICS 

The Industrial Control System (ICS) is often referred to as a collection of different types of **control systems** and their associated equipment such as systems, devices, networks, and controls used to operate and automate several industrial processes. 

An ICS consists of several types of control systems like **SCADA, DCS, BPCS, SIS, HMI, PLCs, RTU, IED**, etc. 

The operation of ICS systems can be configured in three modes, namely, **open loop, closed loop, and manual mode**. 

ICS systems are extensively used in industries like electricity production and distribution, water supply and waste-water treatment, oil and natural gas supply, chemical and pharmaceutical production, pulp and paper, and food and beverages. 

![ICS Components](/IoT-and-OT-Hacking/OT-Hacking/images/ICS-Components.png) 

![ISC architecture](/IoT-and-OT-Hacking/OT-Hacking/images/ICS-Architecture.png) 


## Components of an ICS - Distributed Control System (DCS) 

![DCS](/IoT-and-OT-Hacking/OT-Hacking/images/DCS.png) 

DCS is a highly engineered and **large-scale control system** that is often used to perform industry specific tasks. 

It contains a **centralized supervisory control** unit used to control multiple local controllers, thousands of I/O points, and various other field devices that are part of the overall production process. 

It operates using a centralized supervisory control loop (SCADA, MTU, etc.) that connects a group of **localized controllers** (RTU/PLC) to execute the overall tasks required for the working of an entire production process. 

## Supervisory Control and Data Acquisition (SCADA) 

![SCADA](/IoT-and-OT-Hacking/OT-Hacking/images/SCADA.png) 

SCADA is a **centralized supervisory control** system that is used for controlling and monitoring industrial facilities and infrastructure. 

It provides **centralized controlling and monitoring** of multiple process inputs and outputs by integrating the data acquisition system with the data transmission system and Human Machine Interface (HMI) software. 

> ### The SCADA architecture comprises the following hardware: 
>
> 1. Control server (SCADA-MTU)
>
> 2. Communication devices (network cables, radio devices, telephone lines, cables, etc.) 
>
> 3. Field sites distributed geographically consisting of PLCs, RTUs, etc. which are used to monitor and control the operation of industrial equipment. 


## Programmable Logic Controller (PLC)

![PLC](/IoT-and-OT-Hacking/OT-Hacking/images/PLC.png) 

A programmable logic controller (PLC) is a small **solid-state control computer** where instructions can be customized to perform a specific task. 

PLC systems consists of three modules: 
>
> 1. ### CPU Module: 
>
> - It comprises of a central processor and its memory component. 
>
> 2. ### Power Supply Module:
>
> - It provides a necessary supply of power required for the CPU and I/O modules by converting the power from AC to DC. 
>
> 3. ### I/O Modules: 
>
> - These are used in connecting the sensors and actuators with the system for sensing and controlling the real-time values such as pressure, temperature, and flow. 

PLCs are used in industries such as the steel industry, automobile industry, energy sector, chemical industry, glass industry, and paper industry. 


## Basic Process Control System (BPCS) 

![BPCS](/IoT-and-OT-Hacking/OT-Hacking/images/BPCS.png) 

A BPCS is responsible for **process control and monitoring** of the industrial infrastructure. 

It is a system that **responds to input signals** from the process and associated equipment to generate output signals that cause the process and its associated equipment to operate based on an approved design control strategy. 

A BPCS is applicable to all sorts of control loops like temperature control loops, batch control, pressure control loops, flow control loops, feedback and feed-forward control loops used in industries such as chemical, oil and gas, and food and beverages. 

Listed below are some of the important functions offered by BPCS: 
>
> - Offers trending and alarm/event logging facilities. 
>
> - Provides an interface from which an operator can monitor and control a system using an operator console (HMI). 
>
> - Controls the processes that in turn optimize the plant operation to enhance the quality of the product. 
>
> - Generates production data reports. 


## Safety Instrumented Systems (SIS) 

![SIS](/IoT-and-OT-Hacking/OT-Hacking/images/SIS.png) 

An SIS is an automated control system designed to **safeguard the manufacturing environment** in case of any hazardous incident in the industry. 

It is an essential component of a **risk management strategy** that uses layers of protection to prevent the operational boundaries of critical processes from reaching an unsafe operating condition. 

**An SIS system basically comprises of sensors, logic solvers and final control elements that maintain safe operation of processes by performing the following functions**. 
>
> 1. ### Field Sensors collect information: 
> 
> - **Sensors collect information** to determine and measure the process parameters (temperature, pressure, etc.) to predict if the equipment is operating in a safe state or not. 
>
> 2. ### Logic solvers act as controllers: 
>
> - Logic solvers act as controllers that capture signals from the sensors and execute the pre-programmed actions to avoid risk by providing output to the final control elements. 
>
> 3. ### The final control elements: 
>
> - The final control elements implement the actions determined by the logic controller to bring the system to a safe state. 

![SIS-Layers](/IoT-and-OT-Hacking/OT-Hacking/images/SIS-Layers.png)

Typical examples of SIS systems are fire and gas systems, safety interlock systems, safety shutdown systems, etc. 


## OT Technologies and Protocols 

Industrial network protocols constitute the real-time interconnectivity and information exchange between industrial systems and zones. These network protocols are deployed across the ICS network in any industry. To understand any industrial network, a security engineer needs to understand the protocols existing beneath the networks. 

![OT-Protocols](/IoT-and-OT-Hacking/OT-Hacking/images/OT-Protocols.png) 

### Protocols used on Level 4 and 5: 
>
> #### DCOM
>
> - DCOM (Distributed Component Object Model) is Microsoft’s proprietary software that enables software components to communicate directly over a network reliably and securely. 
>
> #### DDE
>
> - DDE (Dynamic Data Exchange) is used for IPC (Inter-Process Communication). 
>
> #### FTP/SFTP 
>
> - FTP establishes a connection to the specific server or computer, and it is also used to download or transfer files. SFTP verifies the identity of the client, and once a secured connection is established information is exchanged. 
>
> #### GE-SRTP 
>
> - GE-SRTP (Service Request Transport Protocol), developed by GE Intelligent Platforms, is used to transfer data from PLCs, and runs on a selected number of GE PLCs that turn digital commands into physical actions. 
>
> #### IPv4/IPv6 
>
> - IPv4 is a connectionless protocol used in packet-switched networks. IPv6 is used for packet-switched internetworking, which provides end-to-end datagram transmission across multiple IP networks. 
>
> #### OPC
>
> - OPC (Open Platform Communications) is a set of client/server protocols designed for the communication of real-time data between data acquisition devices like PLCs and interface devices like HMIs. 
>
> #### TCP/IP 
>
> - TCP/IP is a suite of communication protocols used for the interconnection of networking devices over the Internet. 
>
> #### Wi-Fi 
>
> - Wi-Fi is a technology that is widely used in wireless local area networking or LAN. The most common Wi-Fi standard used in homes or companies is 802.11n, which offers a maximum speed of 600 Mbps and a range of approximately 50 m. 

### Protocols used in Level 3 
>
> #### CC-Link:
>
> - A CC-Link (Control and Communications Link) is an open industrial network that enables devices from different manufacturers to communicate. It is used in machine, process control, and building automation. 
>
> #### HSCP: 
>
> - Hybrid SCP (Secure Copy Protocol) is developed for transmitting larger file sizes at high speed on long-distance and wideband infrastructure. 
>
> #### ICCP (IEC 60870-6): 
>
> - ICCP (Inter-Control Center Communications Protocol) (IEC 60870-6) provides a set of standards and protocols for covering ICS or SCADA communication in power system automation. 
>
> #### IEC 61850: 
>
> - IEC 61850 is a common protocol that enables interoperability and communications between the IEDs at electrical substations. 
>
> #### ISA/IEC 62443: 
>
> - ISA/IEC 62443 provides a flexible framework for addressing and mitigating current and future security vulnerabilities in industrial automation and control systems. 
>
> #### Modbus: 
>
> - Modbus is a serial communication protocol that is used with PLCs and enables communication between many devices connected to the same network. 
>
> #### NTP: 
>
> - NTP (Network Time Protocol) is a networking protocol that is used for clock synchronization between computer systems over packet-switched and variable-latency data networks. 
>
> #### Profinet: 
>
> - Profinet is a communication protocol used to exchange data between controllers like PLCs and devices like RFID readers. 
>
> #### SuiteLink: 
>
> - SuiteLink protocol is based on TCP/IP and runs as a service on Windows operating systems. It is mostly used in industrial applications that value time, quality, and high throughput. 
>
> #### Tase-2
>
> - Tase-2, also referred to as IEC 60870-6, is an open communication protocol that enables the exchange of time-critical information between control systems through WAN and LAN. 

### Protocols used in Level 2 
>
> #### 6LoWPAN: 
>
> - IPv6 over Low Power Personal Area Networks (6LoWPAN) is an Internet Protocol used for communication between smaller and low-power devices with limited processing capacity; it is mainly used for home and building automation. 
>
> #### DNP3: 
>
> - DNP3 (Distributed Network Protocol 3) is a communication protocol used to interconnect components within process automation systems. 
>
> #### DNS/DNSSEC: 
>
> - Domain Name System Security Extensions (DNSSEC) provide a way to authenticate DNS response data and can secure information provided by DNS. 
>
> #### FTE: 
>
> - Fault Tolerant Ethernet (FTE) is designed to provide rapid network redundancy, and each node is connected twice to a single LAN through dual network interfaces. 
>
> #### HART-IP: 
>
> - The HART-IP protocol is used to integrate WirelessHART gateways and HART multiplexers tightly and efficiently for sending and receiving digital information. 
>
> #### IEC 60870-5-101/104: 
>
> - This is an extension of the IEC 101 protocol with some modifications in transport, network, link, and physical layer services. It enables communication between the control station and substation through the standard TCP/IP network. 
>
> #### SOAP: 
>
> - SOAP (Simple Object Access Protocol) is a messaging protocol containing a stern set of rules that can administrate data transfer between client and server using the XML message format. 

### Protocols used in Level 0 and 1 

> #### BECnet: 
>
> - BACnet (Building Automation and Control network) is a data communication protocol designed for building automation and control networks that implements standards such as ASHRAE, ANSI, and ISO 16484-5. 
>
> #### EtherCAT: 
>
> - Ethernet for Control Automation Technology (EtherCAT) is an Ethernet-based fieldbus system that is appropriate for both hard and soft real-time computing necessities in automation technology. 
>
> #### CANopen: 
>
> - CANopen is a high-level communication protocol based on the CAN (Controller Area Network) protocol. It is used for embedded networking applications like vehicle networks. 
>
> #### Crimson: 
>
> - Crimson is the common programming platform used for a variety of Red Lion products such as G3 and G3 Kadet series HMIs, Data Station Plus, Modular Controller, and the Productivity Station. 
>
> #### DeviceNet: 
>
> - DeviceNet is another variant of the Common Industrial Protocol (CIP) that is used in the automation industry for interconnecting control devices to exchange data. 
>
> #### Zigbee: 
>
> - Zigbee is a short-range communication protocol that is based on IEEE 203.15.4 standard. Zigbee is used for devices that transfer data intermittently at a low data rate in a restricted area and within a range of 10–100 m. 
>
> #### ISA SP100: 
>
> - ISA SP100 is a committee for establishing the industrial wireless standard ISA100. ISA100 is used for the industrial manufacturing environment and process automation industry. 
>
> #### MELSEC-Q: 
>
> - MELSEC-Q provides an open and seamless network environment integrating different levels of automation networks such as CC-Link IE, high-speed, and large-capacity ethernet-based integrated open networks. 
>
> #### Niagara Fox: 
>
> - Niagara Fox protocol is a building automation protocol used between the Niagara software systems developed by Tridium. 
>
> #### Omron Fins: 
>
> - Omron Fins is used by PLC programs for transferring data and performing other services with remote PLC connected on an Ethernet network. It can also be used by remote devices such as FieldServer for transferring data. 
>
> #### PCWorx: 
>
> - PCWorx is used in many ICS components, and they make a series of inline controllers (ILCs). These controllers allow the use of different ICS protocols and some common TCP/IP protocols. 
>
> #### Profibus: 
>
> - Profibus is more complex than Modbus, and is designed and developed to address interoperability issues. It is employed in process automation and factory automation fields. 
>
> #### Sercos II: 
>
> - The serial real-time communication system (Sercos II) comprises a digital drive interface appropriate for use in industrial machines. It is used in complex motion control applications with high specification designs. 
>
> #### S7 Communications: 
>
> - S7 Communication is a Siemens proprietary protocol that runs between programmable logic controllers (PLCs) of the Siemens S7-300/400 family and is used in PLC programming and for accessing PLC data from SCADA. 
>
> #### WiMax: 
>
> - Worldwide Interoperability for Microwave Access (WiMax) is based on the standard IEEE 802.16 and is envisioned for wireless metropolitan area networks. WiMax operates at frequencies between 2.5 GHz and 5.8 GHz with a transfer rate of 40 Mbps. 


# Iot Concepts 

The IoT is an important and emerging topic in the field of technology, economics, and society in general. It is referred to as the web of connected devices, made possible by the intersection between machine-to-machine communications and big data analytics. The IoT is a future-facing development of the Internet and abilities of physical devices that are gradually narrowing the gap between the virtual and physical world. This section deals with some of the important IoT concepts that one should be familiar with to understand the advanced topics covered later in this module. 

![IoT Devices](/IoT-and-OT-Hacking/IoT-Concepts/IoT.png) 

## What is the IoT? 

> - Internet of Things (IoT), also known as **Internet of Everything (IoE)**, refers to the network of devices having IP addresses and the capability to sense, collect, and send data using embedded sensors, communication hardware and processors. 
>
> - In IoT, the term **thing** is used to refer to a device that is **implanted on natural, human-made, or machine-made objects** and has the functionality of **communicating over the network**. 

## How the IoT Works 

![IoT Workings](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-workings.png) 

> - IoT technology includes four primary systems: 
>>
>> 1. ### Sensing Technology 
>> - Sensors embedded in the devices sense a wide variety of information from their surroundings, including temperature, gases, location, workings of some industrial machinery, or health data of a patient. 
>>
>> 2. ### IoT Gateways 
>> - Gateways are used to bridge the gap between an IoT device (internal network) and the end-user (external network), thus allowing them to connect and communicate with each other. The data collected by the sensors in the IoT device is sent to the connected user or cloud through the gateway. 
>>
>> 3. ### Cloud Server/Data Storage 
>> - After traveling through the gateway, the collected data arrives at the cloud, where it is stored and undergoes data analysis. The processed data is then transmitted to the user, who can take certain actions based on the information received. 
>>
>> 4. ### Remote Control using Mobile App 
>> - The end-user uses remote controls such as mobile phones, tablets, laptops, etc. installed with a mobile app to monitor, control, retrieve data, and take a specific action on IoT devices from a remote location. 


## IoT Architecture

![IoT Architecture](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-architecture.png) 

> - The IoT architecture includes several layers, from the Application layer at the top to the Edge Technology layer at the bottom. These layers are designed in such a way that they can meet the requirements of various sectors, including societies, industry, enterprises, governments, etc. 

>> ### Iot Architecture Layers 
>>
>> 1. #### Edge Technology Layer 
>> - This layer consists of all the hardware components, including sensors, radio-frequency identification (RFID) tags, readers, or other soft sensors, and the device itself. These entities are the primary part of the data sensors that are deployed in the field for monitoring or sensing various phenomena. This layer plays an important part in data collection, and in connecting devices within the network and with the server. 
>>
>> 2. #### Access Gateway Lay 
>> - This layer helps to bridge the gap between two endpoints, such as a device and a client. The initial data handling also takes place in this layer. This layer carries out message routing, message identification, and subscribing. 
>>
>> 3. #### Internet Layer
>> - This is a crucial layer as it serves as the main component in carrying out communication between two endpoints, such as device-to-device, device-to-cloud, device-to-gateway, or back-end data sharing. 
>>
>> 4. #### Middleware Layer 
>> - This is one of the most critical layers that operates in two-way mode. As the name suggests, this layer sits in the middle of the application layer and the hardware layer, thus behaving as an interface between these two layers. It is responsible for important functions such as data management, device management, and various issues like data analysis, data aggregation, data filtering, device information discovery, and access control. 
>>
>> 5. #### Application Layer
>> - This layer, placed at the top of the stack, is responsible for the delivery of services to the relevant users from different sectors, including building, industrial, manufacturing, automobile, security, healthcare, etc. 


## IoT Application Areas and Devices 

![Areas and Devices](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-areas-and-devices.png) 
![Areas and Devices](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-areas-and-devices-2.png) 
![Areas and Devics](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-areas-and-devices-3.png) 
![Areas and Devices](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-areas-and-devices-4.png) 


## Iot Technologies and Protocols

The IoT includes a wide range of new technologies and skills. The challenge in the IoT space is the immaturity of technologies with associated services, and that of the vendors providing them. This poses a key challenge for the organizations exploiting the IoT. For successful communication between two endpoints, IoT primarily implements standard and networking protocols. The major communication technologies and protocols with respect to the range between a source and the destination are as follows:  

![IoT Tech and Protocols](/IoT-and-OT-Hacking/IoT-Concepts/images/IoT-tech-and-protocols.png) 

### Short-Range Wireless Communication 
>
>> #### Bluetooth Low Energy (BLE): 
>> - BLE or Bluetooth Smart is a wireless personal area network. This technology is designed to be applied in various sectors such as healthcare, security, entertainment, and fitness. 
>>
>> #### Light-Fidelity (Li-Fi) 
>> - Li-Fi is like Wi-Fi with only two differences: the mode of communication and the speed. Li-Fi is a Visible Light Communications (VLC) system that uses common household light bulbs for data transfer at a very high speed of 224 Gbps. 
>>
>> #### Near-Field Communication (NFC): 
>> - NFC is a type of short-range communication that uses magnetic field induction to enable communication between two electronic devices. It is primarily used in contactless mobile payment, social networking, and the identification of documents or other products. 
>>
>> #### QR Codes and Barcodes: 
>> - These codes are machine-readable tags that contain information about the product or item to which they are attached. A quick response code, or QR code, is a two-dimensional code that stores product information and can be scanned using smartphones, whereas a barcode comes in both one-dimensional (1D) and two-dimensional (2D) forms of code. 
>>
>> #### Radio-Frequency Identification (RFID): 
>> - RFID stores data in tags that are read using electromagnetic fields. RFID is used in many sectors including industrial, offices, companies, automobiles, pharmaceuticals, livestock, and pets. 
>>
>> #### Thread:
>> - A thread is an IPv6-based networking protocol for IoT devices. Its main purpose is home automation so that the devices can communicate with each other on local wireless networks. 
>>
>> #### Wi-Fi: 
>> - Wi-Fi is a technology that is widely used in wireless local area networking (LAN). At present, the most common Wi-Fi standard that is used in homes or companies is 802.11n, which offers a maximum speed of 600 Mbps and a range of approximately 50 m. 
>>
>> #### Wi-Fi Direct: 
>> - This is used for peer-to-peer communication without the need for a wireless access point. Wi-Fi direct devices start communication only after deciding which device will act as an access point. 
>>
>> #### Z-Wave: 
>> - Z-Wave is a low-power, short-range communication designed primarily for home automation. It provides a simple and reliable way to wirelessly monitor and control household devices like HVAC, thermostats, garages, home cinemas, etc. 
>>
>> #### Zig-Bee: 
>> - This is another short-range communication protocol based on the IEEE 203.15.4 standard. Zig-Bee is used in devices that transfer data infrequently at a low rate in a restricted area and within a range of 10–100 m. 
>>
>> #### Adaptive Network Topology (ANT): 
>> - Adaptive Network Topology (ANT) is a multicast wireless sensor network technology mainly used for short-range communication between devices related to sports and fitness sensors. 


### Medium-Range Wireless Communication: 
>
>> #### HaLow: 
>> - This is another variant of the Wi-Fi standard; it provides an extended range, making it useful for communications in rural areas. It offers low data rates, thus reducing the power and cost of transmission. 
>>
>> #### LTE-Advanced: 
>> - LTE-Advanced is a standard for mobile communication that provides enhancement to LTE, focusing on providing higher capacity in terms of data rate, extended range, efficiency, and performance. 
>>
>> #### 6LoWPAN: 
>> - IPv6 over Low-Power Wireless Personal Area Networks (6LoWPAN) is an Internet protocol used for communication between smaller and low-power devices with limited processing capacity, such as various IoT devices. 
>>
>> #### QUIC: 
>> - Quick UDP Internet Connections (QUICs) are multiplexed connections between IoT devices over the User Datagram Protocol (UDP); they provide security equivalent to SSL/TLS. 
>>


### Long-Range Wireless Communication: 
>
>> #### LPWAN: 
>> - Low Power Wide Area Networking (LPWAN) is a wireless telecommunication network, designed to provide long-range communications between two endpoints. Available LPWAN protocols and technologies include the following: 
>>> 1. ##### LoRaWAN 
>>> - A Long Range Wide Area Network (LoRaWAN) is used to support applications such as mobile, industrial machine-to-machine, and secure two-way communications for IoT devices, smart cities, and healthcare applications. 
>>> 2. ##### Sigfox: 
>>>> - This is used in devices that have short battery life and need to transfer a limited amount of data. 
>>> 3. ##### Neul: 
>>> - This is used in devices that have short battery life and need to transfer a limited amount of data. 
>>
>> #### Very Small Aperture Terminal (VSAT): 
>> - VSAT is a communication protocol that is used for data transfer using small dish antennas for both broadband and narrowband data. 
>>
>> #### Cellular: 
>> - Cellular is a type of communication protocol that is used for communication over a longer distance. It is used to send high-quality data but with the drawbacks of being expensive and having high power consumption. 
>>
>> #### MQTT: 
>> - Message Queuing Telemetry Transport (MQTT) is an ISO standard lightweight protocol used to transmit messages for long-range wireless communication. It helps in establishing connections to remote locations, for example via satellite links. 
>>
>> #### NB-IoT: 
>> - Narrowband IoT (NB-IoT) is a variant of LoRaWAN and Sigfox that uses more enhanced physical layer technology and the spectrum used for machine-to-machine communication. 


### Wired Communication 
>
>> #### Ethernet: 
>> - Ethernet is the most commonly used type of network protocol today. It is a type of LAN (Local Area Network) that consists of a wired connection between computers in a small building, office, or campus. 
>>
>> #### Multimeadia over Coax Alliance (MoCA):
>> - MoCA is a type of network protocol that provides high-definition videos and related content to homes over existing coaxial cables. 
>>
>> #### Power-Line Communication (PLC): 
>> - This is a type of protocol that uses electrical wires to transmit power and data from one endpoint to another. PLC is required for applications in different areas such as home automation, industrial devices, and broadband over power lines (BPL). 


### IoT Operating Systems 

IoT devices consist of both hardware and software components. Hardware components include end devices and gateways, whereas software components include operating systems. Due to an increase in the production of hardware components (gateways, sensor nodes, etc.), traditional IoT devices that previously used to run without an OS started adopting new OS implementations specifically programmed for IoT devices. These operating systems provide the devices with connectivity, usability, and interoperability. 
>
> #### IoT Operating Systems (OS): 
>
>> 1. ##### Windows 10 IoT: 
>> - This is a family of operating systems developed by Microsoft for embedded systems. 
>>
>> 2. ##### Amazon FreeRTOS: 
>> - This is a free open-source OS used in IoT microcontrollers that makes low-power, battery-operated edge devices easy to deploy, secure, connect, and manage. 
>>
>> 3. ##### Contiki: 
>> - This is used in low-power wireless devices such as street lighting, sound monitoring systems, etc.
>>
>> 4. ##### Fuchsia: 
>> - This is an open-source OS developed by Google for various platforms, such as embedded systems, smartphones, tablets, etc. 
>>
>> 5. ##### RIOT: 
>> - This has fewer resource requirements and uses energy efficiently. It has the ability to run on embedded systems, actuator boards, sensors, etc. 
>>
>> 6. ##### Ubuntu Core: 
>> - Also known as Snappy, this is used in robots, drones, edge gateways, etc. 
>>
>> 7. ##### ARM Mbed OS: 
>> - This is mostly used for low-powered devices such as wearable devices. 
>>
>> 8. ##### Zephyr: 
>> - This is used in low-power and resource-constrained devices. 
>>
>> 9. ##### Embedded Linux: 
>> - This is used with all small, medium, and large embedded systems. 
>>
>> 10. ##### NuttX RTOS: 
>> - This is an open-source OS primarily developed to support 8-bit and 32-bit microcontrollers of embedded systems. 
>>
>> 11. ##### Integrity RTOS: 
>> - Primarily used in the aerospace or defense, industrial, automotive, and medical sectors. 
>>
>> 12. ##### Apache Mynewt: 
>> - This supports devices that work on the BLE protocol. 

### IoT Application Protocols: 
>
>> #### Constrained Application Protocol (CoAP): 
>> - Constrained Application Protocol (CoAP) is a web transfer protocol used to transfer messages between constrained nodes and IoT networks. This protocol is mainly used for machine-to-machine (M2M) applications such as building automation and smart energy. 
>>
>> #### Edge: 
>> - Edge computing helps the IoT environment to move computational processing to the edge of the network, allowing smart devices and gateways to perform tasks and services from the cloud end. Moving computational services to the edge of the network improves content caching, delivery, storage, and management of the IoT. 
>>
>> #### Lightweight Machine-to-Machine (LWM2M): 
>> - Lightweight Machine-to-Machine (LWM2M) is an application-layer communication protocol used for application-level communication between IoT devices; it is used for IoT device management. 
>>
>> #### Physical Web: 
>> - Physical Web is a technology used to enable faster and seamless interaction with nearby IoT devices. It reveals the list of URLs being broadcast by nearby devices with BLE beacons. 
>>
>> #### eXtensible Messaging and Presence Protocol (XMPP): 
>> - eXtensible Messaging and Presence Protocol (XMPP) is an open technology for real-time communication used for IoT devices. This technology is used for developing interoperable devices, applications, and services for the IoT environment. 
>>
>> #### Mihini/M3DA: 
>> - Mihini/M3DA is a software used for communication between an M2M server and applications running on an embedded gateway. It allows IoT applications to exchange data and commands with an M2M server. 



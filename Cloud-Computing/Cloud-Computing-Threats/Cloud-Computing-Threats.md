# Cloud Computing Threats

- Most organizations adopt cloud technology because it reduces the cost via optimized and efficient computing. Robust cloud technology offers different types of services to end-users; however, many people are concerned about critical cloud security risks and threats, which attackers may take advantage of to compromise data security, gain illegal access to networks, etc. This section deals with significant security threats and vulnerabilities affecting cloud systems. 


## [OWASP](https://owasp.org) Top 10 Cloud Security Risks 

![OWASP Cloud Top 10](/Cloud-Computing/Cloud-Computing-Threats/images/OWASP-10.png) 

- **The table below summarizes the top 10 cloud security risks, according to OWASP**. 

>
> 1. ### Accountability and Data Ownership 
>
>>
>> - Organizations use the public cloud for hosting business services instead of a traditional data center. 
>>
>> - Sometimes using the cloud causes the loss of data accountability and control, whereas using a traditional data center helps in controlling and protecting the data logically and physically. 
>>
>> - Using the public cloud can jeopardize data recoverability and result in critical risks, which the organization needs to mitigate promptly. 
>>
>
> 2. ### User Identity Federation 
>
>>
>> - Enterprises use services and applications of different cloud providers, creating multiple user identities and complicating the management of multiple user IDs and credentials. 
>>
>> - Cloud providers have less control over the user lifecycle /offboarding. 
>>
>
> 3. ### Regulatory Compliance 
>
>>
>> - Following regulatory compliance can be complex. 
>>
>> - Data that is secured in one country may not be secured in another country owing to the lack of transparency and different regulatory laws followed across various countries. 
>>
>
> 4. ### Business Continuity and Resiliency 
>
>>
>> - Performing business continuity in an IT organization ensures that the business can be conducted in a disaster situation. 
>>
>> - When organizations use cloud services, there is a chance of risk or monetary loss if the cloud provider handles the business continuity improperly. 
>>
>
> 5. ### User Privacy and Secondary Usage of Data 
>
>>
>> - The use of social websites poses a risk to personal data because they are stored in the cloud and most social application providers mine user data for secondary usage. 
>>
>> - The default share feature in social networking sites can jeopardize the privacy of user personal data. 
>>
>
> 6. ### Service and Data Integration 
>
>>
>> - Organizations must ensure proper protection when proprietary data are transferred from the end-user to the cloud data center. 
>>
>> - Unsecured data in transit are susceptible to eavesdropping and interception attacks. 
>>
>
> 7. ### Multi Tenancy and Physical Security 
>
>>
>> - Cloud technology uses the concept of multi-tenancy for sharing resources and services among multiple clients, such as networking, databases. 
>>
>> - Inadequate logical segregation may lead to tenants interfering with each other’s security features. 
>>
>
> 8. ### Incidence Analysis and Forensic Support 
>
>>
>> - When a security incident occurs, investigating applications and services hosted at a cloud provider can be challenging because event logs are distributed across multiple hosts and data centers located at several countries and governed by different laws and policies. 
>>
>> - Owing to the distributed storage of logs across the cloud, law enforcing agencies may face problem in forensics recovery. 
>>
>
> 9. ### Infrastructure Security 
>
>>
>> - Configuration baselines of the infrastructure should comply with the industry best practices because there is constant risk of malicious actions. 
>>
>> - Misconfiguration of infrastructure may allow network scanning for vulnerable applications and services to retrieve information, such as active unused ports and default passwords and configurations. 
>>
>
> 10. ### Non-Production Environment Exposure 
>
>>
>> - Non-production environments are used for application design and development and to test activities internally within an organization. 
>>
>> - Using non-production environments increases the risk of unauthorized access, information disclosure, and information modification. 
>>
>


## OWASP Top 10 Serverless Security Risks 


- Though serverless computing simplifies the process of application deployment and eliminates the need for managing the server and hardware by the developers, it also passes some of the security threats to the cloud service providers. **Serverless applications still execute a code and vulnerabilities within the code may open gateways to various application-level attacks, such as XSS, structured query language (SQL) injection, DoS, and broken authentication and authorization**; i.e., serverless applications are vulnerable to the same type of attacks as traditional web applications. 


![OWASP Serverless Risks](/Cloud-Computing/Cloud-Computing-Threats/images/OWASP-Serverless-Risks.png) 


- The table below summarizes the top 10 serverless security risks, according to OWASP. 


>
> 1. ### Injection 
>
>>
>> - #### Attack Vectors
>>
>> - Input arrives not only from API but also from serverless functions that are invoked from various event sources, such as cloud storage events **(S3 Blob), stream data processing (AWS Kinesis), database modifications (DynamoDB, CosmoDB), code modifications (AWS CodeCommit), and notifications (SMS, email, IoT)**. 
>>
>> - Firewall cannot filter the events generated through email or a database. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **SQL/NoSQL Injection**
>>>
>>> - **OS Command Injection**
>>>
>>> - **Code Injection**
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - Impact depends on the **permissions of the vulnerable function**. 
>>>>
>>>> - If the **function has access to the cloud storage, the injected code can delete data or upload corrupted data. 
>>>>
>>>
>>
>
> 2. ### Broken Authentication 
>
>>
>> - #### Attack Vectors
>>
>> - **Serverless functions are stateless**, are executed separately, have different goals, and are triggered by different events. 
>>
>> - Attackers try to **identify missing resources, such as open APIs and public cloud storage**. 
>>
>> - If **functions are invoked through organizational emails**, attackers can **send spoofed emails to trigger the functions and execute internal functionality without authentication**. 
>>>
>>> - #### Security Weakness
>>>
>>> - **Poor Design of Identity and access Controls. 
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - Accessing functions **without authentication leads to sensitive data leakage, system business logic breakage, and execution flow disruption**. 
>>>>
>>>
>>
>
> 3. ### Sensitive Data Exposure 
>
>>
>> - #### Attack Vectors
>>
>> - Attacks on traditional web applications, such as **cracking keys, man-in-the-middle (MiTM) attacks, and data stealth in transit and at rest**, are also applicable to serverless applications. 
>>
>> - Attackers target **cloud storage (S3, Blob) and database tables (DynamoDB, CosmoDB)**. 
>>
>>>
>>> - #### Security Weakness 
>>>
>>> - **Storing sensitive data in plaintext or using weak encryption**. 
>>>
>>> - **Writing data to the /tmp directory** without removing after use. 
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - **Exposure of sensitive data, such as PII, health records, credentials, and credit card details**. 
>>>>
>>>
>>
>
> 4. ### XML External Entities (XXE) 
>
>>
>> - #### Attack Vectors 
>>
>> - If serverless functions are **running inside internal virtual private networks (VPNs)**, attacks such as **scanning internal networks and DoS, are not possible**. 
>>
>> - These attacks **only affect the designated container** in which the function is running. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **Using XML processors** might make the application vulnerable to XXE attacks. 
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - Impact depends on the compromised resource. 
>>>>
>>>> - **Leakage of data from cloud storage and database**. 
>>>>
>>>
>>
>
> 5. ### Security Misconfiguration
>
>>
>> - #### Attack Vectors
>>
>> - Misconfigured functions with a **long timeout and low concurrency limit** allow attackers to perform **DoS attack**. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **Poor Patch Management**. 
>>>
>>> - **Functions with long timeout configuration and low concurrency**. 
>>>
>>>>
>>>> - #### Impact
>>>>
>>>> - **Sensitive information leakage, loss of money, Dos, and unauthorized access to cloud resources**. 
>>>>
>>>
>>
>
> 6. ### Broken Access Control
>
>>
>> - #### Attack Vectors 
>>
>> - The stateless nature of serverless architecture allows attackers to **exploit over-privileged functions to gain unauthorized access to resources**. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **Granting functions access and privileges to unnecessary resources**. 
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - Impact depends on the compromised resource. 
>>>>
>>>> - **Leakage of data from cloud storage and database**. 
>>>>
>>>
>>
>
> 7. ### Cross-Site Scripting (XSS) 
>
>>
>> - #### Attack Vectors
>>
>> - In traditional applications, XSS vulnerabilities arrive from **databases or reflective inputs**, but in serverless applications, they also arrive from sources such as **emails, logs, cloud storage, IoT, etc**. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **Untrusted input used to generate data without proper escaping**. 
>>>
>>>>
>>>> - #### Impact
>>>>
>>>> - **User Impersonation**. 
>>>>
>>>> - **Access to Sensitive data, such as API keys**. 
>>>>
>>>
>>
>
> 8. ### Insecure Deserialization 
>
>>
>> - #### Attack Vectors
>>
>> - **Dynamic languages (e.g., Python, NodeJS) along with JavaScript object notation (JSON)**, a serialized datatype, allow attackers to **perform deserialization attacks**. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **Deserialization vulnerabilities in Python, JavaScript, etc**. 
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - Impact depends on the sensitivity of data the application handles. 
>>>>
>>>> - **Running arbitrary code, data leakage, resource and account control**. 
>>>>
>>>
>>
>
> 9. ### Using Components with Known Vulnerabilites 
>
>>
>> - #### Attack Vectors
>>
>> - Serverless functions are used for **microservices**, which **depend on third-party libraries** for execution. 
>>
>> - Vulnerable third-party libraries allow attackers to gain an **entry point to serverless application**. 
>>
>>>
>>> - #### Security Weakness 
>>>
>>> - **Lack of knowledge on component-heavy deployment patterns**. 
>>>
>>>>
>>>> - #### Impact
>>>>
>>>> - Business impact depends on the specification of known vulnerabilities. 
>>>>
>>>
>>
>
> 10. ### Insufficient Logging and Monitoring
>
>>
>> - #### Attack Vectors
>>
>> - Complex serverless **auditing and lack of monitoring and timely response** pave the way for various attacks. 
>>
>>>
>>> - #### Security Weakness
>>>
>>> - **Insufficient security monitoring and auditing**. 
>>>
>>>>
>>>> - #### Impact 
>>>>
>>>> - The impact of late security incident identification can be significant. 


## Cloud Computing Threats 

![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats.png) 


![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-2.png) 

### Data Breach/Loss 

> - An improperly designed cloud computing environment with multiple clients is at high risk of a data breach because a flaw in one client’s application can allow attackers to access other client’s data. Data loss or leakage is highly dependent on cloud architecture and operation. 
>
> - Data is erased, modified or decoupled (lost). 
> - Encryption keys are lost, misplaced or stolen. 
> - Data are accessed illegally owing to improper authentication, authorization, and access controls. 
> - Data is misused by the CSP. 
>
> #### Countermeasures
>
>> - Encrypt the data stored in the cloud and the data in transit to protect data integrity. 
>>
>> - Implement strong key generation, storage, and management. 
>>
>> - Check for data protection both during design and runtime. 
>>
>> - Enforce multi-factor authentication. 
>>
>> - Perform secure data backups regularly to recover from data loss. 
>>
>> - Deploy data loss prevention (DLP) software to detect potential threats to data. 
>>
>> - Enforce appropriate security policies by classifying the data according to sensitivity levels. 
>>
>> - Deploy cloud access security brokers (CASBs) that restrict operations such as data distribution over the Internet. 
>>
>> - Employ micro-segmentation to limit data access to a few network nodes. 
>>
>> - Audit and monitor the privileged accounts to detect and reduce data breaches. 
>>
>> - Employ a perimeter firewall to filter the data packets entering and exiting the network.


### Abuse and Nefarios Use of Cloud Services

> - Attackers **create anonymous access to cloud services** and perpetrate attacks such as. 
>> - **Password and key cracking**. 
>> - Building Rainbow Tables. 
>> - **CAPTCHA-solving** farms. 
>> - Launching **dynamic attack points**. 
>> - Hosting **exploits** on cloud platforms. 
>> - Hosting **malicious data**. 
>> - **Botnet** command and control. 
>> - **DDoS**. 


### Insecure Interfaces and APIs. 

> - Related risks due to insecure interfaces and APIs. 
>>
>> - Circumvention of **user defined policies**. 
>> - Credentials Leakage. 
>> - Breach in **logging and monitoring facilites**. 
>> - Dependency on unknown APIs. 
>> - Reuse of **passwords/tokens**. 
>> - Poor input-data validation. 



![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-3.png) 

### Insufficient Due Dilligence

> - Ignorance of the CSP’s cloud environment poses risks to **operational responsibilities** such as security, encryption, incident response, and other issues such as contractual issues, design, and architectural issues. 

### Shared Technology Issues

> - Most underlying components that make up the cloud infrastructure (e.g., GPU and CPU caches) **do not offer strong isolation properties** in a multi-tenant environment which allows attackers to attack other machines if they can exploit the vulnerabilities in a client’s applications. 

### Unknown Risk Profile 

> - Client organizations are unable to get a clear picture of the internal security procedures, security compliance, configuration hardening, patching, auditing, and logging, etc. as they are less involved with **hardware and software ownership** and maintenance in the cloud. 

### Unsynchronized System Clocks 

> - Unsynchronized clocks can **affect the working of automated tasks**. 
> - The network administrator cannot accurately analyze the log files for any malicious activity, if the timestamps are mismatched. 


![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-4.png) 


### Inadequate Infrastructure Design and Planning

> - A shortage of computing resources and/or poor network design can result in unacceptable **network latency or an inability to meet agreed service levels**. 

### Conflicts between Client Hardening Procedures and Cloud Environment 

> - Certain client hardening procedures may conflict with a **cloud provider’s environment**, making their implementation by the client impossible. 

### Loss of Operational and Security Logs

> - The loss of security logs poses a **risk for managing the implementation of the information security management program**. 
> - Loss of security logs may occur in cases of under-provisioning of storage. 

### Malicious Insiders

> - Disgruntled current or former employees, contractors, or other business partners who have authorized access to cloud resources, can misuse their access to compromise the **information available in the cloud**. 


![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-5.png) 


### Illegal Access to the Cloud


> - **Weak authentication and authorization controls** could lead to illegal access, thereby compromising confidential and critical data stored in the cloud. 


### Loss of Business Reputation Due to Co-tenant Activites 

> - Resources are shared in the cloud, thus **malicious activity** by one co-tenant might affect the reputation of the another, resulting in poor service delivery, data loss, etc. that can be detrimental to an organization. 

### Privilege Escalation

> - A **mistake in the access allocation** system can result in a customer, third party, or employee getting more access rights than needed. 


### Natural Disasters 

> - Depending on **geographic location and climate**, data centers may be exposed to natural disasters such as **floods, lightening, earthquakes, etc.** that can affect the cloud services. 


### Hardware Failure 

> - Hardware failures such as switches and servers in data centers can make the **cloud data inaccessible**. 



![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-6.png) 



### Supply-Chain Failure 

> - Cloud providers outsource certain tasks to third parties. Thus the security of the **cloud is directly proportional to the security of each link and the extent of dependency on third parties**. 

> - A disruption in the chain may therefore lead to a **loss of data privacyand integrity**, as well as **services unavailability, a violation of the SLA, and economic and reputational losses**, which in turn results in the failure to meet customer demand and cascading. 


### Modifying Network Traffic

> - In the cloud, the network traffic may be modified due to flaws while provisioning or de-provisioning the **network, or vulnerabilities in communication encryption**. 

> - Modification of network traffic may cause **loss, alteration, or theft of confidential data** and communications. 


### Isolation Failure 

> - Following **isolation failure**, attackers may try to **control operations** of other cloud customers to **gain illegal access** to the data. 



![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-7.png) 


### Cloud Provider Acquisition

> - The acquisition of the cloud provider may **increase the probability of a tactical shift** which may put non-binding agreements at risk. This could make it difficult to satisfy the security requirements


### Management Interface Compromise

> - Customer management interfaces of cloud providers are accessible via the Internet and facilitate **access to many resources**. This enhances the risk, particularly when combined with **remote access and web browser vulnerabilities**. 


### Network Management Failure 

> - Poor network management leads to **network congestion, misconnection, misconfiguration**, lack of resource isolation, etc., which affects service and security. 


### Authentication Attacks

> - Weak authentication mechanisms (weak passwords, re-use of passwords, etc.) and the inherent limitations of **one-factor authentication mechanisms** can allow an attacker to gain unauthorized access to cloud computing systems. 



![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-8.png) 



### VM-Level Attacks

> - The cloud extensively uses **virtualization technology**. This threat arises due to the **existence of vulnerabilities in the hypervisors**. 


### Lock-In

> - The difficulties experienced by a user when **migrating from in-house systems or from one cloud service provider to another** due to the lack of tools, procedures, or standard data formats, poses potential threats to data, application, and service portability. 


### Licensing Risks 

> - The organization may **incur a huge licensing fee** if the software deployed in the cloud is charged on a per instance basis. 


### Loss of Goverance 

> - When using cloud infrastructures, the customer **gives up control to the cloud service provider** including control of issues that may affect security. 


### Loss of Encryption Keys 

> - The loss of encryption keys required for **secure communication** or systems access provide a potential attacker with the opportunity to get **unauthorized access to assets**. 



![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-9.png) 



### Riks from Changes of Jurisdiction

> - A change in the jurisdiction of the data can lead to the risk that the **data or information system may be blocked or impounded** by a government or other organization. 


### Undertaking Malicious Probes or Scans 

> - Malicious probes or scanning allows an attacker to collect **sensitive information** that may lead to a **loss of confidentiality, integrity, and availability of services and data**. 


### Theft of Computer Equipment 

> - **Poor controls over the physical parameters such as smart card access at the point of entry** may lead to the loss of physical equipment and sensitive data. 


### Cloud Service Termination or Failure

> - The termination of cloud service due to non-profitability or disputes might lead to **data loss unless end-users are legally protected**. 


### Subpoena and E-Discovery 

> - If customer data or services are subpoenaed or subjected to a **cease and desist request from authorities or third parties**, access to such data and services may be compromised. 



![Cloud Threats](/Cloud-Computing/Cloud-Computing-Threats/images/Cloud-Threats-10.png) 



### Improper Data Handling and Disposal

> - If it is difficult to ascertain data handling and disposal procedures followed by CSPs due to **limited access to cloud infrastructure**, such data may be compromised. 


### Loss/Modification of Backup Data 

> - Attackers might exploit vulnerabilities such as **SQL injection**, insecure user behavior like **storing passwords, and reusing passwords** to gain illegal access to the data backups in the cloud. 


### Compliance Risks

> - Organizations that seek to obtain compliance with standards and laws may be put at risk if the CSP **cannot provide evidence of their own compliance** with the necessary requirements, outsources cloud management to third parties, and/or **does not permit audit by the client**. 


### Economic Denail of Sustainability (EDOS) 

> - If an attacker engages the cloud with a malicious service or executes malicious code that **consumes a lot of computational power and storage from the cloud server**, then the legitimate account holder is charged for this kind of computation until the primary cause of CPU usage is detected. 


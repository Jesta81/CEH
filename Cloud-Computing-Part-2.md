# Cloud Computing Part 2 #



## Cloud Security ##


1. Which of the following security controls involves keeping a warning sign on a fence or property that informs potential attackers of adverse consequences if they proceed to attack?

	1. Preventive controls
	2. [x] Deterrent controls
	3. Corrective controls
	4. Detective controls


2. Which of the following vulnerabilities in serverless security can be resolved by using the cloud provider’s built-in services, such as AWS Trust Advisor, to identify public resources and by setting functions with a minimum required timeout?


	1. [x] Security misconfiguration
	2. Broken access control
	3. XML external entities
	4. Cross-site scripting 


3. Which of the following measures is NOT a best practice for securing a container environment?


	1. [x] Use a single database for all applications
	2. Perform regular scanning of the images in the repository
	3. Store sensitive data externally and allow dynamic access at runtime
	4. Configure orchestrators to deploy a set of hosts separately based on their sensitivity level


4. Which of the following best practices allows security professionals to secure the docker environment?


	1. Disable the read-only mode on file systems and volumes
	2. Always expose the docker daemon socket
	3. [x] Always run docker images with --security-opt=no-new-privileges
	4. Never use tools such as InSpec and DevSec to detect docker vulnerabilities


5. Which of the following best practices helps security professionals in securing a serverless computing environment?


	1. Maximize serverless permissions in the development phase
	2. Never use secret storage for sensitive information
	3. Disable signed requests for cloud vendors
	4. [x] Deploy functions in minimal granularity 


6. The components such as NIDS/NIPS, firewalls, DPI, Anti-DDoS, QoS, DNSSEC, and OAuth are included in which of the following cloud security control layers?


	1. Applications layer
	2. [x] Network layer
	3. Management layer
	4. Computer and storage


7. Which of the following categories of security controls minimizes the consequences of an incident by limiting the damage?


	1. [x] Corrective controls
	2. Deterrent controls
	3. Preventive controls
	4. Detective controls

	 Explanation:

    Deterrent Controls: These controls reduce attacks on the cloud system. Example: Warning sign on the fence or property to inform adverse consequences for potential attackers if they proceed to attack
    Preventive Controls: These controls strengthen the system against incidents, probably by minimizing or eliminating vulnerabilities. Example: Strong authentication mechanism to prevent unauthorized use of cloud systems.
    Detective Controls: These controls detect and react appropriately to the incidents that happen. Example: Employing IDSs, IPSs, etc. helps to detect attacks on cloud systems.
    **Corrective controls: These controls minimize the consequences of an incident, probably by limiting the damage. Example: Restoring system backups.**


8. Which of the following practices allows administrators to secure a container environment from various cloud-based attacks?


	1. [x] Harden the host environment by removing non-critical native services.
	2. Change the users’ default privileges from non-root to root.
	3. Implement immutable containers that allow container modification after deployment.
	4. Write sensitive information to code and configuration files.


9. Which of the following practices assists cloud administrators in securing a Docker environment from various cyberattacks?


	1. Disable the read-only mode on filesystems and volumes by unsetting the --read-only flag.
	2. Secure the API endpoints with HTTP when exposing the RESTful API.
	3. [x] Limit SSH login connections to the admin for processing the log files of containers.
	4. Enable the inter-container communication feature when running the Docker daemon by using --icc=false. 


10. Which of the following practices helps security professionals in protecting a serverless computing environment from various cyberattacks?


	1. [x] Use timeouts to limit how longer serverless functions can execute.
	2. Never use third-party security tools.
	3. Maximize serverless permissions in the development phase to reduce the attack surface area.
	4. Disable signed requests for cloud vendors to protect the data in transit and to prevent HTTP replay attacks.


11. Which of the following is a network routing solution that establishes and manages communication between an on-premises consumer network and VPCs via a centralized unit?


	1. Public and private subnets
	2. Interface endpoint
	3. VPC endpoint
	4. [x] Transit gateways


12. Which of the following entities of cloud network security establishes a private connection between a VPC and another cloud service without access to the Internet, external gateways, NAT solutions, VPN connections, or public addresses?


	1. Public subnet
	2. [x] VPC endpoint
	3. Transit gateway
	4. Gateway-load-balancer endpoint


13. George, a security engineer, was tasked with implementing security controls to prevent attacks such as XSS, CSRF, and session hijacking on the organization’s cloud environment. For this purpose, George selected a cloud security control that contains a set of rules, processes, policies, controls, and techniques that administer all the data exchange between collaborative cloud platforms such as Box, Google G Suite, Slack, and Microsoft Office 365.

	Identify the security control implemented by George in the above scenario.

	1. High availability across zones
	2. Cloud integration and auditing
	3. Instance awareness
	4. [x] Cloud application security


14. Which of the following is an app discovery tool that provides full visibility and risk information to manage cloud applications in a secure and organized manner?


	1. Stream Armor
	2. [x] Cisco Umbrella
	3. BeRoot
	4. OllyDbg


15. Which of the following terms refers to on-premises or cloud-hosted solutions for enforcing security, compliance, and governance policies in cloud applications?


	1. Container
	2. [x] CASB
	3. Cluster
	4. Kubernetes



## Cloud Hacking ##


1. Which of the following information can be enumerated when an attacker runs the command # ps -ef | grep apiserver in Kubernetes etcd?


	1. Secrets stored in the Kubernetes cluster
	2. Decoding keys
	3. [x] Location of the etcd server and PKI information
	4. Retrieve a key and convert it into the YAML format


2. Which of the following Nimbostratus commands is used by an attacker to dump all the permissions for provided credentials?


	1. [x] $ nimbostratus dump-permissions --access-key=... --secret-key=...
	2. $ nimbostratus dump-credentials
	3. $ nimbostratus dump-ec2-metadata
	4. $ nimbostratus create-iam-user --access-key=... --secret-key=...


3. Which of the following is the docker command used by an attacker to create a container from an image to exploit the docker remote API?


	1. $ docker -H Remote IP:Port exec modest_goldstine ls
	2. $ docker -H Remote IP:Port pull alpine
	3. $ docker -H docker host run --network=host --rm marsmensch/nmap -ox IP Range
	4. [x] $ docker -H Remote IP:Port run -t -d alpine


4. Which of the following is a security vulnerability that arises mostly from business associates and current or former employees who already have trusted access to an environment and do not need to compromise AWS credentials separately for performing malicious activities?


	1. [x] Insider threat
	2. Social engineering
	3. Password reuse
	4. Reading local file


5. Given below are the different steps to exploit misconfigured AWS S3 buckets.

    1. Setup the AWS command-line interface
    2. Identify S3 buckets
    3. Configure aws-cli
    4. Exploit S3 buckets
    5. Extract access keys
    6. Identify vulnerable S3 buckets

What is the correct sequence of steps involved in exploiting misconfigured AWS S3 buckets?

**2,1,5,3,6,4**


6. Which of the following docker commands is used by an attacker to retrieve MySQL database credentials?


	1. $ docker -H docker host run --network=host --rm marsmensch/nmap -ox IP Range
	
	2. [x] $ docker -H docker remote host exec -i some-mysql env
	
	3. $ docker -H docker host exec -i some-mysql mysql -u root -p password -e “show databases”
	
	4. $ docker -H docker remote host ps | grep mysql


7. Which of the following scripts is an example of a lambda function that responds to user-delete events by creating more copies of the deleted user?


	1. backdoor_created_roles_lambda
	2. [x] rabbit_lambda
	3. cli_lambda
	4. backdoor_created_users_lambda


8. Which of the following tools allows an attacker to perform account enumeration on an Azure Active Directory (AD) environment and assess the overall security of the target Azure environment?


	1. [x] Azucar
	2. Hetty
	3. bettercap
	4. OWASP ZAP


9. Which of the following tools contains two main scanning modules, AWStealth and AzureStealth, which attackers can use to discover users, groups, and roles that have the most sensitive and risky permissions?


	1. DroidSheep
	2. CxSAST
	3. [x] SkyArk
	4. Fiddler


10. Given below are the various steps involved in abusing AWS Lambda functions using a black-box scenario.

    1. Once the files are uploaded, the tags of the individual files can be calculated using a Lambda function.
    
    2. The attacker uploads files to S3 and then rechecks their configurations.
    
    3. The attacker exfiltrates the cloud credentials of an account and starts enumeration for higher privileges with the acquired AWS credentials.
    
    4. An attacker accesses a misconfigured S3 bucket that was not implemented with any credentials. The misconfigured buckets that the attacker gains access to may contain various organizational files.

What is the correct sequence of steps involved in abusing AWS Lambda functions using a black-box scenario?

**4,2,1,3**
# Container Orchestration and Kubernetes

## Container Orchestration

- Container orchestration is an **automated process** of managing the **lifecycles of software containers and their dynamic environments**. 

- It is used for scheduling and distributing the work of individual containers for microservices-based applications spread across multiple clusters. 

![Container Orchestration](/Cloud-Computing/Kubernetes/images/Orchestration.png) 

- Various tasks can be automated using container orchestrator, such as. 

>
> - Provisioning and deployment of containers. 
>
> - Failover and redundancy of containers. 
>
> - Creating or destroying containers to distribute the load evenly across host infrastructure. 
>
> - Moving containers from one host to another on resource exhaustion or host failure. 
>
> - Automatic resource allocation between containers. 
>
> - Exposing running services to the external environment. 
>
> - Performing load balancing, traffic routing, and service discovery between containers. 
>
> - Performing a health check of running containers and hosts. 
>
> - Ensuring the availability of containers. 
>
> - Configuring application-related containers. 
>
> - Securing the communication between containers. 
>


## What is Kubernetes? 

- Kubernetes, also known as K8s, is an open-source, portable, extensible, orchestration platform developed by Google for **managing containerized applications and microservices**. 
- Containers provide an efficient way for packaging and running applications. 
- In a real-time production environment, containers must be managed efficiently to bring downtime to zero. 
- For example, if a container experiences failure, another container boots automatically. 
- To overcome these issues, Kubernetes provides a **resilient framework to manage distributed containers, generate deployment patterns, and perform failover and redundancy for applications**. 

![Kubernetes](/Cloud-Computing/Kubernetes/images/Kubernetes.png) 

### Features provided by Kubernetes: 

>
> ### Service Discovery 
>
> - Kubernetes allows a service to be discovered via a DNS name or IP address. 
>
> ### Load Balancing: 
>
> - When a container receives heavy traffic, Kubernetes automatically distributes the traffic to other containers and performs load balancing. 
>
> ### Storage Orchestration:
>
> - Kubernetes allows developers to mount their own storage capabilities, such as local and public cloud storage. 
>
> ### Automated rollouts and rollbacks: 
>
> - Kubernetes automates the process of creating new containers, destroying existing containers, and moving all resources from one container to another. 
>
> ### Automatic bin Packing: 
>
> - Kubernetes can manage a cluster of nodes that run containerized applications. 
>
> - If you specify the resources needed to run the container, such as processing power and memory, Kubernetes can automatically allocate and deallocate resources to the containers. 
>
> ### Self-Healing: 
>
> - Kubernetes automatically performs a health check of the containers, replaces the failed containers with new containers, destroys failed containers, and avoids advertising unavailable containers to clients. 
>
> ### Secret and Configuration Management: 
>
> - Kubernetes allows users to store and manage sensitive information such as credentials, secure shell (SSH) keys, and OAuth tokens. 
>
> - Application configuration and sensitive information can be deployed and updated without the need to rebuild the container images. 
>


### Kubernetes Cluster Architecture: 

- When Kubernetes is deployed, clusters are generated. 
- A cluster is a group of computers known as nodes, which execute the applications inside the containers managed by Kubernetes. 

- A cluster comprises a minimum of one master node and one worker node. 

- The worker nodes contain pods (a group of containers), and the master node manages them. 

- The below figure shows the various components of the Kubernetes cluster architecture. 

![Kubernetes Architecture](/Cloud-Computing/Kubernetes/images/Kub-Arch.png) 

> ### Master Coomponents: 
>
> - The components of the master node provide a cluster control panel and perform various activities, such as **scheduling, detecting, and handling cluster events**. 
> - These master components can be executed by any computer in the cluster. 
>
>> ### Kube-apiserver: 
>>
>> - The API server is an integral part of the Kubernetes control panel that responds to all API requests. It serves as a **front-end utility for the control panel** and it is the **only component that interacts with the etcd cluster and ensures data storage**. 
>>
>> ### Etcd cluster: 
>>
>> - It is a distributed and consistent **key-value storage** where **Kubernetes cluster data, service discovery details, API objects, etc. are stored**. 
>>
>> ### Kube-scheduler: 
>>
>> - Kube-scheduler is a master component that **scans newly generated pods and allocates a node for them**. 
>>
>> - It assigns the nodes based on factors such as the **overall resource requirement, data locality, software/hardware/policy restrictions, and internal workload interventions**. 
>>
>> ### Kube-controller-manager: 
>>
>> - Kube-controller-manager is a master component that **runs controllers**. 
>>
>> - Controllers are generally **individual processes (e.g., node controller, endpoint controller, replication controller, service account and token controller)** but are combined into a single binary and run together in a single process to reduce complexity. 
>>
>> ### cloud-controller-manager: 
>>
>> - This is the master component used to **run controllers that communicate with cloud providers**. 
>>
>> - Cloud-controller-manager enables the **Kubernetes code and cloud provider code to evolve separately**. 
>>
>
> ### Node components: 
>
> - Node or worker components **run on each node in the cluster**, managing working pods and supplying the Kubernetes runtime services. 
>
>> ### Kubelet: 
>>
>> - Kubelet is an important service agent that runs on each node and **ensures containers running in a pod**. 
>>
>> - It also ensures **pods and containers are healthy and running as expected**. 
>>
>> - Kubelet does not handle containers that are not generated by Kubernetes. 
>>
>> ### Kube-proxy: 
>>
>> - It is a network proxy service that also runs on every worker node. 
>>
>> - This service **maintains the network rules that enable network connection to the pods**. 
>>
>> ### Container Runtime: 
>>
>> - Container runtime is a software designed to **run the containers**. 
>>
>> - Kurbernetes supports various container runtimes, such as **Docker, rktlet, containerd, and cri-o**. 
>>
>

## Kubernetes VT. Docker

 - As discussed above, Docker is an open-source software that can be installed on any host to
build, deploy, and **run containerized applications** on a single operating system. 
>
> - **Containerization isolates running applications** from other services and applications running on the host OS. 
>
> - **Kubernetes** is a **container orchestration platform** that **automates the process of creating, managing, updating, scaling, and destroying containers**. 
>
> - Both **Dockers and Kubernetes** are based on **microservices architecture**, they are built using the **Go programming language** to deploy small lightweight binaries, and use the **YAML file for specifying application configurations and stacks**. 
>
> - When Kubernetes and Docker are coupled together, they **provide efficient management and deployment of containers in a distributed architecture**. 
>
> - When **Docker is installed on multiple hosts with different operating systems**, you can use **Kubernetes to manage these Docker hosts through container provisioning, load balancing, failover and scaling, and security**. 
>


![Kubernetes and Docker](/Cloud-Computing/Kubernetes/images/Kube-and-Docker.png) 



## Clusters and Containers

![Clusters and Containers](/Cloud-Computing/Kubernetes/images/C-and-C.png) 

### - Cluster 

- A cluster refers to a **set of two or more connected nodes that run parallelly to complete a task**. 

- Workloads with individual, parallelizable tasks are shared among the nodes. 

- These tasks utilize the combined memory and computational power of all the nodes in a cluster. One of the nodes acts as a master node, which is responsible for allocating the work, retrieving the results, and giving a response. 

>
> #### - Types of Cluster Computing
>
>> - 1. #### Highly Available (HA) or Fail-over: 
>>
>> - In a fail-over cluster, **more than one node runs simultaneously to offer high availability (HA) or continuous availability (CA)**. 
>>
>> - If one node fails, the other node assumes its responsibility with **minimum or no downtime**. 
>>
>> 2. #### Load Balancing: 
>>
>> - In a load-balancing cluster, the **workload is distributed among the nodes to avoid overstressing a single node**. 
>>
>> - The load balancer performs **periodic health checks on each node to identify node failures and reroutes the incoming traffic to another node**. 
>>
>> - A load-balancing cluster is also a highly available cluster. 
>>
>> 3. #### High-Performance Computing: 
>>
>> - In a high-performance computing (HPC) cluster, the nodes are configured to provide extreme performance by **parallelizing the tasks**. 
>>
>> - **Scaling** also helps in **maximizing performance**. 
>>
>

### Clusters in the Cloud

- Clusters in the cloud are **sets of nodes hosted on virtual machines (VMs)** and are often coupled with **virtual private clouds**. 

- **Cloud clustering minimizes the effort and time** required to establish a cluster. 

- In a cloud environment, the clusters can be **scaled up on demand** by adding additional resources or instances such as **VMs** easily. 

- The cloud also provides the flexibility of **upgrading infrastructure** according to **changes in requirements**. 

- Furthermore, the cloud **enhances latency and resiliency via node deployment** in many availability zones. 

- Cloud clustering **maximizes the cluster’s availability, security, and maintainability**. 

### Containers and their Relationship with Clusters 

- **Containers** help in **running applications reliably under different computing environments**. 

- For instance, an organization develops a web application building the frontend and backend as microservices. To deploy this web application, containers can be pushed onto a VM in the cloud. If either the VM or the hardware fails, then the application is inaccessible until traffic is handled by a fail-over server. 

- To enhance the availability, scalability, and performance of web applications, push the containerized applications onto several nodes in a cluster. Consequently, containers running on various nodes **maximize resource utilization**. Moreover, the risk of **single-node failure can be eliminated** by placing an **instance of a container on every node in a cluster**. 


## Container Security Challenges

- Organizations are widely adopting container-based platforms owing to their features (e.g., flexibility, continuous application delivery, efficient deployment). However, the rapid growth and propagation of container technology have resulted in many security challenges. 


![Container Security](/Cloud-Computing/Kubernetes/images/Container-Security.png) 


- Discussed below are some of the challenges regarding container security. 


>
> 1. ### Inflow of vulnerable Source Code
>
>> - Containers constitute an open-source platform used by developers to regularly update, store, and use images in a repository. 
>>
>> - This results in an **enormous uncontrolled code** that may include vulnerabilities, which can compromise security. 
>>
>
> 2. ### Large Attack Surface 
>
>> - The **host OS consists of many containers, applications, VMs, and databases in the cloud or on-premises**. 
>>
>> - A large attack surface implies a **large number of vulnerabilities and an increased difficulty in detecting them**. 
>>
>
> 3. ### Lack of Visibility 
>
>> - A **container engine runs the container, interfaces with the Linux kernel**, and creates another layer of abstraction camouflaging the actions of the containers and making it **difficult to track activities of specific containers or users**. 
>>
>
> 4. ### Compromising Secrets 
>
>> - **Containers require sensitive information, such as API keys, usernames, or passwords, for accessing any services**. Attackers who illicitly gain access to this sensitive information can compromise security. 
>>
>
> 5. ### DevOps Speed 
>
>> - **Containers can be executed promptly and, after execution, are stopped and removed**. 
>>
>> - **This fugitiveness helps attackers launch attacks and hide themselves without installing any malicious code**. 
>>
>
> 6. ### Noisy Neighboring Containers 
>
>> - A **container may consume and exhaust all available system resources**, which directly affects the operation of other neighboring containers creating a **denial-of-service (DoS) attack**. 
>>
>
> 7. ### Container Breakout to the Host 
>
>> - **Containers that runs as root** may break the containment and gain access to the host OS through **privilege escalation**. 
>>
>
> 8. ### Network-Based Attacks 
>
>> - Attackers may **exploit failed containers** having **active raw sockets and outbound network connections** to launch various network-based attacks. 
>>
>
> 9. ### Bypassing Isolation 
>
>> - Attackers, after compromising the security of a container, may escalate privileges to **gain access to other containers or the host itself**. 
>>
>
> 10. ### Ecosystem Complexity 
>
>> - Containers are built, deployed, and managed using **multiple vendors and sources**. This makes it **complex to secure and update the individual components** because they **originate from different repositories**. 
>>
>


## Container Management Platforms 


![Docker](/Cloud-Computing/Kubernetes/images/Docker.png) 


> ### Docker 
>
>> - [Docker](https://www.docker.com) is an **independent container platform** that helps in **building, managing, and securing all applications**, from traditional applications to the latest microservices, and **deploying them across cloud environments**. 
>>
>> - Docker contains the latest container content library and ecosystem with **more than 100,000 container images**, which allow developers to create and deploy applications. 
>>
>> - Docker also features **core building blocks**, such as **Docker Desktop, Docker Engine, and Docker Hub**, for easily sharing and managing application stacks. 
>>
>
> ### Aditional Container Management Platforms
>
> - Amazon Elastic Container Service [(Amazon ECS)](https://aws.amazon.com) 
>
> - [Microsoft Azure Container Instances (ACI)](https://azure.microsoft.com) 
>
> - [Red Hat OpenShift Container Platform](https://www.redhat.com) 
>
> - [Portainer](https://portainer.io) 
>
> - [Rancher](https://rancher.com) 


> ## Kebernetes Platforms 
>
> - Listed below are various Kubernetes platforms. 
>
>> - [Kubernetes](https://kubernetes.io) is an open-source **container orchestration engine** for automating **deployment, scaling, and management of containerized applications**. 
>>
>> - It also **groups different containers** that make up an application into several **logical units** for easy management and discovery. 
>>
>> - It allows users to take advantage of **on-premises, hybrid, or cloud infrastructure** to migrate workloads from one place to another. 
>>
>> - Kubernetes can also **deploy and update secrets and application configurations** without rebuilding the container images and without exposing secrets in the stack configuration. 
>>
>
> - [Amazon Elastic Kubernetes Service (EKS)](https://aws.amazon.com) 
>
> - [Docker Kubernetes Service (DKS)](https://www.docker.com) 
>
> - [Knative](https://cloud.google.com) 
>
> - [IBM Cloud Kubernetes Service](https://www.ibm.com) 
>
> - [Google Kubernetes Engine (GKE)](https://cloud.google.com) 
>

![Kubernetes](/Cloud-Computing/Kubernetes/images/Kubernetes-2.png) 


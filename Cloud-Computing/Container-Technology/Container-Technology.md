# Container Technology  
>
> - Container technology is an emerging container-based virtualization service. It helps developers and IT teams in developing, running, and managing containerized applications by using the API of the service provider or a web portal interface. Containers and clusters can be deployed in on-premises datacenters or over the cloud.  
>
> - Docker
> - Kubernetes


## What is a Container?  

![What is a Container](/Cloud-Computing/Container-Technology/images/What-is-a-Container.png) 

>
> - A container is a package of an application/software including all its dependencies, such as library and configuration files, binaries, and other resources that run independently from other processes in the cloud environment. 
> 
> - A CaaS service includes the virtualization and management of containers through orchestrators.  
> 
> - Using these services, subscribers can develop rich, scalable containerized applications through the cloud or on-site data centers.


### Features. 

> 
> - Porability and consistency  
> - Security
> - High efficiency and cost effectiveness
> - Scalability
> - Robustness


## Container Technology Architecture. 

### Tier-1. 
> 
> - Developer machines - image creation, testing and accreditation. 

### Tier-2. 
> 
> - Testing and accreditation systems - verification and validation of image contents, signing images and sending them to the registries. 

### Tier-3. 
> 
> - Registries - storing images and disseminating images to the orchestrators based on requests. 

### Tier-4. 
> 
> - Orchestrators - transforming images into containers and deploying containers to hosts. 

### Tier-5. 
> 
> - Hosts - operating and managing containers as instructed by the orchestrator. 


## Container Lifecycle. 

![Container Lifecycye](/Cloud-Computing/Container-Technology/images/container-lifecycle.png) 

### Image Creation, Testing, and Accreditation. 
> 
> - The first phase of the container technology is the image generation and validation. In this phase, the application or software components are developed and stored into an image (or images). The image consists of the required files and resources to execute the container. The image creation is handled by the developers and is responsible for integrating the essential components of the application. Once the image is created, the security teams carry out the image testing and accreditation.  


### Image Storage and Retrieval. 
>
> - Images are usually placed in central locations known as registries. Registries provide various services to developers, such as storing images, tagging, and cataloging images for easy identification, version control for easy discovery and reuse, and fetching and downloading images created by other developers. Registries can be provided as a service or be self-hosted. Popular registry services include Docker Hub, Amazon Elastic Container Registry (ECR), Docker Trusted Registry (DTR), etc.  


### Container Deployment and Management. 
> 
> - Orchestrators are tools that allow DevOps administrators to fetch images from the registries, deploy them into containers, and manage container operation. This is the final phase of the container lifecycle, where the latest version of the application is deployed and comes into live usage/action. Orchestrators are helpful in monitoring container resource consumption and job execution, identifying host failures, and automatically restarting containers on new hosts. When resources are exhausted, an orchestrator allocates additional resources to the containers. When an application running in the container needs to be updated, the existing containers are destroyed, and new containers are created from the updated images. Popular orchestrators include Kubernetes, Docker Swarm, Nomad, Mesos, etc.  


## Containers vs Virtual Machines. 

![Containers vs Virtual Machines](/Cloud-Computing/Container-Technology/images/containers-vs-virtual-machines.png) 

### Virtual Machines. 
>
> - Heavyweight
> - Run on independent operating systems
> - Harware-based virtualization
> - Slower provisioning
> - Limited performance
> - Completely isolated making it more secure
> - Created and launched in minutes

### Containers. 
>
> - Lightweight and portable
> - Share a single host operating system
> - OS-based virtualization
> - Scalable and real-time provisioning
> - Native performance
> - Process-level isolation, partially secured
> - Created and launched in seconds


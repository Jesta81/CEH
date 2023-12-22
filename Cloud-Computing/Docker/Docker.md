# Docker. 


## What is Docker?  

![What is Docker?](/Cloud-Computing/Docker/images/what-is-docker.png) 

>
> - Docker is an open source technology used for developing, packaging, and running applications and all its dependencies in the form of containers, to ensure that the application works in a seamless environment. 
>
> - Docker provied a Platform-as-a-Service (PaaS) through OS-level-virtualization and delivers containerized software packages. 


### Docker Engine. 
>
> - The Docker engine is a client/server application installed on a host that allows to develop, deploy, and run applications using the following components. 

#### Server. 
>
> - It is a persistent back-end process, also known as a daemon process (dockerd command). 

#### Rest API. 
> 
> - This API allows the communication and assignment of tasks to the daemon. 

#### Client CLI. 
> 
> - It is the command-line interface used to communicate with the daemon and where various Docker commands are initiated. 

![Docker Engine](/Cloud-Computing/Docker/images/docker-engine.png) 


### Docker Swarm. 
> 
> - Communicate with containers and assign jobs to different containers. 
> - Expand or reduce the number of containers beased on the load. 
> - Carry out a health check and handle the lifecycle of different containers. 
> - Dispense a failover and redundancy to continue a process even if node failure occurs. 
> - Perform timely sotware updates to all containers. 


### Docker Architecture. 
> 
> - The Docker architecture employs a client/server model and consists of various components, such as the host, client, network, registry, and other storage units. The Docker client interacts with the Docker daemon, which develops, runs, and distributes the containers. The Daemon and Docker clients can carry out operations on the same host; alternatively, users can connect the Docker client to remote daemons. The communication between the Docker client and the Docker server daemon is established via REST API. 

![Docker Architecture](/Cloud-Computing/Docker/images/docker-architecture.png) 

#### Docker Daemon. 
>
> - The Docker daemon (dockerd) processes the API requests and handles various Docker objects, such as containers, volumes, images, and networks. 

#### Docker Client. 
>
> - It is the primary interface through which users communicate with Docker. When commands such as docker run are initiated, the client passes related commands to dockerd, which then executes them. Docker commands use the Docker API for communication. 

#### Docker Registries. 
> 
> - Docker registries are locations where images are stored and pulled, and can be either private or public. Docker Cloud and Docker Hub are two popular public registries. Docker Hub is a predefined location of Docker images, which can be used by all users.  


### Docker Objects. 


#### Images. 
>
> - Images are used to store and deploy containers. They are read-only binary templates with instructions for container creation. 

#### Containers. 
>
> - Application resources run inside the containers. A container is a runnable instance of an application image. Docker CLI or API is used to create, launch, stop, and destroy these containers. 

#### Services. 
>
> - Services enable users to extend the number of containers across daemons, and together they serve as a swarm with several managers and workers. Each swarm member is a daemon, and all these daemons can interact with each other using Docker API. 

#### Networking. 
>
> - It is a channel through which all isolated containers communicate. 

#### Volumes. 
> 
> - It is a storage where persisting data created by Docker and used by Docker containers are stored. 
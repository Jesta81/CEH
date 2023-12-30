# Hacking Android OS. 
>
> - The number of people using smartphones and tablets is increasing rapidly, as these devices support a wide range of functionalities. Android is the most popular mobile OS because it is a platform that is open to all applications. Like other OSs, Android has certain vulnerabilities, and not all Android users install patches to update and secure the OS software and apps. Such a casual approach of users allows attackers to exploit vulnerabilities and launch various types of attacks to steal valuable data stored on the victims’ devices. 
>

## Android OS
>
> - Android is a software environment developed by Google for mobile devices. It includes an operating system, middleware, and key applications.

### Features. 
>
> - Application framework enabling the reuse and replacement of components. 
>
> - Provides  a variety of pre-built UI components. 
>
> - Integrated browser based on the open source Blink and WebKit engine.  
>
> - Media support for common audio, video, and still image formats (MGEG4, H.264, MP3, AAC, AMR, JPG, PNG, GIF). 
>
> - Rich development environment including a device emulator, tools for debugging, memory, and performance profiling, and a plugin for the Eclipse IDE. 

## Android Architecture

> - Android is a Linux-based OS designed for portable devices such as smartphones and tablets. It is a stack of software components categorized into six sections (System Apps, Java AP Framework, Native C/C++ Libraries, Android Runtime, Hardware Abstraction Layer (HAL), and Linux kernel) and five layers. 
>

[Source:](https://developer.android.com) 

![Android Architecture](/Hacking-Mobile-Platforms/Hacking-Android/images/android-arch.png) 

### System Apps. 
>
> - dialer
> - email
> - calendar
> - SMS messaging
> - web browsers
> - contact managers

### Java API Framework

> Android platform functions are made available to developers through APIs written in Java. The application framework offers many high-level services to applications, which developers incorporate in their development.  
>
> Some of the application framework blocks are as follows: 
>
>> ### Content Providers
>> - Manages data sharing between applications. 
>>
>> ### View System
>> - For developing lists, grids, text boxes, buttons, and so on. 
>>
>> ### Activity Manager
>> - Controls the activity life cycle of applications. 
>>
>> ### Location Manager
>> - Manages location using GPS or cell towers. 
>>
>> ### Package Manager
>> - Keeps track of the applications installed on the device. 
>>
>> ### Notification Manager
>> - Helps applications display custom messages in a status bar. 
>>
>> ### Resource Manager
>> - Manages various types of resources used. 
>>
>> ### Telephony Manager
>> - Manages all voice calls. 
>>
>> ### Window Manager
>> - Manages application windows. 


### Native C/C++ Libraries
>
> - The next layer comprises the native libraries. Libraries are “written” in C or C++ and are specific to particular hardware. This layer allows the device to control different types of data. 
>
> The native libraries are as follows: 
>> ### WebKit and Blink
>> - web browser engine to display HTML content. 
>>
>> ### Open Max AL
>> - companion API to OpenGL ES but used for multimedia (video and audio) rather than audio only. 
>>
>> ### Libc
>> - Comprises System C libraries
>>
>> ### Media Framework
>> - provides media codecs that allow recording and playback of different media formats. 
>>
>> ### Open GL | ES
>> - 2D and 3D graphics library. 
>>
>> ### Surface Manager
>> - meant for display management. 
>>
>> ### SQLite
>> - database engine used for data storage purposes. 
>> 
>> ### FreeType
>> - meant for rendering fonts
>>
>> ## SSL
>> - meant for internet security. 

### Android Runtime
>
> It includes core libraries and the ART virtual machine.
>
>> ### Android Runtime (ART):
>> - For Android versions beyond 5.0, apps have their own runtime processes and instances. Android runtime has features such as ahead-of-time (AOT) compilation, just-in-time (JIT) compilation, optimized garbage collection (GC), and Dalvik Executable format (DEX) files to compress machine code. 
>>
>> ### Core Libraries:
>> - The set of core libraries allows developers to write Android applications using Java. 


### Hardware Abstraction Layer
> 
> - The hardware abstraction layer is used to expose the device’s hardware capabilities to the Java API framework that resides at a higher level. It acts as an abstraction layer between the hardware and the software stack. HAL comprises various modules that are required for the hardware equipment in the device, such as audio, camera, Bluetooth, sensors, and so on. 

### Linux Kernel
>
> - The Android OS relies on the Linux kernel. This layer comprises low-level device drivers such as audio driver, binder (IPC) driver, display driver, keypad driver, Bluetooth driver, camera driver, shared memory driver, USB driver, Wi-Fi driver, Flash memory driver, and power management for the various hardware components. The functions of this layer include memory management, power management, security management, and networking. 


## Android Device Administration API

![Source](https://developer.android.com) 

> - The Device Administration API provides device administration features at teh system level. 
>
> - This API allows developers to create security-aware applications that are useful in enterprise settings, where IT professionals require strong control over employee devices. 

![Android API policies](/Hacking-Mobile-Platforms/Hacking-Android/images/api-policies.png) 
![Android API policies](/Hacking-Mobile-Platforms/Hacking-Android/images/api-policies-2.png) 


## Android Rooting

![Android Rooting](/Hacking-Mobile-Platforms/Hacking-Android/images/rooting.png)
>
> - Rooting allows Android users to attain privileged control (known as "root access") within Android's subsystem. 
>
> - Rooting process involves exploiting security vulnerabilities in the device firmwareand copying the SU binary to a location in the current process's PATH (e.g., /system/xbin/su) and granting it executable permissions with the chmod command. 

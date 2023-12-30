# Hacking iOS

> iOS is a mobile OS developed by Apple. Apple does not license iOS for installation on non-Apple hardware. The company has increased its product range by including mobile phones, tablets, and other mobile devices. The rapid increase in the use of Apple devices has attracted the attention of attackers. The design flaws in iOS make it vulnerable to malicious apps, hidden network profiles, MITM attacks, etc. Attackers can hack iOS to gain root-level access to Apple devices. 
> 
> This section introduces the following: Apple iOS; jailbreaking iOS; types, tools, and techniques of jailbreaking; guidelines for securing iOS devices; and iOS device tracking tools. 


## Apple iOS

> - iOS is **Apple's mobile operating system**; it supports Apple devices such as iPhone, iPod touch, iPad, and Apple TV. 
>
> - The user interface is based on the concept of **direct manipulation**, with **multi-touch** gestures. 


### iOS architecture

![iOS architecture](/Hacking-Mobile-Platforms/hacking-iOS/images/iOS-architecture.png) 

> The iOS architecture comprises five layers: Cocoa application, media, core services, core OS and kernel, and device drivers. The lower-level layers contain fundamental services and technologies, whereas the higher-level layers build upon the lower layers to provide more sophisticated services and technologies. 
>
> ### 1. Cocoa Application: 
> - This layer contains key frameworks that help in building iOS apps. These frameworks define the appearance of the apps, offer basic app infrastructure, and support key technologies such as multitasking, touch-based input, push notifications, and many high-level system services. Cocoa apps use the AppKit framework. 
>
> ### 2. Media: 
> - This layer contains the graphics, audio, and video technologies that enable multimedia experiences in apps. 
>
> ### 3. Core Services: 
> - This layer contains fundamental system services for apps. The key services are Core Foundation and Foundation frameworks (define the basic types that all apps use). Individual technologies that support features such as social media, iCloud, location, and networking belong to this layer. 
>
> ### 4. Core OS: 
> - This layer contains low-level features on which most other technologies are based. Frameworks in this layer are useful when dealing explicitly with security or communicating with an external hardware and networks. The services provided by this layer are dependent on the Kernel and Device Drivers layer. 
>
> ### 5. Kernel and Device Drivers: 
> - The lowest layer of the iOS architecture includes the kernel, drivers, BSD, file systems, infrastructure technologies such as networking. 


## Jailbreaking 

![Jailbreaking iOS](/Hacking-Mobile-Platforms/hacking-iOS/images/iOS-jailbreaking.png) 

> - Jailbreaking is defined as the process of **installing a modified set of kernel patches** that allows users to run third-party applications not signed by the OS vendor. 
>
> - Jailbreaking provides **root access to the operating system** and permits downloading of third-party applications, themes, and extensions on iOS devices. 
>
> - Jailbreaking **removes sandbox restrictions**, which enables malicious apps to access restricted mobile resources and information. 
>
> ### Jailbreaking, like rooting, also comes with many security and other risks to your device, which include the following:
>> 1. Voiding your phone's warranty 
>> 2. Poor performance 
>> 3. Malware infection
>> 4. "Bricking" the device
>
> ### Types of Jailbreaking 
> The three types of jailbreaking are discussed below: 
>>
>> #### Userland Exploit
>> - A userland jailbreak **allows user-level access** but does not allow iboot-level access. 
>>
>> #### iBoot Exploit 
>> - An iboot jailbreak allows both **user-level access** and **iboot-level access**. 
>>
>> #### Bootrom Exploit 
>> - A bootrom jailbreak allows both **user-level access** and **iboot-level access**. 


## Jailbreaking Techniques 

![Jailbreaking Techniques](/Hacking-Mobile-Platforms/hacking-iOS/images/jailbreaking-techniques.png) 

### Untethered Jailbreaking 
> - An untethered jailbreak has the property that if the user turns the device off and back on, the device will completely start up, and the **kernel will be patched** without the help of a computer; in other words, it will be jailbroken after each reboot. 

### Semi-tethered Jailbreaking 
> - A semi-tethered jailbreak has the property that if the user turns the device off and back on, the device will completely start up and **will no longer have a patched kernel**, but it will still be **usable for normal functions.** To use jailbroken addons, the user need to start the device with the help of a **jailbreaking tool**. 

### Tethered Jailbreaking 
> - With a tethered jailbreak, if the device starts back up on its own, it will **no longer have a patched kernel**, and it may get stuck in a partially started state; for it to completely start up with a patched kernel, it must be "re-jailbroken" with a computer (using the "boot tethered" feature of a jailbreaking tool) each time it is turned on. 

### Semi-untethered Jailbreaking 
> - A semi-untethered jailbreak is similar to a semi-tethered jailbreak. In this type of a jailbreak, when the device reboots, the kernel is not patched, but the kernel can still be patched without using a computer. This is done using an app installed on the device. 


## Jailbreaking iOS Using Hexxa Plus

> - [Hexxa Plus](https://pangu8.com) is a **jailbreak repo extractor** for the latest iOS, which allows the user to install themes, tweaks, and apps. 
>
> - Using Hexxa Plus, the user can install the **latest iOS jailbreak** apps by extracting repos.

![Hexxa Plus](/Hacking-Mobile-Platforms/hacking-iOS/images/hexxa-plus.png) 

![Hexxa Plus](/Hacking-Mobile-Platforms/hacking-iOS/images/hexxa-plus-2.png) 


## iOS Jailbreaking Tools 

### Apricot

> - [Apricot](https://pangu8.com) jailbreak is the latest method to get a **virtual jailbreak experience** in the latest iOS versions on iPhone models. 
>
> - Apricot features provide a realistic experience to an iPhone running the latest iOS version. 
>
> Additional iOS Jailbreaking tools. 
> - [checkra1n](https://checkra.in) 
> - [Yuxigon](https://yuxigon.com) 
> - [Sileo](https://cydia-app.com) 
> - [Fugu14](https://pangu8.com) 
> - [Bregxi](https://pangu8.com) 


## iOS Hacking using Spyzie

![Sypzie](/Hacking-Mobile-Platforms/hacking-iOS/images/spyzie.png) 

> - [Sypzie](https://spyzie.io) allows attackers to **hack SMSs, call logs, app chats, GPS, etc**. 
>
> - This tool is compatible with all types of iOS devices, including iPhone, iPad, and iPod. 
>
> - Attackers hack the target device remotely in an **invisible mode** without even jailbreaking the device. 


## Hacking Network using Network Analyzer Pro 

![Net Analyzer Pro](/Hacking-Mobile-Platforms/hacking-iOS/images/network-analyzer-pro.png) 

> - [Network Analyzer Pro](https://apps.apple.com) discovers all **LAN devices' addresses** and names. 
>
> - Network Analyzer Pro allows attackers to gather information, such as devices connected to the network, their IP addresses, NetBIOS, mDNS (Bonjour), LLMNR, DNS name, etc. 


## iOS Trustjacking

> - iOS Trustjacking is a vulnerability that can be exploited by an attacker to read messages and emails and **capture sensitive information** from a remote location without the victim’s knowledge. 
>
> - This vulnerability exploits the **“iTunes Wi-Fi Sync”** feature, where the victim connects their phone to any trusted computer that is already infected by an attacker. 

![iOS Trustjacking](/Hacking-Mobile-Platforms/hacking-iOS/images/iOS-trustjacking.png) 

> Once the victim clicks on **“Trust,”** the attacker gets access to the connected iOS device through the infected computer, which continues until the phone resets the connection settings. The data and screen operations of the compromised device can later be monitored from the desktop without the user’s knowledge. The infected system can allow the attacker to read the user’s activity even after the device is out of the communication zone. It can also enable the attacker to backup or restore data to read SMS history, deleted photos, and apps. The attacker can also replace original apps of the device with malicious apps from the previously connected PC. 


## Analyzing and Manipulating iOS Applications 

### Manipulating an iOS Application using cycript

> - [cycript](http://www.cycript.org) is a **runtime manipulation tool** used by attackers to exploit the vulnerabilities in source code and modify the functionality during application runtime. 
>
> - cycript is a JavaScript (JS) interpreter that can understand Objective-C, Objective-C++, and JS commands. 
>
> - Using cycript, attackers can perform various activities such as **method swizzling, authentication bypass, and jailbreak detection bypass**. 

![cycript](/Hacking-Mobile-Platforms/hacking-iOS/images/cycript.png) 

### iOS Method Swizzling 

> - Method swizzling, also known as **monkey patching**, is a technique that involves modifying the existing methods or **adding new functionality** at runtime. 
>
> - Objective-C runtime enables the switching of the method functionality from an existing functionality to a customized one. 
>
> - Attackers use this technique to perform logging, **JavaScript injections, detection bypass, and authentication bypass**. 

[iOS Method Swizzling](/Hacking-Mobile-Platforms/hacking-iOS/images/method-swizzling.png) 


### Extracting Secrets Using Keychain Dumper 

> - iOS devices contain an **encrypted storage system** called a **keychain** that **stores secrets such as passwords, certificates, and encryption keys**. 
>
> - Attackers use tools such as [Keychain Dumper](https://github.com) to extract keychains from the target iOS device. 

![Keychain Dumper](/Hacking-Mobile-Platforms/hacking-iOS/images/keychain-dumper.png) 


### Analyzing an iOS Application Using objection 

> - Attackers use the [objection](https://github.com) tool to perform **method hooking, bypass SSL pinning**, and **bypass jailbreak detection** on the target iOS device. 

![objection](/Hacking-Mobile-Platforms/hacking-iOS/images/objection.png) 


## iOS Malware

### NoReboot

> - [NoReboot](https://blog.malwarebytes.com) Trojan allows attackers to spy on the victim’s device by exploitingthe device’s in-built microphoneand camera. 
>
> - NoReboot can **fake device reboot** and run in the background without any interruption during spy operation. 

![NoReboot](/Hacking-Mobile-Platforms/hacking-iOS/images/NoReboot.png) 


### Peagasus 

> - [Pegasus](https://firewalltimes.com) is spyware developed by an Israel-based company that supplies spyware to international government agencies to snoop on **internal and external political opponents**. 
>
> - It exploits vulnerabilites such as **zero-click exploits**. 
>
> - Government agencies use this spyware to monitor **terrorist activities, spy on activists, or political propaganda**. 

### Additional iOS Malware

> - XcodeSpy
> - XCSSET
> - KeyRaider
> - Prynt Stealer
> - Clicker Trojan malware


## Securing iOS Devices

> 1. Use **passcode lock** feature for locking iPhone. 
>
> 2. Only use iOS devices on **secured** and **protected** Wi-Fi networks. 
>
> 3. Do not access web services on a **compromised network**. 
>
> 4. Deploy only **trusted** third-party **applications** on iOS devices. 
>
> 5. Disable **Javascript and add-ons** from web browser. 
>
> 6. Do not store sensitive data on **client-side database**. 
>
> 7. Do not open **links or attachments** from unknown sources. 
>
> 8. **Do not jailbreak or root your device** if used within enterprise environments. 
>
> 9. Change default password of iPhone's **root password** from **alpine**. 
>
> 10. Configure **Find My iPhone** and utilize it to wipe a lost or stolen device. 
>
> 11. **Enable Jailbreak detection** and also protect access to **iTunes AppleID and Google accounts**, which are tied to sensitive data. 
>
> 12. Regularly upate your device OS with **security patches** released by Apple. 


## iOS Device Security Tools

[Avira Mobile Security](/Hacking-Mobile-Platforms/hacking-iOS/images/avira.png) 

### Avira Mobile Security

> - The [Avira](https://www.avira.com) provides features like **web protection and identity safeguarding**, identifies Phishing websites that target you personally, securing emails, tracking your device, identifying activities, organizing device memory, backing up all your contacts, etc. 

#### Additional iOS security tools

> - [Norton Mobile Security for iOS](https://us.norton.com) 
> - [LastPass Password Manager](https://www.lastpass.com) 
> - [Lookout Personal for iOS](https://www.lookout.com) 
> - [McAfee Security for mobile](https://www.mcafee.com) 
> - [Trend Micro Mobile Security](https://trendmicro.com) 


## iOS Device Tracking Tools

### Find My

> - [Find My iPhone](https://support.apple.com) helps locate and protect Apple devices that are lost or stolen. 
>
> - It helps locate a missing device on a map, remotely lock it, play a sound, display a message, and remotely erase all data on it. 

### How to Setup Find My for iPhone, iPad, or iPod Touch

1. Open the **Settings** app. 
2. Tap **Settings -> [your name] -> Find My**. 
3. Tap **Find My [device]** and then turn on **Find My [device]**. 
4. To view the device even when it is offline, **turn of Find My network**. 

![Find My](/Hacking-Mobile-Platforms/hacking-iOS/images/Find-My.png) 

#### Additional iOS device tracking tools

> - [Spybubble](https://thespybubble.com) 
> - [Prey Find my Phone Tracker GPS](https://apps.apple.com) 
> - [iHound](http://ihoundgps.com) 
> - [FollowMee GPS Location Tracker](https://apps.apple.com) 
> - [Mobistealth](https://www.mobistealth.com) 


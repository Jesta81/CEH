# Email Encryption

## Digital Signature
>
> - Digital signature uses aysmmetric cryptography to simulate the security properties of a **signature in digital rather than written form**. 
>
> - A digital signature may be further protected by **encrypting the signed email** for confidentiality. 

![Digital Signature](/Cryptography/Email-Encryption/images/Digital-Signature.png) 


## Secure Sockets Layer (SSL).

![SSL Handshake](/Cryptography/Email-Encryption/images/SSL.png) 

>
> - SSL is an application layer protocol developed by Netscape for **managing the security** of message transmission on the Internet. 
>
> - It uses **RSA asymmetric (public key) encryption** to encrypt data transferred over SSL connections. 
> 
### SSL offers "channelsecurity" with three basic properties. 
>
> #### Private Channel. 
>
>> - All the messages are encrypted after a simple handshake is used to define a secret key. 
>
> #### Authenticated Channel. 
>
>> - The server endpoint of the conversation is always encrypted, whereas the client endpoint is optinally authenticated. 
>
> #### Reliable Channel. 
> 
>> - Message transfer has an intergrity check. 


## Transport Layer Security (TLS). 

![TLS Handshake](/Cryptography/Email-Encryption/images/TLS.png) 

>
> - TLS is a protocol **to establish a secure connection** between a client and a server and ensure the privacy and integrity of information during transmission. 
>
> - It uses the **RSA algorithm** with 1024 and 2048 bit strengths. 

### TLS consists of 2 layers: TLS Record Protocol and TLS Handshake Protocol. 

#### TLS Handshake Protocol. 
>
> - It allows the client and server to authenticate each other, select an encryption algorithm, and exchange a symmetric key prior to data exchange. 
>
> - The peer's identity can be authenticated using asymmetric cryptography. This can be made optional but is mostly required for at least one of the peers. 
>
> - The negotiation of a shared secret is secure. 
> 
> - The negotiation is reliable. 

#### TLS Record Protocol. 
> 
> - It provides secured connections with an encryption method, such as DES. 
>
>> ##### The connection is private. 
>>
>> - Uses symmetric cryptography for data encryption, DES. 
>
>> ##### The connection is reliable. 
>>
>> - It provides a message integrity check at the time of message transport using a keyed MAC. Secure hash functions (e.g. SHA, MD5) help to perform MAC computations. 


## Pretty Good Privacy (PGP). 

> - PGP is a protocol used to encrypt and decrypt data that provides authentication and cryptographic privacy. 
>
> - It is often used for data compression, digital signing, encryption and decryption of messages, emails, files, directories, and to enhance the privacy of email communications. 
>
> - It combines the best features of both conventional and public key cryptography and is therefore known as a hybrid cryptosystem.

### PGP Encryption.  

![PGP Encryption](/Cryptography/Email-Encryption/images/PGP.png) 

### PGP Decryption

![PGP Decryption](/Cryptography/Email-Encryption/images/PGP-decryption.png) 


## GNU Privacy Guard (GPG). 

> - GPG is a **software replacement of PGP** and free implementation of the OpenPGP standard. 
>
> - GPG is also called **hybrid encryption software** as it uses both symmetric and asymmetric key cryptography. 
>
> - It also suppports S/MIME and SSH. 

### GPG Encryption.

![GNU Privacy Gaurd (GPG) Encryption](/Crpytography/Email-Encryption/images/GPG-Encryption.png)  

> - GPG encrypts messages individually by using asymmetric-key pairs. 
>
> - The user sends the raw file, and GPG is used for signing the file using the sender’s private key for confirming the file content at the time of signing. 
>
> - Then, the file is encrypted using the receiver’s public key. Now, the file can be decrypted only with the receiver’s private key. 
>
> - After encrypting the data, the encrypted file can be stored locally, distributed to the FTP servers, or sent to email recipients. 

### GPG Decryption. 

![GPG Decryption](/Cryptography/Email-Encryption/images/GPG-Decryption.png) 

> - GPG decryption is the reverse process of GPG encryption. 
>
> - As the asymmetric-key pairs are used, GPG searches for the receiver’s private key for decrypting the file. 
>
> - Signature verification is done automatically by the GPG using the sender’s public key after the decryption. 


## Web of Trust (WOT). 

> - Web of Trust (WOT) is a **trust model of PGP**, OpenPGP, and GnuPG systems. 
> 
> - Everyone in the network is a Certificate Authority (CA) and signs for other trusted entities. 
> 
> - WOT is a chain of a network in which individuals intermediately validate each other's certificates using their signatures. 
>
> - Every user in the network has a ring of public keys to encrypt the data, and they introduce many other users whom they trust. 

![Web of Trust](/Cryptography/Email-Encryption/images/WoT.png) 



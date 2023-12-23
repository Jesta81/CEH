# Encryption Algorithms. 
>
> - Encryption is the process of converting readable plaintext into an unreadable ciphertext using a set of complex algorithms that transform the data into blocks or streams of random alphanumeric characters. This section deals with ciphers and various encryption algorithms such as DES, AES, RC4, RC5, RC6, DSA, RSA, MD5, SHA, etc.


## Ciphers. 
>
> - In cryptography, a cipher is an algorithm (a series of well-defined steps) for performing encryption and decryption. Encipherment is the process of converting plaintext into a cipher or code; the reverse process is called decipherment. A message encrypted using a cipher is rendered unreadable unless its recipient knows the secret key required to decrypt it. Communication technologies (e.g., Internet, cell phones) rely on ciphers to maintain both security and privacy. Cipher algorithms may be open-source (the algorithmic process is in the public domain while the key is selected by a user and is private) or closed-source (the process is developed for use in specific domains, such as the military, and the algorithm itself is not in the public domain). Furthermore, ciphers may be free for public use or licensed.  


## Types of ciphers. 

![Types of cipers](/Cryptography/Encryption-Algorithms/images/Types-of-ciphers.png) 


### Classical Ciphers. 
>
> - Classical ciphers are the most basic type of ciphers, which operate on letters of the alphabet (A–Z). These ciphers are generally implemented either by hand or with simple mechanical devices. Because these ciphers are easily deciphered, they are generally unreliable.  
>
> #### Types of classical ciphers. 
>>
>> ##### Substitution cipher. 
>>
>> - A block of palintext is replaced with ciphertext. 
>>
>> - For example, **HELLO WORLD** can be encrypted as **PSTER HGFST**. (i.e., H=P, E=S, etc.).  
>>
>> - Examples of Substitution ciphers. 
>>
>>> - Beale cipher
>>> - autokey cipher
>>> - Gronsfeld cipher
>>> - Hill cipher
>>
>> ##### Transposition cipher. 
>>
>> - The letters of the plaintext are shifted about to form the cryptogram. 
>>
>> - For example, **CRYPTOGRAPHY** when encrypted becomes **AOYCRGPTYRHP**. 
>>
>> - Examples of Transposition ciphers. 
>>
>>> - Rail fence cipher
>>> - route cipher
>>> - Myszkowski transposition


### Modern Ciphers. 
>
> - Withstand wide range of attacks. 
>
> - Provide message secrey, integrity, and authentication of the sender. 
>
> - calculated using a one-way mathematical function that is capable of facoring large prime numbers. 
>
> #### Types of Modern ciphers
>
>> ##### Symmetric-key algorithms (Private-key cryptography):
>>
>> - Use the same key for encrpytion and decryption. 
>>
>> ##### Asymmetric-key algorithms (Public-key cryptography):  
>>
>> - Use two different keys for encryption and decryption. 
>>
>> ##### Block cipher:  
>>
>> - Deterministic algorithms operating on a block (a group of bits) of fixed size with an unvarying transformation specified by a symmetric key. 
>>
>> - Most modern ciphers are block ciphers. 
>>
>> - Used to encrypt bulk data. 
>>
>> - Examples of Block ciphers. 
>>
>>> - DES
>>> - AES
>>> - IDEA
>>
>> ##### Stream cipher. 
>>
>> - Symmetric-key ciphers are plaintext digits combined with a key stream (pseudorandom cipher digit stream).
>>
>> - User applies the key to each bit, one at a time. 
>>
>> - Examples of Stream ciphers. 
>>
>>> - RC4
>>> - SEAL


## Data Encryption Standard (DES). 
>
> - DES is designed to encipher and decipher blockes of data consisting of 64 bits under control of a 56-bit key. 
>
> - DES is the **archetypal block cipher** -- an algorithm that takes a fixed-length string of plaintext bits and transfroms it into a ciphertext bit string of the same length.
>
> - Due to the **inherent weakness** of DES with today's technologies, some organizations triple repeat the process **(3DES)** for added strength until they can afford to update their equipment to AES capabilities. 


## Advanced Encryption Standard (AES). 
>
> - AES is a **symmetric-key** algorithm used by the US government agencies to secure sensitive but unclassified material. 
>
> - AES is an **iterated block cipher** that works by repeating the same operation **multiple** times. 
>
> - It has a **128-bit** block size with key sizes of 128, 192, and 256 bits for AES-128, 192, and 256 bits for AES-128, AES-192, and AES-256, respectively. 

![DES and AES](/Cryptography/Encryption-Algorithms/images/DES-and-AES.png) 


## RC4, RC5, and RC6 Algorithms. 
>
> ### RC4
>
> - A variable key size **symmetric key stream cipher** with byte-oriented operations and is based on the use of a random permutation. 
>
> ### RC5
>
> - It is a **parameterized algorithm** with a variable block size, variable key size, and variable number of rounds.  The key size is **128 bits**. 
>
> ### RC6
>
> - RC6 is a **symmetric key block cipher** derived from RC5 with two additional features. 
>
>> - **Integer multiplication**. 
>>
>> - **four 4-bit working registers** (RC5 uses two 2-bit registers). 

![RC4, RC5, and RC6 Algorithms](/Cryptography/Encryption-Algorithms/images/RC4-RC5-RC6.png) 


## Blowfish. 
>
> - Symmetic block cipher designed to replace DES or IDEA. 
>
> - Splits data into a block length of 64 bits and produces a key ranging from 32 bits to 448 bits. 
>
> - High speed and efficient. 
>
>> - Blowfish is used in software ranging from password protection tools to e-commerce websites for securing payments. 
>
> - **16-round Feistel cipher working on 64-bit blocks**. 
>
> - Key size ranges from **32 bits to 448 bits**. 
>
> Blowfish algorithm has 2 parts. 
>
> - Part 1 - Key Expansion. 
>
>> - Breaks original key into a set of subkeys. 
>>
>> - A key of no more than 448 bits is separated into 4,168 bytes. 
>>
>> - P-array and four 32-bit S-boxes. 
>>
>> - P-array contains 18 32-bit subkeys. 
>>
>> - S-box contains 256 entries. 
>
> - Part 2 - Data encryption. 
>
>> - Round function splits the 32-bit input into four 8-bit quarters and uses the quarters as input to the S-boxes. 
>>
>> - The outputs are added modulo **232** and **XORed** to produce the final **32-bit output**. 


## Twofish and Threefish
>
> ### Twofish
>
>> - Twofish uses a **block size of 128 bits** and **key sizes** up to **256 bits**. It's a Feistel cipher. 
>>
>> - It works fast for CPU or hardware and is also flexible with **network based applications**. 
>>
>> - It even enables various levels of performance trade-off with parameters of **encryption speed, hardware gate count, memory usage**, etc. 
>
> ### Threefish
>
>> - Threefish is a large tweakable symmetric-key block cipher in which the block and key sizes are equal, i.e., **256, 512, and 1024**. 
>>
>> - It involves just three operations: **Addition-Rotation-XOR** (ARX). 
>>
>> - Threefish blocks of sizes **256, 512, and 1024** involve 72, 72, and 80 rounds of computations, respectively. 

![Twofish and Threefish](/Cryptography/Encryption-Algorithms/images/Twofish-and-Threefish.png) 


## Serpent and TEA
>
> ### Serpent
>
>> - Serpent uses a **128-bit symmetric block cipher** with 128, 192, or 256 bit key sizes. 
>>
>> - It involves **32 operating rounds** on four 32-bit word blocks using 8 variable S-boxes with 4-bit entry and 4-bit exit; each S-Box parallely works 32 times. 
>>
>> - The 32 rounds of computational operations include various **substitutions** and **permutations**. 
>
> ### Tiny Encyption Algorithm (TEA). 
>
>> - TEA is a **Feistal cipher** that uses 64 rounds. 
>>
>> - It uses a **128-bit key** operating on a **64-bit blocks**. 
>>
>> - It also uses a constant that defined as **232/the golden ratio**. 

![Serpent and TEA](/Cryptography/Encryption-Algorithms/images/Serpent-and-TEA.png) 


## CAST-128. 
>
>> - CAST-128 or CAST5 is a **symmetric-key** block cipher. 
>>
>> - It has a **12 or 16 round Feistel network** with 64-bit block size. 
>>
>> - It uses a key size varying from 40 to 128 bits in 8-bit increments. 
>>
>> - CAST-128 consists of large 8x32 bit S-boxes and uses the masking key adn rotation key. 
>>
>> - The **round function** consists of three alternating types for performing addition, subraction, or XOR operations at different stages. 
>>
>> - CAST-128 is used as a default cipher in **GPG and PGP**. 

![CAST-128](/Cryptography/Encryption-Algorithms/images/CAST-128.png) 


## Government Standard block cipher (GOST) and Camellia. 
>
> ### GOST Block Cipher
>
>> - GOST block cipher, also called as **Magma**, is a symmetric key block cipher. 
>>
>> - It is a **32-round Feistel network** working on 64-bit blocks with 256-bit key length. 
>>
>> - It consists of an S-box that can be kept secret, and it contains approximately **354 bits** of secret information. 
>
> ### Camellia
>
>> - Camellia is a symmetric key block cipher with either **18 rounds** (for 128-bit keys) or **24 rounds** (for 256-bit keys). 
>>
>> - It is a Feistel cipher working with **128-bit** blocks and has key sizes of **128, 192, and 256-bits**. 
>>
>> - It is used as part of the **Transport Layer Security** (TLS) protocol. 

![GOST-and-Camillia](/Cryptography/Encryption-Algorithms/images/GOST-and-Camillia.png) 


## Digital Signature Algorithm (DSA) and Related Signature Schemes
>
> ### DSA
>
> - Federal Information Processing Standard (FIPS) for digital signatures. 
>
> - FIPS 186-2 specifies the Digital Signature Algorithm that may be used in the **generation and verification of digital signatures** for sensitive, unclassified applications. 
>
> ### Digital Signature
>
> - A digital signature is **computed using a set of rules (i.e., the DSA) and a set of parameters** such that the identity of the signatory and integrity of the data can be verified. 
>
> ### Processes involved in DSA. 
>
>> #### Signature Generation Process. 
>>
>> - The private key is used to know who has signed it. 
>>
>> #### Signature Verification Process. 
>>
>> - The public key is used to verify whether the given digital signature is genuine. 

![DSA and Related Signature Schemes](/Cryptography/Encryption-Algorithms/images/DSA.png) 


## Rivest Shamir Adleman (RSA). 
>
> - RSA is a public-key cryptosystem for **internet encryption** and **authentication**. 
>
> - It uses **modular arithmetic and elementary number theories** to perform computations using two large prime numbers. 
>
>> ### RSA Signature Scheme
>>
>> RSA involves both a public key and a private key. 
>>
>> - The public key can be used by anyone for encrypting messages. 
>>
>> - The messages that the user encrypts with the public key require the private key for decryption. 

![RSA](/Cryptography/Encryption-Algorithms/images/RSA.png) 


## Diffie-Hellman
>
> - A cryptographic protocol that allows two parties to establish a **shared key over an insecure channel**. 
>
> - It does not provide any authentication for the key exchange and is **vulnerable to many cryptographic attacks**. 

![Diffie-Hellman](/Cryptography/Encryption-Algorithms/images/Diffie-Hellman.png) 


## YAK
>
> - YAK is a public-key based Authenticated Key Exchange (AKE) protocol. 
>
> - The authentication of YAK is based on the public key pairs, and it requires PKI to distribute authentic public keys. 
>
> - YAK is a variat of two-pass Hashed Menezes-Qu-Vanstone (HMQV) protocol using zero-knowledge proofs (ZKP) for proving knowledge of ephemeral secret keys from both parties. 

![YAK](/Cryptography/Encryption-Algorithms/images/YAK.png) 


## Message Digest (One-Way Hash) Functions. 
>
> - Hash functions **calculate a unique fixed-size bit string** representation called a message digest of any arbitrary block of information.
>
> - If any given bit of the function's input is changed, then every output bit has a **50 percent** chance of changing. 
>
> - It is computationally infeasible to have two files with the **same message digest value**. 
>
>> Widely used message digest functions include the following algorithms. 
>>
>> - ### MD5
>> - ### SHA
> Message digests are also called one-way hash functions because they cannot be reversed.

![Message Digest Functions](/Cryptography/Encryption-Algorithms/images/message-digest.png) 


## Message Digest Function: MD5 and MD6
>
> - The MD5 algorithm takes a message of **arbitrary length** as the input and then outputs a **128-bit fingerprint** or message digest of the input. 
>
> - MD5 is not collision resistant; use of the lastest algorithms, such as **MD6, SHA-2, and SHA-2**, is recommended. 
>
> - **MD6** uses a Merkle tree-like stucture to allow for immense parallel computation of hashes for very long inputs. It is resistant to different cyptanalysis attacks. 
>
> - MD5 and MD6 are deployed for digital signature applications, file integrity checking, and storing passwords. 

![MD5 and MD6](/Cryptography/Encryption-Algorithms/images/MD5-and-MD6.png) 


## Message Digest Function: Secure Hashing Algorithm (SHA). 
>
> - This algorithm generates a cryptographically secure one-way hash; it was published by **NIST** as a **US Federal Information Processing Standard**. 
>
>> ### SHA-1
>>
>> - It produces a **160-bit digest** from a message with a maximum length of **(264-1) bits**, and it resembles the MD5 algorithm. 
>
>> ### SHA-2
>>
>> - It is a family of two similar hash functions with different block sizes, namely, **SHA-256, which uses 32-bit words, and SHA-512, which uses 64-bit words**. 
>
>> ### SHA-3
>>
>> - SHA-3 uses the **sponge construction**, in which message blocks are **XORed** into the initial bits of the state, which is then invertibly permuted. 

![SHA Hashing](/Cryptography/Encryption-Algorithms/images/SHA.png) 


## RIPEMD-160 and HMAC
>
> ### RIPEMD-160
>
>> - **RACE Integrity Primitives Evaluation Message Digest (RIPEMD) is a 160-bit hash algorithm** developed by Hans Dobbertin, Antoon Bosselaers, and Bart Preneel. 
>>
>> - The exist 128, 256, and 320 bit versions of this algorithm, which are called **RIPEMD-128, RIPEMD-256, and RIPEMD-320**. 
>>
>> - The compression function consists of **80 stages made up of 5 blocks that execute 16 times each**. 
>>
>> - This process **repeats twice** by combining the results at the bottom using **modulo 32 addition**. 
>
> ### Hash-based message authentication code (HMAC). 
>
>> - HMAC is a type of **message authentication code (MAC)**. that combines a **cryptographic key** with a cryptographic hash function. 
>>
>> - It is widely used to verify the **integrity of the data and authentication** of a message. 
>>
>> - This algorithm includes an **embedded hash function**, key size, and the size of the hash output. 
>>
>> - As HMAC executes the underlying hash function twice, it protects from various **length extension attacks**. 

![RIPEMD-and-HMAC](/Cryptography/Encryption-Algorithms/images/RIPEMD-and-HMAC.png) 


## CHAP
>
> - The Challenge-Handshake Authentication Protocol (CHAP) is an authentication mechanism used by Point-to-Point Protocol (PPP) servers to authenticate or validate the identity of remote clients or network hosts. 
>
> - It is more secure and effective compared to Password Authentication Procedure (PAP), as it regularly verifies the identity of the client using a three-way handshake and provides protection against replay attacks. 


## EAP
> 
> - The Extensible Authentication Protocol (EAP) is an authentication protocol that was originally designed for point-to-point connections. 
> 
> - It is used as an alternative to the CHAP and PAP authentication protocols, as it is more secure and supports different authentication mechanisms such as passwords, smart tokens, one-time passwords (OTPs), secure ID card, digital certificates, and public-key encryption mechanisms. 
>
> - After the selection of the EAP authentication mechanism, a session is established and messages are exchanged between the client and the authenticating server. The session consists of requests and responses for authentication information. 


## GOST - Hash Function
> 
> - This hash algorithm was initially defined in the Russian national standard GOST R 34.11-94 “Information Technology - Cryptographic Information Security - Hash Function.”  
> 
> - It produces a fixed-length output of 256 bits. The input message is broken up into chunks of 256-bit blocks. 
>
> - If a block is less than 256 bits, then the message is padded by appending as many zeros to it as are required to make the length of the message 256 bits.
>
> - The remaining bits are filled with a 256-bit integer arithmetic sum of all previously hashed blocks. Then, a 256-bit integer representing the length of the original message, in bits, is produced. 


## Elliptic Curve Cryptography (ECC). 
>
> - ECC is a modern public-key cryptography developed to **avoid larger cryptographic key usage**. 
>
> - The cyptosystem in ECC depends on **number theory and mathematical elliptic curves (algebraic structure)**. 
>
> - ECC was proposed as a **replacement for the RSA algorithm** to reduce the usage of key size. 

## Quantum Cryptography
>
> - Quantum cryptography is based on quantum mechanics, such as quantum key distribution (QKD). 
> 
> - Data is encrypted by a **sequence of photons** with a spinning trait while travelling from one end to another. 
>
> - Attackers can eavesdrop but cannot manipulate the data because the photons are transferred through arbitrary filters. 

## Homomorphic Encryption. 
>
> - Homomorphic encryption allows users to secure and leave their data in an encrypted format even while it is being processed or manipulated. 
>
> - Encryption and decryption are done by the **same key holder**. 
> 
> - It enables a user to encrypt the confidential data and out-source it to the **enterprise via cloud services** to process the given data. 

![Other Encryption Techniques](/Cryptography/Encryption-Algorithms/images/Other-Encryption-Techniques.png) 


## Hardware-Based Encryption
>
> - Hardware-based encryption uses computer hardware for assisting or replacing the software when the data encryption process is underway. 
>
> - These devices are also capable of storing encryption keys and other sensitive information in secured areas of RAM or other nonvolatile storage devices. 
>
> ### Types of harware encryption devices. 
>
>> #### TPM
>>
>> - Trusted platform module (TPM) is a crypto-processor or chip that is present on the motherboard that can securely store the encryption keys, and it can perform many cryptographic operations.  
>
>> #### HSM
>>
>> - Hardware security module (HSM) is an additional external security device that is used in a system for crypto-processing and can be used for managing, generating, and securely storing cryptographic keys. 
>
>> #### USB Encryption
>>
>> - USB encryption is an additional feature for USB storage devices that offers onboard encryption services. 
>
>> #### Hard Drive Encryption
>>
>> - Hard drive encryption is a technology where the data stored in the hardware can be encrypted using a wide range of encryption options. 

![Other encryption Techniques](/Cryptography/Encryption-Algorithms/images/Other-Encryption-Techniques-2.png) 



# Public Key Infrastructure (PKI). 
>
> - PKI is a **set of hardware, software, people, policies, and procedures** required to create, manage, distribute, use, store, and revoke **digital certificates**. 
>

> ## Components of PKI. 

> ### Certificate Management System. 
>
> - Generates, distributes, stores, and verifies certificates. 

> ### Digital Certificates. 
>
> - Establishes credentials of a person when performing online transactions. 

> ### Validation Authority (VA). 
>
> - Stores certificates (with their public keys). 

> ### Certification Authority (CA). 
>
> - Issues and verifies digital certificates. 

> ### End User. 
>
> - Requests, manages, and uses certificates. 

> ### Registration Authority (RA). 
>
> - Acts as the verifier for the CA. 


![PKI process](/Cryptography/PKI/images/PKI-process.png) 


## PKI process steps. 
>
> 1. The subject. (user, company, or system) intending to exchange information securely applies for a certificate to the Registration Authority (RA). 
>
> 2. The RA receives the request from the subject, verifies the subject's identity, and requests the CA to issue a public key certificate to the user. 
>
> 3. The CA issues the public key certificate binding the subject's identity with the subject's public key; then, the updated information is sent to the Validation Authority (VA). 
>
> 4. When a user makes a transaction, the user duly signs the message digitally using the public key certificate and sends the message to the client. 
>
> 5. The client verifies the authenticity of the user by inquiring with the VA about the validity of the user's public key certificate. 
>
> 6. The VA compares the public key certificate of the user with that of the updated information provided by the CA and determines the result (valid or invalid).  

## Certification Authorities (CA). 
>
> Certification authorities (CAs) are trusted entities that issue digital certificates. The digital certificate certifies the possession of the public key by the subject (user, company, or system) specified in the certificate. This aids others to trust signatures or statements made by the private key that is associated with the certified public key. 

> ### Popular CAs. 
>
> - #### Comodo
>
> - #### IdenTrust
>
> - #### DigiCert CertCentral
>
> - #### GoDaddy

## Signed Certificate (CA) vs Self-Signed Certificate. 


![Signed Certificate](/Cryptography/PKI/images/Signed-Certificate.png) 


![Self-Signed Certificate](/Cryptography/PKI/images/Self-Signed-Certificate.png) 


> ### Signed Certificate. 
>
> - User gets a digital certificate from a trustworthy CA. 
>
> - The digital certificate contains name of the certificate holder, a serial number, expiration dates, a copy of the certificate holder's public key and the digital signature of the CA. 
>
> - User signs the document using the digital certificate and sends to the reciever. 
>
> - The reciever can verify the certificate by enquiring with the Validation Authority (VA). 
>
> - VA certifies the validity of the certificate. 

> ### Self-Signed Certificate. 
>
> - User creates self-signed digital certificate using a certification creation tool such as. 
>
>> #### Adobe Acrobat Reader
>>
>> #### Java's keytool
>>
>> #### Apple Keychain
>
> - The certificate contains name of the user, user's public key and his digital signature. 
>
> - User signs the document using the self-signed certificate and sends to the receiver. 
> 
> - The receiver can verify the certificate by enquiring with the user. 
>
> - User verifies the certificate to the receiver. 


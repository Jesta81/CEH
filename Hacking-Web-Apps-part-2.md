1. Which of the following countermeasures should be followed to protect web applications against broken authentication and session management attacks?


	1. Apply pass phrasing with at least five random words
	
	2. Never use SSL for all authenticated parts of the application
	
	3. [x] Submit session data as part of GET and POST
	
	4. Do not check weak passwords against a list of the top bad passwords

 Explanation:

Some of the countermeasures to defend broken authentication and session management attacks include:

    Use SSL for all authenticated parts of the application
    Verify whether all the users’ identities and credentials are stored in a hashed form
    Never submit session data as part of a GET, POST
    Apply pass phrasing with at least five random words
    Limit the login attempts and lock the account for a specific period after a certain number of failed attempts
    Use a secure platform session manager to generate long random session identifiers for secure session development
    Make sure to check weak passwords against a list of the top bad passwords 


2. Which statement is TRUE regarding network firewalls in preventing web application attacks?


	1. Network firewalls can prevent attacks because they can detect malicious HTTP traffic.
	
	2. [x] Network firewalls cannot prevent attacks because ports 80 and 443 must be kept opened.
	
	3. Network firewalls cannot prevent attacks if they are properly configured.
	
	4. Network firewalls cannot prevent attacks because they are too complex to configure.

 Explanation:

    Port 80 and 443 are linked with "the Internet." Port 443 is the HTTP protocol and Port 80/HTTP is the World Wide Web. By default, these ports are left open to allow outbound traffic on your network and since these ports are kept open, network firewalls cannot prevent attacks.


3. In which type of fuzz testing does the protocol fuzzer send forged packets to the target application that is to be tested?


	1. [x] Protocol-based
	2. Generation-based
	3. None of the above
	4. Mutation-based


4. If you are responsible for securing a network from any type of attack and if you have found that one of your employees is able to access any website that may lead to clickjacking attacks, what would you do to avoid the attacks?


	1. Configure Application certification rules
	2. Delete Cookies
	3. [x] Harden browser permission rules
	4. Enable Remote Management


4. Which of the following practices helps security professionals defend web applications against SQL injection attempts?


	1. Use dynamic SQL and construct queries with user input
	
	2. [x] Avoid using shared databases and the same account for multiple databases
	
	3. Do not move extended stored procedures to an isolated server
	
	4. Never use custom error messages


5. Which of the following practices can make an organizational network susceptible to LDAP injection attacks?


	1. Use SaaS-based testing services for combating LDAP injection attacks
	
	2. Use LDAPS for encrypting and securing communication on web servers
	
	3. Sanitize all the user-end inputs and escape any special characters
	
	4. [x] Never configure LDAP with bind authentication


6. Which of the following practices makes an organization’s web application vulnerable to file injection attacks?


	1. [x] Allow the execution of files in default directories
	
	2. Employ a WAF security layer for monitoring the file injection attacks at the server
	
	3. Check for PHP wrappers such as PHP filter and PHP ZIP to prevent access to sensitive files in the local server’s file system
	
	4. PHP: Disable allow_url_fopen and allow_url_include in php.ini


7. Identify the practice that assists system administrators in securing an organization’s web application from external server-side injection attempts.


	1. Do not include “use strict” at the beginning of the function
	
	2. Use the eval() function to parse the user input
	
	3. Use code serialization
	
	4. [x] Ensure that only short alphanumeric strings are accepted as user input


8. Which of the following practices helps security experts secure an organization’s web application from the server-side, including injection attacks?


	1. Use pages with file name extensions such as .stm, .shtm, and .shtml
	
	2. [x] Implement SUExec for the execution of pages as the file owner
	3. Ensure that user input includes characters used in SSI directives
	4. Never use HTML encoding to the user input before executing it on the web pages


9. Identify the practice that makes an organization’s web application vulnerable to server-side including injection attempts.


	1. Ensure that directives are confined only to the web pages where they are required
	2. Implement SUExec for the execution of pages as the file owner
	3. [x] Use pages with file name extensions such as .stm, .shtm, and .shtml.
	4. Apply HTML encoding to the user input before executing it on the web pages


10. Which of the following practices makes an organization’s web server vulnerable to log injection attacks?


	1. Use correct error codes and easily recognizable error messages
	
	2. Examine the application carefully for any vulnerability that is used to render logs
	
	3. Control execution flow by using proper synchronization
	
	4. [x] Always view logs with tools having the ability to interpret control characters within a file


11. Identify the practice that makes an organization’s web application vulnerable to HTML injection attacks.


	1. Check the inputs for unwanted script or HTML code such as script, and html tags.
	2. [x] Disable the HttpOnly flag on the server side
	
	3. Educate the developer teams along with the security teams regarding the most prevalent HTML injection attacks and their preventive measures
	
	4. Employ security solutions that avoid false positives and detect possible injections


12. Identify the practice that makes an organizational web server vulnerable to XSS attacks.


	1. Implement a stringent security policy
	
	2. Employ automated VAPT tools during the source-code development phase of a web application.
	
	3. [x] Never use context-sensitive encoding when altering the browser document on the client side.
	
	4. Use browsers that are capable of in-built security filtering from the client side to obstruct the execution of malicious scripts


13. Which of the following is a WAF that can secure websites, web applications, and web services against known and unknown attacks?


	1. GRASSMARLIN
	2. Binwalk
	3. OpenOCD
	4. [x] ThreatSentry


14. Which of the following practices helps security professionals protect an organization’s web application from broken access control risks?


	1. Never use the session timeout mechanism
	
	2. [x] Enforce model access control that registers ownership instead of allowing the user to modify the record
	
	3. Implement allow by default, except for public resources
	
	4. Retain session tokens on the server-side on user logout


15. Which of the following practices helps security analysts prevent unvalidated redirects and forwards on a web application?


	1. Disable notification pop-up pages while redirecting users to a new web page
	
	2. Allow URL as a user input for the destination
	
	3. [x] Implement token ID verification for redirecting web pages
	
	4. Never implement the use of absolute and relative URLs during redirection


16. Which of the following practices helps security experts defend an organization’s application environment from watering hole attacks?


	1. Avoid using browser plug-ins that block HTTP redirects
	
	2. Allow users for granting additional permissions to websites
	
	3. [x] Use web filters to detect attacks on websites and prevent browsers from accessing infected pages
	
	4. Avoid running the web browser in a virtual environment


17. Which of the following practices helps security experts protect web applications from cookie/session poisoning attempts?


	1. Store plaintext or weakly encrypted passwords in cookies
	
	2. [x] Avoid using generators for creating session identifiers
	
	3. Do not implement cookie timeout
	
	4. Never use cookie randomization to change the website or a service cookie whenever the user makes a request

 Explanation:

Some countermeasures against cookie/session poisoning attacks are as follows:

    Do not store plaintext or weakly encrypted passwords in cookies.
    Implement cookie timeout.
    The authentication credentials of any cookie should be associated with an IP address.
    Make logout functions available.
    Employ cookie randomization to change the website or a service cookie whenever the user makes a request.
    Use a VPN that adopts high-grade encryption and traffic routing to prevent session sniffing.
    Restrict multipurpose cookies to ensure that a single task is assigned for an individual cookie.
    Ensure that HTTPS communication is used to secure the flow of information.
    Enable synchronous session management to enhance cookie security.
    Avoid using generators for creating session identifiers. 


18. Identify the practice that makes web applications susceptible to external password reset attacks.


	1. Use advanced multi-factor authentication (MFA) techniques
	
	2. Ensure that all password reset URLs are used only once and set an expiry time limit
	
	3. [x] Avoid sending a temporary password via the registered email address; instead reset the password directly
	
	4. Perform proper validation of random token and email link combinations before executing the request


19. Which of the following practices helps security professionals secure web applications from same-site attacks?


	1. Never educate users on CNAME DNS entry verification and its impacts
	
	2. Disable DNS misconfiguration verification and validation process
	
	3. [x] Duly update DNS records on the corresponding DNS server
	
	4. Avoid using dangling domain records as a validation mechanism

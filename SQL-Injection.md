## SQL Injection Methodology, Tools, and Evasion Techniques

1. Which of the following issues can be detected when testers send long strings of junk data, similar to strings for detecting buffer overruns that throw SQL errors on a page?


	1. [x] Truncation
	2. SQL modification
	3. SQL injection
	4. Input sanitization


2. Which of the following SQL injection queries is used by an attacker to extract table column names?


	1. http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,TABLE_NAME,3,4 from sysobjects where xtype=char(85)--
	
	2. [x] http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,column_name,3,4 from DB_NAME.information_schema.columns where table_name ='EMPLOYEE_TABLE'--
	
	3. http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,COLUMN-NAME-1,3,4 from EMPLOYEE_NAME --
	
	4. http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,DB_NAME,3,4--

 **Explanation:**

Extract Database Tables: http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,TABLE_NAME,3,4 from sysobjects where xtype=char(85)—

[EMPLOYEE_TABLE] Returned from the server

**Extract Table Column Names: http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,column_name,3,4 from DB_NAME.information_schema.columns where table_name ='EMPLOYEE_TABLE'--**

**[EMPLOYEE_NAME]**

Extract Database Name: http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,DB_NAME,3,4--

[DB_NAME] Returned from the server

Extract 1st Field Data: http://www.certifiedhacker.com/page.aspx?id=1 UNION SELECT ALL 1,COLUMN-NAME-1,3,4 from EMPLOYEE_NAME –

[FIELD 1 VALUE] Returned from the server


3. In which of the following database technologies is the SQL query [SELECT * FROM syscat.columns WHERE tabname= 'tablename'] used for column enumeration?


	1. MSSQL  **SELECT name FROM syscolumns** 
	2. [x] DB2 **syscat.columns**
	3. MySQL  
	4. Oracle
 

 4. Which of the following database management systems contains the system table called “MsysObjects”?


	1. [x] MS Access **MsysACEs, MsysObjects, MsysQueries, MysyRelationships**
	2. MySQL **mysql.user, mysql.db, mysql.tables_priv**
	3. MSSQL **sysobjects, syscolumns, systypes, sysdatabases**
	4. Oracle **SYS.USER_OBJECTS, SYS_TABLES, SYS.USER_TABLES, SYS.**


Which of the following operators is used for string concatenation in an Oracle database?


	1. [x] ' '||' 
	2. concat(,) 
	3. ' '+' '
	4. " "&" "



5. Which of the following queries is used to create a database account in Microsoft SQL Server?


	1. CREATE USER victor IDENTIFIED BY 'Pass123' **Ms Access**
	
	2. CREATE USER victor IDENTIFIED BY Pass123 TEMPORARY TABLESPACE temp DEFAULT TABLESPACE users; GRANT CONNECT TO victor; GRANT RESOURCE TO victor; **Oracle**
	
	3. [x] exec sp_addlogin 'victor', 'Pass123' exec sp_addsrvrolemember 'victor', 'sysadmin'
	
	4. INSERT INTO mysql.user (user, host, password) VALUES ('victor', 'localhost', PASSWORD('Pass123')) **MySql**


6. Which of the following DB2 queries allows an attacker to perform column enumeration on a target database?


	1. [x] SELECT * FROM syscat.columns WHERE tabname= 'tablename' **DB2**
	
	2. SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'tablename') sp_columns tablename **MSSQL**

	3. show columns from tablename **MS Access**
	
	4. SELECT * FROM all_tab_columns WHERE table_name='tablename' **MySQL**


7. Which of the following MSSQL queries allows an attacker to perform column enumeration on a target database?


	1. SELECT attnum,attname from pg_class, pg_attribute WHERE relname= 'tablename' AND pg_class.oid=attrelid AND attnum > 0 **Postgresql**
	
	2. SELECT * FROM all_tab_columns WHERE table_name='tablename' **Oracle**
	
	3. SELECT * FROM syscat.columns WHERE tabname= 'tablename' **DB2**
	
	4. SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'tablename') **MSSQL**


8. A tester has been hired to perform source code review of a web application to detect SQL injection vulnerabilities. As part of the testing process, he needs to get all the information about the project from the development team. During the discussion with the development team, he comes to know that the project is in the initial stage of the development cycle. As per the above scenario, which of the following processes does the tester need to follow in order to save the company’s time and money?


	1. [x] The tester needs to perform static code analysis as it covers the structural and statement coverage testing
	
	2. The tester needs to perform static code analysis as it covers the executable file of the code
	
	3. The tester needs to perform dynamic code analysis as it finds and fixes the defects
	
	4. The tester needs to perform dynamic code analysis as it uncovers bugs in the software system


9. David, a penetration tester, was asked to check the MySQL database of the company for SQL injection attacks. He decided to check the back end database for a double blind SQL injection attack. He knows that double blind SQL injection exploitation is performed based on an analysis of time delays and he needs to use some functions to process the time delays. David wanted to use a function which does not use the processor resources of the server. Which of the following function David need to use?


	1. addcslashes()
	2. mysql_query()
	3. benchmark()
	4. [x] sleep()


10. Which of the following tools does an attacker use to perform SQL injection exploitation through techniques such as union and blind SQL exploitation and bypass certain IPS/IDS rules with generic filters?


	1.  [x] Mole **SQLi**
	2. Weevely **PHP Uploader**
	3. Astra **API Fuzzer**
	4. China Chopper **Web Shell**


11. In which of the following evasion techniques does an attacker use a WHERE statement that is always evaluated as “true” so that any mathematical or string comparison can be used, such as “' or '1'='1'”?


	1. [x] Variations **WHERE statement always 'true'**
	2. Declare variables **variable SQL statements**
	3. Case variation **Upper and lowercase letters**
	4. Null byte **Uses Null byte char %00**

12. Fill in the blank:

function is an IDS evasion technique that can be used to inject SQL statements into MySQL database without using double quotes.


	1. CHR()
	2. CONV()
	3. ASCIISTR()
	4. [x] CHAR()


13. Williams, a professional hacker, targeted a web application that uses a MongoDB backend database. He employed MongoDB operations such as $eq to create a malicious command using which he could bypass the authentication process and exfiltrate the customers’ data stored in the database.

Which of the following attacks did Williams perform in the above scenario?


	1. Smurf attack
	2. LDAP injection
	3. Command injection
	4. [x] NoSQL injection




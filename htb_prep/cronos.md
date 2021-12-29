###nmap

```
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works

```

######Go to 10.10.10.13, see default apache page, no worries, normally it means apache doesnt configure properly. Start burp to intercept the traffic, change the hostname from IP to 'cronos.htb', it returns a page as below

![[Screenshot 2021-12-19 at 7.39.03 PM.png]]

######Edit the host file to link ip to DNS

![[Screenshot 2021-12-19 at 7.40.44 PM.png]]
######run dirbuster, while running dirbuster, since port 53 (DNS) is listening, do nslookup and find subdomains
```
nslookup cronos.htb

dig axfr @10.10.10.3 cronos.htb
```
![[Screenshot 2021-12-19 at 7.52.10 PM.png]]
######add subdomains to hosts file
![[Screenshot 2021-12-19 at 7.55.29 PM.png]]
######broswe to the admin.cronos.htb, saw login page.
![[Screenshot 2021-12-19 at 7.57.58 PM.png]]
#####guess password, admin@admin, didnt success, do simple sql injection: ' or '1'='1
![[Screenshot 2021-12-19 at 8.01.19 PM.png]]

######sql injection for username 
![[Screenshot 2021-12-19 at 8.19.11 PM.png]]
direct to the below page:
![[Screenshot 2021-12-19 at 8.19.27 PM.png]]
try command injection, works www-data
![[Screenshot 2021-12-19 at 8.22.04 PM.png]]

```

```
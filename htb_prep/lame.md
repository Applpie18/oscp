nmap
```
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.14
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: WAP|broadband router|remote management|general purpose|storage-misc
Running (JUST GUESSING): Linux 2.4.X|2.6.X (92%), Arris embedded (92%), Dell embedded (92%), Dell iDRAC 6 (92%), ZyXEL embedded (92%), Linksys embedded (90%)
OS CPE: cpe:/o:linux:linux_kernel:2.4.36 cpe:/h:dell:remote_access_card:6 cpe:/o:linux:linux_kernel:2.4 cpe:/o:linux:linux_kernel:2.6.22 cpe:/o:linux:linux_kernel:2.6 cpe:/o:dell:idrac6_firmware cpe:/h:zyxel:nsa-200 cpe:/h:linksys:wet54gs5
Aggressive OS guesses: DD-WRT v24-sp1 (Linux 2.4.36) (92%), Arris TG862G/CT cable modem (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Linux 2.4.27 (92%), Linux 2.6.22 (92%), Linux 2.6.8 - 2.6.30 (92%), Dell iDRAC 6 remote access controller (Linux 2.6) (92%), ZyXEL NSA-200 NAS device (92%), OpenWrt White Russian 0.9 (Linux 2.4.30) (90%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.755 days (since Wed Dec 22 04:12:04 2021)
TCP Sequence Prediction: Difficulty=208 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h31m20s, deviation: 3h32m10s, median: 1m18s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-12-22T22:19:57-05:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

NSE: Script Post-scanning.
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
Initiating NSE at 22:19
Completed NSE at 22:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 74.30 seconds
           Raw packets sent: 2076 (95.036KB) | Rcvd: 34 (2.164KB)
```

port21: 
```
searchspolit vsftpd 2.3.4
msfconsole
run

[vulnerblity has been patched] https://www.exploit-db.com/exploits/17491

```

port445: Samba smbd 3.0.20-Debian
```
searchspolit Samba 3.0.20

![[Screenshot 2021-12-23 at 11.48.00 .png]]

```
```
![[Screenshot 2021-12-23 at 11.49.52 .png]]

```


![[Screenshot 2021-12-23 at 11.52.20 .png]]

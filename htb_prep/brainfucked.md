### wordpress
```
Wpscan

Password: Wpscan2021!

Username:megan
```

### To enumerate username:
```
wpscan --url https://brainfuck.htb --disable-tls-checks --api-token 1tOuZjR3zQ0xOtaZUQhD7dbsLIcrqOK3Gr1NYpNxKaw --enumerate u
```

### To decrypt ssh key – john
```
python /usr/share/john/ssh2john.py id_rsa > id_rsa.john

sudo john id_rsa.john --wordlist=/usr/share/wordlists/rockyou.txt
```


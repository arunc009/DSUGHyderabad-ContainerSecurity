# DSUGHyderabad-ContainerSecurity
A brief hands on demonstration on cool kernel features which can be leveraged to harden containers. 


# Hands On Introduction to Container Security

## Linux Capabilities

 * Drop all
  * Add required

  
### Default Capabilities

**Create a Basic Container**
```sh
arunc@arun:~$ docker container run -it --name mortal01 alpine sh
/ # apk add -U libcap
fetch http://dl-cdn.alpinelinux.org/alpine/v3.10/main/x86_64/APKINDEX.tar.gz
fetch http://dl-cdn.alpinelinux.org/alpine/v3.10/community/x86_64/APKINDEX.tar.gz
(1/1) Installing libcap (2.27-r0)
Executing busybox-1.30.1-r2.trigger
OK: 6 MiB in 15 packages
/ # capsh 
.dockerenv  dev/        home/       media/      opt/        root/       sbin/       sys/        usr/
bin/        etc/        lib/        mnt/        proc/       run/        srv/        tmp/        var/
/ # capsh --print
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Ambient set =
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
 secure-no-ambient-raise: no (unlocked)
uid=0(root)
gid=0(root)
groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
More info on Capabalities Man Page: http://man7.org/linux/man-pages/man7/capabilities.7.html

**Hold on**: Do we really think we need all these capabilities? Just for a basic container who suppose to receive request and respond may be Apache web server for an example.
```sh
arunc@arun:~$ docker run -dit --name web httpd 
1a30464e5469f28f3243fe6cd30e0263908f5f3702ae6b6152e7a6d073314bf2

arunc@arun:~$ docker container ls
CONTAINER ID        IMAGE               COMMAND              CREATED             STATUS              PORTS               NAMES
1a30464e5469        httpd               "httpd-foreground"   4 seconds ago       Up 2 seconds        80/tcp              web

arunc@arun:~$ docker inspect 1a30464e5469 | egrep '"IPAdd'
"IPAddress": "172.17.0.2",

arunc@arun:~$ curl -I 172.17.0.2
HTTP/1.1 200 OK
Date: Tue, 12 May 2020 15:58:01 GMT
Server: Apache/2.4.43 (Unix)
Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
ETag: "2d-432a5e4a73a80"
Accept-Ranges: bytes
Content-Length: 45
Content-Type: text/html
```

Lets see Capabilities added to it from host perspective:
```sh
arunc@arun:~$ pscap | grep httpd
19859 19892 root        httpd             chown, dac_override, fowner, fsetid, kill, setgid, setuid, setpcap, net_bind_service, net_raw, sys_chroot, mknod, audit_write, setfcap
```
Wait, what provides pscap:  `libcap-ng-utils` Package. Simple` apt install <package-name>` should do it.
More info: http://manpages.ubuntu.com/manpages/bionic/man8/pscap.8.html

**Drop All**
```sh
arunc@arun:~$ docker run -dit --cap-drop=all --name web01 httpd 
ab4211065a617088a22e625b2cd4559b45035dd00d97153c7322157320172052

arunc@arun:~$ docker container ls 
CONTAINER ID        IMAGE               COMMAND              CREATED             STATUS              PORTS               NAMES
1a30464e5469        httpd               "httpd-foreground"   8 minutes ago       Up 8 minutes        80/tcp              web

arunc@arun:~$ docker container ls -a
CONTAINER ID        IMAGE               COMMAND              CREATED             STATUS                     PORTS               NAMES
ab4211065a61        httpd               "httpd-foreground"   11 seconds ago      Exited (1) 9 seconds ago                       web01
1a30464e5469        httpd               "httpd-foreground"   9 minutes ago       Up 8 minutes               80/tcp              web
```
Oops the container `web01` is in exited state but why? lets figure out.
```sh
arunc@arun:~$ docker logs ab4211065a61
AH00558: httpd: Could not reliably determine the server's fully qualified domain name, using 172.17.0.3. Set the 'ServerName' directive globally to suppress this message
(13)Permission denied: AH00072: make_sock: could not bind to address 0.0.0.0:80
no listening sockets available, shutting down
AH00015: Unable to open logs
```
Alright, `could not bind to address` make sense. As we have dropped all capabilities. 

But here the the question, how do i know what all capabilities are needed for proper functioning of my application? 

Well, for that  some sort of profiling is needed and `Redhat` has got all ears for this.  

For this, `system-tap` is the utility provided by redhat which can be leveraged for tracing:

 - system call 
 - memory allocation 
 - process/thread etc

Let's see how we can trace a simple process i.e.  `apache`:

```sh
pataka{90}$ ./container_check.stp -DKRETACTIVE=100 -c "sudo strace -c -f /usr/sbin/httpd -DFOREGROUND"
Missing separate debuginfos, use: debuginfo-install kernel-3.10.0-957.el7.x86_64 kmod-kvdo-6.1.1.125-5.el7.x86_64 
starting container_check.stp. monitoring 18015
strace: Process 18021 attached
strace: Process 18022 attached
strace: Process 18023 attached
strace: Process 18025 attached
strace: Process 18024 attached
^Cstrace: Process 18020 detached
strace: Process 18021 detached
strace: Process 18022 detached
strace: Process 18023 detached
strace: Process 18025 detached
strace: Process 18024 detached
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 28.32    0.017532           4      4504        19 open
 21.88    0.013542           3      4545           read
 19.69    0.012189           3      4531           close
 17.95    0.011115          20       567           select
  2.59    0.001602           3       568           wait4
  1.80    0.001116           4       281           lseek
  1.79    0.001107           3       434           mmap
  1.79    0.001106           3       393           mprotect
  0.54    0.000335           3       118           munmap
  0.50    0.000311           1       249           fstat
  0.42    0.000258           4        63           poll
  0.27    0.000170           2        71           fcntl
  0.24    0.000147           6        26           write
  0.24    0.000146           2        77        39 stat
  0.24    0.000146           4        36           recvfrom
  0.16    0.000100           6        18           getsockopt
  0.16    0.000099           4        24           setsockopt
  0.13    0.000081           3        24         6 connect
  0.12    0.000073           3        25           socket
  0.11    0.000070           7        10           semop
  0.11    0.000068          14         5           setuid
  0.11    0.000066           4        18           umask
  0.10    0.000063           7         9           sendmsg
  0.08    0.000049          10         5           setgroups
  0.07    0.000043           4        11           pipe
  0.06    0.000037           7         5           epoll_create1
  0.05    0.000031           2        17           geteuid
  0.05    0.000030           2        16           semctl
  0.05    0.000028           6         5           epoll_ctl
  0.04    0.000026          13         2         2 statfs
  0.04    0.000023           1        19           brk
  0.04    0.000023           1        35           rt_sigaction
  0.04    0.000023          12         2           unlink
  0.04    0.000022           4         6           bind
  0.03    0.000016           2         7           semget
  0.02    0.000014           3         5           clone
  0.02    0.000013           3         5           setgid
  0.02    0.000012           1        15           recvmsg
  0.02    0.000011           1         8           getdents
  0.01    0.000006           6         1           shmget
  0.01    0.000006           6         1           shmat
  0.01    0.000006           1         5           sendto
  0.01    0.000006           1        11           getsockname
  0.01    0.000005           1         5         1 access
  0.01    0.000005           3         2           shmctl
  0.01    0.000005           5         1           listen
  0.01    0.000004           4         1           set_tid_address
  0.01    0.000004           1         4           openat
  0.00    0.000003           3         1           rt_sigprocmask
  0.00    0.000003           2         2           dup3
  0.00    0.000002           2         1           getrlimit
  0.00    0.000002           2         1           getuid
  0.00    0.000002           2         1           getgid
  0.00    0.000002           2         1           arch_prctl
  0.00    0.000002           0         6           set_robust_list
  0.00    0.000000           0         1           execve
  0.00    0.000000           0         2           uname
  0.00    0.000000           0         3           futex
------ ----------- ----------- --------- --------- ----------------
100.00    0.061906                 16809        67 total


capabilities used by executables
      executable:      prob capability

           httpd:           cap_setgid
           httpd:           cap_setuid
           httpd: cap_net_bind_service

          strace:       cap_sys_ptrace

            sudo:     cap_dac_override
            sudo:           cap_setgid
            sudo:           cap_setuid
            sudo:        cap_net_admin
            sudo:     cap_sys_resource
            sudo:      cap_audit_write



capabilities used by syscalls
      executable,              syscall (       capability ) :            count
           httpd,               setgid (       cap_setgid ) :                5
           httpd,               setuid (       cap_setuid ) :                5
           httpd,            setgroups (       cap_setgid ) :                5
           httpd,                 bind ( cap_net_bind_service ) :                1
          strace,               ptrace (   cap_sys_ptrace ) :                2
            sudo,            setresgid (       cap_setgid ) :                6
            sudo,            setresuid (       cap_setuid ) :                9
            sudo,               setuid (       cap_setuid ) :                1
            sudo,               setgid (       cap_setgid ) :                1
            sudo,            setgroups (       cap_setgid ) :                5
            sudo,            setrlimit ( cap_sys_resource ) :                2
            sudo,               sendto (  cap_audit_write ) :                6
            sudo,               execve ( cap_dac_override ) :                1
            sudo,           setsockopt (    cap_net_admin ) :                2


forbidden syscalls
      executable,              syscall:            count


failed syscalls
      executable,              syscall =            errno:            count
           httpd,                 stat =           ENOENT:               39
           httpd,              connect =           ENOENT:                6
           httpd,              accept4 =                 :                5
           httpd,                 open =           ENOENT:               19
           httpd,               access =           ENOENT:                1
           httpd,               statfs =           ENOENT:                2
           httpd,               select =                 :                1
          stapio,                      =            EINTR:                1
          stapio,               execve =           ENOENT:                2
          stapio,        rt_sigsuspend =                 :                1
          strace,               access =           ENOENT:                1
          strace,               ptrace =            ESRCH:                1
            sudo,                 stat =           ENOENT:               24
            sudo,              recvmsg =           EAGAIN:                3
            sudo,                ioctl =           ENOTTY:                2
            sudo,                      =            EINTR:                2
            sudo,                 open =           ENOENT:               99
            sudo,               access =           ENOENT:                4
            sudo,              connect =           ENOENT:                6
            sudo,               statfs =           ENOENT:                2
            sudo,           getsockopt =      ENOPROTOOPT:                1
            sudo,                 read =           EAGAIN:                2
            sudo,                 poll =                 :                2

```
 The stdout contains a lot of information but take a close look at the capabilities being used which are :
 - setgid 
 - setuid 
 - net_bind_service

 Alright, so we got the necessary capabilities for our process. Lets give it a try again.
 ```sh
 arunc@arun:~$ docker run -dit --cap-drop=all --cap-add=setgid --cap-add=setuid --cap-add=net_bind_service --name web02 httpd 
c5facc037cdfc50bf02874ba0633a40d0936b609fa044aaa398b8bd5a2f15e14

arunc@arun:~$ docker container ls
CONTAINER ID        IMAGE               COMMAND              CREATED             STATUS              PORTS               NAMES
c5facc037cdf        httpd               "httpd-foreground"   4 seconds ago       Up 3 seconds        80/tcp              web02
1a30464e5469        httpd               "httpd-foreground"   10 minutes ago      Up 10 minutes       80/tcp              web

arunc@arun:~$ docker inspect c5facc037cdf | grep "IPAdd"
"IPAddress": "172.17.0.3",

arunc@arun:~$ curl -I 172.17.0.3
HTTP/1.1 200 OK
Date: Tue, 12 May 2020 14:30:01 GMT
Server: Apache/2.4.43 (Unix)
Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
ETag: "2d-432a5e6t75d80"
Accept-Ranges: bytes
Content-Length: 45
Content-Type: text/html
```

From host perspective:
```sh
arunc@arun:~$ pscap | grep httpd
19859 19892 root        httpd             chown, dac_override, fowner, fsetid, kill, setgid, setuid, setpcap, net_bind_service, net_raw, sys_chroot, mknod, audit_write, setfcap
21438 21468 root        httpd             setgid, setuid, net_bind_service
```
For installation/Configuration & examples of `system-tap` utility. Please refer to the links below:

 - Installation/Configuration: https://access.redhat.com/articles/882463
 -    Examples: https://sourceware.org/systemtap/examples/

## Cgroups

 - Limits the resources which a process or set of process can use. 
 - It could be CPU,Memory,Network I/O or access to filesystem

### Default memory
```sh
arunc@arun:~$ docker run -ti --name stress-test containerstack/alpine-stress sh
/ # hostname
7628bce61cb8
```
What's the number?
```sh
arunc@arun:/sys/fs/cgroup/memory/docker/7628bce61cb88cf8f5246c7fd59fea359de353d7d99d590992468e0e6aa06697$ cat memory.limit_in_bytes 
9223372036854771712
```
Is it for real? This seems to be giant.

Let's rollout some hogs.
```sh
# 250M Each worker
/ # stress --vm 2 --vm-bytes 250M --timeout 5s
stress: info: [7] dispatching hogs: 0 cpu, 0 io, 2 vm, 0 hdd
stress: info: [7] successful run completed in 5s

# 500M Each worker
/ # stress --vm 2 --vm-bytes 500M --timeout 5s
stress: info: [10] dispatching hogs: 0 cpu, 0 io, 2 vm, 0 hdd
stress: info: [10] successful run completed in 5s
```

But how do i mark a upper limit on it? Simple `docker` provides this feature out of the box. Use `--memory` flag.

See:
```sh
arunc@arun:~$ docker run -ti --memory 10M --name stress-test-02 containerstack/alpine-stress sh
/ # stress --vm 2 --vm-bytes 50M --timeout 5s   <---- 50M Each worker
stress: info: [7] dispatching hogs: 0 cpu, 0 io, 2 vm, 0 hdd
stress: FAIL: [7] (415) <-- worker 9 got signal 9
stress: WARN: [7] (417) now reaping child worker processes
stress: FAIL: [7] (451) failed run completed in 0s

/ # stress --vm 2 --vm-bytes 5M --timeout 5s   <---- 5M Each worker
stress: info: [10] dispatching hogs: 0 cpu, 0 io, 2 vm, 0 hdd
stress: info: [10] successful run completed in 5s

/ # stress --vm 2 --vm-bytes 11M --timeout 5s  <---- 11M Each worker
stress: info: [13] dispatching hogs: 0 cpu, 0 io, 2 vm, 0 hdd
stress: FAIL: [13] (415) <-- worker 15 got signal 9
stress: WARN: [13] (417) now reaping child worker processes
stress: FAIL: [13] (451) failed run completed in 0s
```
Alright, the above results are as per expectations. This can be done for other resources as well. See below:
Specify Custom cgroups: [https://docs.docker.com/engine/reference/run/#specify-custom-cgroups](https://docs.docker.com/engine/reference/run/#specify-custom-cgroups)

## Namespaces

 - It restrict the visibility of group of processes to the rest of the system

Spawn a simple container.
```sh
arunc@arun:~$ docker run -d alpine /bin/sh -c "sleep 10000"
dde21d341192ed4d14d7f2cf52ff838463348498b645ad45ca1c87e9bf308a35

arunc@arun:~$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS               NAMES
dde21d341192        alpine              "/bin/sh -c 'sleep 1…"   6 seconds ago       Up 5 seconds                            hungry_agnesi

arunc@arun:~$ docker exec -it dde21d341192 sh
/ # ps
PID   USER     TIME  COMMAND
    1 root      0:00 sleep 10000
    5 root      0:00 sh
    9 root      0:00 ps
/ # read escape sequence
```
As it can be seen the sleep is running as the `init` process with PID 1 inside a container.

How it looks like outside the container (at host level)? Let's see:
```sh
arunc@arun:~$ ps -ef | grep [s]leep
root     14690 14664  1 19:23 ?        00:00:00 sleep 10000
```
At host level that init process is mapped to process id `14690`. That's how it looks like. 

Let's explore a bit more:

Spawn a `maria-db` container.
```sh
arunc@arun:~$ docker run --name mariadb -e MYSQL_ROOT_PASSWORD=123 -d mariadb

arunc@arun:~$ docker ps
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS               NAMES
55136b4175e6        mariadb             "docker-entrypoint.s…"   13 seconds ago      Up 11 seconds       3306/tcp            mariadb

arunc@arun:~$ docker exec -it 55136b4175e6 sh
# ps auxww
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
mysql        1  0.3  1.3 1921296 87808 ?       Ssl  14:31   0:00 mysqld
root       208  7.7  0.0   4628   884 pts/0    Ss   14:35   0:00 sh
root       212  0.0  0.0  34404  2892 pts/0    R+   14:35   0:00 ps auxww
```
Alright, so `msyqld` daemon is running as the `init` process inside the container with PID `1` and with `msyql` user.  It's quite normal and that's how a normal mysql database would run.

But how things looks outside container? Lets see:
```sh
arunc@arun:~$ ps -ef | grep [m]ysql
vboxadd  16437 16408  0 20:01 ?        00:00:00 mysqld
```
Oh no, at the host level the process which is running inside container with `msyql` is mapped to some user `vboxadd` but how? I really would not want this to happen. As i may cause unknown issue may be right now or in near future. What if i delete this user from host? There are unknown unknowns associated here. Though, PID mapping is as usual. 

Reason: let's see what's the user id of `mysql` user inside container. 
```sh
# id mysql
uid=999(mysql) gid=999(mysql) groups=999(mysql)
```
And at host level?
```sh
arunc@arun:~$ cat /etc/passwd | grep vboxadd
vboxadd:x:999:1::/var/run/vboxadd:/bin/false
```
Holy moly!!

well this explains whats happening above.  Alright, how can we mitigate this? 

Mitigation:

Instead of this:
```sh
RUN groupadd -r mysql && useradd -r -g mysql mysql
```
Add this:
```sh
RUN groupadd -g 1099 -r mysql && useradd -u 1099 -r -g mysql mysql
```
To your `Dockerfile` or `docker run` coammand.

### User namespace

What if i run my docker daemon in some other namespace? will that be the permanent solution for the problems like above?

Let's explore:

A user would then be required. we got this for now. 
```sh
root@arun:~# cat /etc/passwd | grep swapy
swapy:x:6000:6000:swapy,,,:/home/swapy:/bin/false

root@arun:~# cat /etc/group | grep swapy
swapy:x:6000:
```
You also need to have subordinate UID and GID ranges specified in the /etc/subuid and /etc/subgid files, respectively
```sh
root@arun:~# cat /etc/subuid
swapy:165536:65536

root@arun:~# cat /etc/subgid
swapy:165536:65536
```
For more info on `subuid` & `subgid` : [http://man7.org/linux/man-pages/man5/subuid.5.html](http://man7.org/linux/man-pages/man5/subuid.5.html)

Also, we need to instruct docker daemon as well. 
```sh
--- /etc/docker/daemon.json
{
     "userns-remap": "swapy"
}
```
Restart docker and try running `maria-db` container again.
```sh
root@arun:~# docker run --name mariadb -e MYSQL_ROOT_PASSWORD=123 -d mariadb
Unable to find image 'mariadb:latest' locally
latest: Pulling from library/mariadb
23884877105a: Pull complete 
bc38caa0f5b9: Pull complete 
2910811b6c42: Pull complete 
36505266dcc6: Pull complete 
e69dcc78e96e: Pull complete 
222f44c5392d: Pull complete 
efc64ea97b9c: Pull complete 
9912a149de6b: Pull complete 
7ef6cf5b5697: Pull complete 
8a05be3688e0: Pull complete 
889cef5b730e: Pull complete 
f58917949c8d: Pull complete 
76c3d568c399: Pull complete 
90f46b218c1a: Pull complete 
Digest: sha256:0fac2fa5ec295d16c356e567cfe676f92605b60f3b257f2958e23676c2acf937
Status: Downloaded newer image for mariadb:latest
d72c07c1b4bddf9d2e2ce94aaf422a69c9b82e4e3adab862a26cc6d0d88d6f6d

root@arun:~# docker ps -a
CONTAINER ID        IMAGE               COMMAND                  CREATED             STATUS              PORTS               NAMES
d72c07c1b4bd        mariadb             "docker-entrypoint.s…"   24 seconds ago      Up 3 seconds        3306/tcp            mariadb
```
Checkout the `USER-ID` and `USER` inside the container.
```sh
root@d72c07c1b4bd:/# ps auxww
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
mysql        1  2.2  1.3 1921296 87860 ?       Ssl  14:05   0:00 mysqld
root       173 11.0  0.0  18500  3412 pts/0    Ss   14:06   0:00 /bin/bash
root       219  0.0  0.0  34404  2812 pts/0    R+   14:06   0:00 ps auxww
```
How things looks at host level. Lets see:
```sh
root@arun:~# ps -ef | grep [m]ysqld
166535   26331 26297  1 19:35 ?        00:00:00 mysqld
```
From where the above `USER-ID` is coming? Exactly from `subuid` file which we have configured in the previous step.
```sh
root@arun:~# cat /etc/subuid
swapy:165536:65536
```
Also, the thing to note here is the `containers` & `images` present in the earlier namespace would not be seeing here in the brand new namespace i.e `swapy`.  Try running `docker container ls -a` & `docker images`. You should be seeing stuff related to `maria-db` container only. 

A closer look can be taken at filesystem (at host level) to see how images are being stored. 

This is how things would look like:

For default namespace:
```sh
root@arun:~# ls -lF /var/lib/docker/image/overlay2/imagedb/content/sha256/
total 124
-rw------- 1 root root 6649 Oct 13  2019 01a52b3b5cd14dffaff0908e242d11275a682cc8fe3906a0a7ec6f36fbe001f5
-rw------- 1 root root 1503 Oct 20  2019 10fcec6d95c4a29f49fa388ed39cded37e63a1532a081ae2386193942fc12e21
-rw------- 1 root root 1497 Oct 11  2019 19485c79a9bbdca205fce4f791efeaa2a103e23431434696cc54fdd939e9198d
-rw------- 1 root root 3638 May  6 20:05 1e7c408656ac561ec8ca226c8d6161fbf7d6c727fc5e8800c669df41b05ff99d
-rw------- 1 root root 3100 May  6 20:05 23f68ff39a82772be80265ea8de3209200cd7fcb85ab9aaa4a04673081f1a1a3
-rw------- 1 root root 2656 May  6 20:05 2b97066672d4c62ca863cfd366eb3f50e563b3cf74c9b6262cd25d3b8a45184f
-rw------- 1 root root 3411 Sep 20  2019 2ca708c1c9ccc509b070f226d6e4712604e0c48b55d7d8f5adc9be4a4d36029a
-rw------- 1 root root 2647 May  6 19:05 4852a9ba3b0fc60f2c852fa36043db647f0dfdf21877304585ab3e3c1f9d9d60
-rw------- 1 root root 3774 May  6 20:06 4d9f404fdde435f6968f1ea726aaf947cb36673d5c3d5c87a2b4e93a7f814305
-rw------- 1 root root 4014 May  6 20:06 5adb9ec1e5e50c0847dcc9e994486c2f119128bd7cd8030f2583477eea3cf971
-rw------- 1 root root 2019 May  6 18:38 5e42ba7a3e14409763b6b4edc4ae017aedde1ddd2e72c5b01318393593ab3773
-rw------- 1 root root 7623 Oct 13  2019 95a9e476c63463922bbc17d0e8c3a8bf3e906e411477337086c41a7f66323870
-rw------- 1 root root 1512 Oct 16  2019 961769676411f082461f9ef46626dd7a2d1e2b2a38e6a44364bcbecf51e66dd4
-rw------- 1 root root 9404 May 20 20:01 9c1f27148b1fa1caae83f085f2e5b04f52a025b2a465ab52b4883326bd70892a
-rw------- 1 root root 1862 May  6 18:38 9f266d35e02cc56fe11a70ecdbe918ea091d828736521c91dda4cc0c287856a9
-rw------- 1 root root 3563 May  6 20:05 a8e0bf524edd9cd22987cb40cd6ebcdfcb55364806d2450af79cde7a61846280
-rw------- 1 root root 3297 May  6 20:05 ab8c67130f1e08f91873027b64ecbf73bd600510fd5486b87c960e2e43576eaa
-rw------- 1 root root 2885 May  6 20:05 b21562a6d7da8ad2d39b7f5881b3795a2d74f681a80a506a08bb6b7825220abc
-rw------- 1 root root 7350 May 12 20:28 b2c2ab6dcf2e526597d0a5fc506f123088e6572a8a656f04cea86d4f559c66e9
-rw------- 1 root root 6134 Oct 13  2019 bb1ccaa5880c02fae266e2850d22bf308f0ab6d871ea38a15c3fc966b00be193
-rw------- 1 root root 3464 May 18 18:07 c9ada8e833a28cbb9a000dc658bc27f3989dcbc73db24334818ea04db66b0297
-rw------- 1 root root 4215 May  6 20:06 f028e34c34c047f517a491c94cce5644b89feb7bea9bdadb2011a4a1910fa9cc
-rw------- 1 root root 6669 Oct 13  2019 f949e7d76d63befffc8eec2cbf8a6f509780f96fb3bacbdc24068d594a77f043
```
Images are being stored at `/var/lib/docker/image/overlay2/imagedb/content/sha256/` by their hash names.

whereas, for custom namespace `swpay` this is how it looks like:
```sh
root@arun:/var/lib/docker/165536.165536/image/overlay2/imagedb/content/sha256# ls -al
total 24
drwx------ 2 root root 4096 May 22 22:09 .
drwx------ 3 root root 4096 May 21 19:23 ..
-rw------- 1 root root 9404 May 22 22:09 9c1f27148b1fa1caae83f085f2e5b04f52a025b2a465ab52b4883326bd70892a
-rw------- 1 root root 1507 May 22 22:08 f70734b6a266dcb5f44c383274821207885b549b75c8e119404917a61335981a
```
Note the `user-id` appended to path after docker. 

That's it for the talk. 

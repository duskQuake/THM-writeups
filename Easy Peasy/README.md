# Easy Peasy Writeup

## TASK 1 [Enumeration with Nmap]
We'll start our enumeration process by running an nmap scan. However, I will actually be using rustscan, as it has a few extra performance bells and whistles that I prefer. So, we'll run this command: rustscan -a 10.10.153.96 -- -sC -sV -oA 10.10.153.96 -v -A
with this command, we get these results:

PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack nginx 1.16.1
| http-methods: 
|_  Supported Methods: GET HEAD
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: nginx/1.16.1
|_http-title: Welcome to nginx!
6498/tcp  open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 30:4a:2b:22:ac:d9:56:09:f2:da:12:20:57:f4:6c:d4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCf5hzG6d/mEZZIeldje4ZWpwq0zAJWvFf1IzxJX1ZuOWIspHuL0X0z6qEfoTxI/o8tAFjVP/B03BT0WC3WQTm8V3Q63lGda0CBOly38hzNBk8p496scVI9WHWRaQTS4I82I8Cr+L6EjX5tMcAygRJ+QVuy2K5IqmhY3jULw/QH0fxN6Heew2EesHtJuXtf/33axQCWhxBckg1Re26UWKXdvKajYiljGCwEw25Y9qWZTGJ+2P67LVegf7FQu8ReXRrOTzHYL3PSnQJXiodPKb2ZvGAnaXYy8gm22HMspLeXF2riGSRYlGAO3KPDcDqF4hIeKwDWFbKaOwpHOX34qhJz
|   256 bf:86:c9:c7:b7:ef:8c:8b:b9:94:ae:01:88:c0:85:4d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN8/fLeNoGv6fwAVkd9oVJ7OIbn4117grXfoBdQ8vY2qpkuh30sTk7WjT+Kns4MNtTUQ7H/sZrJz+ALPG/YnDfE=
|   256 a1:72:ef:6c:81:29:13:ef:5a:6c:24:03:4c:fe:3d:0b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNgw/EuawEJkhJk4i2pP4zHfUG6XfsPHh6+kQQz3G1D
65524/tcp open  http    syn-ack Apache httpd 2.4.43 ((Ubuntu))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.43 (Ubuntu)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

How many ports are open? [3]

What is the version of nginx? [1.16.1]

What is running on the highest port? [Apache]

## TASK 2 [Compromising the Machine]
Before continuing, lets download the easypeasy.txt file provided to us, as it may be useful. Upon opening it, we see its a wordlist of passwords! I'm sure we'll need this later. Now continuing with the excersize...
Since we see an obvious http server on the machine, we can run gobuster to scan for any directories that may be hidden on the server. We'll do that with this command: gobuster dir -u http://10.10.153.96/ -w /usr/share/wordlists/dirb/common.txt -o dirs.log
Where dir indicates directory mode, -u [url] -w [wordlist] -o [outputfile]
with this scan, we find two files and a directory:
/hidden               (Status: 301) [Size: 169] [--> http://10.10.153.96/hidden/]
/index.html           (Status: 200) [Size: 612]                                  
/robots.txt           (Status: 200) [Size: 43] 
The homepage is just a welcome screen indicating a successful server installation. Obviously, there is going to be more to this box than that.
First, lets check out the robots.txt file and see if there's anything off about it.
User-Agent:*
Disallow:/
Robots Not Allowed

A fairly normal robots.txt file... lets check that directory. /hidden gives us this picture:
![lost-places-1928727_960_720](https://user-images.githubusercontent.com/93058891/152861022-0d899765-34ee-44ef-be5f-293a3b6dad85.jpg)
However, I'm going to ignore the picture for now asnd instead run another gobuster scan on the /hidden directory with this command: 
gobuster dir -u http://10.10.153.96/hidden -w /usr/share/wordlists/dirb/common.txt -o dirsh.log 
results find two items:
/index.html           (Status: 200) [Size: 390]
/whatever             (Status: 301) [Size: 169] [--> http://10.10.153.96/hidden/whatever/]

Visiting this directory gives us this image:
![norway-772991_960_720](https://user-images.githubusercontent.com/93058891/152862426-d37fc980-24d8-4207-bb45-77076e5ccf27.jpg)
But worse, the title text tells us "dead end". I guess we'll investigate these pictures now. We'll start by simply inspecting the source code of the pages. The first looks normal, but on the second one, we find this...

<p hidden="">ZmxhZ3tmMXJzN19mbDRnfQ==</p>

Let's use Cyberchef to decode it. Putting the text inside the HTML into Cyberchef gives us our first flag!

Let's now move on to the other http server on the machine. To do this, just add :65524 to the end of the IP in the URL. The homepage of the site is an Apache default page. Let's run another gobuster scan on this server like this, with the port in the url: 

gobuster dir -u http://10.10.153.96:65524/ -w /usr/share/wordlists/dirb/common.txt -o dirs6.log

Nothing of note other than a robots.txt file. This one looks a little different though:

User-Agent:*
Disallow:/
Robots Not Allowed
User-Agent:a18672860d0510e5ab6699730763b250
Allow:/
This Flag Can Enter But Only This Flag No More Exceptions

That second User-Agent looks like a hash. Trying the usual sites doesn't seem to yield a result, though. With enough research, we are able to find a site that cracks it. The result is the second flag!

The exercise hints at a hidden directory but gobuster already pulled up nothing. So let's inspect the source code. In the source, we find this line: 
<p hidden>its encoded with ba....:REDACTED</p>

This looks like an encrypting algorithm.

















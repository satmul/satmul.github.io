---
layout: post
title: "Hack The Box - Remote"
date: 2020-09-25
---
<div markdown=1 class="blurb" >
Hi there ! this is a writeup for HTB Remote box. 

## Enumeration : 

First find some ports that available on this box, there are many interesting ports that we can enumerate.

![](/image/remote/nmap.png)

Enumerate the directory with gobuster, and i found /contact.

![](/image/remote/gobuster.png)

## Foothold :

Website on /contact, click on the blue box and will be redirected to /umbraco login page

![](/image/remote/contact.png)

![Umbraco Login Page](/image/remote/login.png)

## User :

We don't know the login credentials yet, but we got mountd (2049) port. Lets enumerate that port. 
Use showmount to get available directory and mount the directory to local machine.

![](/image/remote/port2049.png)

![](/image/remote/umbracosdf.png)

We got admin@htb.local and hashed password, crack the password with any tools that you like. 
I would recommend you use [CrackStation](http://crackstation.net/). Use this credentials to login on umbraco website.

![](/image/remote/creds.png)

![](/image/remote/login1.png)

Find the version of the umbraco website, tap the red circles to check the version. 
This website use Umbraco Version 7, search the [exploit](https://github.com/noraj/Umbraco-RCE)

![](/image/remote/rce.png)

Use -c to get user.txt

![](/image/remote/user.png)

If you want reverse shell follow this step

![](/image/remote/rev.png)

![](/image/remote/nc1.png)

## Privilege Escalation :

See the user privileges (enabled state)

![](/image/remote/priv.png)

Upload Winpeas from local machine to the box. Winpeas will detect any vulnerability on the box.

![](/image/remote/winpeas.png)

This box vulnerable on usosvc, use this vulnerability to get reverse shell. 
After this payload is executed restart the usosvc service with "sc stop usosvc" and start the service again "sc start usosvc". 
Don't forget to set nc listener on your local machine.

![](/image/remote/usosvc.png)

![](/image/remote/nc1.png)

Congratulations you get the Root flag !

![](/image/remote/root.png)

KEEP LEARNING ! Ciao!


- powered by [Jekyll](http://jekyllrb.com) 

</div>

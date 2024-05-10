---
layout: post
title: "Hack The Box - Mirai"
date: 2020-09-29
---
<div markdown=1 class="blurb" >
Hi there ! This is Mirai Hack The Box Writeup - Linux box - Easy

## Summary :
<ul class="summary">
    <li>nmap</li>
    <li>gobuster</li>
    <li>ssh</li>
    <li>grep</li>
</ul>

## Enumeration :
At first nmap the box. Got several ports, lets check port 80 (HTTP) there is nothing, just a blank page.

![](/image/mirai/nmap.PNG)

So check the directory with gobuster, I got /admin and /swfobjects.js, admin seems legit for my foothold. When i checked the js file, i got nothing.

![](/image/mirai/gobuster.PNG)

![](/image/mirai/swf.PNG)

This is the /admin page, I got Pi-hole login page. I didn't know the credentials yet, when I google the default credentials for Pi-hole it returns user : pi, password : raspberry. but when I tried the credentials, it doesn't work. 

![](/image/mirai/pihole.PNG)


## Foothold :
Then I tried the ssh port with the default credentials "pi@10.10.10.48" password : raspberry. Yep! I'm inside the box!!

![](/image/mirai/ssh.PNG)

## User :
User Flag

![](/image/mirai/user.PNG)

## Privilege Escalation :
So this "pi" user can do anything on this box, see the privileges on sudo -l. Sudo su works in here, but the flag is accidentally deleted and there is a message that the root flag is on usb stick.

![](/image/mirai/privesc.PNG)

Move to the /media/usbstick, use grep for take the "accidentally" deleted files. 

![](/image/mirai/mount.PNG)

![](/image/mirai/deleted.PNG)

![](/image/mirai/grep.PNG)

## Root : 
Yes! I got the root flag!

![](/image/mirai/root.PNG)

KEEP LEARNING! CIAO!
If you want to keep in touch with me, check the link below ~ see ya !







</div>
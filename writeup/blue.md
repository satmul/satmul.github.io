---
layout: post
title: "Hack The Box - Blue"
date: 2020-09-27
---
<div markdown=1 class="blurb" >
Hi There, Welcome back with me! So this is my writeup for Hack The Box - Blue.

## Enumeration :
So as usual the first step is nmap-ing the box so we can know some open ports.

![](/image/blue/nmap.PNG)

I found several open ports, there are many msrpc ports (number 40k++). Also I found SMB port (139) that serves as a place for file sharing. Lets enumerate the port, the parameters that i use is -L (list all the shares). Usually smbclient will ask for credentials but in this box we can login without any credentials.

![](/image/blue/smbclient.PNG)

I found many shares to enum, Lets try "Users" share. There are many directories and files, but there is nothing important. 

![](/image/blue/users.PNG)

There is nothing on "Share", "ADMIN$", "IPC$", and "C$" share.

![](/image/blue/share.PNG)

![](/image/blue/smbDollar.PNG)


## EXPLOIT (USER & ROOT) :
Then I realized why i did't try the Eternal Blue SMB exploit. So i just use msfconsole for the exploit. Lets pick ms17_010_eternalblue, on this case lets use EternalBlue for windows 7. If the box OS is windows 8 just pick the windows 8 version, it depends on situation.

![](/image/blue/eternal.PNG)

Set the RHOSTS to the box ip, and for the SMBPASS/SMBUSER leave it empty because i didn't have the credentials. run "check" for msfconsole to check if the box is vulnerable to this attack method.

![](/image/blue/eternal1.PNG)

Yes! this box is vulnerable with EternalBlue, and voila we got shell on this box.

![](/image/blue/whoami.PNG)

## USER FLAG:

![](/image/blue/usertxt.PNG)

## ROOT FLAG:

![](/image/blue/root.png)

KEEP LEARNING! CIAO!
If you want to keep in touch with me, check the link below ~ see ya !



</div>
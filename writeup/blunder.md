---
layout: post
title: "Hack The Box - Blunder"
date: 2020-10-18
---
Hi there ! This is my Blunder machine Writeup, this is a pretty straight-forward box.
![](/image/blunder/blunder.png)

## Enumeration : 
So lets enumerate the ports with nmap. 

![](/image/blunder/nmap.png)


Check the HTTP port, so this is the webpage. There's nothing i can get here, i need more enumeration for my foothold.

![](/image/blunder/web.png)

Scanning directory with gobuster, i got many interesing directory! lets check admin! Also there is a robots.txt file, check another .txt file in this webpage.

![](/image/blunder/gobuster.png)

![](/image/blunder/fuzz.png)

There are two .txt file in this page (robots.txt and todo.txt), I got the username (fergus) for the login page.

![](/image/blunder/todo.png) 

## Foothold :

This is my foothold for this machine! but i need the credentials for login to this page, i tried admin admin & simple SQL injection but it didn't work. So i think that i can make wordlists from the webpage (second photo). Use CEWL to make the wordlists.

![](/image/blunder/login.png)

After i create the wordlists and get the username for login page, lets bruteforce it! Check the *[Bludit Login exploit](https://www.exploit-db.com/exploits/48746)* and change the required parameters for this script. So this is the result of the process (fergus : RolandDeschain)

![](/image/blunder/brute.png)

So after i logged in on this page, there is "New Content" tab. So basically this is a file upload features, and i can use this features to upload reverse shell to this machine. *[Automated Script](https://github.com/cybervaca/CVE-2019-16113)*, don't forget so set listener on your machine.

![](/image/blunder/shell.png)

## User :

We got shell on this machine as www-data! I need more enum for privilege escalation to higher user. I got the .php file that contains hashed password, lets crack with *[CrackStation](https://crackstation.net/)*, Plaintext = Password120.

![](/image/blunder/usersPhp.png)

![](/image/blunder/crackStation.png)

I tried this password to change user to Hugo, and i'm in !

![](/image/blunder/hugoShell.png)


## User Flag :

![](/image/blunder/userFlag.png)

## Privilege Escalation :

For privilege escalation to root, i ran sudo -l and it returns "hugo can run this following commands on blunder : (ALL, !root) /bin/bash" and i searched how to exploit this, i found this *[exploit](https://www.exploitdb.com/exploits/47502)*. 

Basically this command  can run /bin/bash as any user, when the exploit is running sudo doesn't check the user id and executes the payload with arbitrary user id with sudo privileges.
*"-u#-1"* returns 0 = Root id.

![](/image/blunder/privEsc.png)

## Root Flag :

![](/image/blunder/rootFlag.png)

Fin.





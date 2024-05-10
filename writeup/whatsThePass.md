---
layout: post
title: "Cyber Yoddha CTF 2020- What's The Password - Forensic"
date: 2020-11-02
---
This is the chall description :

![](/image/cyberYoddha/wtp/wtp.PNG)

## CHALL :
Given this image with some hints "Magic Words" and "Sudo"

![](/image/cyberYoddha/wtp/sudo.jpg)

First check the file with file command : file [fileName], this is a JPEG file. 

![](/image/cyberYoddha/wtp/fileSudo.PNG)

The creator leave some hints **"There was something hidden"** that means there is a file that hidden on this image, to solve this i use steghide

steghide extract -sf sudo.jpg and fill the password with "sudo" thats the m4giC w0Rd ~

![](/image/cyberYoddha/wtp/steghideSudo.PNG)

**Flag** : CYCTF{U$3_sud0_t0_achi3v3_y0ur_dr3@m$!}

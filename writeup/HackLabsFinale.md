---
layout: post
title: "Hacklabs Finale Week - Writeup"
date: 2020-12-24
---

Hi there, this is the writeup for my final week. Join the Discord server (links on HackLabs Instagram account) **[Click Here](https://www.instagram.com/hacklabs.id/)**. Lets get started !
*note : I'm new in CTF :D

![small](/image/hacklabs.jpg)

## Incremental Crunchy Cracker - Forensics

Given a protected .zip file with some password hint (is digit) and the title is Incremental & Crunchy. Either you can make the wordlist with crunch or crack it straight away with JohnTheRipper.

So i convert the zip into hash with zip2john.

![large](/image/HacklabsFinale/increment1.png)

And crack the hash with Incremental mode with John,

![large](/image/HacklabsFinale/increment2.png)

I got the password of the zip : 9489484

![large](/image/HacklabsFinale/increment3.png)

Extract it with the password, and this is the flag : 

![med](/image/HacklabsFinale/increment4.png)


**Flag** : HACKLABS{anjay_gurih_beut_crackernya}


## Marcopolo Exodus - Misc

Given .xlsm file with macro inside it, to see the source code of the macro press (alt+f11).
When i click the first box it returns the first part of the flag : HACKLABS{, then i click the second box and the macro wants a password but i dont know the password yet.

![challDesc](/image/HacklabsFinale/marco1.png)

macro source code, password for the second box is : sumimasen_4669. If i input the correct password it will return a "ROTTED" string. Lets try to rotate it with ROT47. The result is : m4lware_m4cro_iz_ and this is the second part of the flag.

![med](/image/HacklabsFinale/marco2.png)

For the last part, macro will request an input from user. If input is true then sheet2 will available.

![med](/image/HacklabsFinale/marco3.png)

In the sheet2 i can't find the flag right away. So i just find the "}" because i think the last part of the flag is in sheet2 but it's hidden.

![challDesc](/image/HacklabsFinale/marco4.png)

Last part of the flag :

![med](/image/HacklabsFinale/marco5.png)

**Flag** : HACKLABS{m4lware_m4cro_iz_very_deadb33f}

## Man's Best Friend - OSINT

Given a video from Sherpa youtube channel. In this chall i need to find the exact location where the video is taken.

So i took a screenshot and reverse search the image with yandex or google reverse image. 

![challDesc](/image/HacklabsFinale/sherpa1.png)

There is a big red building and small white building. I need to find what the name of the building.

![](/image/HacklabsFinale/sherpa2.png)

The red building name is Fistral Outlook Hotel. Lets find where is it exactly. I look on google earth (Towan Headland) to see the satelite view and i got the Fistral Outlook Hotel and the white building.

![](/image/HacklabsFinale/sherpa3.png)

**Flag** : HACKLABS{Towan_Headland}

## 17.878.103.347.812.890.625 – Cryptography

Given a encrypted .png image with XOR algorithm. I've been stuck in this challenge, but i managed it with some googling how XOR algorithm works.So XOR works like this take an example we want to XOR A with B.

A XOR B = C, and B XOR C = A. So XOR is reversible, right?

I came with some ideas, what if i XOR the correct .png header with the encrypted header ? Based on my previous explanation XOR is reversible.

Encrypted header : 15 5F 43 17 80 60 D1 6B
Correct .png header : 89 50 4E 47 0D 0A 1A 0A
Result : 9C 0F 0D 50 8D 6A CB 61

![](/image/HacklabsFinale/xor1.png)

Then XOR the encrypted image with the previous result with cyberchef :3
It shows a correct .png file! lets see what's inside it.

![](/image/HacklabsFinale/xor2.png)

A Github logo? Im curious if HackLabs have a github account, lets see.

![small](/image/HacklabsFinale/xor3.png)

After i visited the Hacklabs's github account, there's a folder that contains this challenge flag but it's a fake flag. Github have some features to see what's been changed recently.

![](/image/HacklabsFinale/xor4.png)

**Flag** : HACKLABS{W3_H4v3_a_g1THuB_p4G3_t0_y0U_kN0w}


## Is it shredded? - Forensic

Given a "shredded" .jpg file. I tried to unshred the image with Photoshop. After reassembling the shredded image it returns a fake flag :<.

![challDesc](/image/HacklabsFinale/shredded.jpg)

![challDesc](/image/HacklabsFinale/solveShredded.png)

So i found a similar challenge "Warpspeed". If .jpg is resized it will be "shredded" and if its a .png file it will corrupt the file. *thanks to Felix (he told me after i solved this challenge)

Lets change the image size with hex editor.

![challDesc](/image/HacklabsFinale/shreddedSize.JPG)

After bruteforcing the image size, i found the flag on the bottom of the image !

![challDesc](/image/HacklabsFinale/shreddedFlag.jpg)

**Flag** : HACKLABS{hmm_kok_pecah_ya_gan}


## Covert Pipe - Forensic

Given .pcap file, I tried to inspect all the protocols that available in this file. ICMP protocol seems good to me, i can see ping request with some data. 
*I'm inspired by this [**Writeup**](https://scgajge12.blogspot.com/2019/02/for-ctf-beginners-network-2scapy.html)

![challDesc](/image/HacklabsFinale/pipe1.png)

Then i use the script to get the data from ICMP protocol and it returns a Base64 encoded strings, just decode that string with online tools or base64 -d in Linux terminal.

![large](/image/HacklabsFinale/pipe2.png)

**Flag** : HACKLABS{icmp_exfiltration_is_annoying}

## Truly Antagonist - Misc

Back again with another zip cracking challenge, given a hint that the first password of the first zip is phone number with XL operator (11 digits). Lets make the wordlist with crunch and crack the zip with John.

![](/image/HacklabsFinale/antag1.png)

![](/image/HacklabsFinale/antag2.png)

1st zip password : 08781337696

![](/image/HacklabsFinale/antag3.png)

Unzip the 1st zip and i got the 1st part of the flag with hints for cracking the 2nd part.

![](/image/HacklabsFinale/antag4.png)

Time to make the wordlist based on regex with exrex.py and repeat the previous steps.

![](/image/HacklabsFinale/antag5.png)

2nd zip password : 3n_s484h_n03R

![](/image/HacklabsFinale/antag6.png)

I got the 2nd part of the flag and the hints, repeat the steps again :c

![](/image/HacklabsFinale/antag7.png)

![](/image/HacklabsFinale/antag8.png)

last zip password : bl00d_&_bones

![](/image/HacklabsFinale/antag9.png)

last part of the flag 

![](/image/HacklabsFinale/antag10.png)

**Flag** : HACKLABS{th3_r3gx_pr0digy_let_s_praize_hail_hannibal_th3_p0ligl0sint}


That's all folks. Thank you for the amazing challs and Thank you for reading this writeup! See ya ~








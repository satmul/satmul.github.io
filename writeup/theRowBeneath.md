---
layout: post
title: "Cyber Yoddha CTF 2020- The Row Beneath - Forensic"
date: 2020-11-02
---
<div markdown=1 class="blurb" >

![](/image/cyberYoddha/trb.PNG)

So the challenge is image forensic, lets find the flag! 

## CHALL :
![](/image/cyberYoddha/plan.png)

As usual i always check what kind of file  is this with command : file [fileName], and it returns a JPEG file. 

![](/image/cyberYoddha/filePlan.png)

Lets run binwalk to make sure it is a JPEG, yep it's a JPEG file. 

![](/image/cyberYoddha/binwalkPlan.PNG)

I looked the title of the challenge : **The Row Beneath**, so the creator means there's flag on the bottom row of the flag.
So i just ran HXD to check the hex values, or you can run strings commands and the flag is there!

![](/image/cyberYoddha/flagPlan.png)

Fin!


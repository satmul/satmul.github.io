---
layout: post
title: "ICTF - November Chall Writeup"
date: 2020-12-13
---
Hi there CTF Lovers! Welcome back to my blog. This is my ICTF November Writeup Challs, this is the discord link to join (https://discord.gg/zjpvn2c). They will post one chall everyday and its valid for one month.
*note : i can't make the web challs because the server is not available, sorry :(
<br>
So lets begin with the chall! 
## not-so-difficult-rsa
![challDesc](/image/ICTF/11-20/RSA.JPG)

Given the cipher message = 418871322481172992333830847014255718220369100285625324577813
803226422566253833997303544405729373353110445741042373932191
8076207587152546291602684395254731
<br>
<br>
And we got the public key, so i think if i got the Alice and Bob RSA public key  we can make private key from it to decrypt the cipher message. By the way the hint is **"Alice send to Carol"** so we can use Alice public key to decrypt the message. I use RsaCTFTool to solve this. 

Alice public key 
<br>
n = 59092732279913540922799274551477981413603258445741
34029077480285650908196752702184649665808028347577569087
598335548616511503237225954122574741834625790443
<br>
e = 65537
<br>
Command : python3 RsaCtfTool.py -n [n value] -e [e value] --uncipher [cipher message]


![](/image/ICTF/11-20/RSA1.JPG)
![](/image/ICTF/11-20/RSA2.JPG)


## Password Protection 
![challDesc](/image/ICTF/11-20/passProtect.JPG)

So this is the zip cracking chall. Lets use John (zip2john) or fcrackzip, but in this chall i chose fcrackzip
<br>
![](/image/ICTF/11-20/passProtect1.JPG)

Command : fcrackzip -v -D -u -p [wordlist] [zipFile]
<br>
-v : verbose 
<br>
-D : Dictionary attack mode
<br>
-u : unzip -> reduce false password
<br>
-p : password file
<br>
![](/image/ICTF/11-20/passProtect2.JPG)

The password is **secure** and lets we get the flag on flag.txt !

**flag** : ictf{wh@7_@r3_y0u_d01ng_h3r3?}

## same-pictures

![challDesc](/image/ICTF/11-20/same-pictures.JPG)

Given 2 images and i need to find the differences. At the first time i use **diff** to compare the images to see if there is any differences but i got stuck in this chall because i can't get the flag :(. Thanks to my bestfriend, Anthony that gave me a hint about linux command **cmp** . 

![](/image/ICTF/11-20/same-pic1.JPG)

Yes! the image is different. The parameters that i use is -b for print the differing bytes 
<br>and -l/--verbose to output the byte numbers.

![](/image/ICTF/11-20/same-pic2.JPG)

**flag** : ictf{messing_around}

## RestInPeace-john

![challDesc](/image/ICTF/11-20/rip-john.JPG)

Another zip cracking chall but it's different than before. Lets use fcrackzip again !

![](/image/ICTF/11-20/rip-john1.JPG)

The password is = johncena and i get .mp3 file with Pacman soundtrack

![small](/image/ICTF/11-20/rip-john2.JPG)

I tried to see the metadata with **exiftool** but the flag is not there. Then i thought what if the flag is in the spectogram but i got nothing. After that, i tried the **strings** command and hopin' that i will get the flag. After all this time, the flag is under my nose :c

![](/image/ICTF/11-20/rip-john3.JPG)

**flag** : ictf{u_used_johntheripper_and_strings}

## Build-a-Cipher 1

![challDesc](/image/ICTF/11-20/cipher1.JPG)

Given cipher message that i need to decrypt with dictionary cipher / substitutional cipher. This is the char map for decrypt/encrypt.

![small](/image/ICTF/11-20/cipher2.JPG)

Lets use **[dcode.fr](https://www.dcode.fr/word-substitution)** to decrypt the message and add the char map, so basically the cipher works like this if ciphered message is "p" so it will be decrypted as "a" and so on (based on the char map).

![](/image/ICTF/11-20/cipher3.JPG)

**flag** : ictf{dictionary_cipher_are_ezzz}

## Walking-with-bin

![challDesc](/image/ICTF/11-20/bin1.JPG)

Given an image that i need to do some "forensic" thing, from the title i know that i need to use binwalk to check some hidden files in the picture.

![](/image/ICTF/11-20/bin2.JPG)

Yep, there is a .pdf file. Let's extract that file with foremost 

![](/image/ICTF/11-20/bin3.JPG)

Open the .pdf file, but it's a blank pdf! (try ctrl+a and i got the flag :3)

![med](/image/ICTF/11-20/bin4.JPG)

**flag** : ictf{th1s_1s_j0hn_c3n@}

## Build-a-cipher 2

![challDesc](/image/ICTF/11-20/buildCipher1.JPG)

Given .py file that i need to reverse to decrypt the message.

![](/image/ICTF/11-20/buildCipher2.JPG)

Soooo basically this file will encrypt our message with "random" numbers from randint function from (1-100) and add the "random" number to the char. To reverse this i just need to change the **"n+=random"** to **"n-=random"** because the "random" variable is constantly set to "5" and run the .py file again.

![](/image/ICTF/11-20/buildCipher3.JPG)

**flag** : ictf{5huff13d_charac7h3r5}

## Lo-Siento-Bella

![challDesc](/image/ICTF/11-20/lsb.JPG)

Given a png file that i must extract the Least Significant Bit (given hints on the title -> LSB). LSB is a steganography technique to hide some message in image file but the image remain the same. Lets extract the lsb with zsteg.

![](/image/ICTF/11-20/lsb1.JPG)

**flag** : ictf{h1d1ng_1n_1ns1gn1f1canc3}


## modern-images

![challDesc](/image/ICTF/11-20/mod-img.JPG)

Another forensic challenge, so the .png file is broken. Lets check the chunk to fix the image! 
*friendly reminder : .png chunk must contain (PNG signature, IHDR, IDAT, and IEND)

![](/image/ICTF/11-20/mod-img1.JPG)

Lets compare the this image with healthy .png file, and just replace the .png signature.

![](/image/ICTF/11-20/mod-img2.JPG)

And i got this image, it looks like QR-Code (?) but i can't scan it :(. Use google to see QR-Code types. Then i visited **[Wikipedia](https://en.wikipedia.org/wiki/QR_code)** about QR-Code, and the QR-Code is generated with JAB code, use **[JABCode](https://jabcode.org/scan)** to scan the QR-code.

![small](/image/ICTF/11-20/mod-img3.JPG)

![small](/image/ICTF/11-20/mod-img4.JPG)

**flag** : ictf{m0d3rn_b@rc0d3$_@re_c00l}

## Duality 

![challDesc](/image/ICTF/11-20/duality.JPG)

Given a .pdf file, is it a real .pdf file or sumthin? lets check it first with binwalk.

![](/image/ICTF/11-20/duality1.JPG)

Whoops, this is a ELF file! lets remove the .pdf extension and run it!

![](/image/ICTF/11-20/duality2.JPG)

The program ask some password to get the flag, but i dont know the password yet :( . Time to see the **strings** from the ELF file to check if the password is hardcoded.

![](/image/ICTF/11-20/duality3.JPG)

There is a "Superman" string, i think this is the password. Run the ELF again and input password as "Superman"

![](/image/ICTF/11-20/duality4.JPG)

**flag** : ictf{c0nv0lut3d_w@ys_to_h1d3_data}

## PDF Editors

![](/image/ICTF/11-20/pdf.JPG)

Last one is forensic chall! The flag is burried, i need to dig it!

![](/image/ICTF/11-20/pdf1.JPG)

The tools that i used to solve this chall is Foxit Reader, just move the AAA strings and i got the flag !

![](/image/ICTF/11-20/pdf2.JPG)

**flag** : ictf{k@m1_1s_a_g00d_pdf_3dd170r}

Thank you for visiting ! See you in another writeup !!!

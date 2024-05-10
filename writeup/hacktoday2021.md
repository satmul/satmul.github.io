---
layout: post
title: "HackToday 2021"
date: 2021-08-26
---

Hi, This is HackToday 2021 Writeup. I didn't post all solved challenge by my team, I only post the challenges that I complete. So lets goo

# Web Exploitation
## Destiny
Given a website that receives an input as plaintext for DNS (Domain Name System). The workflow of this website is Receiving User Input, Checking to DNS server, Return IP Address.


![](/image/HackToday2021/destiny1.JPG)

Based on my reconnaissance, This website is vulnerable to Command Injection. But there is a blacklist for some symbols such as (space, ', ", ;) *as far as I tested.

So the attack method of this challenge is:
1. Bypass the Command Injection Blacklist
2. List all of the files on the server
3. Get the flag

The first testing that I used is **a|whoami** and it returns **root**. 
Move on to the next step, list all the files with **ls -la** but space is blacklisted.. Thankyou to [Bypass Bash Restrictions - HackTrick](https://book.hacktricks.xyz/linux-unix/useful-linux-commands/bypass-bash-restrictions) that gives me **${IFS}** to bypass space. 

Because of that, I can list the file with **ls${IFS}-la**. There is another problem, this website only returns one line of the executed command. 


To bypass that, I used **Head** and **Tail** command to list file per line. 
The payload is **a|ls|head${IFS}-n${IFS}1${IFS}|${IFS}tail${IFS}-n${IFS}1**, so the idea of this payload is List all the file with Head to returns the desired line (from line 1 until), and Tail to cut the unwanted line. This is the demonstration to make it more easier.

![](/image/HackToday2021/destiny2.JPG)

So, I changed the **head -n [line index]** to enumerate the files. 
Then I found the flag with this name **problem_setter_choose_this_name_instead_of_flag_dot_txt**. Just open the flag with **a|cat${IFS}problem_setter_choose_this_name_instead_of_flag_dot_txt**.

Flag : hacktoday{escape_shell_command_with_a_little_shell_knowledge}

# Forensic
## Where
Given a PCAP network capture. So lets analyze that, first thing that i've done is to see the Export HTTP Object. There is a .png file that seems suspicious to me.

![](/image/HackToday2021/where1.JPG)

![](/image/HackToday2021/where2.JPG)

The image said its on **alternate**, after stuck for a long time the author said that **"how to hide data, especially in Windows"**. 

After some research, I know how to hide data in Windows with **"Alternate Data Stream"**. If you want to know how ADS works, visit this [link](https://id.wikipedia.org/wiki/Alternate_data_stream).

The I used Alternate Stream Views to see the alternate data of the .png file. It shows the alternate streams of the .png file.

![](/image/HackToday2021/where3.JPG)

The flag is on **aaaa.png_not_flag.txt** 

flag : hacktoday{semoga_dapet_drop_card_ROX_aamiin} 


## Hide n Seek
Given a PDF file that only consist of plain text "Our game of hide and seek has just begun". But this is a forensic chall right? There must be something.

Inspect the PDF file with pdf-parser to see information of the PDF.

![](/image/HackToday2021/hideme1.JPG)

There is an embedded file, just extract it with pdf-parser again. **./pdf-parser -o 8 hideme.pdf**

![](/image/HackToday2021/hideme2.JPG)

![](/image/HackToday2021/hideme3.JPG)

Based on the dump file, the format of the dump file is Hexadecimal. Just decode it with Cyberchef or sumthin else. It's another .PDF file! but theres a problem, when I tried to open that file it was protected with password. Then I bruteforce the password with pdfcrack and rockyou.txt

![](/image/HackToday2021/hideme4.JPG)

![](/image/HackToday2021/hideme5.JPG)

The password of the .pdf file is **HIDEandSEEK27**. 

Just select all of the pdf file and you shall get the flag :D
![](/image/HackToday2021/hideme6.JPG)

Flag : hacktoday{embedded_files_in_pdf's_with_passwword}


Credit : SenyumSemangat(Chevaliers, SynTh, BlackBear)

Fin.




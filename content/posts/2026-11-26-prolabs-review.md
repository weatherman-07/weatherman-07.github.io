+++
title = "what got me into pentesting"
date = 2026-11-26
summary = ""
tags = ["pentest"]
+++

<img src="/assets/media/prolabs-review/boink.gif" alt="" style="max-width:100%;margin:1.5em 0;display:block">

My Cybersecurity journey started with me joining a college CTF team called [Cryptonite](https://ctftime.org/team/62713). I started off a rev and crypto guy in my first year, I stuck to rev for long but gave up midway on crypto when the real math started coming in. It was just a decision to choose between rev or crypto and I went with rev. But along with this I've also been trying out other domains so I was developing surface level knowledge on webex as well.

Then comes 2025.

My senior, the Attack Defence Head of the team decides to groom me for a OT/ICS based national pentesting competition. I won't go into how the competition went but ig long story short we finished 1st in it. Pre-comp I was training intensely, I went into Go and Rust rev, was revising my Windows fundamentals and went into more of android. Parallelly I had to take webex seriously now and since it was a pentesting competition, I had to pick that up too.

So I started off with doing some easy-medium HTB machines and got the gist of what this whole scene might be about, but then the competition wasn't going to be a single machine judging by it's previous edition. My team had to train on networked labs and pivoting. Here comes HTB Pro Labs.

You can look up what they are. We started off with P.O.O., Dante and then Alchemy. Sweet treat it was ngl. But I didn't absorb everything very well, not to the best of my expectations. Though my workflows and methodologies devised were perfect for what I was in my opinion, coz for when the pentesting competition started, one of my ideas just rooted the hosting within 10 mins. Yeah that was funny.

So post competition I started doing webex seriously, rev and other domains that I tried didn't give the thrill of "exploiting" anything. Seeking that thrill I got a VIP sub and started doing machines again, and I was on a roll. Post that I took a break and just focused on webex and teaching my juniors stuff.

Then comes 2026.

I was expecting the same competition that I prepped so hard for would come back again and I wanted my juniors to participate as well. It didn't happen eventually but in hopes of "it might happen" I had to improve myself in the first place to teach anyone. That was the initial intention, but that eventually changed drastically.

I started with Dante and Alchemy, and doing it alone gave a real thrill and feel-good moments. I was feeling ecstatic whenever my gut feeling on what the exploit might be went right. Maybe I'll make a blog about it sometime on my mindset when I do pentest if it helps anyone. So naturally, I was getting the better of myself and I swayed away from the intention to learn and teach to just learn. For 3 months I was glued to my chair day and nite to exploit it all. I had to learn binex for some stuff but my fundamentals were pretty strong for it by end of 2025 so that helped a lot.

The whole idea of exploiting things motivated me to further do work on binex which my knowledge progress might be indicated from my writeups for LACTF.

I'm sorry if I did a bad job explaining how I got into it, I'll prolly improve this blog once I collect all my thoughts together.

I've dropped my reviews on all the Pro Labs below so that you get an idea which lab offers what and which one might be your calling. Difficulty order I'd rank them: Dante, Alchemy, Zephyr, RastaLabs, Offshore, Wutai, Ifrit, Wanderer, Shinra, Cybernetics, APTLabs.

---

## Dante

<img src="/assets/media/prolabs-review/cert-dante.jpg" alt="Dante Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Dante is an entry level beginner friendly Pro Lab with 14 machines and 27 flags to capture. It took me 5 days to finish. Don't expect anything realistic, the lab is meant for you to get a gist of figuring out your workflows and approach. Something worth building upon while doing this lab is taking notes on your approach/sequence of things you do. By workflows I mean figuring out ways to improve upon getting the work done efficiently. You can save a lot of time by running things in parallel but that only comes through practice. So I'd suggest making all the mistakes you could when attempting it for the first time, and once you finish the lab, redo it by fixing all your mistakes.

I wasn't making notes in particular but I was maintaining a Discord thread logging my thoughts as I went, which I did for all the other Pro Labs too.

Don't expect any realistic scenarios, there's no hardening and the VMs are pretty old so evasion definitely isn't the focus. Since it's spread across multiple subnets, pivoting is the thing you'll learn. You could use chisel but ligolo is just way easier to work with. Max you'll go is a double pivot, but multi-pivot management is something you'll build muscle memory for. Most of the machines are Linux and it kind of boils down to finding the right CVE. Post exploitation is worth taking seriously even here, you still need to make sense of whatever data is present since it may help with credential reuse or similar cases down the chain.

One thing I hate: people just enable SeImpersonatePrivilege on the Windows machines, which kills the actual intended exploit primitive to root the box.

---

## Alchemy

<img src="/assets/media/prolabs-review/cert-alchemy.jpg" alt="Alchemy Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Alchemy is easy-medium difficulty Pro Lab focusing on Operational Technology (OT) and Industrial Control Systems (ICS) environments. It's set in a fictional brewing company called Sogard Brewing Co. The theme is pretty dope I'd say, it's built around an operational brewery plant. At the end of the day even if you learn nothing new from this lab, you'd at least learn how to pump some good ice cold beer!

In terms of realism, I'd say it does a good job, matter of fact the story tops the list followed by Offshore. The network is segregated into two sections, an IT and an OT section. IT section is again somewhere around the same level as Dante, nothing too crazy except for the fact that it includes some popular ICS software to exploit. This is a good step up compared to Dante in the sense that you'll have to do a better job at making sense of the information retrieved post exploitation. This will help in better traversing the OT section.

The highlight of the Lab, the OT section will introduce you to some custom PLCs each communicating over Modbus taking care of a certain section of the brewing process. Sufficient documentation will be available to retrieve and understand the PLC logic from the ST files. The exploits you devise will cover a good spectrum of OT exploits and you'll be able to tune your scripts based on the live info displayed by the Human Machine Interface for a particular PLC.

I would say attempt the OT section unprepared, preparation might cloud your expectation or create tunnel vision when you actually sit and think of an exploit. The whole memory map, r/w registers & coils can be learnt on the go. This kinda helped me come across that Modbus has no authentication by itself, vendors mimic security by reserving registers for passwords and blocking reads/writes until correct values are written at certain regions. The difficult part though is scripting. You'll have to depend on pymodbus throughout for coil enumeration and the final exploit. The fun part though is sometimes it'll either be an actual logic bug that you'll notice in the ST file or it might be a web exploit to get the flag. Anyways, still the tip remains **make sense of the information present**.

**PS: I solved this way back at the start of the year and recently came to know that this Pro Lab has been removed. It might turn up in the enterprise section sometime later but nonetheless it's sad to know that it's not included anymore in the Pro Lab sub.**

---

## Zephyr

<img src="/assets/media/prolabs-review/cert-zephyr.jpg" alt="Zephyr Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Zephyr is pure Active Directory. It's recommended to do this lab if you're planning on taking CPTS. If you're comfortable with the AD in this, CPTS AD will be a cakewalk. From here onwards things are less CVE-based exploits, even in Zephyr you'll have to understand the hosted application to achieve RCE. Ultimate lesson from this Lab would be to start learning to work with a C2 but you'll never appreciate a C2 for what it is unless you've managed/struggled to do everything manually.

So the environment spans multiple domains with cross-forest trust relationships between them unlike the previous two. You'll also be introduced to delegation abuse and ADCS (hurray!), ACL abuse, relay attacks and coercion. It was frustrating for me when I reached the cross-forest attacks part coz it was completely new to me and I couldn't wrap my head around it for a while. You can get through the cross-forest part without fully understanding why a certain trust works the way it does, the lab won't stop you. But that feels like leaving money on the table. But yeah one stepping stone this lab provides is about learning how Windows does access control. Overall this is a management nightmare so you'll definitely figure out some new workflow lessons. You'll also familiarize yourself with impacket, cme, nxc, rubeus, powerview and the goat bloodyAD.

Almost forgot, there is a firewall so gl managing to finish the lab and managing pivots and revshells with only 2 ports (I would suggest taking your time and just pondering on how to counter this wall of bypassing the firewall. It'll bring out lots of ideas out of you, maybe even novel ones). The foothold is again "social engineering" so if you're ever stuck there just hit the HTB discord community and ask for help.

Also yeah a tip, **spray creds**.

PS: I went back and solved this recently once more and seems the VMs have been updated so you'll have to figure out a way to bypass AMSI.

---

## RastaLabs

<img src="/assets/media/prolabs-review/cert-rastalabs.jpg" alt="RastaLabs Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

RastaLabs made by the goat [rastamouse](https://rastamouse.me/) 9 years ago. Bro disappeared from the HTB community to work on Crystal Palace. This is the first lab that has some proper defense running like Defender and AppLocker so FAFO isn't going to work out like before. You'll have to figure out your payload before dropping it. Since this is where you start working on evasion, it's better to spin up a VM and test your loaders or BOFs before dropping. Again C2 would help greatly but I never learn my lesson and continued doing things manually.

Anyways so this time OSINT is actually important, you're not just a pentester anymore you're moving to red team. There is a difference between both. Information gathering on the social side of things will help a lot. Ig this is one of those labs that is pivoting towards more of a Threat Actor/APT-based approach. It may have helped in giving some direction to APTLabs.

Why OSINT, coz this time you'll have to do **Phishing** and it has to work on a well known Mail Server. Apart from this on the AD side you'll definitely progress from Zephyr and learn some new stuff like LAPS and GPO abuse. Again the firewall sticks, and it's gonna be the case for the next Pro Labs. Also it'd be great if you already know a bit of Binary Exploitation or you'll have to learn that from scratch.

Hmm honestly I have no advice on this one. The lab is pretty old so it's bound to break a lot. Just be kind and patient towards it.

---

## Offshore

<img src="/assets/media/prolabs-review/cert-offshore.jpg" alt="Offshore Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Offshore is HUGE. 21 machines 38 flags straight up cancer. The story setup is solid though, second only to Alchemy in terms of immersion and impression (the certificate is pink!). You're a so-called pentester hired by a financial company mandated to do quarterly tests per regulatory compliance, and the company has done several acquisitions that are connected via domain trusts. That context actually makes sense of the environment you're walking into.

Five domains to compromise that means 5 DCs. huge as hell for a lab. Before you get to the AD part your web exploitation skills are gonna get tested good. There's a nice change of pace where you'll have to exploit real software for which you'll have to understand the software itself very well. Once you're inside CORP, it's the most ACL-heavy lab so far. I won't explain the AD section in this much since by now it should be on you to figure out how to form the exploit chain since your foundation after the previous labs should be solid.

Use this lab as an opportunity to work with a large BloodHound layout. You'll be pulling the zip a lot very often so make sure to maybe try learning and writing cypher queries by yourself, I didn't but I realized that could've helped saving a lot of time. Take breaks on this one the layout is pretty big and you might need to get on pen & paper to memorize the things.

The lab is old and large and shared with other players, so things break. Expect some friction.

---

## Wutai

<img src="/assets/media/prolabs-review/cert-wutai.jpg" alt="Wutai Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Wutai is where, setting-wise things get realistic, very realistic. Wutai, Shinra and Ifrit were previously part of [xct](https://vuln.dev/)'s Vulnlabs which got ported to HTB's ecosystem ever since xct joined their content team. Vulnlabs used to be the OG Pro Labs since they actually focused on evasion a lot. You'd be given a Wazuh read-only account to watch your detections fire in real time and tune your approach accordingly. That feedback loop is something you won't find in most labs and it changes how you think about what you're running (again reminder to test your payloads by recreating the environment in a VM). You should think beyond and go a step further to reverse Wazuh rules and create bypasses.

Two domains, wutai.vl and work.junon.vl (a parent company and its subsidiary Junon). WSUS also makes an appearance, so Windows Update infrastructure as an attack vector is something you'll get exposure to. The reverse engineering element listed in the description isn't huge but it's there. Overall on the AD side I felt it was fairly easy mind you I finished Shinra before going to Wutai and Shinra had relatively harder AD so Wutai was a cakewalk, it took me 2 days to finish.

I'm putting this one here because you should test your speed on this one. There isn't much going on in exploitation terms apart from WSUS and one more thing but the evasion and payload dev aspect alone places this above the previous labs. Again I encourage to get creative, I did try out a way to drop a png which has shellcode embedded in it with some obfuscation for my loader to execute.

---

## Ifrit

<img src="/assets/media/prolabs-review/cert-ifrit.jpg" alt="Ifrit Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Ifrit is the second Vulnlab port alongside Wutai and Shinra. Same deal with the SIEM, you get a read-only Kibana dashboard this time to watch detections. The key difference from Wutai is that this one is an assumed breach scenario, you're handed a list of VDI users with their passwords already, so there's no initial foothold phase. You just log in and go.

AppLocker is on from the start and it's tighter than what you've seen before. The default policy restricts execution to C:\Windows, so you'll need to figure out your AppLocker bypass before anything else moves. Three domains: ifrit.vl as the root, with eu-ifrit.vl and it-ifrit.vl as children. ADCS shows up with ESC so you'll get hands-on with certificate-based attacks more than any previous lab. I gave up a lot on this one coz the foothold itself was very hard.

Ultimately though with this one I was able to figure out my loader game that still works on the latest Windows 11.

---

## Wanderer

<img src="/assets/media/prolabs-review/cert-wanderer.jpg" alt="Wanderer Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Finally, ippsec made his own Pro Lab. Wanderer is in a league of its own since it brings completely new things. Setting wise it's post apocalyptic, full Fallout universe, and the theme runs deep. The character names, the machine names, all Fallout lore.

What immediately stands out is there's no traditional AD foothold. Two public-facing Linux entry points, and the DC is basically the final destination. The lab is about variety more than depth.

The entry points cover web API exploitation and mobile app analysis. The mobile side requires Android emulation and dealing with certificate pinning before you can even see the traffic, so if you haven't done that before, here's your first time. The VoIP angle is the most unique thing in any Pro Lab I've done. voip01 runs Asterisk PBX and the two ways you interact with it are both things you won't find anywhere else. I'll leave it at that.

There's a WiFi network in the lab too, and the credential for it is something you'll have already collected by the time you need it.

The internal machines will put you through GitLab CI/CD abuse and a few creative privilege escalation paths. The AD part is almost a footnote. Some cloud-flavored pivoting gets you what you need to close it out.

The rest of the portion of the lab except for the new things that you'll come across seem a bit forced. It seems like ippsec wanted to introduce a few new things but that made up 40% of the lab and he just buffered the rest 60% with whatever he could find to make it a "Pro Lab".

---

## Shinra

<img src="/assets/media/prolabs-review/cert-shinra.jpg" alt="Shinra Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Shinra was the most recent addition to Pro Labs and it came along with Wutai. Absolute game changer. I wanted to blood it so bad ever since it came out but was long stuck on the last flag for a good while, somehow managed to be the 4th person to finish it. Also the SIEM sticks, read-only account to watch detections. This time Idk what EDR it was across all endpoints but it was doing a very good job. So evasion and covert operations is the entire point here.

This was the first lab where I started using a C2, Sliver made sense to me and along with the Armory it did the job. Though Sliver droppers were getting caught, I had to take a step back and make some new loaders. There was no way I could reverse to see where the EDR was catching my payloads so I just targeted to make my loaders work on the latest Defender. My implants were still Sliver-generated. Honestly I should've started using C2's before this lab but better now than never coz there's no way you can do Cybernetics and APTLabs without one.

Three AD forests to compromise. Again phishing is there. The lab covers a lot of ground like CI/CD infrastructure attacks and binary exploitation. Though the backdooring applications part is hella cool like it'll blow your mind. The whole setup is so so close to realistic. I won't talk much about the AD part, don't want to ruin the fun. I have a tip though, go through [this blog](https://www.vaadata.com/blog/ad-cs-security-understanding-and-exploiting-esc-techniques/) carefully.

---

## Cybernetics

<img src="/assets/media/prolabs-review/cert-cybernetics.jpg" alt="Cybernetics Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

Cybernetics is RTO level II and the biggest by a lot. Five domains, 25 flags, 28+ machines. The fictional company's gone through several pentest rounds and hardened after each one, so fully patched OS and EDR across all hosts. Zero CVE-based exploits. If you haven't worked with a C2 till now you're gonna feel the need on this one. Shinra should've pushed you there but Cybernetics will make sure. It was fun and funny as well coz I started doing this lab in between an offline bootcamp that started teaching C2.

Phishing is back and honestly the hardest part of this lab for most. Once you're past it the AD side flows much better, the cross-forest work is familiar territory by now. What makes Cybernetics stand out is the DevOps depth. It exposes you to the widest range of DevOps tooling and shows you how they interconnect as an attack surface. Not necessarily the most realistic simulation but the best survey of that stack. Same advice from Offshore applies here, work with large layouts in BloodHound. There's also an RDS published app breakout. Kiosk environments, restricted app contexts, escaping them. First time you'll see it in a Pro Lab.

The last domain is Inception themed. Flag names, machine names, all of it. It's a fun last leg. But I'll warn that this is gonna take a lot of time, so I'd again suggest to hit the HTB Discord community and ask for a nudge.

**PS: Same as Alchemy, Cybernetics has been removed from the Pro Lab sub. Hopefully it turns up in the enterprise section at some point.**

---

## APTLabs

<img src="/assets/media/prolabs-review/cert-aptlabs.jpg" alt="APTLabs Pro Lab Certificate of Completion" style="max-width:65%;border-radius:6px;margin:1.5em auto;border:none;display:block">

APTLabs is the final one. Level III, 5 AD forests, 20 flags, 18 machines. You'll feel like killing yourself but it's rewarding. No other professional expensive ahh cert comes close to this, OSEP doesn't even come close. The name gives it away, it puts you in the mindset of a state sponsored threat actor. You'll have to think like an APT group operating against a managed service provider and working through all of its clients. That framing is intentional and runs throughout the whole lab.

Fully patched, zero CVE-based exploits, same deal as Cybernetics and Shinra but pushed further. AMSI, JEA and WDAC are all layered and active simultaneously.

The phishing section here is an entire chain in itself but it'll somewhere along the line teach you the actual perception of a victim clicking on something. It's not "send a document and wait" like the previous labs. 2FA is in the picture and you'll be building things from the perimeter before the phish even fires. Most involved phishing across all 11 labs.

Here's the fun part and it's the actual tone setter, the user accounts are not in English. The naming conventions, the usernames, the way everything is structured looks foreign. It's friction that makes complete sense given the scenario, you're attacking another country's infrastructure, so of course it doesn't look like every previous lab right. Language would've constricted your approach in any and all labs but this will ig teach you to be open to all things that come at you.

Identity federation is a core part of the attack chain, more so than any lab before this. What you can do with a compromised federation server across trusted domains goes much further than you'd expect. SCCM also shows up as a lateral movement path and it's not incidental, it's one of the main routes into a client network.

JEA is in here too. If you haven't come across it before, watch [this DEF CON 25 talk](https://www.youtube.com/watch?v=6vOiHKDRhbM) by Lee Holmes before you hit that wall.

This is gonna take the longest of any lab. Only tip would be to go beyond default wordlists for cracking. Whoever made this was definitely smoking the good stuff or has been in the APT scenes for some time. Nonetheless if you're looking for some spice, this is the one.

**PS: One of the only labs that could help develop an APT mindset, but sadly it's been removed from the Pro Lab sub as well.**

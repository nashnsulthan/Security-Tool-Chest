# Introduction 
Anticipating and mitigating security threats is critical during software development. This paper is going to detail and investigate security vulnerabilities and mitigation strategies to help software developers build secure applications and prevent operating system leaks. This paper examines common vulnerabilities, and provides relevant mitigation strategies, from several relevant perspectives. This paper hopes to encompesses the cyber Kill chain as part of the five stage compramision stages, displaying releavent tools, books and stratagies at each stage. 
# Staging for Red Teams

![Image description](https://airbus-cyber-security.com/wp-content/uploads/2017/06/killchain3_m.jpg)
#  Red Team Tools 
## Reconossaiace
- [EyeWitness](https://github.com/ChrisTruncer/EyeWitness) - Is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible. 
- [AQUATONE](https://github.com/michenriksen/aquatone) - Is a set of tools for performing reconnaissance on domain names. 
- [Nmap](https://github.com/nmap/nmap) - Is used to discover hosts and services on a computer network, thus building a "map" of the network. 
- [dnsrecon](https://github.com/darkoperator/dnsrecon) - A tool DNS Enumeration Script.
- [theHarvester](https://github.com/laramies/) - Is a tool for gathering subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public sources. 
- [Metagoofil](https://github.com/laramies/metagoofil) - Is a tool for extracting metadata of public documents (pdf,doc,xls,ppt,etc) availables in the target websites. 
- [SimplyEmail](https://github.com/killswitch-GUI/SimplyEmail) - Email recon made fast and easy, with a framework to build on. 
- [pwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) - Is a python script which checks if the email account has been compromised in a data breach, if the email account is compromised it proceeds to find passwords for the compromised account.
- [GitHarvester](https://github.com/metac0rtex/GitHarvester)- This tool is used for harvesting information from GitHub like Google dork.
- [Maltego](https://www.paterva.com/web7/downloads.php) - Is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. 
- [SpiderFoot]( https://github.com/smicallef/spiderfoot) - The open source footprinting and intelligence-gathering tool.
- [Datasploit](https://github.com/DataSploit/datasploit) - Is an OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats.

## Weaponisation 
- [Exploit toolkit CVE-2017-8759](https://github.com/bhdresh/CVE-2017-8759) is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft .NET Framework RCE. 
- [CVE-2017-11882](https://github.com/unamer/CVE-2017-11882) Exploit accepts over 17k bytes long command/code in maximum. 
- [Adobe Flash](https://github.com/anbai-inc/CVE-2018-4878) Exploit CVE-2018-4878.
- [Exploit toolkit CVE-2017-0199](https://github.com/bhdresh/CVE-2017-0199) is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. 
- [Demiguise](https://github.com/nccgroup/demiguise) is a HTA encryption tool for RedTeams. 
- [Office-DDE-Payloads](https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads) collection of scripts and templates to generate Office documents embedded with the DDE, macro-less command execution technique. 
- [CACTUSTORCH](https://github.com/mdsecactivebreach/CACTUSTORCH) Payload Generation for Adversary Simulations. 
- [SharpShooter](https://github.com/mdsecactivebreach/SharpShooter) is a payload creation framework for the retrieval and execution of arbitrary CSharp source code.
- [Don't kill my cat](https://github.com/Mr-Un1k0d3r/DKMC) is a tool that generates obfuscated shellcode that is stored inside of polyglot images. The image is 100% valid and also 100% valid shellcode. 
- [Malicious Macro Generator Utility](https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator) Simple utility design to generate obfuscated macro that also include a AV / Sandboxes escape mechanism. 
- [SCT Obfuscator](https://github.com/Mr-Un1k0d3r/SCT-obfuscator) Cobalt Strike SCT payload obfuscator. 
- [Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation) PowerShell Obfuscator.

## Delivery
- [King Phisher](https://github.com/securestate/king-phisher) - Is a tool for testing and promoting user awareness by simulating real world phishing attacks. 
- [FiercePhish](https://github.com/Raikia/FiercePhish) - Is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more. 
- [ReelPhish](https://github.com/fireeye/ReelPhish/) - Is a Real-Time Two-Factor Phishing Tool. 
- [Gophish]( https://github.com/gophish/gophish) - Is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
- [CredSniper]( https://github.com/ustayready/CredSniper) - Is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.
- [PwnAuth](https://github.com/fireeye/PwnAuth) - A web application framework for launching and managing OAuth abuse campaigns.

## Command and Control
- [Cobalt Strike](https://cobaltstrike.com/) is software for Adversary Simulations and Red Team Operations. 
- [Empire](https://github.com/EmpireProject/Empire) is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. 
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. 
- [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) A post-exploitation agent powered by Python, IronPython, C#/.NET. 
- [Pupy](https://github.com/n1nj4sec/pupy) is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python. 
- [Koadic](https://github.com/zerosum0x0/koadic) or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. 
- [PoshC2](https://github.com/nettitude/PoshC2_Python) is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. 
- [Gcat](https://github.com/byt3bl33d3r/gcat) a stealthy Python based backdoor that uses Gmail as a command and control server. 
- [TrevorC2](https://github.com/trustedsec/trevorc2) is a legitimate website (browsable) that tunnels client/server communications for covert command execution. 
- [Merlin](https://github.com/Ne0nd0g/merlin) is a cross-platform post-exploitation HTTP/2 Command & Control server and agent written in golang. 

## Lateral Movement 
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) is a swiss army knife for pentesting networks. 
- [GoFetch](https://github.com/GoFetchAD/GoFetch) is a tool to automatically exercise an attack plan generated by the BloodHound application. 
- [ANGRYPUPPY](https://github.com/vysec/ANGRYPUPPY) a bloodhound attack path automation in CobaltStrike. 
- [DeathStar](https://github.com/byt3bl33d3r/DeathStar) is a Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory environments using a variety of techinques.
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) C# Rewrite of the BloodHound Ingestor. 
- [BloodHound.py](https://github.com/fox-it/BloodHound.py) is a Python based ingestor for BloodHound, based on Impacket. 

## Privllege Esculation 
- [UACMe](https://github.com/hfiref0x/UACME) is an open source assessment tool that contains many methods for bypassing Windows User Account Control on multiple versions of the operating system. 
- [windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits) a collection windows kernel exploit. 
- [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1) aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations. 
- [The Elevate Kit](https://github.com/rsmudge/ElevateKit) demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload. 
- [Sherlock](https://github.com/rasta-mouse/Sherlock) a powerShell script to quickly find missing software patches for local privilege escalation vulnerabilities. 
- [Tokenvator](https://github.com/0xbadjuju/Tokenvator) a tool to elevate privilege with Windows Tokens.

## Remote Access Tools
- [Cobalt Strike](https://cobaltstrike.com/) is software for Adversary Simulations and Red Team Operations.
- [Empire](https://github.com/EmpireProject/Empire) is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. 
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. 
- [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) A post-exploitation agent powered by Python, IronPython, C#/.NET. 
- [Pupy](https://github.com/n1nj4sec/pupy) is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python. 
- [Koadic](https://github.com/zerosum0x0/koadic) or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. 
- [PoshC2](https://github.com/nettitude/PoshC2_Python) is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. 
- [Gcat](https://github.com/byt3bl33d3r/gcat) a stealthy Python based backdoor that uses Gmail as a command and control server. 
- [TrevorC2](https://github.com/trustedsec/trevorc2) is a legitimate website (browsable) that tunnels client/server communications for covert command execution. 

## Wireless Networks
- [Wifiphisher](https://github.com/wifiphisher/wifiphisher) is a security tool that performs Wi-Fi automatic association attacks to force wireless clients to unknowingly connect to an attacker-controlled Access Point. 
- [mana](https://github.com/sensepost/mana) toolkit for wifi rogue AP attacks and MitM. 
## Software For Team Communication
- [RocketChat](https://rocket.chat) is free, unlimited and open source. Replace email & Slack with the ultimate team chat software solution. 
- [Etherpad](https://etherpad.net) is an open source, web-based collaborative real-time editor, allowing authors to simultaneously edit a text document.

## Establish Foothold
- [Tunna](https://github.com/SECFORCE/Tunna) is tools a set of HTTP which will wrap and tunnel any TCP communication over. It can be used to restrictions bypass network in fully firewalled environments. 
- [reGeorg](https://github.com/sensepost/reGeorg) successor to reDuh pwn, a bastion webserver and create SOCKS proxies through the DMZ Pivot.
- [Blade](https://github.com/wonderqs/Blade) is a webshell connection tool based on console, currently under development and aims to be a choice of replacement of Chooper. 
- [TinyShell](https://github.com/threatexpress/tinyshell) Web Shell Framework. 

## Data Exfiltration
- [CloakifyFactory & the Cloakify Toolset](https://github.com/TryCatchHCF/Cloakify) Data Exfiltration & Infiltration In Plain Sight; Evade DLP/MLS Devices; Social Engineering of Analysts; Defeat Data Whitelisting Controls; Evade AV Detection. 
- [DET (is provided AS IS)](https://github.com/sensepost/DET), is a proof of concept to perform Data Exfiltration using either single or multiple channel(s) at the same time. 
- [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator) allows for transfering (exfiltrate) a file over a DNS request covert channel. This is basically a data leak testing tool allowing to exfiltrate data over a covert channel. 

# Blue Team Tools
## Introduction 
-   [Autosnort](https://github.com/da667/Autosnort)  - Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions.
-   [DShell](https://github.com/USArmyResearchLab/Dshell)  - Extensible network forensic analysis framework written in Python that enables rapid development of plugins to support the dissection of network packet captures.
-   [Posh-VirusTotal](https://github.com/darkoperator/Posh-VirusTotal)  - PowerShell interface to VirusTotal.com APIs.

## Communications security (COMSEC)
-   [GPG Sync](https://github.com/firstlookmedia/gpgsync)  - Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team.
-   [AutoSSH]([https://github.com/lucasrhb/autossh](https://github.com/lucasrhb/autossh)) - Due to network restrictions, you may be unable to connect via SSH to your computer. However, you can create a permanent, auto-reconnecting tunnel. 

## DevSecOps
-   [Clair](https://github.com/coreos/clair)  - Static analysis tool to probe for vulnerabilities introduced via application container (e.g., Docker) images.
-   [Gauntlt](http://gauntlt.org/)  - Pentest applications during routine continuous integration build pipelines.
-   [Autosnort](https://github.com/da667/Autosnort) - Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions.
-   [DShell](https://github.com/USArmyResearchLab/Dshell) - Extensible network forensic analysis framework written in Python that enables rapid development of plugins to support the dissection of network packet captures.
-   [Posh-VirusTotal](https://github.com/darkoperator/Posh-VirusTotal) - PowerShell interface to VirusTotal.com APIs.
-   [GPG Sync](https://github.com/firstlookmedia/gpgsync) - Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team.
-   [AutoSSH]([https://github.com/lucasrhb/autossh](https://github.com/lucasrhb/autossh)) - Due to network restrictions, you may be unable to connect via SSH to your computer. However, you can create a permanent, auto-reconnecting tunnel. -   [Gauntlt](http://gauntlt.org/)  - Pentest applications during routine continuous integration build pipelines.
-   [Git Secrets](https://github.com/awslabs/git-secrets)  - Prevents you from committing passwords and other sensitive information to a git repository.
-   [Vault](https://www.vaultproject.io/)  - Tool for securely accessing secrets such as API keys, passwords, or certificates through a unified interface.
## Scripts
Under Development
## Books
Under Development


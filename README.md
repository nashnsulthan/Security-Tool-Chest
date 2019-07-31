

# Introduction 
Anticipating and mitigating security threats is critical during software development. This paper is going to detail and investigate security vulnerabilities and mitigation strategies to help software developers build secure applications and prevent operating system leaks. This paper examines common vulnerabilities, and provides relevant mitigation strategies, from several relevant perspectives. This paper hopes to encompasses the cyber Kill chain as part of the five stage compramision stages, displaying relevant tools, books and strategies at each stage. 

# Staging for Red Teams
![Image description](http://www.iacpcybercenter.org/wp-content/uploads/2015/10/cyber_attack_lifecycle.jpg)

## Passive Intelligence Gathering

**Social Mapper** OSINT Social Media Mapping Tool, takes a list of names & images (or LinkedIn company name) and performs automated target searching on a huge scale across multiple social media sites. <https://github.com/SpiderLabs/social_mapper>

**Skiptracer** OSINT scraping framework, utilizes some basic python webscraping (BeautifulSoup) of PII paywall sites to compile passive information on a target on a ramen noodle budget. <https://github.com/xillwillx/skiptracer>

**ScrapedIn** a tool to scrape LinkedIn without API restrictions for data reconnaissance. <https://github.com/dchrastil/ScrapedIn>

**LinkScrape** A LinkedIn user/company enumeration tool. <https://github.com/NickSanzotta/linkScrape>

**FOCA (Fingerprinting Organizations with Collected Archives)** is a tool used mainly to find metadata and hidden information in the documents its scans. <https://github.com/ElevenPaths/FOCA>

**theHarvester** is a tool for gathering subdomain names, e-mail addresses, virtual hosts, open ports/ banners, and employee names from different public sources. <https://github.com/laramies/theHarvester>

**Metagoofil** is a tool for extracting metadata of public documents (pdf,doc,xls,ppt,etc) availables in the target websites. <https://github.com/laramies/metagoofil>

**SimplyEmail** Email recon made fast and easy, with a framework to build on. <https://github.com/killswitch-GUI/SimplyEmail>

**truffleHog** searches through git repositories for secrets, digging deep into commit history and branches. <https://github.com/dxa4481/truffleHog>

**Just-Metadata** is a tool that gathers and analyzes metadata about IP addresses. It attempts to find relationships between systems within a large dataset. <https://github.com/ChrisTruncer/Just-Metadata>

**Typofinder** a finder of domain typos showing country of IP address. <https://github.com/nccgroup/typofinder>

**pwnedOrNot** is a python script which checks if the email account has been compromised in a data breach, if the email account is compromised it proceeds to find passwords for the compromised account. <https://github.com/thewhiteh4t/pwnedOrNot>

**GitHarvester** This tool is used for harvesting information from GitHub like google dork. <https://github.com/metac0rtex/GitHarvester>

**Onion service** with the same name. <https://github.com/davidtavarez/pwndb/>

## Frameworks

**Maltego** is a unique platform developed to deliver a clear threat picture to the environment that an organization owns and operates. <https://www.paterva.com/web7/downloads.php>

**SpiderFoot** the open source footprinting and intelligence-gathering tool. <https://github.com/smicallef/spiderfoot>

**datasploit** is an OSINT Framework to perform various recon techniques on Companies, People, Phone Number, Bitcoin Addresses, etc., aggregate all the raw data, and give data in multiple formats. <https://github.com/DataSploit/datasploit>

**Recon-ng** is a full-featured Web Reconnaissance framework written in Python. <https://bitbucket.org/LaNMaSteR53/recon-ng>

## Weaponization

**WinRAR Remote Code Execution** Proof of Concept exploit for CVE-2018-20250. <https://github.com/WyAtu/CVE-2018-20250>

**Composite Moniker** Proof of Concept exploit for CVE-2017-8570. <https://github.com/rxwx/CVE-2017-8570>

**Exploit toolkit CVE-2017-8759** is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft .NET Framework RCE. <https://github.com/bhdresh/CVE-2017-8759>

**CVE-2017-11882** Exploit accepts over 17k bytes long command/code in maximum. <https://github.com/unamer/CVE-2017-11882>

**Adobe Flash Exploit CVE-2018-4878** <https://github.com/anbai-inc/CVE-2018-4878>

**Exploit toolkit** CVE-2017-0199 is a handy python script which provides pentesters and security researchers a quick and effective way to test Microsoft Office RCE. <https://github.com/bhdresh/CVE-2017-0199>

**demiguise** is a HTA encryption tool for RedTeams. <https://github.com/nccgroup/demiguise>

**Office-DDE-Payloads** collection of scripts and templates to generate Office documents embedded with 
the DDE, macro-less command execution technique. <https://github.com/0xdeadbeefJERKY/Office-DDE-Payloads>

**CACTUSTORCH** Payload Generation for Adversary Simulations. <https://github.com/mdsecactivebreach/CACTUSTORCH>

**SharpShooter** is a payload creation framework for the retrieval and execution of arbitrary CSharp source code. <https://github.com/mdsecactivebreach/SharpShooter> 

**Don't kill my cat** is a tool that generates obfuscated shellcode that is stored inside of polyglot images. The image is 100% valid and also 100% valid shellcode. <https://github.com/Mr-Un1k0d3r/DKMC>

**Malicious Macro Generator Utility** Simple utility design to generate obfuscated macro that also include a AV / Sandboxes escape mechanism. <https://github.com/Mr-Un1k0d3r/MaliciousMacroGenerator>

**SCT Obfuscator Cobalt Strike** SCT payload obfuscator. <https://github.com/Mr-Un1k0d3r/SCT-obfuscator>

**Invoke-Obfuscation** PowerShell Obfuscator. <https://github.com/danielbohannon/Invoke-Obfuscation>

**ps1encode** use to generate and encode a powershell based metasploit payloads. <https://github.com/CroweCybersecurity/ps1encode>

**Worse PDF** turn a normal PDF file into malicious. Use to steal Net-NTLM Hashes from windows machines. <https://github.com/3gstudent/Worse-PDF>

**SpookFlare** has a different perspective to bypass security measures and it gives you the opportunity to bypass the endpoint countermeasures at the client-side detection and network-side detection. <https://github.com/hlldz/SpookFlare>

**GreatSCT** is an open source project to generate application white list bypasses. This tool is intended for BOTH red and blue team. <https://github.com/GreatSCT/GreatSCT>

**nps** running powershell without powershell. <https://github.com/Ben0xA/nps>

**Meterpreter_Paranoid_Mode.sh** allows users to secure your staged/stageless connection for Meterpreter by having it check the certificate of the handler it is connecting to. <https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL>

**The Backdoor Factory (BDF)** is to patch executable binaries with user desired shellcode and continue normal execution of the prepatched state. <https://github.com/secretsquirrel/the-backdoor-factory>

**MacroShop** a collection of scripts to aid in delivering payloads via Office Macros. <https://github.com/khr0x40sh/MacroShop>

**UnmanagedPowerShell** Executes PowerShell from an unmanaged process. <https://github.com/leechristensen/UnmanagedPowerShell>

**evil-ssdp** Spoof SSDP replies to phish for NTLM hashes on a network. Creates a fake UPNP device, tricking users into visiting a malicious phishing page. <https://gitlab.com/initstring/evil-ssdp>

**Ebowla** Framework for Making Environmental Keyed Payloads. <https://github.com/Genetic-Malware/Ebowla>

**make-pdf-embedded** a tool to create a PDF document with an embedded file. <https://github.com/DidierStevens/DidierStevensSuite/blob/master/make-pdf-embedded.py>

**avet (AntiVirusEvasionTool)** is targeting windows machines with executable files using different evasion techniques. <https://github.com/govolution/avet>

**EvilClippy** A cross-platform assistant for creating malicious MS Office documents. Can hide VBA macros, stomp VBA code (via P-Code) and confuse macro analysis tools. Runs on Linux, OSX and Windows. <https://github.com/outflanknl/EvilClippy>

## Phishing
**King Phisher** is a tool for testing and promoting user awareness by simulating real world phishing attacks. <https://github.com/securestate/king-phisher>

**FiercePhish** is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more. <https://github.com/Raikia/FiercePhish>

**ReelPhish** is a Real-Time Two-Factor Phishing Tool. <https://github.com/fireeye/ReelPhish/>

**Gophish** is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training. <https://github.com/gophish/gophish>

**CredSniper** is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens. <https://github.com/ustayready/CredSniper>

**PwnAuth** a web application framework for launching and managing OAuth abuse campaigns. <https://github.com/fireeye/PwnAuth>

**Phishing Frenzy** Ruby on Rails Phishing Framework. <https://github.com/pentestgeek/phishing-frenzy>

**Phishing Pretexts** a library of pretexts to use on offensive phishing engagements. <https://github.com/L4bF0x/PhishingPretexts>

**Modlishka** is a flexible and powerful reverse proxy, that will take your ethical phishing campaigns to the next level. <https://github.com/drk1wi/Modlishka>

**Evilginx** is a man-in-the-middle attack framework used for phishing credentials and session cookies of any web service. <https://github.com/kgretzky/evilginx>

## Watering Hole Attack

**BeEF** is short for The Browser Exploitation Framework. It is a penetration testing tool that focuses on the web browser. <https://github.com/beefproject/beef>

## Remote Access Tools
**Cobalt Strike** is software for Adversary Simulations and Red Team Operations. <https://cobaltstrike.com/>

**Empire** is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. <https://github.com/EmpireProject/Empire>

**Metasploit Framework** is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. <https://github.com/rapid7/metasploit-framework>

**SILENTTRINITY** A post-exploitation agent powered by Python, IronPython, C#/.NET. <https://github.com/byt3bl33d3r/SILENTTRINITY>

**Pupy** is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python. <https://github.com/n1nj4sec/pupy>

**Koadic** or COM Command & Control, is a Windows post-exploitation rootkit similar to other penetration testing tools such as Meterpreter and Powershell Empire. <https://github.com/zerosum0x0/koadic>

**PoshC2** is a proxy aware C2 framework written completely in PowerShell to aid penetration testers with red teaming, post-exploitation and lateral movement. <https://github.com/nettitude/PoshC2_Python>

## Staging
**Red Baron** is a set of modules and custom/third-party providers for Terraform which tries to automate creating resilient, disposable, secure and agile infrastructure for Red Teams. <https://github.com/byt3bl33d3r/Red-Baron>

**EvilURL** generate unicode evil domains for IDN Homograph Attack and detect them. <https://github.com/UndeadSec/EvilURL>

**Domain Hunter** checks expired domains, bluecoat categorization, and Archive.org history to determine good candidates for phishing and C2 domain names. <https://github.com/threatexpress/domainhunter>

**PowerDNS** is a simple proof of concept to demonstrate the execution of PowerShell script using DNS only. <https://github.com/mdsecactivebreach/PowerDNS>

**Chameleon** a tool for evading Proxy categorisation. <https://github.com/mdsecactivebreach/Chameleon>

**CatMyFish** Search for categorized domain that can be used during red teaming engagement. Perfect to setup whitelisted domain for your Cobalt Strike beacon C&C. <https://github.com/Mr-Un1k0d3r/CatMyFish>

**Malleable C2** is a domain specific language to redefine indicators in Beacon's communication. <https://github.com/rsmudge/Malleable-C2-Profiles>

**Serving Random Payloads** with NGINX. <https://gist.github.com/jivoi/a33ace2e25515a31aa2ffbae246d98c9>

**meek** is a blocking-resistant pluggable transport for Tor. It encodes a data stream as a sequence of HTTPS requests and responses. <https://github.com/arlolra/meek>

**CobaltStrike-ToolKit** Some useful scripts for CobaltStrike. <https://github.com/killswitch-GUI/CobaltStrike-ToolKit>

**RedFile** a flask wsgi application that serves files with intelligence, good for serving conditional RedTeam payloads. <https://github.com/outflanknl/RedFile>

**keyserver** Easily serve HTTP and DNS keys for proper payload protection. <https://github.com/leoloobeek/keyserver>

**HTran** is a connection bouncer, a kind of proxy server. A “listener” program is hacked stealthily onto an unsuspecting host anywhere on the Internet. <https://github.com/HiwinCN/HTran>

## Lateral Movement
**CrackMapExec** is a swiss army knife for pentesting networks. <https://github.com/byt3bl33d3r/CrackMapExec>

**PowerLessShell** rely on MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe. <https://github.com/Mr-Un1k0d3r/PowerLessShell>

**GoFetch** is a tool to automatically exercise an attack plan generated by the BloodHound application. <https://github.com/GoFetchAD/GoFetch>

**ANGRYPUPPY** a bloodhound attack path automation in CobaltStrike. <https://github.com/vysec/ANGRYPUPPY>

**DeathStar** is a Python script that uses Empire's RESTful API to automate gaining Domain Admin rights in Active Directory environments using a variety of techinques. <https://github.com/byt3bl33d3r/DeathStar>

**SharpHound** C# Rewrite of the BloodHound Ingestor. <https://github.com/BloodHoundAD/SharpHound>

**BloodHound.py** is a Python based ingestor for BloodHound, based on Impacket. <https://github.com/fox-it/BloodHound.py>

**Responder** is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication. <https://github.com/SpiderLabs/Responder>

**SessionGopher** is a PowerShell tool that uses WMI to extract saved session information for remote access tools such as WinSCP, PuTTY, SuperPuTTY, FileZilla, and Microsoft Remote Desktop. It can be run remotely or locally. <https://github.com/fireeye/SessionGopher>

**PowerSploi**t is a collection of Microsoft PowerShell modules that can be used to aid penetration testers during all phases of an assessment. <https://github.com/PowerShellMafia/PowerSploit>

**Nishang** is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing. <https://github.com/samratashok/nishang>

## Privllege Esculation 

**The Elevate Kit** demonstrates how to use third-party privilege escalation attacks with Cobalt Strike's Beacon payload. <https://github.com/rsmudge/ElevateKi> 

**Sherlock** a powerShell script to quickly find missing software patches for local privilege escalation vulnerabilities. <https://github.com/rasta-mouse/Sherlock>

**Tokenvator** a tool to elevate privilege with Windows Tokens. 
 <https://github.com/0xbadjuju/Tokenvator>

**Cobalt Strike** is software for Adversary Simulations and Red Team Operations. 
 <https://cobaltstrike.com/> 

**Empire** is a post-exploitation framework that includes a pure-PowerShell2.0 Windows agent, and a pure Python 2.6/2.7 Linux/OS X agent. 
<https://github.com/EmpireProject/Empire>

**Metasploit Framework** is a computer security project that provides information about security vulnerabilities and aids in penetration testing and IDS signature development. <https://github.com/rapid7/metasploit-framework>

**SILENTTRINITY** A post-exploitation agent powered by Python, IronPython, C#/.NET. 
 <https://github.com/rapid7/metasploit-framework>

**Pupy** is an opensource, cross-platform (Windows, Linux, OSX, Android) remote administration and post-exploitation tool mainly written in python. 
 <https://github.com/n1nj4sec/pupy>

## Establish Foothold
**Tunna** is tools a set of HTTP which will wrap and tunnel any TCP communication over. It can be used to restrictions bypass network in fully firewalled environments. <https://github.com/SECFORCE/Tunna>

**reGeorg** successor to reDuh pwn, a bastion webserver and create SOCKS proxies through the DMZ Pivot. <https://github.com/sensepost/reGeorg>

**Blade** is a webshell connection tool based on console, currently under development and aims to be a choice of replacement of Chooper. <https://github.com/wonderqs/Blade>

**TinyShell**  Web Shell Framework. <https://github.com/threatexpress/tinyshell> 

## Adversary Simulation
**MITRE CALDERA** An automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks. <https://github.com/mitre/caldera>

**APTSimulator** A Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised. <https://github.com/NextronSystems/APTSimulator>

**Atomic Red Team** Small and highly portable detection tests mapped to the Mitre ATT&CK Framework. <https://github.com/redcanaryco/atomic-red-team>

**Network Flight Simulator** flightsim is a lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility. <https://github.com/alphasoc/flightsim>

**Metta** A security preparedness tool to do adversarial simulation. <https://github.com/uber-common/metta>

**Red Team Automation (RTA)** RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK. <https://github.com/endgameinc/RTA>

###Wireless Networks
**Wifiphisher** is a security tool that performs Wi-Fi automatic association attacks to force wireless clients to unknowingly connect to an attacker-controlled Access Point. <https://github.com/wifiphisher/wifiphisher>

**mana toolkit** for wifi rogue AP attacks and MitM. <https://github.com/sensepost/mana>

### Embedded & Peripheral Devices Hacking
**magspoof** a portable device that can spoof/emulate any magnetic stripe, credit card or hotel card "wirelessly", even on standard magstripe (non-NFC/RFID) readers. <https://github.com/samyk/magspoof>

**WarBerryPi** was built to be used as a hardware implant during red teaming scenarios where we want to obtain as much information as possible in a short period of time with being as stealth as possible. <https://github.com/secgroundzero/warberry>

**P4wnP1** is a highly customizable USB attack platform, based on a low cost Raspberry Pi Zero or Raspberry Pi Zero W (required for HID backdoor). <https://github.com/mame82/P4wnP1>

**malusb HID spoofing multI** OS payload for Teensy. <https://github.com/ebursztein/malusb>

**Fenrir** is a tool designed to be used "out-of-the-box" for penetration tests and offensive engagements. Its main feature and purpose is to bypass wired 802.1x protection and to give you an access to the target network. <https://github.com/Orange-Cyberdefense/fenrir-ocd>

**poisontap** exploits locked/password protected computers over USB, drops persistent WebSocket-based backdoor, exposes internal router, and siphons cookies using Raspberry Pi Zero & Node.js. 
<https://github.com/samyk/poisontap>

**WHID WiFi HID Injector** An USB Rubberducky / BadUSB On Steroids. <https://github.com/whid-injector/WHID>

## Software For Team Communication
**RocketChat** is free, unlimited and open source. Replace email & Slack with the ultimate team chat software solution. <https://rocket.chat>

**Etherpad** is an open source, web-based collaborative real-time editor, allowing authors to simultaneously edit a text document <https://etherpad.net>

## Log Aggregation
**RedELK Red Team's SIEM** easy deployable tool for Red Teams used for tracking and alarming about Blue Team activities as well as better usability in long term operations. <https://github.com/outflanknl/RedELK/>

**CobaltSplunk Splunk** Dashboard for CobaltStrike logs. <https://github.com/vysec/CobaltSplunk>

**Red Team Telemetry** A collection of scripts and configurations to enable centralized logging of red team infrastructure. <https://github.com/ztgrace/red_team_telemetry>

**Elastic** for Red Teaming Repository of resources for configuring a Red Team SIEM using Elastic. <https://github.com/SecurityRiskAdvisors/RedTeamSIEM>

# Blue Team Tools
![Image description](https://www.infoa.com/wp-content/uploads/2016/05/Cyber_Security_Framework_v.3_Web.png)

## Introduction
Blue Team individuals identify security flaws in information technology systems, verify the effectiveness of security measures, and monitor the systems to ensure that implemented defensive measures remain effective within the future. 

## Software For Team Communication

**RocketChat** is free, unlimited and open source. Replace email & Slack with the ultimate team chat software solution. <https://rocket.chat>

**Etherpad** is an open source, web-based collaborative real-time editor, allowing authors to simultaneously edit a text document. <https://etherpad.net)>

## Automation 
**Autosnort** Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions. <https://github.com/da667/Autosnort>

**DShell** Extensible network forensic analysis framework written in Python that enables rapid development of plugins to support the dissection of network packet captures. <https://github.com/USArmyResearchLab/Dshell>

**Posh-VirusTotal** PowerShell interface to VirusTotal.com APIs. <https://github.com/darkoperator/Posh-VirusTotal>

## Communications Security (COMSEC)
**GPG Sync** Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team. <https://github.com/firstlookmedia/gpgsync>

**AutoSSH**  Due to network restrictions, you may be unable to connect via SSH to your computer. However, you can create a permanent, auto-reconnecting tunnel. 
 <https://github.com/lucasrhb/autossh>

## DevSecOps
**Clair** Static analysis tool to probe for vulnerabilities introduced via application container (e.g., Docker) images. <https://github.com/coreos/clair>

**Gauntlt** Pentest applications during routine continuous integration build pipelines. <http://gauntlt.org/>

**Autosnort** Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions. <https://github.com/da667/Autosnort>

**DShell** Extensible network forensic analysis framework written in Python that enables rapid development of plugins to support the dissection of network packet captures. <https://github.com/USArmyResearchLab/Dshell>

**Posh-VirusTotal** PowerShell interface to VirusTotal.com APIs. 
 <https://github.com/darkoperator/Posh-VirusTotal>

**GPG Sync** Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team. 
 <https://github.com/firstlookmedia/gpgsync> 

**Gauntlt** Pentest applications during routine continuous integration build pipelines. 
 <http://gauntlt.org/>

**Git Secrets** Prevents you from committing passwords and other sensitive information to a git repository. <https://github.com/awslabs/git-secrets)>

**Vault** Tool for securely accessing secrets such as API keys, passwords, or certificates through a unified interface. <https://www.vaultproject.io/>

## Incident Response Tools
**aws_ir** Automates your incident response with zero security preparedness assumptions. <https://www.google.com>

**CIRTKit**  Scriptable Digital Forensics and Incident Response (DFIR) toolkit built on Viper.v <https://www.google.com>

**Fast Incident Response (FIR)** Cybersecurity incident management platform allowing for easy creation, tracking, and reporting of cybersecurity incidents. <https://www.google.com>

**Rekall** Advanced forensic and incident response framework. <https://www.google.com>

**TheHive** Scalable, free Security Incident Response Platform designed to make life easier for SOCs, CSIRTs, and CERTs, featuring tight integration with MISP. <https://www.google.com>

**threat_note** Web application built by Defense Point Security to allow security researchers the ability to add and retrieve indicators related to their research.
Evidence collection <https://www.google.com>

**AutoMacTC** Modular, automated forensic triage collection framework designed to access various forensic artifacts on macOS, parse them, and present them in formats viable for analysis. <https://www.google.com>

**OSXAuditor** Free macOS computer forensics tool. <https://www.google.com>

**OSXCollector** Forensic evidence collection & analysis toolkit for macOS. <https://www.google.com>

**ir-rescue**Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response. <https://www.google.com>

**Margarita Shotgun** Command line utility (that works with or without Amazon EC2 instances) to parallelize remote memory acquisition. <https://www.google.com>

## Books
- [Advanced Penetration Testing](www.google.com)
- [The Basics of Web Hacking](www.google.com)
- [The Basics of Hacking and Penetration Testing](www.google.com)
- [The Art of Deception by Kevin Mitnick](www.google.com)
- [SQL Injection Attacks and Defenses](www.google.com)
- [Metasploit - The Penetration Tester's Guide](www.google.com)
- [Ethical Hacking and Penetration Testing Guide](www.google.com)
- [Network Attacks and Exploitation - A Framework](www.google.com)
- [Python Web Penetration Testing Cookbook](www.google.com)
- [Wireshark for Security Professionals](www.google.com)
- [Mastering Modern Web Penetration Testing](www.google.com)
- [The Shellcoder's Handbook](www.google.com)
- [The Little Black Book of Computer Viruses](www.google.com)
- [XSS Attacks - Cross Site Scripting Exploits and Defense](www.google.com)
- [The Web Application Hacker's Handbook](www.google.com)
- [Ethical Hacking and Countermeasures](www.google.com)
- [Reversing - Secrets of Reverse Engineering](www.google.com)

## Conclusion 
Whether it is to start a new career or just simple curiosity, learning about Malware Analysis can be a very challenging and rewarding path. It can test your patience, concentration and sometimes even your temper, but the payoff when you have been working on a file for hours and finally come across the key function or piece of data you were looking for, cannot be duplicated by anything else.

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)

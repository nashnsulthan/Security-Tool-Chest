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

## Delivery
- [King Phisher](https://github.com/securestate/king-phisher) - Is a tool for testing and promoting user awareness by simulating real world phishing attacks. 
- [FiercePhish](https://github.com/Raikia/FiercePhish) - Is a full-fledged phishing framework to manage all phishing engagements. It allows you to track separate phishing campaigns, schedule sending of emails, and much more. 
- [ReelPhish](https://github.com/fireeye/ReelPhish/) - Is a Real-Time Two-Factor Phishing Tool. 
- [Gophish]( https://github.com/gophish/gophish) - Is an open-source phishing toolkit designed for businesses and penetration testers. It provides the ability to quickly and easily setup and execute phishing engagements and security awareness training.
- [CredSniper]( https://github.com/ustayready/CredSniper) - Is a phishing framework written with the Python micro-framework Flask and Jinja2 templating which supports capturing 2FA tokens.
- [PwnAuth](https://github.com/fireeye/PwnAuth) - A web application framework for launching and managing OAuth abuse campaigns.
- [Metasploit]()
## Command and Control
Under Development
## Privilege Escalation 
Under Development
## Lateral Movement 
Under Development
# Blue Team
-   [Autosnort](https://github.com/da667/Autosnort) - Series of bash shell scripts designed to install a fully functional, fully updated stand-alone snort sensor with an IDS event review console of your choice, on a variety of Linux distributions.
-   [DShell](https://github.com/USArmyResearchLab/Dshell) - Extensible network forensic analysis framework written in Python that enables rapid development of plugins to support the dissection of network packet captures.
-   [Posh-VirusTotal](https://github.com/darkoperator/Posh-VirusTotal) - PowerShell interface to VirusTotal.com APIs.
-   [GPG Sync](https://github.com/firstlookmedia/gpgsync) - Centralize and automate OpenPGP public key distribution, revocation, and updates amongst all members of an organization or team.
-   [AutoSSH]([https://github.com/lucasrhb/autossh](https://github.com/lucasrhb/autossh)) - Due to network restrictions, you may be unable to connect via SSH to your computer. However, you can create a permanent, auto-reconnecting tunnel. -   [Gauntlt](http://gauntlt.org/)  - Pentest applications during routine continuous integration build pipelines.
-   [Git Secrets](https://github.com/awslabs/git-secrets)  - Prevents you from committing passwords and other sensitive information to a git repository.
-   [Vault](https://www.vaultproject.io/)  - Tool for securely accessing secrets such as API keys, passwords, or certificates through a unified interface.


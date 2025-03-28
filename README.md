# Network Analysis (Exfiltration) Lab

## Objective

Enhance proficiency in analyzing PCAP files to identify network exfiltration attempts. Develop the ability to detect unauthorized data transfers, specifically via email, by examining network traffic patterns and anomalies. Improve investigative skills in packet analysis to strengthen network security and incident response capabilities.

### Skills Learned

- Enhanced proficiency in Wireshark for network traffic analysis
- Gained deeper understanding of PCAP analysis techniques
- Learned to identify network exfiltration attempts via email
- Improved ability to detect anomalous network behavior
- Strengthened incident response and forensic investigation skills

### Tools Used

- Wireshark
- PowerShell
- CyberChef
- VirusTotal
- ipinfo.io
- AbuseIPDB
- DomainTools (Whois Lookup)

## Steps

	- For this project, I'll do be doing a retired CyberDefenders lab titled "Hawkeye"

	- First let's take a look at the scenario of the lab.

![image](https://github.com/user-attachments/assets/ab5bbae5-5786-4dc8-bf0c-2b58172f54d9)

	- So I know I'm going to be looking for exfiltration attempts. The goal for me in this lab is to gain experience on this kind of malicious behavior.

	- I get started by downloading the lab files, and extracting the contents.

	- Since I already have Wireshark downloaded, I see a pcap that has a Wireshark icon next to it.
	
![image](https://github.com/user-attachments/assets/efb8c760-6df1-480a-9438-dff768a76f19)

	- If I double click it, it opens the pcap in Wireshark. 

![image](https://github.com/user-attachments/assets/e41ea369-2719-4d54-9202-f5367353becf)

	- We'll configure the same Wireshark settings as the previous lab. I'll make a new field called source/destination port, as well as change the format of the time. 
		○ So now it should look a little different
		○ If you can't remember how to do this, just look at your previous lab on how to investigate pcaps. 

![image](https://github.com/user-attachments/assets/f7fe6f3e-8568-4a2e-83e3-93b29c4a7ee3)

	- So like always; when investigating pcaps it’s good practice to start off with "Statistics" tab in Wireshark to find out general information about the pcap. 

	- I’ll start with the first option in the Statistics tab, "Capture File Properties"
		○ We can find lots of general information in this window, but mainly I'm focused on the total time elapsed. 

![image](https://github.com/user-attachments/assets/83e8a8df-f9f9-4d42-9383-9339563d09cd)

	- The total time elapsed was one hour and three minutes and forty one seconds. The first packet occurred at 3:37 pm and the last packet occurred at 4:40 pm

	- Next I'll take at the "Protocol Hierarchy" option in the Statistics tab

![image](https://github.com/user-attachments/assets/38f70e2a-1319-4593-bc00-75f19f508be8)

	- So I can see a bunch of protocols that exist within this pcap. Some notable ones are:
		○ SMB
		○ SMTP
		○ Kerberos
		○ HTTP, etc.

	- Next we'll look at the "Conversations" option in the Statistics tab. 
		○ I'm trying to identify "top talkers" or the hosts who were having the most conversations between one another.

	- In the Conversations window, I'll need to select the IPv4 tab at the top. I want to see the top talkers for the IPv4 addresses.

	- I'll also need to sort it by bytes. I can do this by selecting "Bytes" field at the top

![image](https://github.com/user-attachments/assets/b904e28c-0027-4edf-b9be-ff834d3670c3)

	- So I can see that the top conversation is with an external IP address, 217.182.138.150

	- It's good practice to track the top three destination IPs, as these Ip addresses could of be of interest later down in the investigation. 
		○ 217.182.138.150
		○ 10.4.10.4
		○ 23.229.162.69

	- Now let's look at the TCP tab and sort it by bytes as well.

![image](https://github.com/user-attachments/assets/d942fdc5-173c-48f8-a82f-0a8437ea071b)

	- So the top convo is port 80 traffic… so this is HTTP traffic. 

	- 445 is SMB, and then 443 is HTTPS.

	- I also see lots of SMTP traffic on port 587. This is related to that third "top talker" address from earlier. 
		○ 23.229.162.69
		○ This is most likely a mail server

	- Now I'll look at the UDP tab and sort it by bytes as well.

![image](https://github.com/user-attachments/assets/204d141a-fc99-43ac-8a79-813e244f9f20)

	- At the top we can see some multi-cast traffic. NetBIOS, NTP, DNS, DHCP

	- Multicast traffic in refers to network packets sent from one source to multiple destinations, but not to everyone on the network (unlike broadcast). Instead, it's delivered only to devices that are part of a specific multicast group. 
		○ Common in streaming, video conferencing, and routing protocols.


	- So nothing super out of the ordinary, and we identified that one of the top talker IP addresses was a mail server. I am still interested in that top IP address, 217.182.138.150

	- I need to filter for that specific IP address, among all of the packets in this pcap. To do that, I need to go back to the main packet list pane, and select the search bar at the top. 
		○ In the bar, I'll use the query:
		○ "ip.addr == 217.182.138.150"

![image](https://github.com/user-attachments/assets/594694b5-55f2-4e4f-9a09-cdf296dddc57)

	- Packet 210 ( the only HTTP packet) is quite interesting. There was a GET request. It occurred at 20:37:54. 

	- If I right-click it and follow the HTTP stream, I can find more information on this specific packet by looking at the conversation between the client and the server. 
		○ I get the following information.

![image](https://github.com/user-attachments/assets/132276e0-9b4b-4d6d-906a-61af26b33698)

	- I can see a binary being downloaded. I can tell because of the file header "MZ" and the content type "application/x-msdownload"

	- A "binary" refers to an executable file or a compiled program, rather than just a plain text file. These files contain machine code that a computer can run, such as .exe, .dll. Or .bin files. 

	- The file header "MZ":
		○ The "MZ" header is a signature found at the beginning of Windows executable files (.exe and .dll)
		○ "MZ" comes from Mark Zbikowski" one of the developers of the DOS executable format. 
		○ Seeing "MZ" in the packet suggest that an executable file is being transferred.

	- Content type "application/x-msdownload":
		○ This MIME type is used for Windows executable, specifically .exe and sometimes .dll files
		○ It signals that the server is serving a Windows binary file for download

	- Since this is HTTP traffic, this could signal a software download, or a potentially suspicious /malicious file transfer in a security context. 



	- So later I want to extract the "application/x-msdownload"  file and perform some OSINT, but before that, I want to determine how our internal IP address communicated with this external IP address.
		○ To do this I need to head back to the main packet list pane and find the first packet related to 217.182.138.150
		○ Its packet 207

![image](https://github.com/user-attachments/assets/da7e1826-1013-4044-9a26-70a695da7952)

	- So from a logical point of view I need to look at what happened before this packet. So I'll need to get rid of the query from earlier and go back to the default pcap packet list.
		○ I need to focus on the packets before 207

![image](https://github.com/user-attachments/assets/7bd711c3-74db-45f2-8f4b-4ecc7f389f60)
![image](https://github.com/user-attachments/assets/31a136e8-3b4a-4c0e-b185-b0ea12681b8c)

	- So looking at packet 206, it's a DNS response from our server back to our internal IP of .132
		○ There was a standard query response for the domain 'proforma-invoices.com'

	- This could be potentially the suspicious download link that in the scenario.
		○ I'll keep note of it for later

	- Scrolling up I can see SMB traffic, but I am more interested in SMTP traffic. Why? Well because I know this protocol exists within this pcap from when I looked at the protocol hierarchy window earlier.  Also the scenario from earlier mentioned email.
		○ So I should probably filter for this traffic and see what I can find
		○ I'll simply type "smtp" at the top of the filter bar

![image](https://github.com/user-attachments/assets/385f4a92-9ec0-48f4-a1e7-f0fb3d1caf4e)

	- I can instantly see a bunch of SMTP traffic that occurs at 20:38:16 so 8:38 pm
		○ The first SMTP packet is 3175

	- So we know that traffic started with our top talker (217.182.138.150) at packet 207
		○ So this SMTP traffic happened afterwards

	- So looking back at the scenario, cyberdefenders does not provide the actual email that was used. But I'm going to assume that the suspicious link was the  "performa" domain I found earlier

	- Getting back to the SMTP traffic, I should follow the TCP stream of the first SMTP packet, to find more information.

![image](https://github.com/user-attachments/assets/1d1ddd9c-95af-482b-ab9d-9592a8805a13)

	- At the top I can see the host name of the mail server, as well as the software version of Exim 4.91

	- We can also see that our client machine is Beijing-5cd1-PC with a public IP address of 173.66.146.112

	- There is an authentication attempt (AUTH login) using the user and password
		○ There are encoded using base-64
		○ A good way to tell is looking at  the padding at the end, if there's equal signs, that could mean base-64. This isn't always the case.

	- To de-code this I'll use the Cyber Chef tool, and paste the username into the input.

![image](https://github.com/user-attachments/assets/ca883353-b5ad-46fa-825c-c8de656ef99b)

- On the left I need to select "From Base64"

![image](https://github.com/user-attachments/assets/29b00994-d7be-4784-9a2d-d9c39577b260)

	- Now the password

![image](https://github.com/user-attachments/assets/8c3a6deb-5d1c-487a-a28f-e3114b11b02e)

	- This is likely the account of the attacker. So I need to perform some OSINT later.

	- If I go back to the TCP stream, I notice that the subject of the email is encoded in base 64 as well. 
		○ I need to copy the subject up until the question mark
		○ Question marks typically represents something else

![image](https://github.com/user-attachments/assets/88a35470-85b6-44d2-9ffb-88fe1271f112)

	- Now let's see what happens we put the subject into cyberchef

![image](https://github.com/user-attachments/assets/b4c00b83-4896-4826-8a7d-8c62bf96dd9d)

	- So this very interesting and bad. 
		○ The user 'roman.mcguire' was most likely the victim and the user account for "BEIJING-SCD1-PC"
		○ Based on the subject line and "Password Logs", it seems that Roman's passwords were most likely stolen

	- If I look at the contents I can see that it is also encoded in base 64, indicated by the "Content-Transfer-Encoding" field

![image](https://github.com/user-attachments/assets/f3a3c441-7801-4cdf-a2e5-b03cca3cdc63)

	- So I'm going to what I've been doing and copy and paste all of the contents into cyber chef. 

![image](https://github.com/user-attachments/assets/773cacb1-8ec0-470a-85e5-f16b8b70f52c)

	- If I expand the output, I can see a wealth of information

![image](https://github.com/user-attachments/assets/2399d200-19cc-4115-8970-21ab1dc2eafe)
![image](https://github.com/user-attachments/assets/bfa229e5-f1d6-40a8-a6f5-8d66aab75ec5)

	- Username is: roman.mcquire914@aol.com

	- Password is: P@ssw0rd$

	- It seems as if the user used the same password for their Bank of America account, as well as for their work email account. 

	- So what does this mean? 
		○ Well basically what happened is that this executable has scraped all of the passwords stored on Roman's computer and the contents were sent at 20:38:16.

	- So when was the last SMTP activity happening?
		○ We just need to filter again for SMTP and then scroll all the way down

![image](https://github.com/user-attachments/assets/fb44db64-d2f7-4eb2-9fef-7076062efcb8)

	- The SMTP packet is 3981 and occurred at 21:40:04 or 9:40 pm. 

	- Let's follow the TCP stream, and look at the contents.
		○ The reason for this is to see if by the end, if there were any more files that had been exfiltrated. 

  ![image](https://github.com/user-attachments/assets/9d160447-2430-4e88-829a-4f5b169e2fbd)

	- I need to do the same and copy and paste the contents into cyber chef.
		○ It seems to be the same when I did it. So nothing new.


	- So let's follow another point of interest and actually export that file that we found earlier and begin generating a file hash on it to perform some OSINT.

	- What do I mean by that?
		○ The reason you export a file is to see it's full contents, including its actual name, structure, and additional metadata.

	- Exporting the file will also allow me to run a file hash
		○ A file hash is a unique fingerprint of a file, generated using a cryptographic algorithm. (MD5, SHA-1, SHA-256). Even a small change in the file results in a completely different hash.

	- So how exactly would a file hash help with OSINT?
		○ Well OSINT uses publicly available data. So a file hash helps with checking for malware, identifying the file, and tracking file distribution (this can link attacks).


	- To start, it would be a good idea to disable Microsoft defender before I export it just in case it does detect malware and blocks it. 

![image](https://github.com/user-attachments/assets/d643d971-ed19-404a-8577-62a24bf39342)

	- Now I can export the file.

	- To do this I'll need to select "File" at the top of Wireshark, and scroll down until I find "Export Objects", hover over it and then select "HTTP"

![image](https://github.com/user-attachments/assets/3e42f762-7f44-4401-b721-0bfcdcddb310)

	- This brings up the Export HTTP object list window

![image](https://github.com/user-attachments/assets/a0fb50d0-f212-426f-bc6c-359287e30f16)

	- At the top we can see the domain name from earlier, proforma-invoices.com

	- I can also see the file name, "tkraw_Protected99.exe"
		○ I need to select it and then save it

	- I saved it the extension ".malware"

![image](https://github.com/user-attachments/assets/2ed26725-180f-44a1-b201-08066ac11339)

	- So now that I have this file saved, I need to open up PowerShell and navigate to the directory that the file is in.

	- Once in the correct directory, I'll need to use the command "Get-FileHash tkraw_Protected99.malware"

![image](https://github.com/user-attachments/assets/6b76b051-aeaa-4af3-96a0-db74a3ad16b7)

	- So I now have the SHA256 hash for this file. 

	- Now I'll copy and paste this hash into virustotal.com 

	- VirusTotal is a free online tool that analyzes files, URLs, and hashes for malware, viruses, and other security threats. It aggregates results from multiple antivirus engines, sandbox environments, and security tools to help identify potential threats.
		○ I go to the website and click the "Search" option

![image](https://github.com/user-attachments/assets/3b8527ee-b122-45d8-b937-bc9c80c11111)

	- I need to paste the file hash into this search bar and hit enter.

![image](https://github.com/user-attachments/assets/7d7ea9e2-a30b-45a9-9fc4-102df84f2807)

	- So CLEARLY this is a dangerous file.
		○ It has 58 vendors detected
		○ Popular threat label is trojan.autoit/gen8, it's threat category is also trojan

	- We can look at the "Community" tab and see other people's verdict on this file. 

![image](https://github.com/user-attachments/assets/ed187af7-a91a-43c7-a617-1c606e16013b)

	- Next let's look at the "Relations" tab:
		○ This shows the contacted domains

![image](https://github.com/user-attachments/assets/609b8bf7-9568-4e6c-a2b4-cca485fa2dce)

	- I can actually see the bot.whatismyipaddress from earlier when I was trying to extract the file

	- This means that there is most likely a scheduled query outbound to whatismyipaddress.com 

	- If I look at the "Details" tab
		○ I can find when the malware was created on this tab

![image](https://github.com/user-attachments/assets/7217b636-4baa-4115-91db-68bd513de6ba)

	- Now let's do some OSINT on the top talker IP address from earlier as well as the domain name itself  (217.182.138.150) (performa-invoices.com)

	- I'll use "www.abuse.ipdb.com" to analyze the IP address

![image](https://github.com/user-attachments/assets/7bed2968-729b-453e-bf27-ee3f4f17e77d)

	- The IP address is not located in their database, however it did find that the ISP is OVH SAS, I can see the usage type, it's located in France. 

	- Let's use VirtusTotal

![image](https://github.com/user-attachments/assets/7f9c15bb-f58c-409f-88ef-1dca1509ee04)

	- There's two vendors that flagged this IP address as malicious.

	- For the domain name. I'll use a whois lookup tool from DomainTools.

![image](https://github.com/user-attachments/assets/302d3d1d-1550-4033-ba37-9a255f0665c4)
![image](https://github.com/user-attachments/assets/615eddbc-e5d7-490c-9b0f-32163f7eac15)

	- With the free account I can't see the history of this domain, BUT I can see "2 changes on 2 unique IP addresses over 6 years"

	- Now I'll put the domain name into Virus Total

![image](https://github.com/user-attachments/assets/cd9c5cbd-bd8b-4cb6-82aa-5829608c0acb)

	- I can see that 12 vendors have flagged this domain as malicious and some as phishing. 


	- Now let's perform some OSINT on the email domain of the actual attacker. 
		○ It was "sales.del@macwinlogistics.in"

	- I'll put "macwinlogistics.in" into VirustTotal to see what pops up.

![image](https://github.com/user-attachments/assets/ae48b227-9d08-411c-8f14-2788076f899c)

	- So there's no reports but there is 10 detected files that are communicating with this domain
	- So I think I've found everything I need to know, I'll start compiling my findings and report it to whoever needs it.


Report Notes:

April 10 2019 @ 20:37:54 UTC
	- User had accessed domain: proforma-invoices.com
	- Requested file: tkraw_protected99.exe
	- Classified as a trojan and malware label: HawkEye
	
About HawkEye:
	- Known for its keylogging capabilities
	- Delivered via Phishing

File: tkraw_protected99.exe
	- Know to query: whatismyipaddress.com

April 10 2019 @ 20:38:15 UTC
	- Host: BEIJING-5CD1-PC
	- Querying domain: whatismyipaddress.com

April 10 2019 @ 20:38:16 UTC
	- Communication towards a Mail Server
		○ IP: 233.229.162.69
	- Authenticated User: sales.del@macwinlogistics.in
	- Passwords related to Roman Mcguire were sent to this email

April 10 2019 @ 21:38:43 UTC
	- Same contents were sent again to this email

April 10 2019 @ 20:38:43 UTC
	- Last mail activity observed

Time Range: 20:37:54 - 21:40:04

Total Duration: 1 Hour, 2 Minutes, 10 Minutes




Answers to the Questions:


	1) How many packets does the capture have?

	- Just go to "Statistics" tab and click the "Capture File Properties" option

	- Total packets captured: 4003

![image](https://github.com/user-attachments/assets/12a661e0-c021-454b-8cfb-799bec7aced4)

	2) At what time was the first packet captured?

	- We can find the answer on this same window

	- First packet capture: 
		○ 2019-04-10 20:37:07 utc


	3) What is the duration of the capture?

	- 01:03:41 

![image](https://github.com/user-attachments/assets/d960bb8f-650e-4d2b-a64b-6bb968e55173)

	4) What is the most active computer at the link level?
	
	- Link level is Layer 2, so this has to do with MAC addresses

	- We can find this from the "Conversations" option in the "Statistics" tab

	- Just need to go to Ethernet

	- Answer: 00:08:02:1c:47:ae

![image](https://github.com/user-attachments/assets/79b96988-02e5-41b7-a0f8-a01b129a5174)

	5) Manufacturer of the NIC of the most active system at the link level?

	- Now to find the manufacture we can look at the OUI, which is the first 3 bytes of a MAC address

	- I know the most active system on the Link level, so the OUI (organizational unique identifier) is  00:08:02

	- Then I need to look up "Wireshark OUI", because this will provide me with a lookup tool

![image](https://github.com/user-attachments/assets/171cac84-07ca-4391-8629-15715b1916d5)
![image](https://github.com/user-attachments/assets/34d79bef-6da2-4d18-8148-2ae7e42ae97d)

	- Manufacturer of NIC: Hewlett-Packard


	6) Where is the headquarter of the company that manufactured the NIC of the most active computer at the link level?

	- This requires simple OSINT, I just typed "Hewlett Packard headquarters" into google

	- HP Headquarters: Palo Alto


	7) The organization works with private addressing and netmask /24. How many computers in the organization are involved in the capture?

	- To find this I head to the "Statistics" tab and then I select the "Endpoints" option

	- I then clicked the IPv4 tab in the Endpoints window and sorted it by address
		○ This is to make sure all of the internal IP addresses are at the top

![image](https://github.com/user-attachments/assets/cdbc58dc-2af3-4c36-86e8-20db90bff2e2)

	- Out of the internal IP addresses we have 10.4.10.2, 10.4.10.4, and 10.4.10.132
		○ 10.4.10.255 is a broadcast address

	- Host (computers) involved: 3 hosts
		


	8) What is the name of the most active computer at the network level?

	- Remember when I followed the SMTP traffic, I saw the host name for the most active computer

	- Beijing-5cd1-PC


	9) What is the IP of the organization's DNS server?

	- I can find this out my going to main packet list pane and then typing 'dns' into the filter bar

![image](https://github.com/user-attachments/assets/10a20a26-47f3-435d-a028-043fa37b6d3c)

	- Then I can just look at the responses

![image](https://github.com/user-attachments/assets/f9957bdc-bd25-4105-87bd-36953184df5a)

	- We can infer that the response query that the DNS server is 10.4.10.4
		○ If it's a response, and the source is 10.4.10.4 we know that it's the server responding back to a query

	10) What domain is the victim asking about in packet 204?

	- I just need to go back to packet 204

![image](https://github.com/user-attachments/assets/2dc4e6a5-af65-494f-996c-67251a6c0976)

	- Domain: proforma-invoices.com


	11) What is the IP of the domain in the previous question?

	- To find this I need to click the packet and then I can expand the protocol pane in the bottom left

	- If I expand the drop down of DNS (response) I can see "Answers"
		○ From there I can see the domain and its associated IP address

![image](https://github.com/user-attachments/assets/cf9f24cd-7d02-4149-a39d-78a3e8ab23f6)

	- IP address: 217.182.138.150


	12) Indicate the country to which the IP in the previous section belongs.

	- Remember when I did OSINT on this IP earlier? 

	- Country of Origin: France


	13) What operating system does the victim's computer run?

	- So how do I find this?

	- I need to look for the "user agent"

	- So this means I need to look for HTTP traffic
		○ I just need to filter for HTTP

	- Then I just need to follow the HTTP stream, and I need to find the host request

![image](https://github.com/user-attachments/assets/96058208-0f68-4323-b2bd-61912f41f8b5)

	- User agent: Windows NT 6.1



	14) What is the name of the malicious file downloaded by the accountant?

	- You can see the file name in the screenshot above as well

	- File name: tkraw_Protected99.exe



	15) What is the md5 hash of the downloaded file?

	- Remember when I found the SHA256 hash of the file in PowerShell?

	- Well I'll use that same command, but this time also specify the algorithm to use

	- You can also copy the SHA256 hash and paste it into VirusTotal as well

![image](https://github.com/user-attachments/assets/4344d137-6191-4bf8-9d3d-b9e23c65b466)

	- MD5 Hash: 71826BA081E303866CE2A2534491A2F7



	16) What software runs the webserver that hosts the malware?
	
	- For this we need to go back to the HTTP traffic and look at the HTTP stream again

	- I'm looking for the software that the server responded with

![image](https://github.com/user-attachments/assets/01f49eed-ce3c-4510-8fb7-4b55ce4e91de)

	- Software: LiteSpeed



	17) What is the public IP of the victim's computer?
	
	- For this we can look at SMTP traffic,  and follow the TCP steam

	- Remember we did see a public IP address earlier

![image](https://github.com/user-attachments/assets/90c659e1-a861-4361-bb00-e9744ac9e293)

	- IP address: 173.66.146.112



	18) In which country is the email server to which the stolen information is sent?
	
	- So where is the email server located?

	- I know the ip address of the mail server: 23.229.162.69

	- Just need to perform some simple OSINT on this IP
		○ I used the website "ipinfo.io"

![image](https://github.com/user-attachments/assets/2527dc7a-825a-4f3e-ad32-14f12af78e5d)

Country: United States



	19) Analyzing the first extraction of information. What software runs the email server to which the stolen data is sent?
	
	- Again we can look at SMTP traffic and follow the TCP stream

![image](https://github.com/user-attachments/assets/8cb88e14-7705-4a11-8092-d64bfc22c08f)

	- Software: Exim 4.91



	20) To which email account is the stolen information sent?

	- Again SMTP traffic, follow TCP stream

![image](https://github.com/user-attachments/assets/225280d1-cc52-4434-ad07-109ac7d22b95)

	- Email: sales.del@macwinlogistics.in


	21) What is the password used by the malware to send the email?
	
	- The password is right above the email address in the screen shot above

	- I decoded it earlier from base 64 and it came out to…

	- Password: Sales@23


	22) Which malware variant exfiltrated the data?
	
	- Remember when I de-coded the contents in Cyber chef earlier?

![image](https://github.com/user-attachments/assets/119b119a-56ce-4d39-8d29-c1aa8703492b)

	- Variant of HawkEye Keylogger: Reborn v9

	23) What are the bankofamerica access credentials? (username:password)
	
![image](https://github.com/user-attachments/assets/8b99e4dd-2ad9-41b2-94c7-7b56676f340d)

User: roman.mcguire
Password: P@ssw0rd$



	24) Every how many minutes does the collected data get exfiltrated?

	- I know that the same contents were exfiltrated twice, I can take the first time and then subtract it from the second time

	- I need to follow the TCP stream and click on the contents

	- I started on packet 3196 at 20:38:16

	- Then I need to look for the next "DATA fragment" that does not occur within 20:38:16

	- The next time I see this is at 20:48:21

	- Then the next is 20:58:25

	- It seems to be happening every 10 minutes

	- Exfiltration time: 10
	
![image](https://github.com/user-attachments/assets/d90430ce-c8d4-45f9-8a99-c7acc6afc5aa)


	- There we go the lab is now complete!


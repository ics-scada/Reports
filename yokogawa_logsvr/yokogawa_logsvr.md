# Overview

In this report, we will focus on the SCADA/ICS protocol, which helps maintain efficiency, process data for smarter decisions, and communicate system issues to help reduce downtime.<br>

This Report provides:

* Mitigation details for a vulnerability affecting working status of PLC.
* Disclosure of exploit runs on ModBus protocol.
* Simulating an attack scenario against Scada Honeypot (Conpot)
* Writing IDS rules to detect attack

The module used was written Juan Vazquez (website) on 03.14.2014.

***

# Vulnerability Overview

#### Improper Input Validation

This module abuses a buffer overflow vulnerability to trigger a Denial of Service of the BKCLogSvr component in the Yokogaca CENTUM CS 3000 product.


For this, this module is a kind of Dos attack that sends crafted UDP packets.<br>


#### Vulnerability Details
A vulnerability was found in Yokogawa CENTUM CS 3000 up to R3.07 and classified as very critical. This issue affects an unknown code of the file BKCLogSvr.exe.This module abuses a buffer overflow vulnerability to trigger a Denial of Service of the BKCLogSvr component in the Yokogaca CENTUM CS 3000 product. The vulnerability exists in the handling of malformed log packets, with an unexpected long level field.<br>

 The root cause of the vulnerability is a combination of usage of uninitialized memory from the stack and a dangerous string copy.

##### Butter Overflow ?

Buffer overflow exploits are attacks that alter the flow of the application by overwriting parts of the memory. A buffer overflow is a common software flaw that results in an error. This error condition occurs when more data is written to a memory location than allocated. When memory overflows, neighboring memory regions are overwritten, causing errors or crashes. If not restricted, specially crafted input can cause a buffer overflow, causing many security issues.

When a buffer overflow corrupts the memory, the software crashes and can thus be used as an out-of-service attack.

##### _Explotability_

This vulnerability could be exploited remotely.

##### _Existence of Exploit_

Known public exploits specifically target this vulnerability.


## Impact

Sending two consecutive packets is enough to trigger the overflow and cause DoS. However, if legit packets are processed by the server, there will be no overflow between the two malformed packets. Unfortunately there is no reliable way due to the use of UDP and lack of response.
<br>
The attack may be initiated remotely. No form of authentication is needed for a successful exploitation. Technical details of the vulnerability are known, but there is no available exploit.
<br> <br>
If the attack is successful, it may be recommended to replace the affected object with an alternative product.

***

# Exploitation of Vulnerability
As we mentioned before, with this exploit; attacker can cause a denial of service of the system.

In order to exploit the vulnerability we need to download [Metasploit](https://github.com/rapid7/metasploit-framework)<br>

After downloading metasploit we can run it by typing;

```
# msfconsole
```

We can see the ModBus Frameworks' modules by typing;

```
# show all
```

```
# use /auxiliary/dos/scada/yokogawa_logsvr
```

```
# show options
```
<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/yokogawa_logsvr/img2/show_options.png">
</p>

We have checked what parameters our exploit needs to run. This exploit needs;<br>

`RHOST` = remote host ip address,<br>
```
# set RHOSTS <ip>
```

After giving the parameters which are wanted we are ready to run it.

```
# run
```

<p align="center">
  <img  src="https://github.com/ics-scada/Reports/blob/main/yokogawa_logsvr/img2/run_.png">
</p>

As you can see above, dos attack has started.

***

# Packet Analysing
Run wireshark while exploit we’ve use running behind.
You see the blue part. This packet is the packet to the modbus protocol we want to analyze.

<p align="center">
  <img width="650" height="350" src="https://github.com/ics-scada/Reports/blob/main/yokogawa_logsvr/img2/wireshark1.png">
</p>


Double-clicking on the line opens the package contents. As seen above, we can see the destination ip address, source ip address and type in the Ethernet 2 line.

<p align="center">
  <img width="650" height="350" src="https://github.com/ics-scada/Reports/blob/main/yokogawa_logsvr/img2/wireshark2.png">
</p>

IP Header holds network layer information. Of these, it keeps all the details of the IPv4 protocol, which is considered the backbone of the OSI model. There is information on the internet protocol version 4 tab above.

<p align="center">
  <img width="650" height="350" src="https://github.com/ics-scada/Reports/blob/main/yokogawa_logsvr/img2/wireshark4.png">
</p>

And finally, as you can see above, we see the package content sent in the data line. A total of ten packages are sent. The package includes the area with the blue part and the first eight numbers there |00 04 00 00| and likewise |00 00 00 00 00 00 00 00| the content is fixed in all packages. Rules will be written according to this content used in rule writing.

***

# Rules
As a result of using this module, an alarm as below was generated by the snort on the target machine.
<br>

```
alert udp $EXTERNAL_NET any -> $HOME_NET 52302 ( 
msg:"PROTOCOL-SCADA Yokogawa CENTUM CS 3000 bkclogserv buffer overflow attempt";
flow:to_server,no_stream; dsize:1024; 
content:"|00 04 00 00|",depth 4; 
content:"|00 00 00 00 00 00 00 00|",within 8,distance 12; 
content:!"|00|",within 1000; 
detection_filter:track by_dst, count 2, seconds 1; 
metadata:policy balanced-ips drop,policy max-detect-ips drop,policy security-ips drop;
reference:bugtraq,66130;
reference:cve,2014-0781;
classtype:attempted-admin;
sid:30802; rev:4; )
```
If we give a brief information about the terms in the rule above. The msg term is the message that the rule will give when it generates an alarm. The term flow allows rules to only apply to certain directions of the traffic flow. This allows rules to only apply to clients or servers. This allows packets related to $HOME_NET clients viewing web pages to be distinguished from servers running in the $HOME_NET.

```
to_server	-> Trigger on client requests from A to B
no_stream	-> Do not trigger on rebuilt stream packets (useful for dsize and stream5)
```

The dsize keyword is used to test the packet payload size. This may be used to check for abnormally sized packets that might cause buffer overflows. In the above rule, packets larger than 1024 bytes will not be accepted.

The term content is the text searched in the incoming package. As mentioned in the package analysis, there are some fixed texts in the packages sent. In the rule, these texts are sought.The depth keyword allows Snort to specify how far into a packet it should search for the specified pattern.The within keyword is a content modifier that makes sure that at most N bytes are between pattern matches using the content keyword.The distance keyword allows to specify how far into a packet Snort should ignore before starting to search for the specified pattern relative to the end of the previous pattern match.

```
content:"|00 04 00 00|",depth 4; 
content:"|00 00 00 00 00 00 00 00|",within 8,distance 12; 
content:!"|00|",within 1000;
```

Detection_filter defines a rate which must be exceeded by a source or destination host before a rule can generate an event.

```
track by_src|by_dst -> Rate is tracked either by source IP address or destination IP address.
count c -> The maximum number of rule matches in s seconds allowed before the detection filter limit to be exceeded.
seconds s -> Time period over which count is accrued.
```

The metadata tag allows  to embed additional information about the rule, typically in a key-value format. Certain metadata keys and values have meaning to Snort.

```
metadata:policy balanced-ips drop,policy max-detect-ips drop,policy security-ips drop;
reference:bugtraq,66130;
reference:cve,2014-0781;
classtype:attempted-admin;
sid:30802; rev:4;
```

The reference keyword allows rules to include references to external attack identification systems.  This plugin is to be used by output plugins to provide a link to additional information about the alert produced.

```
bugtraq	-> 'http://www.securityfocus.com/bid/'
cve -> 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-0781'
```

The classtype keyword is used to categorize a rule as detecting an attack that is part of a more general type of attack class. Snort provides a default set of attack classes that are used by the default set of rules it provides. The sid keyword is used to uniquely identify Snort rules. The rev keyword is used to uniquely identify revisions of Snort rules.

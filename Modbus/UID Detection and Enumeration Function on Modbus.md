# UID Detection and Enumeration Function on Modbus

# Overview
In this report, we will focus on modbus, the most widely used ICS/SCADA protocol. We will use Honeypot as the target.

This Report provides:
- Disclosure of exploit runs on ModBus protocol.
- Simulating an attack scenario against Scada Honeypot (Conpot)
- Modbus attack diagnostic functions in Wireshark
- Writing IDS rules to detect attack

## Vulnerability Overview
Modbus protocol defines several function codes for accessing Modbus registers. There are four different data blocks defined by Modbus, and the addresses or register numbers in each of those overlap. Therefore, a complete definition of where to find a piece of data requires both the address (or register number) and function code (or register type). In other words, it consists of the code for the function requested by the Master to send a message to the Slave.
In the module we use, it determines which services are running in these function codes. For ID detection, we can detect the device ID by applying a brute force attack.


_Explotability_

This vulnerability can be exploited both remotely and locally.

_Existence of Exploit_

It is an unmodifiable vulnerability in the Modbus protocol.

_Difficulty_

An attacker with a medium skill would be able to exploit this vulnerability.

# Affected Produtcs
All devices using the modbus protocol

# Impact
Function codes detected by using this module will reveal many things that can be done in the system. The most important of these is that the system stops or breaks down beyond repair. The stoppage of a smart factory leads to huge monetary losses.


# Exploitation of Vulnerability
It is a ready-made tool that we can perform operations such as scanning, denial of service and vulnerability scanning for ICS/Scada systems in the Smod tool.
In order to exploit the vulnerability we need to download [Smod](https://github.com/Joshua1909/smod)
After downloading smod we can run it by typing;

```sh
cd smod
sudo python smod.py
```
![Smod](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/1.PNG)

We can see the ModBus Frameworks’ modules by typing;

```sh
show modules
use modbus/scanner/getfunc
show options
```
![Smod-2](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/2.PNG)

We have checked what parameters our exploit needs to run. This exploit needs;

RHOST = remote host ip address
UID = Unit id
paramateres.
```sh
set RHOST <ip>
set UID <uid>
```
![Smod-3](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/3.PNG)

After giving the parameters which are wanted we are ready to run it.

```sh
exploit
```
![Smod-4](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/4.PNG)

Before we say exploit, we need to detect UID, and we will use the modbus/scanner/uid module in the smod tool.
```sh
use modbus/scanner/uid
show options
```
![UID-1](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/UID_1.PNG)

```sh
set RHOST <ip>
exploit
```
![alt text](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/UID_2.PNG)

After the UID detection is performed, we can return to the other operation.

For function code detection, we start the process again with the exploit command of the modbus/scanner/getfunc module and we have determined which record is running in which function code.

# Packet Analysing
We perform packet analysis from our attacker machine. Before running your module on our attacker machine, we run our wireshark tool and then run our module.

![Packet-Analysis-1](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/Packet_Analysis.PNG)

We can see how the function code 1 is detected by saying "Modbus.func_code == 1". It is possible to see this number by increasing it in other function codes.

![Packet-Analysis-2](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/Packet_Analysis_2.PNG)

Package includes "mbtcp.trans_id, mbtcp.prot_id, mbtcp.len, mbtcp.unit_id" values

![Packet-Analysis-3](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/Packet_Analysis_3.PNG)
#### MBAP (Modbus Application Protocol Header) Header Section
In Modbus TCP/IP framing, the MBAP header consists of 4 parts. The length of the MBAP header is 7 bytes. The MBAP section is for the communication function. It carries some information so that the master and slave units can communicate with each other.
##### Transaction Identifier 
It is the section that allows two devices to communicate with each other by associating the master and slave points with each other. The process descriptor part is 2 bytes long.
##### Protocol Identifier 
Designed for multiple systems. It takes the value 0 for Modbus. This area has been reserved for future use. The protocol descriptor part is 2 Bytes long.
##### Length 
The length section specifies the data length in bytes, which includes the unit descriptor section and the Modbus TCP/IP PDU sections. The length part is 2 Bytes long.
##### Unit Identifier
This field is used for routing for the system. It is used to identify the remote unit that is not on the network. The volume descriptor part is 1 Byte long.

![Modbus-Protocol](https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/UID%20Detection%20and%20Enumeration%20Function%20on%20Modbus%20Photos/Modbus_Protocol.png)

#### Modbus TCP/IP PDU Section
Modbus TCP/IP PDU section consists of 2 sections, function code and data. In Modbus TCP/IP framing, the Modbus TCP/IP PDU section basically contains the codes for the function.
##### Function Code
The function code section consists of the code for the requested function when sending a message from the master unit to the slave unit. In response to the master unit from the slave unit, it consists of the function code corresponding to the request. The length of the function code is 1 byte.
##### Data Section
The data section contains special data for the requested function when sending a message from the master unit to the slave unit. In response to the master unit from the slave unit, it consists of the response data or error codes to be sent against the request. The data section is of variable length

# Snort Rules
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read Coils Function 1 ";flow:to_server,established; classtype:attempted-recon;sid:3; content: "|01 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read Discreate Inputs Function 2 ";flow:to_server,established; classtype:attempted-recon;sid:4; content: "|02 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read Holding Registers Function 3 ";flow:to_server,established; classtype:attempted-recon;sid:5; content: "|03 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read Input Registers Function 4 ";flow:to_server,established; classtype:attempted-recon;sid:6; content: "|04 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Write Single Coil Funvtion 5 ";flow:to_server,established; classtype:attempted-recon;sid:7; content: "|05 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Write Single Registers Function 6 ";flow:to_server,established; classtype:attempted-recon;sid:8; content: "|06 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read Exception Function 7 ";flow:to_server,established; classtype:attempted-recon;sid:9; content: "|07 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Return Qery Data Function 8 ";flow:to_server,established; classtype:attempted-recon;sid:10; content: "|08 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Get Comm Event Counters Function 11 ";flow:to_server,established; classtype:attempted-recon;sid:11; content: "|0b 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Get Comm Event Log Function 12 ";flow:to_server,established; classtype:attempted-recon;sid:12; content: "|0c 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Write Multiple Coils Function 15 ";flow:to_server,established; classtype:attempted-recon;sid:13; content: "|0f 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Wrtie Multiple Registers Function 16 ";flow:to_server,established; classtype:attempted-recon;sid:14; content: "|10 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Report Slave ID Function 17 ";flow:to_server,established; classtype:attempted-recon;sid:15; content: "|11 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read File Record Function 20 ";flow:to_server,established; classtype:attempted-recon;sid:16; content: "|14 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Write File Record Function 21 ";flow:to_server,established; classtype:attempted-recon;sid:17; content: "|15 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Mask Write Registers Function 22 ";flow:to_server,established; classtype:attempted-recon;sid:18; content: "|16 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read Write Register Function 23 ";flow:to_server,established; classtype:attempted-recon;sid:19; content: "|17 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Read FIFO Queue Function 24 ";flow:to_server,established; classtype:attempted-recon;sid:20; content: "|18 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Encapsulated Interface Transport Function 43 ";flow:to_server,established; classtype:attempted-recon;sid:21; content: "|2b 00 00 00 01|";)
alert tcp $EXTERNAL_NET any -> $HOME_NET 502(msg:"[Possible Unauthorized Request] Modbus Unity (Schneider) Function 90 ";flow:to_server,established; classtype:attempted-recon;sid:22; content: "|5a 00 00 00 01|";) 
```

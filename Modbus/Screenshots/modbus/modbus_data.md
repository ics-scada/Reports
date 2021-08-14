# Modbus

The Modbus communications protocol is the networking granddaddy of the industry. Modbus has stood the test of time and is still being used in a wide range of applications, including industrial automation, process control, building automation, transportation, energy, and remote monitoring.

Modbus is a serial communication protocol developed by Modicon published by Modicon® in 1979 for use with its programmable logic controllers (PLCs). In simple terms, it is a method used for transmitting information over serial lines between electronic devices. The device requesting the information is called the Modbus Master and the devices supplying information are Modbus Slaves. In a standard Modbus network, there is one Master and up to 247 Slaves, each with a unique Slave Address from 1 to 247. The Master can also write information to the Slaves.

### What is it used for?

Modbus is an open protocol, meaning that it's free for manufacturers to build into their equipment without having to pay royalties. It has become a standard communications protocol in industry, and is now the most commonly available means of connecting industrial electronic devices. It is used widely by many manufacturers throughout many industries.Modbus is typically used to transmit signals from instrumentation and control devices back to a main controller or data gathering system, for example a system that measures temperature and humidity and communicates the results to a computer. Modbus is often used to connect a supervisory computer with a remote terminal unit (RTU) in supervisory control and data acquisition (SCADA) systems. Versions of the Modbus protocol exist for serial lines (Modbus RTU and Modbus ASCII) and for Ethernet (Modbus TCP).

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus/modbus-master-slave.jpg">
</p>

***

### How does it work?

Modbus is transmitted over serial lines between devices. The simplest setup would be a single serial cable connecting the serial ports on two devices, a Master and a Slave. 

As already noted, Modbus is a simple master-slave protocol. The master has full control of communication on the bus, whereas a slave will only respond when spoken to. The master will record outputs and read in inputs from each of its slaves, during every cycle.

The slave devices do not “join” the network. They simply respond whenever a master talks to them. If the master never talks to them, then they are idle.  There is also no requirement for diagnostics related to the slave’s health. If the master requests data that does not make sense to the slave, then the slave can send an exception response.

However, if the process variable is bad or if the device has problems functioning, there is nothing in the protocol that requires the slave to report this.


<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus/instrumentationtools.com_modbus-scan.jpg">
</p>



The term “Modbus” typically refers to one of three related protocols: Modbus ASCII, Modbus RTU, or Modbus TCP/IP.

##### Modbus ASCII
Modbus ASCII was the first Modbus and is a serial protocol, typically running on either the RS-232 or RS-485 physical layer. All slaves are polled on demand by the master, and there is only one master. The message frame can be up to 252 bytes in length, and up to 247 addresses are possible. The message frame and function codes, shown in down, are very simple.

##### Modbus RTU
Modbus RTU is really just a small variation on the Modbus ASCII protocol. The only difference is in the encoding of the data. ASCII encodes the message in ASCII characters, while RTU uses bytes, thus increasing the protocol’s throughput. In general, RTU is more popular, particularly in new installations.

##### Modbus TCP
Modbus TCP/IP was added much later. One simple way of thinking about Modbus TCP/IP is to picture it as simply encapsulating a Modbus RTU packet within a TCP/IP packet. There is a bit more to it than that, but this is essentially what Modbus did. As a result, Modbus TCP/IP is also very simple to implement. The tradeoff is that, because it uses TCP/IP protocol for all messages, it is slow compared to other Ethernet industrial protocols – but still fast enough for monitoring applications.

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus/instrumentationtools.com_modbus-function-codes.jpg">
</p>

##### What is the Slave ID?

Each slave in a network is assigned a unique unit address from 1 to 247. When the master requests data, the first byte it sends is the Slave address. This way each slave knows after the first byte whether or not to ignore the message. 

##### What is a function?

The second byte sent by the Master is the Function code. This number tells the slave which table to access and whether to read from or write to the table.

##### What is CRC

CRC stands for Cyclic Redundancy check. It is two bytes added to the end of every modbus message for error detection. Every byte in the message is used to calculate the CRC. The receiving device also calculates the CRC and compares it to the CRC from the sending device. If even one bit in the message is received incorrectly, the CRCs will be different and an error will result. 

##### What is Modbus TCP gateway?

The Modbus TCP Gateway is the device that will bridge the gap between the Modbus TCP protocols to the traditional Modbus Serial protocols.

The gateway works like a relay device where it takes the requests from the TCP (Ethernet) side and then passes it off onto the Gateway’s serial side. Please note with this device the existing limitations such as Modbus Slaves daisy chained remains at 31 devices.

##### What is a Modbus map?

A modbus map is simply a list for an individual slave device that defines - what the data is (eg. pressure or temperature readings)

- where the data is stored (which tables and data addresses)

- how the data is stored (data types, byte and word ordering)

Some devices are built with a fixed map that is defined by the manufacturer. While other devices allow the operator to configure or program a custom map to fit their needs.

***

### How is data stored in Standard Modbus?

Information is stored in the Slave device in four different tables. Two tables store on/off discrete values (coils) and two store numerical values (registers). The coils and registers each have a read-only table and read-write table. Each table has 9999 values. Each coil or contact is 1 bit and assigned a data address between 0000 and 270E. Each register is 1 word = 16 bits = 2 bytes and also has data address between 0000 and 270E.

<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus/servlet.jpg">
</p>

Coil/Register Numbers can be thought of as location names since they do not appear in the actual messages. The Data Addresses are used in the messages. For example, the first Holding Register, number 40001, has the Data Address 0000. The difference between these two values is the offset. Each table has a different offset. 1, 10001, 30001 and 40001.

***

### The physical layer for Modbus

Modbus ASCII and RTU both typically use either the RS-232 or RS-485 physical layer, but can also use other physical layers such as phone lines or wireless.  Recommended Standards (RS) 232 and 485 were established physical layers when Modbus was first developed. RS-232 is for point-to-point, while RS-485 is for multi-drop applications.

In both cases, Modbus did not add any new requirements to these physical layers.   This worked, but it has caused a few problems in the case of RS-485. The problem is that the physical layer has a number of variations: 2-wire, 4-wire, use of common and variations in drivers and grounding methods.

Anyone who has worked with Modbus on RS-485 from multiple vendors will already know how to manage all the variations when connecting two types in a point-to-point configuration. The difficulty comes when the site is multi-vendor and several variations have to be combined on one cable.

There are a number of standards for both phone lines and for wireless. Modbus has excelled in these applications because of the small number of timing constraints in the protocol. Phone lines as well as wireless modems introduce delays in messages. Sometimes these delays are non-linear throughout the message, which can cause real problems for many protocols.

However, Modbus either does not have a problem with this, or it can be adapted so that it will work in these applications.

***

### Modbus PDU and ADU

You can implement MODBUS over several different types of busses and networks, but there is one core component of MODBUS protocol that is used in all of them.  This piece is referred to as the Protocol Data Unit (PDU).   When speaking of MODBUS in general, the PDU is the entirety of the protocol.  The PDU consist of a function code and data.

MODBUS can be used over nearly all busses and networks, however the most common two are Ethernet (TCP/IP) and Serial (RS232, RS485, RS422, etc.).  There are specifications for both MODBUS/TCP and MODBUS serial.  MODBUS/RTU is the most commonly used serial MODBUS protocol.  There is also a less common ASCII version.


<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Modbus/Screenshots/modbus/MODBUS-Frame.png">
</p>

The difference between MODBUS/TCP and MODBUS/RTU is mostly in the transport frames or the wrapper around the PDU.   In both forms of MODBUS, application specific addressing and error checking are attached to the PDU to make the Application Data Unit (ADU).  In MODBUS/TCP the ADU is encapsulated in a TCP packet.  The TCP protocol handles the error checking, which is why it is omitted from the MODBUS/TCP ADU.

MODBUS/RTU Serial – Slave ID and CRC
Slave ID - 1 byte.  Identifies which slave device receives the request.
CRC – 2 bytes.  Insures that the correct amount of bytes were sent and received.

MODBUS/TCP – MODBUS Application Protocol (MBAP)
Transaction Identifier - 2 bytes.  Helps identify each request/response pair when several responses are expected.







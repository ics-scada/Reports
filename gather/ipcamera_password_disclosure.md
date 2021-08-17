# VANDERBILT INDUSTRIES SIEMENS IP CCTV CAMERAS VULNERABILITY

## OVERVIEW

Siemens reports that there is a vulnerability in Siemens-branded IP cameras from Vanderbilt Industries. Vanderbilt has released updates to mitigate this vulnerability.
This vulnerability could be exploited remotely.

# Affected Products

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


# IMPACT
-------------------------------------------------------------------

# Exploitation

We are going to use gather/ipcamera_password_disclosure exploit from metasploit framework.

# What does this exploit do?

SIEMENS IP-Camera (CVMS2025-IR + CCMS2025), JVC IP-Camera (VN-T216VPRU), and Vanderbilt IP-Camera (CCPW3025-IR + CVMW3025-IR) allow an unauthenticated user to disclose the username & password by requesting the javascript page 'readfile.cgi query=ADMINID'. 
Siemens firmwares affected: 
* x.2.2.1798 
*  CxMS2025_V2458_SP1 
*  x.2.2.1798, x.2.2.1235

DICOM-Scan - for identifying medical imaging devices
========

Python-based DICOM scanner -- scans a bunch of computers and tries to determine if its a DICOM medical imaging device.


Lesson Learned
===

DICOM C-language communications generally requires knowledge of the Application Entity Title, but thanks to a library from scaramallion was able to discover that a specific SOP UID could also be used to authenticate.
Note that despite the common DICOM ports, many DICOM providers mask the ports to something else for security through obscurity purposes.  Also note that the pynetdicom3 library has availability of utilizing UIDs instead
of actual AET names which is very helpful since most AET are not known and I have not found a known dictionary of them anywhere.

Note:  This has been tested against an actual DICOM device and successfully identified and authenticated to the device with a C-Echo command.

Example:

```bash
root@docker# ./dicomscanner.py -ip 192.168.10.5
attempting to scan 192.168.10.5
root@docker#
```

```
root@docker# ./smbscanner.py -ip 192.168.10.5
attempting to scan 192.168.10.5
```

In the event that the port is not DICOM, the scanner should attempt a banner grab to try to find out what it is.  Often times, it could be the web wrapper of the DICOM provider in which case you may get a "PDU" output message
as well as a time out message.

If you use the "-results_file" flag, you should get a nice parseable output:

The file should look like the following:

Dependencies:
=============

https://github.com/pydicom/pydicom.git

https://github.com/scaramallion/pynetdicom3.git

Usage:
======

```bash
./dicomscanner.py -h
```

DICOM Checker
  
Example
===

```bash
./dicomscanner.py -ip 192.168.10.5 -port 1104

./dicomscanner.py -netrange 192.168.10.0/24 -port 1104 -results_file results.txt
```

Bugs
====

- suppress PDU error message output to a handler
- suppress and/or redirect a bunch of stdout messages

TODO
===

- add the abiltity to read target files.
- maybe later add other C-language DICOM communication types, but for now not going to do it. :)
If you find other bugs that I haven't mentioned, please report them to gmail (rlastinger) or create a ticket, and I will get to it when I can.  

Help or improvement suggestions are also welcome.  Just email me at gmail (rlastinger).
Enjoy.

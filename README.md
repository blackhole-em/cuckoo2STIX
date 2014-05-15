cuckoo2STIX
===========


A python script to auto-generate STIX content from Cuckoo's reports stored in Mongodb

Dependencies:
pymongo
stix
libtaxii

Code was tested on Python 2.7 with pymongo 2.6.3, stix 1.1.0.4, libtaxii 1.1.101.

Layout:
app.conf - Application configuration settings.
cuckoo2Stix.py - Generates STIX content from Mongodb.
fHostNames.txt - Input file - Whitelist of host names for suppression, one item per line, can be an empty file.
fIpv4Addresses.txt - Input file - Whitelist of IP addresses for suppression, one item per line, can be an empty file.
fSeenEntries.txt - Previously generated items, written by cuckoo2Stix.py, and read in subsequent runs so that duplicate items are not generated. 
log.py - Logger
logs/ - default logs directory
output/ - default output directory
taxiiUpload.py - Sample script to upload TAXII content for a given STIX document

Usage Examples:
Generate STIX for a Cuckoo job id 5555:
$ ./cuckoo2Stix.py --job-id 5555

Generate STIX for all current Cuckoo reports:
$ ./cuckoo2Stix.py

Upload a STIX doc:
$ ./taxiiUpload.py --content-file output/2014-05-14_154234-43e0a2f16464e9dc1922fb8bba7a2750be4bb149.stix.xml

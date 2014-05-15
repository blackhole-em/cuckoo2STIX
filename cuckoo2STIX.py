#!/usr/bin/env python2.7
"""
Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Use at your own risk.

Bug fixes/feature improvements/request - please email: blackhole.em@gmail.com

"""
import sys
import os
import pymongo
import ConfigParser
import argparse
import time
import datetime
import re
import string
from stix.core import STIXPackage, STIXHeader
from stix.indicator import Indicator
from stix.ttp import TTP, Behavior
from stix.common.related import RelatedTTP
from stix.ttp.malware_instance import MalwareInstance
import stix.utils
from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.file_object import File
from cybox.common import Hash
import cybox.utils
import log

_l = log.setup_custom_logger('root')

def reFileName(str_):
    """
    Extract file name and prefix from string based on known patterns,
    otherwise leave the file name as is, and the prefix will be 'None'.
    """
    rv = 'None', str_
    m = re.match(r'((?:[a-zA-Z0-9-]){4,})_(.*)$', str_)
    if m:
        rv = m.group(1), m.group(2)
    else:
        m = re.match(r'(\d+-\d+)\.-\.(.*)$', str_)
        if m:
            rv = m.group(1), m.group(2)
    return rv

def fixAddressObject(xml_):
    """
    Search and replace address object tag when there are multiple items in the 
    list, since can't figure out how to do the same using the library. If the 
    address is a single value or there is no address at all, leave alone.
    """
    rv = xml_
    m = re.search(r'(.*<AddressObj:Address_Value condition="Equals")>(.*comma.*)(<.*)', xml_, re.DOTALL)
    if m:
        rv = m.group(1) + ' apply_condition="ANY">' + m.group(2) + m.group(3)
    return rv
    
def fixDomainObject(xml_):
    """
    Search and replace domain name object tag when there are multiple items in the 
    list, since can't figure out how to do the same using the library. If the 
    domain name is a single value or there is no domains at all, leave alone.
    """
    rv = xml_
    m = re.search(r'(.*<DomainNameObj:Value)>(.*comma.*)(<.*)', xml_, re.DOTALL)
    if m:
        rv = m.group(1) + ' condition="Equals" apply_condition="ANY">' + m.group(2) + m.group(3)
    return rv

def genStixDoc(
        outputDir_,
        targetFileSha1_,
        targetFileSha256_,
        targetFileSha512_,
        targetFileSsdeep_,
        targetFileMd5_,
        targetFileSize_,
        targetFileName_,
        ipv4Addresses_,
        hostNames_):
    """
    Generate Stix document from the input values. The doc structure is the file
    object along with the related network items: addresses, domain names. Output
    is written to files, which are then wrapped with taxii and uploaded using a 
    separate script.
    """
    parsedTargetFileName = reFileName(targetFileName_)[1]
    parsedTargetFilePrefix = reFileName(targetFileName_)[0]
    stix.utils.set_id_namespace({"http://www.equifax.com/cuckoo2Stix" : "cuckoo2Stix"})
    NS = cybox.utils.Namespace("http://www.equifax.com/cuckoo2Stix", "cuckoo2Stix")
    cybox.utils.set_id_namespace(NS)
    stix_package = STIXPackage()

    stix_header = STIXHeader()
    stix_header.title = 'File: ' + parsedTargetFileName + ' with the associated hashes, network indicators'
    stix_header.description = 'File: ' + parsedTargetFileName + ' with the associated hashes, network indicators'
    stix_package.stix_header = stix_header

    # Create the ttp
    malware_instance = MalwareInstance()
    malware_instance.add_name(parsedTargetFileName)
    malware_instance.description = targetFileSha1_
    ttp = TTP(title='TTP: ' + parsedTargetFileName)
    ttp.behavior = Behavior()
    ttp.behavior.add_malware_instance(malware_instance)
    stix_package.add_ttp(ttp)
    
    # Create the indicator for the ipv4 addresses
    ipv4Object = Address(ipv4Addresses_, Address.CAT_IPV4)
    ipv4Object.condition = 'Equals'
    ipv4Indicator = Indicator()
    ipv4Indicator.title = parsedTargetFileName + ': ipv4 addresses'
    ipv4Indicator.add_indicator_type('IP Watchlist')
    ipv4Indicator.add_indicated_ttp(RelatedTTP(TTP(idref=ttp.id_), relationship='Indicates Malware'))
    ipv4Indicator.observable = ipv4Object
    ipv4Indicator.confidence = 'Low'
    
    # Create the indicator for the domain names
    domainNameObject = DomainName()
    domainNameObject.value = hostNames_
    domainNameObject.condition = 'Equals'
    domainNameIndicator = Indicator()
    domainNameIndicator.title = parsedTargetFileName + ': domain names'
    domainNameIndicator.add_indicator_type('Domain Watchlist')
    domainNameIndicator.add_indicated_ttp(RelatedTTP(TTP(idref=ttp.id_), relationship='Indicates Malware'))
    domainNameIndicator.observable = domainNameObject
    domainNameIndicator.confidence = 'Low'

    # Create the indicator for the file
    fileObject = File()
    fileObject.file_name = parsedTargetFileName
    fileObject.file_name.condition = 'Equals'
    fileObject.size_in_bytes = targetFileSize_
    fileObject.size_in_bytes.condition = 'Equals'
    fileObject.add_hash(Hash(targetFileSha1_, type_='SHA1', exact=True))
    fileObject.add_hash(Hash(targetFileSha256_, type_='SHA256', exact=True))
    fileObject.add_hash(Hash(targetFileSha512_, type_='SHA512', exact=True))
    fileObject.add_hash(Hash(targetFileSsdeep_, type_='SSDEEP', exact=True))
    fileObject.add_hash(Hash(targetFileMd5_, type_='MD5', exact=True))
    fileIndicator = Indicator()
    fileIndicator.title = parsedTargetFileName + ': hashes'
    fileIndicator.description = parsedTargetFilePrefix
    fileIndicator.add_indicator_type('File Hash Watchlist')
    fileIndicator.add_indicated_ttp(RelatedTTP(TTP(idref=ttp.id_), relationship="Indicates Malware"))
    fileIndicator.observable = fileObject
    fileIndicator.confidence = 'Low'
    
    stix_package.indicators = [fileIndicator, ipv4Indicator, domainNameIndicator]

    stagedStixDoc = stix_package.to_xml()
    stagedStixDoc = fixAddressObject(stagedStixDoc)
    stagedStixDoc = fixDomainObject(stagedStixDoc)
    today = datetime.datetime.now()
    now = today.strftime('%Y-%m-%d_%H%M%S')
    if not os.path.exists(outputDir_):
        os.makedirs(outputDir_)
    with open (outputDir_ + '/' + now + '-' + targetFileSha1_ + '.stix.xml', 'a') as myfile:
        myfile.write(stagedStixDoc)
    _l.debug('Wrote file: ' + now + '-' + targetFileSha1_ + '.stix.xml')
    return

def main():
    """
    Retrieve network indicators from mongodb, used by cuckoo. Pass to genStixDoc 
    to create the stix doc. Handle de-dup and filter lists for indicators, as 
    well as stix items created in previous runs.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--job-id', dest='jobId', default='', help='Optional - specific job id to pull.')
    config = ConfigParser.ConfigParser()
    args = parser.parse_args()
    config.read('app.conf')
    conn = pymongo.MongoClient(config.get('mongo','dbUrl'))
    with open(config.get('filterOut','fIpv4Addresses')) as fIpv4AddressesFH:
                fIpv4Addresses = [line.rstrip('\n') for line in fIpv4AddressesFH]
    fIpv4AddressesFH.closed
    with open(config.get('filterOut','fHostNames')) as fHostNamesFH:
                fHostNames = [line.rstrip('\n') for line in fHostNamesFH]
    fHostNamesFH.closed
    with open(config.get('filterOut','fSeenEntries')) as fSeenEntriesFH:
                fSeenEntries = [line.rstrip('\n') for line in fSeenEntriesFH]
    fSeenEntriesFH.closed

    ipv4Addresses = []
    hostNames = []
    _l.info('Starting...')

    fSeenEntriesFH = open(config.get('filterOut','fSeenEntries'), 'a', 0)
   
    for dbs in config.get('dbsList','cuckoo').split(','):
        db = conn[dbs]
        db_name = config.get('dbName')
        mongo_collection = getattr(db, db_name)
        _l.debug('Connected to data source.')

        # Get a list of file names and hashes from db
        if args.jobId is '':
            cs = mongo_collection.aggregate([{"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                         "targetFileSha256": "$target.file.sha256",
                                                         "targetFileSha512": "$target.file.sha512",
                                                         "targetFileSsdeep": "$target.file.ssdeep",
                                                         "targetFileMd5": "$target.file.md5",
                                                         "targetFileSize": "$target.file.size",
                                                         "targetFileName": "$target.file.name"}}}])
        else:
            cs = mongo_collection.aggregate([{"$match": {"info.id": int(args.jobId)}},
                                                {"$group": {"_id": {"targetFileSha1": "$target.file.sha1",
                                                 "targetFileSha256": "$target.file.sha256",
                                                 "targetFileSha512": "$target.file.sha512",
                                                 "targetFileSsdeep": "$target.file.ssdeep",
                                                 "targetFileMd5": "$target.file.md5",
                                                 "targetFileSize": "$target.file.size",
                                                 "targetFileName": "$target.file.name"}}}])
        _l.debug('Executed initial aggregation query.')
        for i in cs['result']:
            # Get everything that looks like an ip address
            ipv4Addresses[:] = []
            hostNames[:] = []
            networkUdpSrc = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.udp.src')
            networkUdpDst = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.udp.dst')
            networkIcmpSrc = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.icmp.src')
            networkIcmpDst = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.icmp.dst')
            networkTcpSrc = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.tcp.src')
            networkTcpDst = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.tcp.dst')
            networkDnsAnswersData = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.dns.answers.data')
            networkDomainsIp = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.domains.ip')
            # Aggregate all addresses and remove duplicates and filtered ones
            ipv4Addresses += networkUdpSrc + networkUdpDst + networkIcmpSrc + networkIcmpDst + \
                networkTcpSrc + networkTcpDst + networkDnsAnswersData + networkDomainsIp
            ipv4Addresses = list(set(ipv4Addresses))
            ipv4Addresses = filter(None, ipv4Addresses)
            ipv4Addresses = list(set(ipv4Addresses) - set(fIpv4Addresses))

            # Get everything that looks like a domain name
            networkHttpHost = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.http.host')
            networkHosts = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.hosts')
            networkDnsRequest = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.dns.request')
            networkDomainsDomain = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('network.domains.domain')
            # Aggregate all addresses and remove duplicates and filtered ones
            hostNames += networkHttpHost + networkHosts + \
                networkDnsRequest + networkDomainsDomain
            hostNames = list(set(hostNames))
            hostNames = filter(None, hostNames)
            hostNames = list(set(hostNames) - set(fHostNames))
            # Get file names
            targetFileName = mongo_collection.find(
                {
                    "target.file.sha1": i['_id']['targetFileSha1'],
                    "target.file.sha256": i['_id']['targetFileSha256'],
                    "target.file.sha512": i['_id']['targetFileSha512'],
                    "target.file.ssdeep": i['_id']['targetFileSsdeep'],
                    "target.file.md5": i['_id']['targetFileMd5'],
                    "target.file.size": i['_id']['targetFileSize'],
                    "target.file.name": i['_id']['targetFileName']}).distinct('target.file.name')
           
            # Call the function to create the output, check if seen before first
            if str(i['_id']['targetFileSha1']) + ',' + \
                str(i['_id']['targetFileSha256']) + ',' + \
                str(i['_id']['targetFileSha512']) + ',' + \
                str(i['_id']['targetFileSsdeep']) + ',' + \
                str(i['_id']['targetFileMd5']) + ',' + \
                str(i['_id']['targetFileSize']) not in str(fSeenEntries):
                    if ipv4Addresses or hostNames:
                        genStixDoc(config.get('output','outputDir'),
                                   str(i['_id']['targetFileSha1']),
                                   str(i['_id']['targetFileSha256']),
                                   str(i['_id']['targetFileSha512']),
                                   str(i['_id']['targetFileSsdeep']),
                                   str(i['_id']['targetFileMd5']),
                                   str(i['_id']['targetFileSize']),
                                   i['_id']['targetFileName'],
                                   ipv4Addresses,
                                   hostNames)
                        # Write to file so that we can read back in as filter later
                        fSeenEntriesFH.write(str(i['_id']['targetFileSha1']) + ',' + \
                            str(i['_id']['targetFileSha256']) + ',' + \
                            str(i['_id']['targetFileSha512']) + ',' + \
                            str(i['_id']['targetFileSsdeep']) + ',' + \
                            str(i['_id']['targetFileMd5']) + ',' + \
                            str(i['_id']['targetFileSize']) + '\n')
                        _l.debug('Updated SeenEntries file with: ' + \
                            str(i['_id']['targetFileSha256']) + ',' + \
                            str(i['_id']['targetFileSha512']) + ',' + \
                            str(i['_id']['targetFileSsdeep']) + ',' + \
                            str(i['_id']['targetFileMd5']) + ',' + \
                            str(i['_id']['targetFileSize']) + \
                            ' since content has been written to stix file.\n')
        conn.disconnect()
    fSeenEntriesFH.closed
    _l.info('Ended.')

if __name__ == "__main__":
    main()

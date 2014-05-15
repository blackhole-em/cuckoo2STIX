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
import argparse
import ConfigParser
import libtaxii as t
import libtaxii.messages_11 as tmsg
import libtaxii.clients as tc
import log

_l = log.setup_custom_logger('root')
stixContent = ''

def main():
    config = ConfigParser.ConfigParser()
    config.read('app.conf')
    dstHost = config.get('taxii', 'dstHost')
    dstPort = config.get('taxii', 'dstPort')
    dstPath = config.get('taxii', 'dstPath')
    username = config.get('taxii', 'username')
    password = config.get('taxii', 'password')

    parser = argparse.ArgumentParser(description="Inbox Client")
    parser.add_argument("--host", dest="host", default=dstHost, help="Host where the Inbox Service is hosted. Defaults to " + dstHost)
    parser.add_argument("--port", dest="port", default=dstPort, help="Port where the Inbox Service is hosted. Defaults to " + dstPort)
    parser.add_argument("--path", dest="path", default=dstPath, help="Path where the Inbox Service is hosted. Defaults to " + dstPath)
    parser.add_argument("--content-binding", dest="content_binding", default=t.CB_STIX_XML_11, help="Content binding of the Content Block to send. Defaults to %s" % t.CB_STIX_XML_11 )
    parser.add_argument("--content-file", dest="content_file", default=stixContent, help="File name of the Content Block to send. Required.")

    args = parser.parse_args()
    if args.content_file is '':
        parser.print_help()
        sys.exit(1)

    _l.info('Starting...')
    c = open(args.content_file, 'r')
    
    cb = tmsg.ContentBlock(tmsg.ContentBinding(args.content_binding), c.read())
    c.close()
    taxiiMsg = tmsg.InboxMessage(message_id = tmsg.generate_message_id(), content_blocks=[cb])
    taxiiMsgXml = taxiiMsg.to_xml()

    # send it
    _l.debug('Uploading content.')
    client = tc.HttpClient()
    client.setProxy('noproxy')
    client.setAuthType(tc.HttpClient.AUTH_BASIC)
    client.setAuthCredentials({'username':username, 'password':password})
    resp = client.callTaxiiService2(args.host, args.path, t.VID_TAXII_XML_11, taxiiMsgXml, args.port)
    response_message = t.get_message_from_http_response(resp, '0')
    _l.debug('Response was: ' + response_message.to_xml())
    _l.info('Ended.')

if __name__ == "__main__":
    main()

#!/usr/bin/env python
'''
#**************************************************************************
# PostXML.py
#
# Copyright (c) 2005-2012 Alcatel-Lucent. All Rights Reserved.
#
#**************************************************************************

@author: NSM NDE - SAM TEC - jusheppa

'''
import httplib
import re
import sys
import socket
import logging.handlers
import os
import traceback

class PostXML(Exception):

    PING = """
<ping xmlns="xmlapi_1.0"/>
"""

    XML_SOAP_TEMPLATE = """
<SOAP:Envelope xmlns:SOAP="http://schemas.xmlsoap.org/soap/envelope/">
<SOAP:Header>
<header xmlns="xmlapi_1.0">
<security>
<user>%(username)s</user>
<password hashed="%(hashed_password)s">%(password)s</password>
</security>
</header>
</SOAP:Header>
<SOAP:Body>
%(soap_body)s
</SOAP:Body>
</SOAP:Envelope>"""

    def __init__(self, configPath=None, logger=None):
        if configPath is not None:
            SAMODict = self._parse_config(configPath)
        else:
            SAMODict = self._parse_config('PostXML.cfg')

        if logger is not None:
            self.logger = logger
        else:
            self.logger = self._init_logger(SAMODict)

        self.logger.debug("Init PostXML")

        self.username = SAMODict['username']
        self.password = SAMODict['password']
        self.hashed_password = str(SAMODict['hashed_password']).lower()

        self.XMLTemplate = self.XML_SOAP_TEMPLATE
        self.dict = SAMODict

        self.sam1 = SAMODict['SamUrl1']
        self.sam2 = SAMODict['SamUrl2']
        
        if 'sam' in SAMODict:
            self.logger.debug("The active server is already defined")
            self.server = SAMODict['sam']
        else:
            self.logger.debug("The active server NEEDS to be defined")
            self.get_activeSAM()
               

    def get_activeSAM(self):
        self.logger.debug("Checking who is the active server")
        
        self.server = self.sam1
        self.xml_request(self.PING)
        #checking if the 1st server is available
        if not self.response or self.status != 200:
                self.server = self.sam2
                self.xml_request(self.PING)
                if not self.response or self.status != 200:
                    self.logger.info("No servers are available, shutting down")
                    self.logger.error("No servers available")
        
        self.dict['sam'] = self.server
                
        
    def _post_xml(self, xml):
        self.xml = xml       
        self.error_message = ''

        self.logger.debug("Creating the socket to %s" % (self.server))
        self.logger.debug("python version %s" % (sys.hexversion))

        if self.dict['IsSSL']:
           # self.logger.debug("SSL Enabled - Using HTTPS")
            if sys.hexversion > 0x2060000:
                connection = httplib.HTTPSConnection(self.server, 8443, timeout=120)
            else:
                connection = httplib.HTTPSConnection(self.server, 8443)
        else:
            if sys.hexversion > 0x2060000:
                connection = httplib.HTTPConnection(self.server, 8080, timeout=120)
            else:
                connection = httplib.HTTPConnection(self.server, 8080)

        self.logger.debug("About to send the request to  %s" % (self.server))
        self.logger.debug("Sending the following %s" % (self.xml))
        try :
            connection.request("POST", "/xmlapi/invoke", self.xml, {'Content-type': 'text/xml'})
            conn = connection.getresponse()
            self.response = conn.read()
            self.status = conn.status
            self.logger.debug("got the following response %s" % (self.response))
            
            if conn.status != 200:
                self.error_message = "Connection error - %s" % self.status
                #TODO:add verbose - check OSS Management privileges
                self.logger.error("Error in response. Information below:")
                self.logger.error(self.error_message)
                self.logger.error(self.server)
                self.logger.error(self.response)
                self.logger.error(conn.getheaders())
            if re.search("<result></result>", self.response):
                self.error_message = "Empty SAM-O response"
                self.status = 500
                self.logger.error(self.error_message)
            if re.search('faultstring', self.response):
                soap_error = re.search('<faultstring>(.*)</faultstring>', self.response).group(1)
                self.error_message = "Fault: %s" % soap_error
                self.status = 500
                self.logger.error(self.error_message)                

            connection.close()
            return self.status == 200

        except socket.error, e:
            self.logger.error("Problem with the server %s\n%s" % (self.server, e))
            self.response = False
            self.status = 404
            self.error_message = "Problem with server %s" % self.server
            self.error = e
            connection.close()
            return self.status == 200

        return self.status == 200
    

    def __build_soap_request(self, soap_body):
        self.logger.debug("Building SOAP request")
        return self.XML_SOAP_TEMPLATE % {
            'username': self.username,
            'password': self.password,
            'hashed_password': self.hashed_password,
            'soap_body': soap_body,
            }

    def _init_logger(self, config):
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)
        if not os.path.exists(config['logFolder']):
            os.makedirs(config['logFolder'])
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        fh = logging.handlers.RotatingFileHandler(config['logFolder']+"osslog.log", maxBytes=5242880, backupCount=100)
        # ch = logging.StreamHandler()

        fh.setLevel(logging.DEBUG)
        # ch.setLevel(logging.INFO)

        fh.setFormatter(formatter)
        logger.addHandler(fh)

        # ch.setFormatter(formatter)
        # logger.addHandler(ch)
        return logger

    def _parse_config(self, path):
        config = {}
        try:
            exec(open(path).read())
        except:
            print 'Failed to parse config file, exiting.'
            traceback.print_exc()
            exit(0)
        return config

    def xml_request(self, xml):
        return self._post_xml(self.__build_soap_request(xml))

if __name__ == "__main__":
    pass


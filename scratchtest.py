import xml.etree.ElementTree as ET
import copy
import sys
import os
import subprocess
import re
import libvirt

s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
vsrname = s.read().split()
if len(vsrname) > 1:
    for i in vsrname[1:len(vsrname)]:
        conn1 = libvirt.openReadOnly(None)
        if conn1 == None:
            print 'Failed to open connection to the hypervisor'
            sys.exit(1)
        try:
            dom_i = conn1.lookupByName(i)
        except:
            print 'Failed to find the main domain'
            sys.exit(1)

        raw_xml_i = dom_i.XMLDesc(0)
        iroot = ET.fromstring(raw_xml_i)
        ipaddress_i = re.split(':|=|/', iroot[6][0][0].text)[2]
        print ipaddress_i

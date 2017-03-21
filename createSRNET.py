import os
import sys
import re
import shutil
import socket, struct
from subprocess import PIPE
import subprocess
import xml.etree.ElementTree as ET
from PostXML import PostXML
import libvirt
import copy
from netmiko import ConnectHandler
from xml.dom import minidom
from jinja2 import Environment, FileSystemLoader

'''
Function to delete the vSRs created. This function deletes every virtual SR present on the BOX
'''


# ET.register_namespace("", "xmlapi_1.0")
def destroyvSR():
    s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
    vsrname = s.read().split()
    print len(vsrname)
    if len(vsrname) > 1:
        for i in vsrname[1:len(vsrname)]:
            os.system('virsh destroy %(i)s' % locals())
            os.system('virsh undefine %(i)s' % locals())
            rem_file = '/root/vsrxml/' + str(i) + '.xml'
            rem_os = '/var/lib/libvirt/images/' + str(i) + '.qcow2'
            print rem_file
            os.system('rm -f %(rem_file)s' % locals())
            os.system('rm -f %(rem_os)s' % locals())


def createBridges():
    bridge_no = int(raw_input("\nNumber of Virtual bridges to create: "))
    bridge_name_prefix = raw_input("\nEnter the prefix name of the Bridge: ")
    for x in xrange(bridge_no):
        bridge_name = bridge_name_prefix + str(x + 1)
        os.system('brctl addbr %(bridge_name)s' % locals())
        os.system('ifconfig %(bridge_name)s up' % locals())


def showBridges():
    print os.system('brctl show')


def basicSRConfig():
    s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
    vsrname = s.read().split()
    ipaddress_i = []
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
            ipaddress_i.append(re.split(':|=|/', iroot[6][0][0].text)[2])
            #print ipaddress_i

    for i in range(1,len(vsrname)):
        systemname = vsrname[i]
        ip_addr =  ipaddress_i[i-1]

        device = {
            'device_type': 'alcatel_sros',
            'ip': ip_addr,
            'username': 'admin',
            'password': 'admin',
            'port': 22,
        }
        systemnamecmd = "/configure system name" + " " + systemname
        systemaddr = "/configure router interface system address" + " " + ip_addr + "/32"

        net_connect = ConnectHandler(**device)
        config_commands = ['/configure system snmp packet-size 9216',
                           '/configure system security snmp community private rwa version both',
                           '/configure system snmp no shutdown', '/configure system security telnet-server',
                           '/configure system security ftp-server', '/configure system security user admin access ftp snmp',
                           '/bof persist on', '/bof save', '/admin save','/configure card 1',
        '/card-type iom3-xp-b',
        '/mda 1',
        '/mda-type m5-1gb-sfp-b',
        '/no shutdown',
        '/exit',
        '/mda 2',
        '/mda-type m20-1gb-sfp',
        '/no shutdown',
        '/exit',
        '/no shutdown',
        '/exit all',
        '/configure port 1/1/1 no shutdown',
        '/configure port 1/1/2 no shutdown',
        '/configure port 1/1/3 no shutdown',
        '/configure port 1/1/4 no shutdown',
        '/configure port 1/1/5 no shutdown',
        '/admin save']
        config_commands.insert(0,systemnamecmd)
        config_commands.insert(0, systemaddr)

        print config_commands

        output = net_connect.send_config_set(config_commands)

        print
        print '#' * 50
        print output
        print '#' * 50
        print


def displayBridgesandPorts():
    router_name = raw_input("Enter the router name to modify the ports:")
    s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
    vsrname = s.read().split()
    if router_name in vsrname[1::]:
        print "\nRouter present"
        print "\nFollowing are the current assignment of bridges to the Router Ports:"
        print "\n"
        targetfile = '/root/vsrxml/' + router_name + '.xml'
        tree = ET.parse(targetfile)
        root = tree.getroot()
        print "Port 1/1/1" + "\t" + root[7][2][0].attrib["bridge"]
        print "Port 1/1/2" + "\t" + root[7][3][0].attrib["bridge"]
        print "Port 1/1/3" + "\t" + root[7][4][0].attrib["bridge"]
        print "Port 1/1/4" + "\t" + root[7][5][0].attrib["bridge"]
        print "Port 1/1/5" + "\t" + root[7][6][0].attrib["bridge"]

    else:
        print "Enter the correct router name from this list"
        print vsrname[1::]
    targetfile = '/root/vsrxml/' + router_name + '.xml'


'''Function to assign the router ports to the Bridges'''


def addPortstoBridges():
    router_name = raw_input("Enter the router name to modify the ports:")
    s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
    vsrname = s.read().split()
    if router_name in vsrname[1::]:
        print "\nRouter present"
        print "\nFollowing are the current assignment of bridges to the Router Ports:"
        print "\n"
        targetfile = '/root/vsrxml/' + router_name + '.xml'
        tree = ET.parse(targetfile)
        root = tree.getroot()
        print "Port 1/1/1" + "\t" + root[7][2][0].attrib["bridge"]
        print "Port 1/1/2" + "\t" + root[7][3][0].attrib["bridge"]
        print "Port 1/1/3" + "\t" + root[7][4][0].attrib["bridge"]
        print "Port 1/1/4" + "\t" + root[7][5][0].attrib["bridge"]
        print "Port 1/1/5" + "\t" + root[7][6][0].attrib["bridge"]
        print "\n"
        bridge_names = subprocess.Popen(["brctl show | cut  -f 1 | sed '/^\s*$/d' | sed '1d;$d'"], shell=True,
                                        stdout=subprocess.PIPE).stdout
        bridge_names_list = bridge_names.read().split()
        for i in xrange(1, 6):
            root[7][i + 1][0].attrib["bridge"] = raw_input(
                "\nBridge name to assign the port 1/1/" + str(i) + "\t") or "bridgeunset"
            if root[7][i + 1][0].attrib["bridge"] not in bridge_names_list:
                print "\nThis bridge is not present resetting to bridgeunset"
                root[7][i + 1][0].attrib["bridge"] = "bridgeunset"
        with open(targetfile, "w") as f:
            tree.write(f)
        f.close()

        print ', '.join(bridge_names_list)
        # matching_bridges = [x for x in bridge_names_list]

    else:
        print "Enter the correct router name from this list"
        print vsrname[1::]
    targetfile = '/root/vsrxml/' + router_name + '.xml'


def deleteBridges():
    bridge_name_prefix = raw_input("\nEnter the prefix name of the Bridges to delete: \n")
    bridge_nos = subprocess.Popen(["brctl show | awk '{print $1}'"], shell=True, stdout=subprocess.PIPE).stdout
    bridge_nos_test = bridge_nos.read().split()
    matching_bridges = [x for x in bridge_nos_test if x.startswith(bridge_name_prefix)]

    print "Following Bridges will be Deleted"
    print matching_bridges
    for i in matching_bridges:
        os.system('ifconfig %(i)s down' % locals())
        os.system('brctl delbr %(i)s' % locals())

        # if bridge_nos >1:
        #     print "\nDeleting %(bridge_nos)s bridges"
        #     for i in xrange(bridge_nos):5
        #         bridge_name = bridge_name_prefix + str(i + 1)
        #         os.system('brctl delbr %(bridge_name)s' % locals())


def createvSR():
    router_no = int(raw_input("\nNumber of Virtual Routers to create: "))
    router_name = raw_input("\nEnter the prefix name of the Router: ")
    router_bof_addr = raw_input("\nEnter the First IP address of Router: ")
    srospath = "/root/vsros/"
    dirs = os.listdir(srospath)
    for file in dirs:
        print file
    user_requested_os = raw_input("\nEnter the SR OS to be used from the above list: ")
    user_requested_os_path = '/root/vsros/' + user_requested_os + '/sros-vm.qcow2'

    try:
        socket.inet_aton(router_bof_addr)
        print "ipv4 address"
    except socket.error:
        print "not ipv4 address"
    ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    router_bof_addr_int = ip2int(router_bof_addr)
    for x in xrange(router_no):
        int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
        router_bof_address = int2ip(router_bof_addr_int + x)
        router_bof_address_last_octet = router_bof_address.split(".")[3]
        print router_bof_address_last_octet

        targetfile = '/root/vsrxml/' + router_name + str(router_bof_address_last_octet) + '.xml'
        targetos = '/var/lib/libvirt/images/' + router_name + str(router_bof_address_last_octet) + '.qcow2'
        shutil.copyfile("/root/vsrxml/template2.xml", targetfile)
        shutil.copyfile(user_requested_os_path, targetos)
        tree = ET.parse(targetfile)
        root = tree.getroot()

        # tree = ET.ElementTree(file=targetfile)
        # root = tree.getroot()

        for domain in root.iter("name"):
            domain.text = router_name + str(router_bof_address_last_octet)

        # tree = ET.ElementTree(root)
        # print root[6][0][0].tag
        # print root[6][0][0].attrib
        print root[7][0][1].attrib
        smbios_options = 'TIMOS:address=' + router_bof_address + '/23@active static-route=128.0.0.0/1@135.121.46.1 license-file=ftp://admin1:admin1@138.120.187.9/nodeImages/licenses/timos.none.txt'
        print smbios_options
        print root[6][0]
        root[6][0][0].text = smbios_options
        root[7][0][1].attrib["file"] = targetos
        with open(targetfile, "w") as f:
            tree.write(f)
        f.close()
        os.system('virsh define %(targetfile)s' % locals())
        router_name2 = router_name + str(router_bof_address_last_octet)
        os.system('virsh start %(router_name2)s' % locals())
        os.system('virsh list --all')


def showvSR():
    os.system('virsh list --all')


def redefinevSR():
    s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
    vsrname = s.read().split()
    print len(vsrname)
    if len(vsrname) > 1:
        for i in vsrname[1:len(vsrname)]:
            os.system('virsh destroy %(i)s' % locals())
            os.system('virsh undefine %(i)s' % locals())
            mod_file = '/root/vsrxml/' + str(i) + '.xml'

            os.system('virsh define %(mod_file)s' % locals())
            os.system('virsh start %(i)s' % locals())


class Samossapi(object):
    # def __init__(self):
    #def creatediscoverrule(self, myDiscoveryrule):
    def creatediscoverrule(self):
        discoveryxml = """
          <generic.GenericObject.configureInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>network:topology</distinguishedName>
             <configInfo>
                <netw.Topology>
                  <actionMask>
                    <bit>modify</bit>
                  </actionMask>
                  <objectFullName>network:topology</objectFullName>
                  <children-Set>
                   <netw.TopologyDiscoveryRule>
                     <actionMask>
                       <bit>create</bit>
                     </actionMask>
                     <backupPolicyPointer>network:backup-policy-1</backupPolicyPointer>
                     <dcInterconnectPointer></dcInterconnectPointer>
                     <writeMediationPolicyId>1</writeMediationPolicyId>
                     <statsPollingPolicyId>1</statsPollingPolicyId>
                     <description>vSR_sims</description>
                     <discoveryProtocol>snmp</discoveryProtocol>
                     <topologyGroupPointer>topologyGroup:Network-DiscoveredNes</topologyGroupPointer>
                     <revertOlcState>false</revertOlcState>
                     <administrativeState>up</administrativeState>
                     <dualReadMediationPolicyId>0</dualReadMediationPolicyId>
                     <dualTrapMediationPolicyId>0</dualTrapMediationPolicyId>
                     <id>0</id>
                     <securityMediationPolicyId>1</securityMediationPolicyId>
                     <trapMediationPolicyId>1</trapMediationPolicyId>
                     <dualWriteMediationPolicyId>0</dualWriteMediationPolicyId>
                     <standbyCpmPingPolicyId>1</standbyCpmPingPolicyId>
                     <defaultExternalEms></defaultExternalEms>
                     <ipAddressType>ipv4</ipAddressType>
                     <olcState>inService</olcState>
                     <inBandPingPolicyId>1</inBandPingPolicyId>
                     <readMediationPolicyId>1</readMediationPolicyId>
                     <postDiscoveryActionPointer></postDiscoveryActionPointer>
                     <outOfBandPingPolicyId>1</outOfBandPingPolicyId>
                     <children-Set>
                      <netw.TopologyDiscoveryRuleSpan>
                        <actionMask>
                          <bit>create</bit>
                        </actionMask>
                        <spanId>2</spanId>
                      </netw.TopologyDiscoveryRuleSpan>
                      <netw.TopologyDiscoveryRuleElement>
                        <actionMask>
                          <bit>create</bit>
                        </actionMask>
                        <usage>include</usage>
                        <ipAddress>135.121.47.83</ipAddress>
                        <maskBits>32</maskBits>
                        <ipAddressType>ipv4</ipAddressType>
                      </netw.TopologyDiscoveryRuleElement>
                     </children-Set>
                   </netw.TopologyDiscoveryRule>
                  </children-Set>
                </netw.Topology>
             </configInfo>
         </generic.GenericObject.configureInstance>
         """
        file = ET.fromstring(discoveryxml)
        namespaces = {"": "xmlapi_1.0"}
        for prefix, uri in namespaces.iteritems():
            ET.register_namespace(prefix, uri)


        print file
        b = file.find('{xmlapi_1.0}configInfo/{xmlapi_1.0}netw.Topology/{xmlapi_1.0}children-Set/{xmlapi_1.0}netw.TopologyDiscoveryRule/{xmlapi_1.0}children-Set/')
        print  b
        s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
        vsrname = s.read().split()
        for c in file.findall(".//{xmlapi_1.0}netw.TopologyDiscoveryRuleElement"):

            dupe = copy.deepcopy(c)  # copy <c> node
            for i in range(1,len(vsrname)-1):
                b.append(dupe)  # insert the new node


        discoveryxmlip=ET.tostring(file)






        #myDiscoveryrule.xml_request(discoveryxml)

    def deletediscoveryrule(self, myDeletediscoveryrule):
        deletexml = ''''''
        myDeletediscoveryrule.xml_request(deletexml)

    def createphysicallinks(self, myCreatePhysicallinks):
        physicallinkxml = '''
        <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>physicalLink</distinguishedName>
             <childConfigInfo>
                <netw.PhysicalLink>
                  <actionMask>
                    <bit>create</bit>
                  </actionMask>
                  <gneInterfaceEndpointBPointer></gneInterfaceEndpointBPointer>
                  <gneInterfaceEndpointAPointer></gneInterfaceEndpointAPointer>
                  <endPointBLagMembershipId>0</endPointBLagMembershipId>
                  <endpointABundleInterfacePointer></endpointABundleInterfacePointer>
                  <unmanagedEndpointBIPAddr>0.0.0.0</unmanagedEndpointBIPAddr>
                  <endPointBType>Port</endPointBType>
                  <description></description>
                  <unmanagedEndpointB></unmanagedEndpointB>
                  <endPointBSiteId>0.0.0.0</endPointBSiteId>
                  <unmanagedNeEndpointB></unmanagedNeEndpointB>
                  <endPointASiteId>0.0.0.0</endPointASiteId>
                  <endpointBBundleInterfacePointer></endpointBBundleInterfacePointer>
                  <usesManagedEndpointB>true</usesManagedEndpointB>
                  <endpointAPointer>network:{1}:shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-{3}</endpointAPointer>
                  <endpointBPointer>network:{2}:shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-{4}</endpointBPointer>
                  <endpointBLagInterfacePointer></endpointBLagInterfacePointer>
                  <displayedName>{1}_port_1/1/{3}_to_{2}_port_1/1/{4}</displayedName>
                  <endpointALagInterfacePointer></endpointALagInterfacePointer>
                  <navigationUrl></navigationUrl>
                  <endPointAType>Port</endPointAType>
                  <unmanagedEndpointBIPAddrType>ipv4</unmanagedEndpointBIPAddrType>
                  <endPointALagMembershipId>0</endPointALagMembershipId>
                  <networkElementEndpointBPointer></networkElementEndpointBPointer>
                  <networkElementEndpointAPointer></networkElementEndpointAPointer>
                </netw.PhysicalLink>
             </childConfigInfo>
         </generic.GenericObject.configureChildInstance>'''
        s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
        vsrname = s.read().split()
        position = 1
        print len(vsrname)
        if len(vsrname) > 1:
            for i in vsrname[position:len(vsrname)]:
                # print i
                position = position + 1
                for j in vsrname[position:len(vsrname)]:
                    if i != j:
                        conn1 = libvirt.openReadOnly(None)
                        if conn1 == None:
                            print 'Failed to open connection to the hypervisor'
                            sys.exit(1)
                        try:
                            dom_i = conn1.lookupByName(i)
                        except:
                            print 'Failed to find the main domain'
                            sys.exit(1)
                        conn2 = libvirt.openReadOnly(None)
                        if conn2 == None:
                            print 'Failed to open connection to the hypervisor'
                            sys.exit(1)
                        try:
                            dom_j = conn2.lookupByName(j)
                        except:
                            print 'Failed to find the main domain'
                            sys.exit(1)
                        raw_xml_i = dom_i.XMLDesc(0)
                        raw_xml_j = dom_j.XMLDesc(0)
                        # print raw_xml
                        # xml = minidom.parseString(raw_xml)
                        iroot = ET.fromstring(raw_xml_i)
                        jroot = ET.fromstring(raw_xml_j)
                        for i_interface_index in range(5, 10):

                            for j_interface_index in range(5, 10):

                                if (iroot[13][i_interface_index][1].attrib['bridge'] ==
                                        jroot[13][j_interface_index][1].attrib['bridge']) and (
                                    iroot[13][i_interface_index][1].attrib['bridge'] != 'bridgeunset'):
                                    # print "looks like a match " + iroot[13][i_interface_index][1].value + 'and' + jroot[13][j_interface_index][1].value
                                    print '######'
                                    # print iroot[13][i_interface_index][1].attrib
                                    # print iroot[0].text
                                    iport = iroot[13][i_interface_index][4].attrib['name']
                                    iport = iport.replace("net", "")
                                    # print iport
                                    ipaddress_i = re.split(':|=|/', iroot[6][0][0].text)[2]
                                    # print jroot[0].text
                                    jport = jroot[13][j_interface_index][4].attrib['name']
                                    jport = jport.replace("net", "")
                                    # print jport
                                    ipaddress_j = re.split(':|=|/', jroot[6][0][0].text)[2]

                                    physicallinkxml_edit = ET.fromstring(physicallinkxml)
                                    namespaces = {"": "xmlapi_1.0"}
                                    for prefix, uri in namespaces.iteritems():
                                        ET.register_namespace(prefix, uri)

                                        # physicallinkxml_edit[5][0][14] = 'network:' + ipaddress_i + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + iport
                                        # physicallinkxml_edit[5][0][15] = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                                        # physicallinkxml_edit[5][0][17] = iroot[0].text + '_port_1/1/' + iport + '_to_' + jroot[0].text + '_port_1/1/' + jport

                                        # print physicallinkxml_edit
                                        # print physicallinkxml_edit.findall('endpointAPointer')
                                        # print physicallinkxml_edit.findall('endpointBPointer')
                                        # print physicallinkxml_edit[5][0][15].text
                                        # physicallinkxml_edit.findall('physicallink:endpointAPointer', namespaces).text
                                        # = 'network:' + ipaddress_i + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + iport

                                    for endpointAPointer in physicallinkxml_edit.iter('{xmlapi_1.0}endpointAPointer'):
                                        endpointAPointer.text = 'network:' + ipaddress_i + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + iport
                                        print endpointAPointer.text
                                    for endpointBPointer in physicallinkxml_edit.iter('{xmlapi_1.0}endpointBPointer'):
                                        endpointBPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                                        print endpointBPointer.text
                                    for displayedName in physicallinkxml_edit.iter('{xmlapi_1.0}displayedName'):
                                        displayedName.text = iroot[0].text + '_port_1/1/' + iport + '_to_' + jroot[
                                            0].text + '_port_1/1/' + jport
                                        print displayedName.text

                                    physicallinkxml_edited = ET.tostring(physicallinkxml_edit)
                                    print physicallinkxml_edited

                                    myCreatePhysicallinks.xml_request(physicallinkxml_edited)

                                    # print jroot[13][j_interface_index][4].attrib
                                    print '######'
                                    # myPhysicallinkxmlrule.xml_request(physicallinkxml)

                        conn1.close()
                        conn2.close()

    def enableProtocolsrule(self, myenableProtocols):
        protocolsxml = '''
                         <generic.GenericObject.configureInstance xmlns="xmlapi_1.0">
                           <deployer>immediate</deployer>
                           <distinguishedName>network:135.121.47.83:router-1</distinguishedName>
                           <configInfo>
                             <rtr.VirtualRouter>
                               <actionMask>
                                 <bit>modify</bit>
                               </actionMask>
                               <objectFullName>network:135.121.47.83:router-1</objectFullName>
                               <isisEnabled>true</isisEnabled>
                               <ospfEnabled>true</ospfEnabled>
                               <ldpEnabled>true</ldpEnabled>
                               <mplsEnabled>true</mplsEnabled>
                               <children-Set/>
                             </rtr.VirtualRouter>
                           </configInfo>
                         </generic.GenericObject.configureInstance>'''
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
                enableProtocolsrule_edit = ET.fromstring(protocolsxml)
                namespaces = {"": "xmlapi_1.0"}
                for prefix, uri in namespaces.iteritems():
                    ET.register_namespace(prefix, uri)

                for distinguishedName in enableProtocolsrule_edit.iter('{xmlapi_1.0}distinguishedName'):
                    distinguishedName.text = 'network:' + ipaddress_i + ':router-1'
                    # print distinguishedName.text
                for objectFullName in enableProtocolsrule_edit.iter('{xmlapi_1.0}objectFullName'):
                    objectFullName.text = 'network:' + ipaddress_i + ':router-1'
                    # print objectFullName.text
                enableProtocolsrule_edited = ET.tostring(enableProtocolsrule_edit)
                myenableProtocols.xml_request(enableProtocolsrule_edited)
                # print enableProtocolsrule_edited
                conn1.close()

    def enableOSPFarea0rule(self, myenableOSPFarea0):
        ospfarea0xml = '''
        <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>network:135.121.47.84:router-1</distinguishedName>
             <childConfigInfo>
                <ospf.Site>
                  <actionMask>
                    <bit>create</bit>
                  </actionMask>
                  <overloadAdmininstrativeState>false</overloadAdmininstrativeState>
                  <isRFC1583Compatible>true</isRFC1583Compatible>
                  <lsaGenerateSecondWait>5000</lsaGenerateSecondWait>
                  <externalPreference>150</externalPreference>
                  <tunnelMtuBytes>0</tunnelMtuBytes>
                  <trafficEngineeringSupport>true</trafficEngineeringSupport>
                  <backupNodeSIDType>none</backupNodeSIDType>
                  <advRouterLsaLimitLogOnly>false</advRouterLsaLimitLogOnly>
                  <administrativeState>ospfUp</administrativeState>
                  <redistDelay>1000</redistDelay>
                  <spfMaxWait>10000</spfMaxWait>
                  <overloadStubs>false</overloadStubs>
                  <bootOverloadInterval>0</bootOverloadInterval>
                  <tunnelTablePreference>10</tunnelTablePreference>
                  <ifBaseRefCost>100000000</ifBaseRefCost>
                  <unicastImport>true</unicastImport>
                  <backupNodeSIDipPrefix>0.0.0.0</backupNodeSIDipPrefix>
                  <version>v2</version>
                  <domainId>-1</domainId>
                  <ospfRouterIdAddrType>ipv4</ospfRouterIdAddrType>
                  <rsvpShortcut>false</rsvpShortcut>
                  <prefixSidType>none</prefixSidType>
                  <ospfAdvRtrCapability>disable</ospfAdvRtrCapability>
                  <isAutonomousSystemBorderRouter>false</isAutonomousSystemBorderRouter>
                  <ldpOverRsvp>false</ldpOverRsvp>
                  <templateVersionPointer></templateVersionPointer>
                  <gracefulRestart>false</gracefulRestart>
                  <lsaGenerateMaxWait>5000</lsaGenerateMaxWait>
                  <backupNodeSIDipPrefixType>unknown</backupNodeSIDipPrefixType>
                  <prefixSidRangeMax>1</prefixSidRangeMax>
                  <bgpLsIdSet>false</bgpLsIdSet>
                  <grHelperMode>false</grHelperMode>
                  <multicastImport>false</multicastImport>
                  <bootOverloadAdmininstrativeState>disabled</bootOverloadAdmininstrativeState>
                  <externalLsdbLimit>-1</externalLsdbLimit>
                  <maxPqCost>0</maxPqCost>
                  <overloadExt2>false</overloadExt2>
                  <advertiseTunnelLink>false</advertiseTunnelLink>
                  <loopfreeAlternate>false</loopfreeAlternate>
                  <spfSecondWait>1000</spfSecondWait>
                  <bgpLsId>0</bgpLsId>
                  <spfInitialWait>1000</spfInitialWait>
                  <advRouterLsaLimit>0</advRouterLsaLimit>
                  <instanceIndex>0</instanceIndex>
                  <exportLimitLogPercent>0</exportLimitLogPercent>
                  <internalPreference>10</internalPreference>
                  <overloadInterval>0</overloadInterval>
                  <enableLdpSync>true</enableLdpSync>
                  <prefixSidStartRange>0</prefixSidStartRange>
                  <lsaArrivalWait>1000</lsaArrivalWait>
                  <lsaGenerateInitialWait>5000</lsaGenerateInitialWait>
                  <ospfRouterId>0.0.0.0</ospfRouterId>
                  <incrSpfWait>1000</incrSpfWait>
                  <adjacencySidHold>15</adjacencySidHold>
                  <backupNodeSID>0</backupNodeSID>
                  <remoteLoopfreeAlternate>false</remoteLoopfreeAlternate>
                  <creationOrigin>manual</creationOrigin>
                  <exitOverflowInterval>0</exitOverflowInterval>
                  <advRouterLsaLimitTimeout>0</advRouterLsaLimitTimeout>
                  <exportLimit>0</exportLimit>
                  <lsaAccumulate>1000</lsaAccumulate>
                  <advRouterLsaLimitWarning>0</advRouterLsaLimitWarning>
                  <segmentRoutingAdminState>down</segmentRoutingAdminState>
                  <ribPriorityList></ribPriorityList>
                  <backupNodeSIDipPrefixLength>0</backupNodeSIDipPrefixLength>
                  <children-Set>
                   <ospf.LfaPolicyExclude>
                     <actionMask>
                       <bit>create</bit>
                     </actionMask>
                     <policy5></policy5>
                     <policy4></policy4>
                     <policy3></policy3>
                     <policy2></policy2>
                     <policy1></policy1>
                     <creationOrigin>manual</creationOrigin>
                   </ospf.LfaPolicyExclude>
                   <ospf.ImportPolicy>
                     <actionMask>
                       <bit>create</bit>
                     </actionMask>
                     <policy5></policy5>
                     <policy4></policy4>
                     <policy3></policy3>
                     <policy2></policy2>
                     <policy1></policy1>
                     <creationOrigin>manual</creationOrigin>
                     <vrfName></vrfName>
                   </ospf.ImportPolicy>
                   <ospf.ExportPolicy>
                     <actionMask>
                       <bit>create</bit>
                     </actionMask>
                     <policy5></policy5>
                     <policy4></policy4>
                     <policy3></policy3>
                     <policy2></policy2>
                     <policy1></policy1>
                     <creationOrigin>manual</creationOrigin>
                     <vrfName></vrfName>
                   </ospf.ExportPolicy>
                  </children-Set>
                </ospf.Site>
             </childConfigInfo>
         </generic.GenericObject.configureChildInstance>'''

        ospfarea0xmlbackbone = '''
        <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>network:135.121.47.85:router-1:ospf-v2</distinguishedName>
             <childConfigInfo>
                <ospf.AreaSite>
                  <actionMask>
                    <bit>create</bit>
                  </actionMask>
                  <loopfreeAlternateExclude>false</loopfreeAlternateExclude>
                  <rangeBlackhole>true</rangeBlackhole>
                  <areaAdvRtrCapability>true</areaAdvRtrCapability>
                  <nssaRedistribute>true</nssaRedistribute>
                  <areaIdAddrType>ipv4</areaIdAddrType>
                  <databaseExportExclude>false</databaseExportExclude>
                  <originateDefault>noOriginate</originateDefault>
                  <creationOrigin>manual</creationOrigin>
                  <areaId>0.0.0.0</areaId>
                  <metric>1</metric>
                  <administrativeState>unknown</administrativeState>
                  <areaType>backbone</areaType>
                  <templateVersionPointer></templateVersionPointer>
                  <adjacencyCheck>false</adjacencyCheck>
                </ospf.AreaSite>
             </childConfigInfo>
         </generic.GenericObject.configureChildInstance>'''

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
                ospfarea0xml_edit = ET.fromstring(ospfarea0xml)
                namespaces = {"": "xmlapi_1.0"}
                for prefix, uri in namespaces.iteritems():
                    ET.register_namespace(prefix, uri)

                for distinguishedName in ospfarea0xml_edit.iter('{xmlapi_1.0}distinguishedName'):
                    distinguishedName.text = 'network:' + ipaddress_i + ':router-1'
                    print distinguishedName.text

                    # print objectFullName.text
                ospfarea0xml_edited = ET.tostring(ospfarea0xml_edit)

                ospfarea0xmlbb_edit = ET.fromstring(ospfarea0xmlbackbone)
                namespaces = {"": "xmlapi_1.0"}
                for prefix, uri in namespaces.iteritems():
                    ET.register_namespace(prefix, uri)

                for distinguishedName in ospfarea0xmlbb_edit.iter('{xmlapi_1.0}distinguishedName'):
                    distinguishedName.text = 'network:' + ipaddress_i + ':router-1:ospf-v2'
                    print distinguishedName.text

                    # print objectFullName.text
                ospfarea0xmlbb_edited = ET.tostring(ospfarea0xmlbb_edit)

                myenableOSPFarea0.xml_request(ospfarea0xml_edited)
                myenableOSPFarea0.xml_request(ospfarea0xmlbb_edited)
                print ospfarea0xmlbb_edited
                conn1.close()

    def createinterfaces(self, myCreateinterafces):
        # self, myCreateinterafces
        interfacexml = '''
                    <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
                       <deployer>immediate</deployer>
                       <synchronousDeploy>true</synchronousDeploy>
                       <deployRetries>1</deployRetries>
                       <!-- in milliseconds -->
                       <deployRetryInterval>10000</deployRetryInterval>
                       <distinguishedName>network:135.121.47.83:router-1</distinguishedName>
                       <childConfigInfo>
                         <rtr.NetworkInterface>
                           <actionMask>
                             <bit>create</bit>
                           </actionMask>
                           <displayedName>SDK Network-Interface-Example</displayedName>
                           <portPointer>network:135.121.47.83:shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-1</portPointer>
                            <networkPolicyObjectPointer>Network:1</networkPolicyObjectPointer>
                           <children-Set>
                             <rtr.VirtualRouterIpAddress>
                               <index>1</index>
                               <actionMask>
                                 <bit>create</bit>
                               </actionMask>
                               <ipAddress>12.12.12.6</ipAddress>
                             </rtr.VirtualRouterIpAddress>
                           </children-Set>
                         </rtr.NetworkInterface>
                       </childConfigInfo>
                    </generic.GenericObject.configureChildInstance>'''
        s = subprocess.Popen(["virsh list | awk '{print $2}'"], shell=True, stdout=subprocess.PIPE).stdout
        vsrname = s.read().split()
        position = 1
        ipaddressoctet = 1

        print len(vsrname)
        if len(vsrname) > 1:
            for i in vsrname[position:len(vsrname)]:
                # print i
                position = position + 1
                for j in vsrname[position:len(vsrname)]:
                    if i != j:
                        conn1 = libvirt.openReadOnly(None)
                        if conn1 == None:
                            print 'Failed to open connection to the hypervisor'
                            sys.exit(1)
                        try:
                            dom_i = conn1.lookupByName(i)
                        except:
                            print 'Failed to find the main domain'
                            sys.exit(1)
                        conn2 = libvirt.openReadOnly(None)
                        if conn2 == None:
                            print 'Failed to open connection to the hypervisor'
                            sys.exit(1)
                        try:
                            dom_j = conn2.lookupByName(j)
                        except:
                            print 'Failed to find the main domain'
                            sys.exit(1)
                        raw_xml_i = dom_i.XMLDesc(0)
                        raw_xml_j = dom_j.XMLDesc(0)
                        # print raw_xml
                        # xml = minidom.parseString(raw_xml)
                        iroot = ET.fromstring(raw_xml_i)
                        jroot = ET.fromstring(raw_xml_j)
                        for i_interface_index in range(5, 10):

                            for j_interface_index in range(5, 10):

                                if (iroot[13][i_interface_index][1].attrib['bridge'] ==
                                        jroot[13][j_interface_index][1].attrib['bridge']) and (
                                            iroot[13][i_interface_index][1].attrib['bridge'] != 'bridgeunset'):
                                    # print "looks like a match " + iroot[13][i_interface_index][1].value + 'and' + jroot[13][j_interface_index][1].value
                                    print '######'
                                    # print iroot[13][i_interface_index][1].attrib
                                    # print iroot[0].text
                                    iport = iroot[13][i_interface_index][4].attrib['name']
                                    iport = iport.replace("net", "")
                                    # print iport
                                    ipaddress_i = re.split(':|=|/', iroot[6][0][0].text)[2]
                                    # print jroot[0].text
                                    jport = jroot[13][j_interface_index][4].attrib['name']
                                    jport = jport.replace("net", "")
                                    # print jport
                                    ipaddress_j = re.split(':|=|/', jroot[6][0][0].text)[2]

                                    interfacexml_edit1 = ET.fromstring(interfacexml)
                                    namespaces = {"": "xmlapi_1.0"}
                                    for prefix, uri in namespaces.iteritems():
                                        ET.register_namespace(prefix, uri)

                                        # physicallinkxml_edit[5][0][14] = 'network:' + ipaddress_i + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + iport
                                        # physicallinkxml_edit[5][0][15] = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                                        # physicallinkxml_edit[5][0][17] = iroot[0].text + '_port_1/1/' + iport + '_to_' + jroot[0].text + '_port_1/1/' + jport

                                        # print physicallinkxml_edit
                                        # print physicallinkxml_edit.findall('endpointAPointer')
                                        # print physicallinkxml_edit.findall('endpointBPointer')
                                        # print physicallinkxml_edit[5][0][15].text
                                        # physicallinkxml_edit.findall('physicallink:endpointAPointer', namespaces).text
                                        # = 'network:' + ipaddress_i + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + iport
                                    for distinguishedName in interfacexml_edit1.iter('{xmlapi_1.0}distinguishedName'):
                                        distinguishedName.text = 'network:' + ipaddress_i + ':router-1'
                                        print distinguishedName.text

                                    for portPointer in interfacexml_edit1.iter('{xmlapi_1.0}portPointer'):
                                        portPointer.text = 'network:' + ipaddress_i + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + iport
                                        print portPointer.text
                                    for displayedName in interfacexml_edit1.iter('{xmlapi_1.0}displayedName'):
                                        #displayedName.text = iroot[0].text + '_to_' + jroot[
                                         #    0].text + + '_port_1/1/' + jport
                                        displayedName.text = 'to_' + jroot[0].text + '_port_1/1/' + jport
                                        # + '_port_1/1/' + jport

                                        print displayedName.text
                                    for ipAddress in interfacexml_edit1.iter('{xmlapi_1.0}ipAddress'):
                                        ipAddress.text = '21.21.' + str(ipaddressoctet) + '.1'
                                        print displayedName.text

                                    interfacexml_edited1 = ET.tostring(interfacexml_edit1)
                                    print interfacexml_edited1

                                    myCreateinterafces.xml_request(interfacexml_edited1)

                                    # print jroot[13][j_interface_index][4].attrib
                                    print '######'
                                    # myPhysicallinkxmlrule.xml_request(physicallinkxml)
                                    interfacexml_edit2 = ET.fromstring(interfacexml)
                                    namespaces = {"": "xmlapi_1.0"}
                                    for prefix, uri in namespaces.iteritems():
                                        ET.register_namespace(prefix, uri)
                                    for distinguishedName in interfacexml_edit2.iter('{xmlapi_1.0}distinguishedName'):
                                        distinguishedName.text = 'network:' + ipaddress_j + ':router-1'
                                        print distinguishedName.text
                                    for portPointer in interfacexml_edit2.iter('{xmlapi_1.0}portPointer'):
                                        portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                                        print portPointer.text
                                    for displayedName in interfacexml_edit2.iter('{xmlapi_1.0}displayedName'):
                                        # displayedName.text = iroot[0].text + '_port_1/1/' + iport + '_to_' + jroot[0].text + '_port_1/1/' + jport
                                        #displayedName.text = jroot[0].text + '_to_' + iroot[
                                        #    0].text + '_port_1/1/' + iport
                                        displayedName.text = 'to_' + iroot[0].text + '_port_1/1/' + iport
                                        #+ '_port_1/1/' + iport
                                        print displayedName.text
                                    for ipAddress in interfacexml_edit2.iter('{xmlapi_1.0}ipAddress'):
                                        ipAddress.text = '21.21.' + str(ipaddressoctet) + '.2'
                                        print ipAddress.text
                                    interfacexml_edited2 = ET.tostring(interfacexml_edit2)
                                    print interfacexml_edited2
                                    myCreateinterafces.xml_request(interfacexml_edited2)
                                    ipaddressoctet = ipaddressoctet + 1

                        conn1.close()
                        conn2.close()

    def addinterfacestoprotocols(self, myinterfaceidrule):
        interfaceidxml = '''
        <find xmlns="xmlapi_1.0">
          <fullClassName>netw.NetworkElement</fullClassName>
           <filter>
              <equal name="objectFullName" value="network:135.121.47.83" />
           </filter>
           <resultFilter>
              <attribute>objectFullName</attribute>
              <children>
                 <resultFilter class="rtr.VirtualRouter">
                    <attribute>objectFullName</attribute>
                    <children>
                       <resultFilter class="rtr.NetworkInterface">
                          <attribute>objectFullName</attribute>
                          <attribute>name</attribute>
                          <attribute>routerId</attribute>
                          <children />
                       </resultFilter>
                    </children>
                 </resultFilter>
              </children>
           </resultFilter>
          </find>
            '''
        ospfinterfacexml = '''
         <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>network:135.121.47.83:router-1:ospf-v2:areaSite-0.0.0.0</distinguishedName>
             <childConfigInfo>
                <ospf.Interface>
                  <actionMask>
                    <bit>create</bit>
                  </actionMask>
                  <ribPriority>none</ribPriority>
                  <description></description>
                  <nodeSIDType>none</nodeSIDType>
                  <advertiseSubnet>true</advertiseSubnet>
                  <ipsecstaticSAName>none</ipsecstaticSAName>
                  <interfaceType>pointToPoint</interfaceType>
                  <routerDeadInterval>40</routerDeadInterval>
                  <administrativeState>ospfInterfaceEnabled</administrativeState>
                  <bfdEnabled>false</bfdEnabled>
                  <authKeychain></authKeychain>
                  <loopfreeAlternateExclude>false</loopfreeAlternateExclude>
                  <ospfIfOutboundSAName></ospfIfOutboundSAName>
                  <retransmissionInterval>5</retransmissionInterval>
                  <displayedName></displayedName>
                  <ipAddress>0.0.0.0</ipAddress>
                  <authenticationKey>*******</authenticationKey>
                  <ospfIfInboundSAName></ospfIfInboundSAName>
                  <nodeSID>0</nodeSID>
                  <priority>1</priority>
                  <ospfIfInboundSANamePointer></ospfIfInboundSANamePointer>
                  <creationOrigin>manual</creationOrigin>
                  <mtu>0</mtu>
                  <ospfIfOutboundSANamePointer></ospfIfOutboundSANamePointer>
                  <ipAddressType>ipv4</ipAddressType>
                  <ospfNgIfAdvRtrCapability>true</ospfNgIfAdvRtrCapability>
                  <sidProtection>enabled</sidProtection>
                  <isPassive>false</isPassive>
                  <metric>0</metric>
                  <ospfNgIfLsaFilterOut>none</ospfNgIfLsaFilterOut>
                  <transitDelay>1</transitDelay>
                  <routeNextHopPointer></routeNextHopPointer>
                  <templateVersionPointer></templateVersionPointer>
                  <helloInterval>10</helloInterval>
                  <authenticationType>none</authenticationType>
                  <interfaceId>34</interfaceId>
                </ospf.Interface>
             </childConfigInfo>
         </generic.GenericObject.configureChildInstance>
        '''

        ldpinterafce = '''
         <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>network:135.121.47.83:router-1:ldp</distinguishedName>
             <childConfigInfo>
                <ldp.Interface>
                  <actionMask>
                    <bit>create</bit>
                  </actionMask>
                  <encapType>unknown</encapType>
                  <ipv4PfxFecCapability>enabled</ipv4PfxFecCapability>
                  <description></description>
                  <helloFactor>3</helloFactor>
                  <localLsrType>system</localLsrType>
                  <multicastFwdEnabled>enabled</multicastFwdEnabled>
                  <administrativeState>tmnxInService</administrativeState>
                  <inetAddressType>ipv4</inetAddressType>
                  <administrativeStateIPv4>tmnxInService</administrativeStateIPv4>
                  <bfdEnabled>false</bfdEnabled>
                  <keepAliveFactor>3</keepAliveFactor>
                  <keepAliveTimeout>30</keepAliveTimeout>
                  <ipv4Enabled>true</ipv4Enabled>
                  <helloTimeout>15</helloTimeout>
                  <displayedName></displayedName>
                  <creationOrigin>manual</creationOrigin>
                  <inheritanceMask></inheritanceMask>
                  <additionalForNamingInterfaceName></additionalForNamingInterfaceName>
                  <localLsrIfPointer></localLsrIfPointer>
                  <transportAddressType>system</transportAddressType>
                  <interfaceId>34</interfaceId>
                </ldp.Interface>
             </childConfigInfo>
         </generic.GenericObject.configureChildInstance>
        '''
        mplsinterface = '''
         <generic.GenericObject.configureChildInstance xmlns="xmlapi_1.0">
           <deployer>immediate</deployer>
             <synchronousDeploy>true</synchronousDeploy>
             <deployRetries>1</deployRetries>
             <clearOnDeployFailure>true</clearOnDeployFailure>
             <distinguishedName>network:135.121.47.84:router-1:mpls</distinguishedName>
             <childConfigInfo>
                <mpls.Interface>
                  <actionMask>
                    <bit>create</bit>
                  </actionMask>
                  <adminGroupInclude>0</adminGroupInclude>
                  <administrativeState>mplsUp</administrativeState>
                  <displayedName></displayedName>
                  <teMetric>0</teMetric>
                  <description></description>
                  <interfaceId>0</interfaceId>
                  <additionalForNamingInterfaceName></additionalForNamingInterfaceName>
                </mpls.Interface>
             </childConfigInfo>
         </generic.GenericObject.configureChildInstance>
        '''
        protocols = int(raw_input("\nAdd interfaces to 1) OSPF \
                                  2) MPLS \
                                  3) LDP \
                                  4) ALL "))

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
                interfaceidxml_edit = ET.fromstring(interfaceidxml)
                namespaces = {"": "xmlapi_1.0"}
                for prefix, uri in namespaces.iteritems():
                    ET.register_namespace(prefix, uri)
                for name in interfaceidxml_edit.iter('{xmlapi_1.0}equal'):
                    # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                    name.set('value', 'network:' + ipaddress_i)
                interfaceidxml_edited = ET.tostring(interfaceidxml_edit)
                myinterfaceidrule.xml_request(interfaceidxml_edited)
                # myinterfaceidruleresponse = myinterfaceidrule.response
                myinterfaceidruleresponse = ET.fromstring(myinterfaceidrule.response)
                # print myinterfaceidruleresponse
                namespaces = {"": "xmlapi_1.0"}
                for prefix, uri in namespaces.iteritems():
                    ET.register_namespace(prefix, uri)
                for name in myinterfaceidruleresponse.iter('{xmlapi_1.0}name'):
                    # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                    interfacename = name.text.split('-')[2]

                    '''Adding interfaces to the OSPF instance 0 Area 0.0.0.0'''

                    if interfacename != '1280' and (protocols == 1 or protocols == 4):
                        print interfacename
                        ospfinterfacexml_edit = ET.fromstring(ospfinterfacexml)
                        for prefix, uri in namespaces.iteritems():
                            ET.register_namespace(prefix, uri)
                        if interfacename == '1':
                            for isPassive in ospfinterfacexml_edit.iter('{xmlapi_1.0}isPassive'):
                                # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                                # print ipaddress_i
                                isPassive.text = 'true'
                        for distinguishedName in ospfinterfacexml_edit.iter('{xmlapi_1.0}distinguishedName'):
                            # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                            # print ipaddress_i
                            distinguishedName.text = 'network:' + ipaddress_i + ':router-1:ospf-v2:areaSite-0.0.0.0'
                            # print distinguishedName
                        for interfaceId in ospfinterfacexml_edit.iter('{xmlapi_1.0}interfaceId'):
                            # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                            interfaceId.text = interfacename
                            ospfinterfacexml_edited = ET.tostring(ospfinterfacexml_edit)
                            myinterfaceidrule.xml_request(ospfinterfacexml_edited)

                    '''Adding interfaces to the MPLS'''
                    if interfacename != '1280' and interfacename != '1' and (protocols == 2 or protocols == 4):
                        print interfacename
                        mplsinterface_edit = ET.fromstring(mplsinterface)
                        for prefix, uri in namespaces.iteritems():
                            ET.register_namespace(prefix, uri)
                        # if interfacename == '1':
                        #     for isPassive in ospfinterfacexml_edit.iter('{xmlapi_1.0}isPassive'):
                        #         # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                        #         # print ipaddress_i
                        #         isPassive.text = 'true'
                        for distinguishedName in mplsinterface_edit.iter('{xmlapi_1.0}distinguishedName'):
                            # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                            # print ipaddress_i
                            distinguishedName.text = 'network:' + ipaddress_i + ':router-1:mpls'
                            # print distinguishedName
                        for interfaceId in mplsinterface_edit.iter('{xmlapi_1.0}interfaceId'):
                            # portPointer.text = 'network:' + ipaddress_j + ':shelf-1:cardSlot-1:card:daughterCardSlot-1:daughterCard:port-' + jport
                            interfaceId.text = interfacename
                            mplsinterface_edited = ET.tostring(mplsinterface_edit)
                            myinterfaceidrule.xml_request(mplsinterface_edited)


'''
os.system('virsh undefine %(i)s' % locals())
Code To display the Menu options
os.system('virsh start %(i)s' % locals())
test
'''

options = True
while options:
    print("""
        1. Create new vSR nodes
        2. Delete vSR nodes
        3. Currently running vSR nodes
        4. Show Current Bridges
        5. Create Bridges
        6. Delete Bridges
        7. Add Ports to Bridges
        8. Restart vSR after updating Bridges
        9. Create a Discovery rule in SAM with IPs
        10. Delete a Discovery rule in SAM
        11. Create Adjacencies in SAM
        12. Enable OSPF, ISIS, MPLS, LDP protocols on all the nodes
        13. Enable OSPF area 0 on all the routers
        14. Create interfaces between all routers
        15. Add interfaces to all protocols
        16. Basic SR config
        Press Enter To Quit
        """)
    options = raw_input("What Would You Like To Do Now?: ")
    if int(options) == 1:
        print("\nYou selected to create new vSR nodes.\n")
        createvSR()

    elif int(options) == 2:
        print("\nYou selected to delete vSR nodes\n")
        destroyvSR()

    elif int(options) == 3:
        print("\nCurrently running virtual service router nodes\n")
        showvSR()

    elif int(options) == 4:
        print("\nCreating Bridges:\n")
        showBridges()

    elif int(options) == 5:
        print("\nCreating Bridges:\n")
        createBridges()

    elif int(options) == 6:
        print("\nDeleting Bridges\n")
        deleteBridges()

    elif int(options) == 7:
        print("\nModifying Bridges\n")
        addPortstoBridges()

    elif int(options) == 8:
        print("\nRestarting vSR nodes\n")
        redefinevSR()

    elif int(options) == 9:
        print("\nCreating a Discovery rule in SAM \n")
        #myDiscoveryrule = PostXML()
        Samossapidiscoveryrule = Samossapi()
        #Samossapidiscoveryrule.creatediscoverrule(myDiscoveryrule)

        Samossapidiscoveryrule.creatediscoverrule()

    elif int(options) == 10:
        print("\nDeleting a Discovery rule in SAM \n")
        myDeletediscoveryrule = PostXML()
        Samossapideletediscoveryrule = Samossapi()
        Samossapideletediscoveryrule.deletediscoveryrule(myDeletediscoveryrule)

    elif int(options) == 11:
        print("\nCreating Physical Links\n")
        myCreatePhysicallinks = PostXML()
        Samossapicreatephysicallinksrule = Samossapi()
        Samossapicreatephysicallinksrule.createphysicallinks(myCreatePhysicallinks)

    elif int(options) == 12:
        print("\nEnabling the protocols OSPF ISIS LDP and MPLS on a fresh routers")
        myenableProtocols = PostXML()
        Samossapienableprotocolssrule = Samossapi()
        Samossapienableprotocolssrule.enableProtocolsrule(myenableProtocols)

    elif int(options) == 13:
        print("\nEnable OSPF area 0 on all the interfaces")
        myenableOSPFarea0 = PostXML()
        Samossapienableprotocolssrule = Samossapi()
        Samossapienableprotocolssrule.enableOSPFarea0rule(myenableOSPFarea0)

    elif int(options) == 14:
        print("\nCreate interafces between routers and assign IP address")
        myCreateinterafces = PostXML()
        Samossapicreateinterfacerule = Samossapi()
        Samossapicreateinterfacerule.createinterfaces(myCreateinterafces)

    elif int(options) == 15:
        print("\nAdd interfaces to the protocols")
        myinterfaceidrule = PostXML()
        Samossapicreateinterfacerule = Samossapi()
        Samossapicreateinterfacerule.addinterfacestoprotocols(myinterfaceidrule)

    elif int(options) == 16:
        print("\nBasic SR config:\n")
        basicSRConfig()

    else:
        print("\nNot Valid Choice Try again")
        print("\nPress Enter...")
        os.system('clear')
        ans = True




        # for child in root:
        #      print child.tag, child.attrib
        # print root[7][2][0].tag
        # print root[7][2][0].attrib
        # print root[7][3][0].tag
        # print root[7][3][0].attrib
        # print root[7][4][0].tag
        # print root[7][4][0].attrib
        # print root[7][5][0].tag
        # print root[7][5][0].attrib
        # print root[7][6][0].tag
        # print root[7][6][0].attrib

        # root[7][4][1].attrib["bridge"] = "ram3"
        # tree.write('/home/sr1.txt')

        # print "###########################"
        # print "###########################"
        # for child_of_root in root:
        #     print child_of_root.tag, child_of_root.attrib
        #
        # print "###########################"
        # print "###########################"
        #
        # for subelem in root:
        #   print subelem.tag, subelem.attrib
        #
        # print "###########################"
        # print "###########################"
        # for elem in tree.iter():
        #     print elem.tag, elem.attrib
        #
        # print "###########################"
        # print "###########################"

        # for elem in tree.iterfind('devices/interface//'):
        #     print elem.tag, elem.attrib

        # print ('creating {} virtual routers'.format(router_no))

        # print "Current running virtual machines on this KVM"
        # os.system('virsh list')
        # os.system('virsh list')



        # PATH = os.path.dirname(os.path.abspath(__file__))
        # TEMPLATE_ENVIRONMENT = Environment(
        #     autoescape=False,
        #     loader=FileSystemLoader(os.path.join(PATH, 'templates')),
        #     trim_blocks=False)
        # def render_template(template_filename, context):
        #     return TEMPLATE_ENVIRONMENT.get_template(template_filename).render(context)
        # def create_vsr_domain():
        #     fname = "bridge.xml"
        #     param = [3, 'ieee', 3]
        #     context = {
        #         'param': param
        #     }
        #     #
        #     with open(fname, 'w') as f:
        #         html = render_template('bridge.xml', context)
        #         f.write(html)
        # def main():
        #     create_vsr_domain()

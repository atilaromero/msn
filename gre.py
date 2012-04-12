#!/usr/bin/python
from impacket import ImpactDecoder, ImpactPacket
from impacket.ImpactPacket import Header
from impacket.ImpactDecoder import Decoder, IPDecoder, ARPDecoder, DataDecoder

class GRE(Header):
    protocol=47
    def __init__(self, aBuffer = None):
        Header.__init__(self, 4)
        if(aBuffer):
            self.load_header(aBuffer)
    def get_header_size(self):
        "Return size of Ethernet header"
        return 4
    def get_ether_type(self):
        "Return ethernet data type field"
        return self.get_word(2)

class GREDecoder(Decoder):
    def __init__(self):
        pass

    def decode(self, aBuffer):
        e = GRE(aBuffer)
        off = e.get_header_size()
        if e.get_ether_type() == ImpactPacket.IP.ethertype:
            self.ip_decoder = IPDecoder()
            packet = self.ip_decoder.decode(aBuffer[off:])
        elif e.get_ether_type() == ImpactPacket.ARP.ethertype:
            self.arp_decoder = ARPDecoder()
            packet = self.arp_decoder.decode(aBuffer[off:])
        else:
            self.data_decoder = DataDecoder()
            packet = self.data_decoder.decode(aBuffer[off:])

        e.contains(packet)
        return e

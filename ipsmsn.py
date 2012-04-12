#!/usr/bin/python
import os
import sys
import whois as whoispack
import time
import pure_pcapy
from impacket import ImpactDecoder, ImpactPacket

whoiscache={}
def whois(ip):
    if whoiscache.has_key(ip):
        return whoiscache[ip]
    n=whoispack.NICClient()
    resp=n.whois_lookup({},ip,0).split('\n')
    time.sleep(1)
    lines=[x for x in resp if x.lower().startswith('owner:')]
    s2=''
    if lines:
        s=lines[0]
        s=[x.lstrip('owner:').strip() for x in s]
        s=[x for x in s if x]
        if s:
            s2=s[0]
        whoiscache[ip]=s2
    return s2
    
    

def listIPs(infpath):
    result=[]
    linkdecoder=None
    def f(h,rawp):
        ipdecoder=ImpactDecoder.IPDecoder()
        tcpdecoder=ImpactDecoder.TCPDecoder()
        plink=linkdecoder.decode(rawp)
        if plink.get_ether_type() == ImpactPacket.IP.ethertype:
            pip=ipdecoder.decode(plink.get_data_as_string())
            if pip.get_ip_p() == ImpactPacket.TCP.protocol:
                ptcp=tcpdecoder.decode(pip.get_data_as_string())
                if ptcp.get_th_dport() == 1863 or ptcp.get_th_sport() == 1863:
                    load=ptcp.get_data_as_string()
                    process(load,h)
    def process(load,h):
        if load:
            if load.count('4vPI')>0 or load.count('IPv4')>0:
                ls=load.split('\r\n')
                ffrom=''
                ip=''
                for l in ls:
                    if l.startswith('From: '):
                        ffrom=l.split(':')[2].split(';')[0].rstrip('>').lstrip(' ')
                    else:
                        ips=''
                        if l.count('4vPI')>0 and l.count('Addrs'[::-1])>0:
                            ips=l.split(':',1)[1][::-1].split(':')[0].split(' ')
                        if l.count('IPv4')>0 and l.count('Addrs')>0:
                            ips=l.split(':',1)[1].split(':')[0].split(' ')
                        if ffrom and ips:
                            for ip in ips:
                                ip=ip.strip(' ')
                                if ip and not (ip.startswith('192.168.') or
                                               ip.startswith('127.') or
                                               ip.startswith('10.') ):
                                    k=ip+'\t'+ffrom.strip(' ')
                                    t=time.localtime(h.ts[0]+h.ts[1]*0.000001)
                                    ts=time.strftime('%Y-%m-%d %X %Z',t)
                                    result.append(k+'\t'+ts+'\t'+whois(ip))
    def g(h,p):
        try:
            f(h,p)
        except KeyboardInterrupt:
          sys.exit(1)
        except:
            print sys.exc_info()
            pass
    r=pure_pcapy.open_offline(infpath)
    datalink=r.datalink()
    if datalink == pure_pcapy.DLT_LINUX_SLL:
        linkdecoder=ImpactDecoder.LinuxSLLDecoder()
    elif datalink == pure_pcapy.DLT_EN10MB:
        linkdecoder=ImpactDecoder.EthDecoder()
    else:
        raise Exception("Datalink type not supported: %i"%datalink)
    r.dispatch(-1,g)
    return result

"""
def listIPs(infpath):
    result=[]
    def f(p):
        if hasattr(p,'load'):
            if p.load.count('4vPI')>0 or p.load.count('IPv4')>0:
                ls=p.load.split('\r\n')
                ffrom=''
                ip=''
                for l in ls:
                    if l.startswith('From: '):
                        ffrom=l.split(':')[2].split(';')[0].rstrip('>').lstrip(' ')
                    else:
                        ips=''
                        if l.count('4vPI')>0 and l.count('Addrs'[::-1])>0:
                            ips=l.split(':',1)[1][::-1].split(':')[0].split(' ')
                        if l.count('IPv4')>0 and l.count('Addrs')>0:
                            ips=l.split(':',1)[1].split(':')[0].split(' ')
                        if ffrom and ips:
                            for ip in ips:
                                ip=ip.strip(' ')
                                if ip and not (ip.startswith('192.168.') or
                                               ip.startswith('127.') or
                                               ip.startswith('10.') ):
                                    k=ip+'\t'+ffrom.strip(' ')
                                    t=time.localtime(p.time)
                                    ts=time.strftime('%Y-%m-%d %X %Z',t)
                                    result.append(k+'\t'+ts+'\t'+whois(ip))
    def g(p):
        try:
            f(p)
        except:
            pass
    try:
        r=PcapReader(infpath)
    except:
        return result
    r.dispatch(g)
    return result
"""

def exportips(filelist):
    for x in filelist:
        l=listIPs(x)
        for y in l:
            print y

def main():
    import sys
    if len(sys.argv)<2:
        print "%s pcap1 pcap2 pcap3 ... "%sys.argv[0]
        sys.exit(1)
    exportips(sys.argv[1:])

if __name__=='__main__':
    main()


#!/usr/bin/python
# In KVM/XEN: /usr/local/livecloud/pyagexec/script/net_ghost.py
# In NSP:     /usr/local/livegate/script/net_ghost.py

import os
import sys
import time
import threading
import signal
import random
import commands
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, ARP, IP, ICMP, IPerror, Dot1Q, TCP, sendp, sniff


sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 1)
TERMINATE = False
next_hop_mac = None
icmp_payload = '2Cloud ^NetGhost^'


def print_traceroute(pkt, direction='REPLY'):
    if direction == 'REQUEST':
        return pkt.sprintf(
            '{ICMPerror:%3dr,ICMPerror.seq%}{!ICMPerror:%3dr,ICMP.seq%} '
            '%.time% %-15s,IP.src%                 %-s,IP.ttl%')
    else:
        return pkt.sprintf(
            '{ICMPerror:%3dr,ICMPerror.seq%}{!ICMPerror:%3dr,ICMP.seq%} '
            '%.time%                 %-15s,IP.src% %-s,IP.ttl%')


def print_tcp_packet(pkt):
    return pkt.sprintf(
        '%.time% [%Ether.src% > %Ether.dst%] '
        '[%IP.src% > %IP.dst% frag %dr,IP.frag% ttl %IP.ttl% '
        'len %dr,IP.len% id %-6dr,IP.id%]\n      '
        '[vlan {Dot1Q:%4dr,Dot1Q.vlan%}{!Dot1Q:   1}] '
        '[sport %5dr,TCP.sport% dport %5dr,TCP.dport% '
        'seq %TCP.seq% ack %TCP.ack% flags %TCP.flags% '
        'win %TCP.window% opt %TCP.options%]')


def print_icmp_packet(pkt):
    return pkt.sprintf(
        '%.time% [%Ether.src% > %Ether.dst%] '
        '[%IP.src% > %IP.dst% frag %dr,IP.frag% ttl %IP.ttl% '
        'len %dr,IP.len% id %-6dr,IP.id%]\n      '
        '[vlan {Dot1Q:%4dr,Dot1Q.vlan%}{!Dot1Q:   1}] '
        '[%-12s,ICMP.type% code %ICMP.code% '
        'id %rr,ICMP.id% seq %rr,ICMP.seq%] %Raw.load%')


def print_arp_packet(pkt, op='REPLY'):
    if op == 'REQUEST':
        return pkt.sprintf(
            '%.time% [%Ether.src% > %Ether.dst%] '
            '[%-7s,ARP.op% %ARP.pdst% %ARP.hwdst% '
            'tell %ARP.psrc% %ARP.hwsrc%]')
    elif op == 'REPLY':
        return pkt.sprintf(
            '%.time% [%Ether.src% > %Ether.dst%] '
            '[%ARP.psrc% %-7s,ARP.op% %ARP.hwsrc% '
            'tell %ARP.pdst% %ARP.hwdst%]')


def signal_handler(sig, frame):
    if sig == signal.SIGINT:
        print '\nTerminating 2Cloud NetGhost, waiting for ' \
            'main thread and receiver thread ...'
        global TERMINATE
        TERMINATE = True


class ReceiverThread(threading.Thread):
    def __init__(self, iface, protocol, src_ip, src_mac,
                 dst_ip, dst_port, limit, expire):
        threading.Thread.__init__(self)
        self.iface = iface
        self.protocol = protocol
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.limit = limit
        self.expire = expire

    def run(self):
        global TERMINATE
        global next_hop_mac
        if self.protocol == 'ARP':
            print_func = print_arp_packet
            lf = lambda(p): Ether in p and p[Ether].dst == self.src_mac \
                and ARP in p and p[ARP].pdst == self.src_ip \
                and p[ARP].psrc == self.dst_ip
        elif self.protocol in ['ICMP', 'TRACEROUTE']:
            if self.protocol == 'ICMP':
                print_func = print_icmp_packet
            else:
                print '  %-3s %-15s %-15s %-15s %-3s' % (
                    'SEQ', 'TIME', 'REQUEST', 'REPLY', 'TTL')
                print_func = print_traceroute
            lf = lambda(p): Ether in p and p[Ether].dst == self.src_mac \
                and IP in p and p[IP].dst == self.src_ip and ICMP in p \
                and (p[IP].src == self.dst_ip or
                     (IPerror in p and p[IPerror].dst == self.dst_ip))
        elif self.protocol in ['TCP']:
            print_func = print_tcp_packet
            lf = lambda(p): Ether in p and p[Ether].dst == self.src_mac \
                and IP in p and p[IP].dst == self.src_ip \
                and p[IP].src == self.dst_ip and TCP in p \
                and p[TCP].sport == self.dst_port
        try:
            n_recv = 0
            while not TERMINATE and self.expire > 0:
                begin = time.time()
                pkt = sniff(iface=self.iface, lfilter=lf,
                            count=1, timeout=self.expire)
                self.expire -= time.time() - begin
                if pkt:
                    print '<', print_func(pkt[0])
                    if not next_hop_mac and Ether in pkt[0]:
                        next_hop_mac = pkt[0][Ether].src
                    if protocol == 'TRACEROUTE':
                        if IP in pkt[0] and pkt[0][IP].src == self.dst_ip:
                            TERMINATE = True
                            break
                    n_recv += 1
                    if n_recv >= self.limit:
                        break
        except Exception as e:
            print e
        print >> sys.stderr, 'NetGhost receiver thread is exit now, ' \
            'receive %d pkts.' % n_recv


def send_arp(iface, src_ip, vlan, src_mac, dst_ip, silence=False):
    if vlan == 0:
        pkt = Ether(
            dst="ff:ff:ff:ff:ff:ff",
            src=src_mac,
            type=0x0806
        )
    else:
        pkt = Ether(
            dst="ff:ff:ff:ff:ff:ff",
            src=src_mac,
            type=0x8100
        )/Dot1Q(
            vlan=vlan,
            prio=0
        )
    pkt = pkt/ARP(
        hwtype=0x0001,
        ptype=0x0800,
        op=0x0001,
        hwdst="ff:ff:ff:ff:ff:ff",
        hwsrc=src_mac,
        psrc=src_ip,
        pdst=dst_ip
    )
    if not silence:
        print '>', print_arp_packet(pkt, 'REQUEST')
    sendp(pkt, iface=iface, verbose=0)


def send_icmp(iface, src_ip, vlan, src_mac, dst_ip, dst_mac,
              ip_id, icmp_id, icmp_seq, ttl, protocol):
    if vlan == 0:
        pkt = Ether(
            dst=dst_mac,
            src=src_mac,
            type=0x0800
        )
    else:
        pkt = Ether(
            dst=dst_mac,
            src=src_mac,
            type=0x8100
        )/Dot1Q(
            vlan=vlan,
            prio=0
        )
    pkt = pkt/IP(
        id=ip_id,
        src=src_ip,
        dst=dst_ip,
        ttl=ttl,
        len=(len(icmp_payload)+28)
    )/ICMP(
        id=icmp_id,
        seq=icmp_seq
    )/icmp_payload
    if protocol == 'ICMP':
        print '>', print_icmp_packet(pkt)
    else:
        print '>', print_traceroute(pkt, 'REQUEST')
    sendp(pkt, iface=iface, verbose=0)


def send_tcp(iface, src_ip, vlan, src_mac,
             dst_ip, dst_mac, ip_id, src_port, dst_port, tcp_seq):
    if vlan == 0:
        pkt = Ether(
            dst=dst_mac,
            src=src_mac,
            type=0x0800
        )
    else:
        pkt = Ether(
            dst=dst_mac,
            src=src_mac,
            type=0x8100
        )/Dot1Q(
            vlan=vlan,
            prio=0
        )
    pkt = pkt/IP(
        id=ip_id,
        src=src_ip,
        dst=dst_ip,
        len=40,
    )/TCP(
        sport=src_port,
        dport=dst_port,
        seq=tcp_seq,
        flags='S',
    )
    print '>', print_tcp_packet(pkt)
    sendp(pkt, iface=iface, verbose=0)


def get_port_name(mac, silence=False):
    cmd = 'ovs-vsctl --bare -- --columns=name find interface ' \
        '\'external_ids:attached-mac="%s"\'' % mac
    rc, output = commands.getstatusoutput(cmd)
    if not rc and output:
        return output
    cmd = 'ovs-vsctl --bare -- --columns=name find interface ' \
        '\'mac_in_use="%s"\'' % mac
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        if silence:
            return None
        print >> sys.stderr, 'Can not find vport of %s, cmd=%s' % (mac, cmd)
        sys.exit(1)
    return output


def get_ofport(port):
    cmd = 'ovs-vsctl --bare -- get interface %s ofport' % port
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        print >> sys.stderr, 'Can not find ofport of %s, cmd=%s' % (port, cmd)
        sys.exit(1)
    return int(output)


def get_vlantag(port):
    cmd = 'ovs-vsctl --bare -- get port %s tag' % port
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        print >> sys.stderr, 'Can not find vlan of %s, cmd=%s' % (port, cmd)
        sys.exit(1)
    return int(output)


def remove_invalid_device(devices=[]):
    cmd = 'ovs-vsctl --bare -- --columns=ofport find interface name='
    for i in range(len(devices)-1, -1, -1):
        rc, output = commands.getstatusoutput(cmd+devices[i])
        if rc or not output:
            del(devices[i])
            continue
        ofport = output.split('\n')[0]
        if int(ofport) <= 0:
            del(devices[i])
    return devices


def get_port_list_by_vlantag(vlantag):
    cmd = 'ovs-vsctl --bare -- --columns=name find port tag=%s' % vlantag
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        print >> sys.stderr, 'Can not find port by %s, cmd=%s' % (vlantag, cmd)
        sys.exit(1)
    port_list = output.split('\n')
    while '' in port_list:
        port_list.remove('')
    return remove_invalid_device(port_list)


def get_data_br(mac):
    iface = get_port_name(mac, False)
    cmd = 'ovs-vsctl port-to-br %s' % iface
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        print >> sys.stderr, 'Can not find bridge of vport %s, cmd=%s' % (
            iface, cmd)
        sys.exit(1)
    if output == 'br-int':  # openstack
        output = 'br-vlan'
    return output


def get_physical_port(mac, data_br):
    br = data_br

    if not br:
        br = get_data_br(mac)

    cmd = 'ovs-vsctl list-ifaces %s | grep -Exo ' \
        '"eth[0-9]+|em[0-9]+|(p[0-9]+){2}" | head -n 1' % br
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        print >> sys.stderr, 'Can not find physical port in %s, cmd=%s' % (
            br, cmd)
        sys.exit(1)
    return output


def update_fdb_generate_garp(mac, ip):
    port_name = get_port_name(mac, False)
    ofport = get_ofport(port_name)
    vlantag = get_vlantag(port_name)
    nei_port_list = get_port_list_by_vlantag(vlantag)
    nei_port_list.remove(port_name)

    for nei_port in nei_port_list:
        send_arp(nei_port, ip, 0, mac, ip, True)

    data_br = get_data_br(mac)
    phy_port = get_physical_port(src_mac, data_br)

    send_arp(phy_port, ip, vlantag, mac, ip, True)

    cmd = ('ovs-appctl ofproto/trace %s in_port=%s,dl_src=%s,'
           'dl_dst=ff:ff:ff:ff:ff:ff,arp,arp_spa=%s,arp_tpa=%s,'
           'arp_sha=%s,arp_op=1 -generate' %
           (data_br, ofport, mac, ip, ip, mac))
    rc, output = commands.getstatusoutput(cmd)
    if rc or not output:
        print >> sys.stderr, 'Can not update fdb'
        sys.exit(1)


if __name__ == '__main__':
    if not (
        (len(sys.argv) >= 9 and len(sys.argv) <= 10 and sys.argv[1] in ['ARP'])
            or (len(sys.argv) == 10 and sys.argv[1] in ['ICMP', 'TRACEROUTE'])
            or (len(sys.argv) == 11 and sys.argv[1] in ['TCP'])
            or (len(sys.argv) == 9 and sys.argv[1] in ['GARP'])):
        print """
Usage:
  {cmd} ARP  <interval> <count> <vlan> <src_ip> <src_mac> \
<dst_ip> <dst_mac|-> [<data_br>]
  {cmd} GARP 0 0 0 <src_ip> <src_mac> - -
  {cmd} <ICMP|TRACEROUTE> <interval> <count> <vlan> <src_ip> <src_mac> \
<dst_ip> <dst_mac|-> <next_hop>
  {cmd} TCP <interval> <count> <vlan> <src_ip> <src_mac> \
<dst_ip> <dst_mac|-> <next_hop> <dst_port>
i.e.,
  {cmd} ARP  0.1 10 10 192.168.21.4 0e:da:2f:21:78:fd 192.168.0.1 -
  {cmd} GARP 0 0 0 100.100.100.20 52:54:00:25:94:e1 - -
  {cmd} ICMP   1 10 10 192.168.21.4 0e:da:2f:21:78:fd 192.168.0.1 - \
192.168.0.1
  {cmd} TCP    1 10 10 192.168.21.4 0e:da:2f:21:78:fd 192.168.0.1 - \
192.168.0.1 80
""".format(cmd=os.path.basename(sys.argv[0]))
        sys.exit(1)

    protocol = sys.argv[1]
    interval = float(sys.argv[2])
    count = int(sys.argv[3])
    vlan = int(sys.argv[4])
    src_ip = sys.argv[5]
    src_mac = sys.argv[6]
    dst_ip = sys.argv[7]
    dst_mac = sys.argv[8]
    next_hop = ''
    data_br = None
    if protocol == 'GARP':
        update_fdb_generate_garp(src_mac, src_ip)
        sys.exit(0)
    if protocol != 'ARP':
        next_hop = sys.argv[9]
    else:
        if len(sys.argv) == 10:
            data_br = sys.argv[9]
    dst_port = 0
    if protocol == 'TCP':
        dst_port = int(sys.argv[10])

    if not dst_mac or len(dst_mac) != 17:
        iface = get_physical_port(src_mac, data_br)
    else:
        iface = get_port_name(dst_mac, True)
        if not iface:
            iface = get_physical_port(src_mac, data_br)
        else:
            vlan = 0  # send packet to local vport

    signal.signal(signal.SIGINT, signal_handler)

    if protocol != 'ARP':
        if dst_mac and len(dst_mac) == 17:
            next_hop_mac = dst_mac
        else:
            rt = ReceiverThread(
                iface, 'ARP', src_ip, src_mac, next_hop, 0, 1, 2)
            rt.start()
            time.sleep(1)  # wait after receiver thread begin to sniff
            send_arp(iface, src_ip, vlan, src_mac, next_hop, False)
            rt.join()
            if not next_hop_mac:
                print >> sys.stderr, 'NetGhost main thread is exit now, ' \
                    'can not resolve mac address of %s.' % next_hop
                sys.exit(1)

    rt = ReceiverThread(iface, protocol, src_ip, src_mac, dst_ip, dst_port,
                        count, interval * count + 1)
    rt.start()
    time.sleep(1)  # wait after receiver thread begin to sniff

    ip_id = random.randint(10000, 32000)
    icmp_id = random.randint(10000, 65000)
    seq = 1
    ttl = 64
    while not TERMINATE:
        if protocol == 'ARP':
            send_arp(iface, src_ip, vlan, src_mac, dst_ip, False)
        elif protocol in ['ICMP', 'TRACEROUTE']:
            if protocol == 'TRACEROUTE':
                ttl = seq
            send_icmp(iface, src_ip, vlan, src_mac, dst_ip, next_hop_mac,
                      ip_id, icmp_id, seq, ttl, protocol)
        elif protocol in ['TCP']:
            send_tcp(iface, src_ip, vlan, src_mac, dst_ip, next_hop_mac,
                     ip_id, icmp_id + seq, dst_port, icmp_id + seq)
        ip_id += 1
        seq += 1
        if seq > count:
            break
        time.sleep(interval)

    rt.join()
    print >> sys.stderr, 'NetGhost main thread is exit now, ' \
        'send %d pkts.' % (seq - 1)

#!/bin/sh

### FIXME
# 1. The naming format of consts should be further unified;
# 2. The coding style of scripts should be further unified;
# 3. Some code should be improved, e.g. >/dev/null can be simplied into >$-;
# 4. More consts can be extracted from scripts, including some basic functions, e.g. consts like VPORT_FORMAT;
# 5. ...

### Kernel related ...
 KERN_INFO="YunShan NSP kernel v4.0.0"
 KERN_DMESG="/var/log/dmesg"

### OvS related ...
 # FIXME: somewhere OVS_VSCTL is equal to OVS_VSCTL_BARE
 OVS_VSCTL="ovs-vsctl --timeout=10 --"
 OVS_VSCTL_BARE="ovs-vsctl --timeout=10 --bare --"

### OvS Bridge related ...
 LC_CTRL_BR_ID=0
 LC_DATA_BR_ID=1
 LC_ULNK_BR_ID=2
 LC_TUNL_BR_ID=3
 LC_STOR_BR_ID=4

 LC_TUNL_BR_NAME="tunbr"
 MS_BR="br-ms"
 OPENSTACK_DATA_BR="br-int"
 OPENSTACK_TUNL_BR="br-vlan"

 CTRL_IF_NICK_NAME="lc_br0"
 DATA_IF_NICK_NAME="lc_br1"
 TUNL_IF_NICK_NAME="lc_br3"

 DEFAULT_MTU=1500
 LC_CTRL_BR_MTU=$DEFAULT_MTU
 LC_DATA_BR_MTU=$DEFAULT_MTU
 LC_STOR_BR_MTU=8000

### OvS Flow Table related ...
 TABLE_SRC=0
 TABLE_DST=1
 TABLE_ISOLATE=31
 TABLE_NORMAL=32

 TABLE_PORT_TO_MS=32
 TABLE_MS_TRANSFER=40
 TABLE_MS_ARP=50
 TABLE_MS_ACL=60
 TABLE_MS_FORWARD=70
 TABLE_MS_DST=80
 TABLE_TO_RECOVERY=33
 TABLE_TO_RESUBMIT=41
 TABLE_IN_TO_PHY_AND_ACL=51
 TABLE_IN_TO_NORMAL=61
 TABLE_OUT_TO_PATCH=71
 TABLE_OUT_TO_PHY=81

 TABLE_PORT_TO_DVS=32
 TABLE_DVS_ARP=100

### OvS Flow Entry related ...
 WAN_FLOW_COOKIE_FORMAT="0xfff2fff0%08x"
 LAN_FLOW_COOKIE_FORMAT="0xfff2fff1%08x"
 VPN_FLOW_COOKIE_FORMAT="0xfff2fff4%08x"
 SNAT_FLOW_COOKIE_FORMAT="0xfff2fff2%08x"
 DNAT_FLOW_COOKIE_FORMAT="0xfff2fff3%08x"
 MAC_ENTRY_COOKIE="0x4"
 MAC_FLOOD_COOKIE="0x2"
 DEF_DROP_COOKIE="0x1"

 OVSNAT_FLOW_COOKIE_FORMAT_1="0xfff0%08x%04x"
 OVSNAT_FLOW_COOKIE_FORMAT_2="0xfff1%08x%04x"
 # used in tunnel_worker.py. for LiveCloud 2.4: "0x0%08lx%07lx"
 TUNNEL_FLOW_COOKIE_FORMAT='0xfff3%06x%06x'

 VPORT_FLOW_COOKIE_FORMAT="0xfff4fff0%08x"

 MS_VPORT_FLOW_COOKIE_FORMAT="0xff1ff%03x%08x"
 MS_PAIR_FLOW_COOKIE_FORMAT="0xff3ff%03x%08x"
 MS_ACL_FLOW_COOKIE_FORMAT="0xff2f%04x%08x"
 MS_VPORT_FLOW_COOKIE_MASK="0xfffff000ffffffff"
 MS_FLOW_COOKIE_GLOBAL="0xff1f"

 DVS_VPORT_FLOW_COOKIE_FORMAT="0xfe1ffff0%08x"
 DVS_VPORT_FLOW_COOKIE_MASK="0xffffffff00000000"

 MAC_ENTRY_DEFAULT_IDLE_TIME=300

 SKB_MARK_BITS=24
 SKB_MARK_MASK=0xffffff

 GRE_QUEUE_ID=1
 GRE_PROTO_ID=47
 GRE_POLICY_COOKIE="0x1"
 GRE_POLICY_PRIORITY=61000

### VIF/PIF related ...
 LC_TUNL_PORT="nspbr1"
 VETH_DATA_TUNL="int-$OPENSTACK_TUNL_BR"

 LC_DATA_TUNL_PATCH_PORT="patch-data-tunl"
 LC_TUNL_DATA_PATCH_PORT="patch-tunl-data"
 LC_TUNL_ULNK_PATCH_PORT="patch-tunl-ulnk"
 PATCH_MS_DATA="patch-ms-data"
 PATCH_DATA_MS="patch-data-ms"

 BOND_NAME_PFX="bond"
 PIF_NAME_PFX="eth"
 PIF_OFPORT=1

### Instance VGW related ...
 ROUTER_ID_FLOOR=256
 # 220:strongswan 253:default 254:main 255:local
 BLACK_ROUTER_IDS=(0 220 253 254 255)

 INVALID_ISP_ID=0
 MIN_ISP_ID=1
 MAX_ISP_ID=16
 MAX_WAN_IF_INDEX=8
 MIN_LAN_IF_INDEX=10
 MAX_IF_INDEX=40
 VALVE_WAN_IF_INDEX=1
 VALVE_LAN_IF_INDEX=$MIN_LAN_IF_INDEX
 # used to distinguish egress flows of valve
 VALVE_WAN_ISP_ID=$VALVE_WAN_IF_INDEX
 # used to distinguish ingress flows of valve
 VALVE_LAN_ISP_ID=$VALVE_LAN_IF_INDEX

 ROLE_VGATEWAY=7
 ROUTER_TYPE_VALVE=1

 KEY_CHAIN_CONN="CONN"
 MAX_CONN_BURST=10000
 VALVE_BR_PREFIX="br"

 WAN_VPORT_PREFIX="w"
 LAN_VPORT_PREFIX="l"
 IFB_VPORT_PREFIX="i"

 VPORT_FORMAT="[0-9]+-[$WAN_VPORT_PREFIX$LAN_VPORT_PREFIX]-[0-9]+"

### Instance VM related ...
 LC_VM_CTRL_IFINDEX=6

 SLOT_BASE=0x03
 SLOT_OFFSET=8

 # FIXME: change from IFB_VPORT_PREFIX to VM_IFB_VPORT_PREFIX
 VM_IFB_VPORT_PREFIX="ifb"

### TC/QoS related ...
 TC_MIRR_PRIO=1
 TC_CTRL_PRIO=2
 TC_BASE_PRIO=9

 HANDLE_FORMAT="[0-9a-f]+::[0-9a-f]+"
 # 0x0000:  b083 fec4 59e2 ae79 fe56 c86a 0800 4500  ....Y..y.V.j..E.
 # 0x0010:  0060 e752 0000 4001 4e56 7a73 280c 7a73  .`.R..@.NVzs(.zs
 # 0x0020:  2802 0000 4ab8 ba21 0005 0000 0005 4c69  (...J..!......Li
 # 0x0030:  7665 436c 6f75 6420 5072 6f62 6521 4c69  veCloud.Probe!Li
 # 0x0040:  7665 436c 6f75 6420 5072 6f62 6521 4c69  veCloud.Probe!Li
 # 0x0050:  7665 436c 6f75 6420 5072 6f62 6521 4c69  veCloud.Probe!Li
 # 0x0060:  7665 436c 6f75 6420 5072 6f62 6521       veCloudoud.Probe!
 PATTERN=0x4c697665 # "Live"
 PATTERN_OFFSET=48

 DEFAULT_RATE=128000
 BASIC_RATE=`(( _burst = 16 * 8 )); echo $_burst`

### Const related ...
 NULL="/dev/null"

 ETH_BROADCAST="01:00:00:00:00:00/01:00:00:00:00:00"
 ARP_REQUEST_OPCODE=1
 ARP_REPLY_OPCODE=2

 MIN_IPV4='0.0.0.0'
 MAX_IPV4='255.255.255.255'
 MIN_PORT=1
 MAX_PORT=65535

### Format related ...
 MAC_FORMAT="([0-9a-f]{2}:){5}[0-9a-f]{2}"
 IP_FORMAT="([0-9]{1,3}\.){3}[0-9]{1,3}"
 # FIXME: change from IPM_FMT to IPM_FORMAT
 IPM_FORMAT="$IP_FORMAT/[0-9]{1,2}"

### Time related ...
 REALTIME_STAT_EXPIRE=8
 GENERAL_STAT_EXPIRE=90

### Path related ...
 LIVECLOUD_CONF_DIR="/usr/local/livecloud/conf"
 LIVEGATE_SCRIPT_DIR="/usr/local/livegate/script"
 STRONGSWAN_CONF_DIR="/etc/strongswan/ipsec.d"

 OPENSTACK_MS_VLANTAG_MAPPING="/usr/local/livecloud/openstack_ms_vlantag_mapping"
 OPENSTACK_VPORT_VLANTAG_MAPPING="/usr/local/livecloud/openstack_vport_vlantag_mapping"

 NET_STAT='/tmp/nsp_net_stat'
 CPU_STAT='/tmp/nsp_cpu_stat'
 MEM_STAT='/tmp/nsp_mem_stat'

### Self-defined Parameter related ...
 MS_TYPE_HOST="HOST"
 MS_TYPE_SERVICE="SERVICE"
 MS_TYPE_ISP="ISP"
 MS_TYPE_GATEWAY="GATEWAY"

 COMPUTE_TYPE_LIVECLOUD="LIVECLOUD"
 COMPUTE_TYPE_OPENSTACK="OPENSTACK"

 VLANTAG_FOR_SPOOF=4095
 VLANTAG_NONE=-1
 NEXT_MS_NOT_EXIST=4096

### Text Color related ...
 txtund=$(tput sgr 0 1               2> /dev/null) # Underline
 txtbld=$(tput bold                  2> /dev/null) # Bold
 bld_black=${txtbld}$(tput setaf 0   2> /dev/null)
 bld_red=${txtbld}$(tput setaf 1     2> /dev/null)
 bld_green=${txtbld}$(tput setaf 2   2> /dev/null)
 bld_yellow=${txtbld}$(tput setaf 3  2> /dev/null)
 bld_blue=${txtbld}$(tput setaf 4    2> /dev/null)
 bld_magenta=${txtbld}$(tput setaf 5 2> /dev/null)
 bld_cyan=${txtbld}$(tput setaf 6    2> /dev/null)
 bld_white=${txtbld}$(tput setaf 7   2> /dev/null)
 wrap_info=${txtbld}
 wrap_pass=${bld_green}
 wrap_warn=${bld_yellow}
 wrap_err=${bld_red}
 wrap_over=$(tput sgr0               2> /dev/null)

 ERROR() { echo "${wrap_err}ERROR${wrap_over} [`date +%H:%M:%S`]" ; }
 WARN() { echo "${wrap_warn}WARNING${wrap_over} [`date +%H:%M:%S`]" ; }
 INFO() { echo "${wrap_info}INFO${wrap_over} [`date +%H:%M:%S`]" ; }
 DONE() { echo "${wrap_pass}DONE${wrap_over} [`date +%H:%M:%S`]" ; }

### Function related ...
 IP2NUM()
 {
     IP=(`echo $1 | awk -F'.' '{print $1, $2, $3, $4}'`)
     (( NUM = (((((${IP[0]} << 8) | ${IP[1]}) << 8) | ${IP[2]}) << 8) | ${IP[3]} ))
     echo $NUM
 }

 NUM2IP()
 {
     NUM=$1
     IP1=$(($NUM>>24))
     IP2=$(($NUM>>16&0xff))
     IP3=$(($NUM>>8&0xff))
     IP4=$(($NUM&0xff))
     IP=`echo "$IP1.$IP2.$IP3.$IP4"`
     echo $IP
 }

### Others ...
 HOST_NAME=`hostname`

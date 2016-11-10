#!/bin/sh

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh

usage()
{
    echo "Usage: $0 <vgateway_id> <role> [<if_index>]"
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 1
fi

vgateway_id=$1
role=$2
if_index=$3
: ${if_index:='[0-9]+'}

if [[ "$role" != "$ROLE_VGATEWAY" ]]; then
    exit 0
fi

ip_masklen_to_ip_gw()
{
    arr=(`echo $1 | awk -F'/' '{print $1, $2}'`)
    ip_num=`IP2NUM ${arr[0]}`
    mask_num=${arr[1]}
    (( gw_num = ((ip_num & (0xffffffff ^ ((1 << (32 - mask_num)) - 1))) + 1) ))
    gw=`NUM2IP $gw_num`
    echo -n "${arr[0]} $gw"
}

ip_masklen_to_ip_bc()
{
    arr=(`echo $1 | awk -F'/' '{print $1, $2}'`)
    ip_num=`IP2NUM ${arr[0]}`
    mask_num=${arr[1]}
    (( bc_num = (ip_num | ((1 << (32 - mask_num)) - 1)) ))
    bc=`NUM2IP $bc_num`
    echo -n "${arr[0]} $bc"
}

vg_wan_vports=`ip link list | grep -Ewo "$vgateway_id-$WAN_VPORT_PFX-$if_index"`
for vg_wan_vport in $vg_wan_vports; do
    ipmls=`ip addr list dev $vg_wan_vport |
        grep -Eo " inet $IPM_FORMAT " | awk '{print $2}'`
    for ipml in $ipmls; do
        ip_gw=(`ip_masklen_to_ip_gw $ipml`)
        ip=${ip_gw[0]}
        gw=${ip_gw[1]}
        if [[ -z "$ip" || -z "$gw" ]]; then
            echo "ARPING $gw from $ip $vg_wan_vport error"
            continue
        fi
        ip route add table local local $ip dev $vg_wan_vport \
            proto kernel scope host src $ip 2>$-
        arping $gw -I $vg_wan_vport -s $ip -b -w 2 -f 2>&1 |
            grep --color $gw
        ip route del table local local $ip dev $vg_wan_vport \
            proto kernel scope host src $ip 2>$-
    done
done
vg_lan_vports=`ip link list | grep -Ewo "$vgateway_id-$LAN_VPORT_PFX-$if_index"`
for vg_lan_vport in $vg_lan_vports; do
    ipmls=`ip addr list dev $vg_lan_vport |
        grep -Eo " inet $IPM_FORMAT " | awk '{print $2}'`
    for ipml in $ipmls; do
        ip_bc=(`ip_masklen_to_ip_bc $ipml`)
        ip=${ip_bc[0]}
        bc=${ip_bc[1]}
        if [[ -z "$ip" || -z "$bc" ]]; then
            echo "ARPING $bc from $ip $vg_lan_vport error"
            continue
        fi
        ip route add table local local $ip dev $vg_lan_vport \
            proto kernel scope host src $ip 2>$-
        arping $bc -I $vg_lan_vport -s $ip -b -w 2 -f 2>&1 |
            grep --color $bc
        ip route del table local local $ip dev $vg_lan_vport \
            proto kernel scope host src $ip 2>$-
    done
done

exit 0

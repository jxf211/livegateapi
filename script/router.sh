#!/bin/bash

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh
alias iptables="iptables -w"

print_usage()
{
    echo "`basename $0` Usage:"
    echo "    add wan <router_id> <if_index> <isp> <gateway> <mac> <vlantag>" \
         "<qos_min_rate> <qos_max_rate> <broadcast_min_rate> <broadcast_max_rate>" \
         "<ip> <netmask> [ <ip> <netmask> ... ]"
    echo "    add lan <router_id> <if_index> <mac> <vlantag>" \
         "<qos_min_rate> <qos_max_rate> <ip> <netmask> [ <ip> <netmask> ... ]"
    echo "    get wan <router_id> <if_index>"
    echo "    get lan <router_id> <if_index>"
    echo "    get router <router_id>"
    echo "    delete wan <router_id> <if_index>"
    echo "    delete lan <router_id> <if_index>"
    echo "    delete router <router_id> <remove_vport>"
    echo "    add valve-wan <router_id> <if_index> <isp> <gateway> <mac> <vlantag>" \
         "<qos_min_rate> <qos_max_rate> <broadcast_min_rate> <broadcast_max_rate>" \
         "<ip> <netmask> [ <ip> <netmask> ... ]"
    echo "    add valve-lan <router_id> <if_index> <mac> <vlantag>" \
         "<qos_min_rate> <qos_max_rate>"
    echo "    get valve-wan <router_id> <if_index>"
    echo "    get valve-lan <router_id> <if_index>"
    echo "    get valve <router_id>"
    echo "    delete valve-wan <router_id> <if_index>"
    echo "    delete valve-lan <router_id> <if_index>"
    echo "    delete valve <router_id> <remove_vport>"
    echo "    append nat <nat_type> <router_id> <rule_id> <isp> <protocol>" \
         "<match_if_type> <match_if_index>" \
         "<match_min_ip> <match_max_ip> <match_min_port> <match_max_port>" \
         "<target_if_type> <target_if_index>" \
         "<target_min_ip> <target_max_ip> <target_min_port> <target_max_port>"
    echo "    replace nat <nat_type> <router_id> <rule_id> <isp> <protocol>" \
         "<match_if_type> <match_if_index>" \
         "<match_min_ip> <match_max_ip> <match_min_port> <match_max_port>" \
         "<target_if_type> <target_if_index>" \
         "<target_min_ip> <target_max_ip> <target_min_port> <target_max_port>"
    echo "    delete nat <nat_type> <router_id> <rule_id> <isp>"
    echo "    flush nat <nat_type> <router_id>"
    echo "    append acl <acl_type> <router_id> <rule_id> <protocol>" \
         "<src_if_type> <src_if_index>" \
         "<src_min_ip> <src_max_ip> <src_min_port> <src_max_port>" \
         "<dst_if_type> <dst_if_index>" \
         "<dst_min_ip> <dst_max_ip> <dst_min_port> <dst_max_port> <target>"
    echo "    replace acl <acl_type> <router_id> <rule_id> <protocol>" \
         "<src_if_type> <src_if_index>" \
         "<src_min_ip> <src_max_ip> <src_min_port> <src_max_port>" \
         "<dst_if_type> <dst_if_index>" \
         "<dst_min_ip> <dst_max_ip> <dst_min_port> <dst_max_port> <target>"
    echo "    delete acl <acl_type> <router_id> <rule_id>"
    echo "    flush acl <acl_type> <router_id>"
    echo "    add route <router_id> <dst_ip> <dst_netmask> <next_hop>" \
         "<if_type> <if_index> <isp>"
    echo "    delete route <router_id> <dst_ip> <dst_netmask>"
    echo "    add vpn <router_id> <name> <isp> <left> <lnet_addr> <lnet_mask>" \
         "<right> <rnet_addr> <rnet_mask> <psk>"
    echo "    delete vpn <router_id> <name>"
    echo "    flush vpn <router_id>"
    echo "    add broadcast-qos <router_id> <if_index> <min_bandw> <max_bandw>"
    echo "    delete broadcast-qos <router_id> <if_index>"
    echo "    arping <router_id> <wan|lan> <if_index> <source> <target> <interval>"
    echo "    ping <router_id> <wan|lan> <if_index> <source> <target> <interval>"
    echo "    debug [router_id]"
    echo "    update vlantag <mac> <vlantag>"
    exit 1
}

# Text color variables
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

get_br_name_from_id()
{
    br_id=$1

    br=`ovs-vsctl --bare -- --columns=name find bridge external_ids:lc-br-idx=$br_id`
    if [ -n "$br" ]; then
        echo $br
        return 0
    fi

    br=`ovs-vsctl --bare -- --columns=name find bridge external_ids:lc-br-id=$br_id`
    if [ -z "$br" ]; then
        if [ $br_id -eq $LC_ULNK_BR_ID ]; then
            tunbr=`get_br_name_from_id $LC_TUNL_BR_ID`
            if [ -n "$tunbr" ]; then
                br=`get_br_name_from_id $LC_DATA_BR_ID`
            else
                return 1
            fi
        else
            return 1
        fi
    fi

    echo $br
    return 0
}

br_of_data()
{
    data_br=`get_br_name_from_id $LC_DATA_BR_ID`
    if [[ $? -ne 0 ]]; then
        # TODO handle br missing
        echo "nspbr0"
        return 1
    fi

    echo $data_br
    return 0
}

br_of_uplink()
{
    uplink_br=`get_br_name_from_id $LC_ULNK_BR_ID`
    if [[ $? -ne 0 ]]; then
        # TODO handle br missing
        echo "nspbr0"
        return 1
    fi

    echo $uplink_br
    return 0
}

DATA_BR=`br_of_data`
UPLINK_BR=`br_of_uplink`

ip_mask_num_to_prefix()
{
    ip_num=$1
    mask_num=$2
    (( net_num = ip_num & mask_num ))
    net=`NUM2IP $net_num`
    for i in `seq 0 31`; do
        (( check = 1 << i ))
        (( check &= mask_num ))
        if [[ $check -ne 0 ]]; then
            (( len = 32 - i ))
            echo "$net/$len"
            return
        fi
    done
    echo "$net/0"
}

ip_mask_to_prefix()
{
    ip_num=`IP2NUM $1`
    mask_num=`IP2NUM $2`
    ip_mask_num_to_prefix $ip_num $mask_num
}

ip_mask_to_broadcast_l()
{
    ip_num=`IP2NUM $1`
    mask_num=`IP2NUM $2`
    (( net_num = ip_num & mask_num ))
    net=`NUM2IP $net_num`
    echo "$net"
}

ip_mask_to_broadcast_r()
{
    ip_num=`IP2NUM $1`
    (( mask_num = 0xffffffff ^ `IP2NUM $2`))
    (( net_num = ip_num | mask_num ))
    net=`NUM2IP $net_num`
    echo "$net"
}

ip_masklen_to_prefix()
{
    ipml=$1
    arr=(`echo $ipml | awk -F"/" '{print $1, $2}'`)

    ip_num=`IP2NUM ${arr[0]}`
    mask_num=${arr[1]}
    (( mask_num = 0xffffffff ^ ( (1 << (32 - mask_num)) - 1 ) ))
    ip_mask_num_to_prefix $ip_num $mask_num
}

ip_masklen_to_ip_mask()
{
    ipml=$1
    arr=(`echo $ipml | awk -F"/" '{print $1, $2}'`)

    mask_num=${arr[1]}
    (( mask_num = 0xffffffff ^ ( (1 << (32 - mask_num)) - 1 ) ))
    mask=`NUM2IP $mask_num`
    echo -n "${arr[0]} $mask"
}

ip_mask_to_ip_masklen()
{
    ip=$1
    mask_num=`IP2NUM $2`
    for i in `seq 0 31`; do
        (( check = 1 << i ))
        (( check &= mask_num ))
        if [[ $check -ne 0 ]]; then
            (( len = 32 - i ))
            echo "$ip/$len"
            return
        fi
    done
    echo "$ip/0"
}

ip_range_to_prefix()
{
    beg=`IP2NUM $1`
    end=`IP2NUM $2`
    (( xor = beg ^ end ))      # diff bits
    (( ps1 = xor + 1 ))
    (( chk_xor = xor & ps1 ))  # xor & (xor + 1) == 0 -> xor = 0...01...1
    (( chk_beg = xor & beg ))  # xor & beg == 0       -> beg has 0 in diff bits
    (( chk_end = xor & end ))  # xor & end == xor     -> end has 1 in diff bits
    if [[ $chk_xor -eq 0 && $chk_beg -eq 0 && $chk_end -eq $xor ]]; then
        (( flip = 0xffffffff ^ xor ))
        netmask=`NUM2IP $flip`
        echo `ip_mask_to_prefix $1 $netmask`
    else
        echo ""
    fi
}

ip_range_to_prefix_array()
{
    beg=`IP2NUM $1`
    end=`IP2NUM $2`
    while [[ $beg -lt $end ]]; do
        for i in `seq 1 33`; do
            (( net_addr = beg & ((1 << i) - 1) ))
            if [[ $net_addr -ne 0 ]]; then
                break
            fi
            (( broad_addr = beg + ((1 << i) - 1) ))
            if [[ $broad_addr -gt $end ]]; then
                break
            fi
        done
        (( mask_len = 32 - i + 1 ))
        echo "`NUM2IP $beg`/$mask_len"

        (( beg = beg + (1 << (i - 1)) ))
    done
    if [[ $beg -eq $end ]]; then
        echo "`NUM2IP $beg`/32"
    fi
}

get_isp_router_id()
{
    router_id=$1
    isp_id=$2
    (( iri = (isp_id - 1) * (1 << SKB_MARK_BITS) + router_id ))
    echo $iri
}

get_isp_router_label()
{
    router_id=$1
    isp_id=$2
    (( isp_id = isp_id - 1 ))
    if [[ $isp_id -eq 0 ]]; then
        echo $router_id
    else
        echo $isp_id $router_id | awk '{printf "%d%08d", $1, $2}'
    fi
}

check_ifb_vport()
{
    router_id=$1
    if_index=$2
    pif_mtu=$3

    vport_ifb="${router_id}-${IFB_VPORT_PREFIX}-${if_index}"

    if ! ip addr show $vport_ifb > /dev/null 2>&1; then
        ip link add dev $vport_ifb type ifb 2> /dev/null
        ip link set dev $vport_ifb up && \
        ip link set dev $vport_ifb mtu $pif_mtu
    fi
}

check_wan_vport()
{
    router_id=$1
    if_index=$2
    use_ifb=$3

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"

    if ! ip addr show $vport_name > /dev/null 2>&1; then
        pif_mtu=`ovs-vsctl --timeout=10 list-ifaces $UPLINK_BR | grep "^eth" |
                 xargs -i ip link show {} | grep -Eo "mtu [0-9]+" |
                 cut -d ' ' -f 2 | head -n 1 2> /dev/null`
        if [[ -z "$pif_mtu" ]]; then
            pif_mtu=$DEFAULT_MTU
        fi

        ovs-vsctl --timeout=10 -- --may-exist add-port \
            $UPLINK_BR $vport_name -- set interface $vport_name type=internal 2> /dev/null
        ip link set dev $vport_name up && \
        ip link set dev $vport_name mtu $pif_mtu
    fi

    if [[ "$use_ifb" ]]; then
        check_ifb_vport $router_id $if_index $pif_mtu
    fi

    echo $vport_name
}

check_lan_vport()
{
    router_id=$1
    if_index=$2
    use_ifb=$3

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"

    if ! ip addr show $vport_name > /dev/null 2>&1; then
        pif_mtu=`ovs-vsctl --timeout=10 list-ifaces $DATA_BR | grep "^eth" |
                 xargs -i ip link show {} | grep -Eo "mtu [0-9]+" |
                 cut -d ' ' -f 2 | head -n 1 2> /dev/null`
        if [[ -z "$pif_mtu" ]]; then
            pif_mtu=$DEFAULT_MTU
        fi

        ovs-vsctl --timeout=10 -- --may-exist add-port \
            $DATA_BR $vport_name -- set interface $vport_name type=internal 2> /dev/null
        ip link set dev $vport_name up && \
        ip link set dev $vport_name mtu $pif_mtu
    fi

    if [[ "$use_ifb" ]]; then
        check_ifb_vport $router_id $if_index $pif_mtu
    fi

    echo $vport_name
}

delete_vport()
{
    vport_name=$1

    vport_ifb=`echo $vport_name |
               sed "s/[$WAN_VPORT_PREFIX$LAN_VPORT_PREFIX]/$IFB_VPORT_PREFIX/"`
    delete_interface_qos $vport_name $vport_ifb
    ovs-vsctl --timeout=10 -- --if-exists del-port $vport_name
    ip link del dev $vport_ifb 2> /dev/null
}

delete_valve_vport()
{
    vport_name=$1

    delete_valve_interface_qos $vport_name
    ovs-vsctl --timeout=10 -- --if-exists del-port $vport_name
}

delete_interface_qos()
{
    vport_name=$1
    vport_ifb=$2

    tc qdisc del dev $vport_name ingress 2> /dev/null
    tc qdisc del dev $vport_name root 2> /dev/null
    tc qdisc del dev $vport_ifb root 2> /dev/null
}

config_interface_qos()
{
    vport_name=$1
    min_rate=$2
    max_rate=$3
    # workaround for vpn qos problem: vpn can only use half ingress bandwidth
    vpn_qos_bypass=$4

    vport_ifb=`echo $vport_name |
               sed "s/[$WAN_VPORT_PREFIX$LAN_VPORT_PREFIX]/$IFB_VPORT_PREFIX/"`
    delete_interface_qos $vport_name $vport_ifb

    if [[ $min_rate -eq 0 && $max_rate -eq 0 ]]; then
        return
    fi

    # map ingress qdisc of vport_name to egress qdisc of vport_ifb
    tc qdisc replace dev $vport_name ingress
    tc filter replace dev $vport_name protocol ip parent ffff: prio $TC_MIRR_PRIO u32 \
        match u32 0 0 flowid 1:1 action mirred egress redirect dev $vport_ifb

    (( min_rate = (min_rate < $BASIC_RATE) ? $BASIC_RATE : min_rate ))
    (( max_rate = (max_rate < min_rate) ? min_rate : max_rate ))
    (( def_burst = max_rate / $BASIC_RATE ))
    (( mon_rate = $DEFAULT_RATE ))
    (( mon_burst = mon_rate / $BASIC_RATE ))
    (( sum_rate = max_rate + mon_rate ))
    (( sum_burst = def_burst + mon_burst ))
    if $vpn_qos_bypass; then
        (( sum_rate += max_rate ))
        (( sum_burst += def_burst ))
    fi
    for vport in $vport_name $vport_ifb; do
        # root qdisc
        tc qdisc replace dev $vport root handle 1: htb default 2
        # root class
        tc class replace dev $vport parent 1: classid 1:0 \
            htb rate ${sum_rate}bit burst ${sum_burst}b cburst ${sum_burst}b
        # default queue class
        tc class replace dev $vport parent 1:0 classid 1:2 \
            htb rate ${min_rate}bit ceil ${max_rate}bit \
            burst ${def_burst}b cburst ${def_burst}b
        # default queue qdisc
        tc qdisc replace dev $vport parent 1:2 sfq perturb 10
        # monitor queue class
        tc class replace dev $vport parent 1:0 classid 1:f000 \
            htb rate ${mon_rate}bit ceil ${mon_rate}bit \
            burst ${mon_burst}b cburst ${mon_burst}b
        # monitor queue qdisc
        tc qdisc replace dev $vport parent 1:f000 sfq perturb 10
        # filter to monitor queue
        tc filter replace dev $vport protocol ip parent 1:0 prio $TC_BASE_PRIO u32 \
            match ip protocol 1 0xff \
            match u32 $PATTERN 0xffffffff at $PATTERN_OFFSET flowid 1:f000
    done
    if $vpn_qos_bypass; then
        # vpn-esp queue class
        tc class replace dev $vport_ifb parent 1:0 classid 1:e000 \
            htb rate ${min_rate}bit ceil ${max_rate}bit \
            burst ${def_burst}b cburst ${def_burst}b
        # vpn-esp queue qdisc
        tc qdisc replace dev $vport_ifb parent 1:e000 sfq perturb 10
        # filter to vpn-esp queue
        tc filter replace dev $vport_ifb protocol ip parent 1:0 prio $TC_BASE_PRIO u32 \
            match ip protocol 50 0xff flowid 1:e000
    fi
}

delete_valve_interface_qos()
{
    typeset vport_name if_index

    vport_name=$1
    if_index=$2
    ip=$3

    if [[ -n "$ip" ]]; then
        ipx=`echo $ip | grep -Eo "[0-9]+" | xargs -i printf "%02x" {}`
        handle=`tc filter show dev $vport_name | grep -B 1 "match $ipx" |
            grep -Eo "$HANDLE_FORMAT" | head -n 1`
        tc filter del dev $vport_name protocol ip parent 1:0 prio $TC_BASE_PRIO \
            handle $handle u32 2> /dev/null
    fi

    if [[ -z "$ip" && -n "$if_index" ]]; then
        (( if_index += 1 ))
        tc filter show dev $vport_name | grep "flowid 1:$if_index" |
            grep -Eo "$HANDLE_FORMAT" | while read handle; do
            tc filter del dev $vport_name protocol ip parent 1:0 prio $TC_BASE_PRIO \
                handle $handle u32 2> /dev/null
        done

        tc class del dev $vport_name parent 1:0 classid 1:$if_index 2> /dev/null
        tc qdisc del dev $vport_name parent 1:$if_index 2> /dev/null
    fi

    if [[ -z "$if_index" ]]; then
        tc qdisc del dev $vport_name root 2> /dev/null
    fi
}

config_valve_interface_qos()
{
    typeset vport_name min_rate max_rate if_index

    vport_name=$1
    min_rate=$2
    max_rate=$3
    if_index=$4
    min_if_rate=$5
    max_if_rate=$6
    ip=$7
    path=$8

    if [[ -z "$ip" ]]; then
        (( mon_rate = $DEFAULT_RATE ))
        (( sum_rate = max_rate + mon_rate ))
        (( burst = sum_rate / $BASIC_RATE ))
        tc qdisc replace dev $vport_name root handle 1: htb default 1 2> /dev/null
        tc class replace dev $vport_name parent 1: classid 1:0 \
            htb rate ${sum_rate}bit burst ${burst}b cburst ${burst}b

        if [[ ! "`tc filter show dev $vport_name | grep -o 'flowid 1:f000'`" ]]; then
            (( burst = mon_rate / $BASIC_RATE ))
            tc class replace dev $vport_name parent 1:0 classid 1:f000 \
                htb rate ${mon_rate}bit ceil ${mon_rate}bit \
                burst ${burst}b cburst ${burst}b
            tc qdisc replace dev $vport_name parent 1:f000 \
                handle f000: sfq perturb 10
            tc filter replace dev $vport_name protocol ip parent 1:0 prio $TC_BASE_PRIO u32 \
                match ip protocol 1 0xff \
                match u32 $PATTERN 0xffffffff at $PATTERN_OFFSET flowid 1:f000
        fi
        if [[ -z "$if_index" ]]; then
            return
        fi

        (( min_if_rate = (min_if_rate < $BASIC_RATE) ? $BASIC_RATE : min_if_rate ))
        (( max_if_rate = (max_if_rate < min_if_rate) ? min_if_rate : max_if_rate ))
        (( burst = max_if_rate / $BASIC_RATE ))
        (( if_index += 1 ))
        tc class replace dev $vport_name parent 1:0 classid 1:$if_index \
            htb rate ${min_if_rate}bit ceil ${max_if_rate}bit \
            burst ${burst}b cburst ${burst}b
        tc qdisc replace dev $vport_name parent 1:$if_index \
            handle $if_index: sfq perturb 10
        return
    fi

    (( if_index += 1 ))
    tc filter replace dev $vport_name protocol ip parent 1:0 prio $TC_BASE_PRIO u32 \
        match ip $path $ip flowid 1:$if_index
}

config_policy_rtable_for_local()
{
    typeset ip vport_name isp_router_label

    ip=$1
    ip_broadcast_l=`ip_mask_to_broadcast_l $ip $2`
    ip_broadcast_r=`ip_mask_to_broadcast_r $ip $2`
    vport_name=$3
    isp_router_label=$4

    ip route del table local $ip dev $vport_name 2> /dev/null
    ip route del table local $ip_broadcast_l dev $vport_name 2> /dev/null
    ip route del table local $ip_broadcast_r dev $vport_name 2> /dev/null
    ip route add table $isp_router_label local $ip \
        dev $vport_name proto kernel scope host
    ip route add table $isp_router_label broadcast $ip_broadcast_l \
        dev $vport_name proto kernel scope link
    ip route add table $isp_router_label broadcast $ip_broadcast_r \
        dev $vport_name proto kernel scope link
}

ip_rule_find_min_pref()
{
    typeset min_pref max_pref

    min_pref=`ip rule ls | grep -w local | grep -Eo "^[0-9]+"`
    (( min_pref += 1 ))
    max_pref=`ip rule ls | grep -w main  | grep -Eo "^[0-9]+"`
    (( max_pref -= 1 ))

    while [[ -n "`ip rule ls | grep -wo "^$min_pref:"`" ]]; do
        (( min_pref += 1 ))
        if [[ $min_pref -ge $max_pref ]]; then
            echo "ERROR: policy routing table is full, min_pref=$min_pref, max_pref=$max_pref" >&2
            exit 1
        fi
    done

    echo "pref $min_pref"
    return 0
}

ip_rule_find_max_pref()
{
    typeset max_pref min_pref

    max_pref=`ip rule ls | grep -w main  | grep -Eo "^[0-9]+"`
    (( max_pref -= 1 ))
    min_pref=`ip rule ls | grep -w local | grep -Eo "^[0-9]+"`
    (( min_pref += 1 ))

    while [[ -n "`ip rule ls | grep -wo "^$max_pref:"`" ]]; do
        (( max_pref -= 1 ))
        if [[ $max_pref -le $min_pref ]]; then
            echo "ERROR: policy routing table is full, min_pref=$min_pref, max_pref=$max_pref" >&2
            exit 1
        fi
    done

    echo "pref $max_pref"
    return 0
}

config_router_conntrack()
{
    router_id=$1
    conn_max=$2
    new_conn_per_sec=$3
    new_conn_burst=0
    let new_conn_burst=2*$new_conn_per_sec

    if [[ "$conn_max" == "-1" || "$new_conn_per_sec" == "-1" ]]; then
        delete_router_conntrack $@
        return 0
    fi
    if [[ "$conn_max" -ne "0" && "$new_conn_per_sec" -gt "$conn_max" ]]; then
        new_conn_per_sec=$conn_max
    fi
    if [[ "$conn_max" -ne "0" && "$new_conn_burst" -gt "$conn_max" ]]; then
        new_conn_burst=$conn_max
    fi
    if [[ "$new_conn_burst" -gt "$MAX_CONN_BURST" ]]; then
        new_conn_burst=$MAX_CONN_BURST
    fi

    table="filter"
    chain="FORWARD"
    router_chain="${chain}_${KEY_CHAIN_CONN}_${router_id}"

    iptables -t $table -S $chain | grep -w "$router_chain" > /dev/null 2>&1
    if [ "$?" -eq "0" ]; then
        delete_router_conntrack $@
    fi
    iptables -t $table -N $router_chain
    iptables -t $table -I $chain -m mark --mark $router_id/$SKB_MARK_MASK -j $router_chain

    if [[ -n "$new_conn_per_sec" && "$new_conn_per_sec" != "0" ]]; then
        iptables -t $table -I $router_chain -m mark --mark $router_id/$SKB_MARK_MASK -m conntrack \
            --ctstate NEW,RELATED -m hashlimit --hashlimit-above $new_conn_per_sec/sec --hashlimit-burst $new_conn_burst \
            --hashlimit-htable-max $new_conn_per_sec --hashlimit-name hashlimit_$router_id -j DROP
    fi
    if [[ -n "$conn_max" && "$conn_max" != "0" ]]; then
        iptables -t $table -I $router_chain -m mark --mark $router_id/$SKB_MARK_MASK -m connlimit \
            -m conntrack --ctstate NEW,RELATED --connlimit-above $conn_max --connlimit-saddr --connlimit-mask 0 -j DROP
    fi
    iptables -t $table -A $router_chain -m conntrack --ctstate NEW,RELATED -j CONNMARK --set-mark $router_id/$SKB_MARK_MASK
    iptables -t $table -A $router_chain -j RETURN
}

delete_router_conntrack()
{
    router_id=$1
    table="filter"
    chain="FORWARD"
    router_chain="${chain}_${KEY_CHAIN_CONN}_${router_id}"
    iptables -t $table -S $chain | grep -w "$router_chain" > /dev/null 2>&1
    if [ "$?" -ne "0" ]; then
        return 0
    fi
    iptables -t $table -F $router_chain
    iptables -t $table -D $chain -m mark --mark $router_id/$SKB_MARK_MASK -j $router_chain
    iptables -t $table -X $router_chain
}

get_router_conntrack()
{
    router_id=$1
    table="filter"
    chain="FORWARD"
    router_chain="${chain}_${KEY_CHAIN_CONN}_${router_id}"
    iptables -t $table -S $chain | grep -w "$router_chain"
    iptables -t $table -S $router_chain
}

config_wan()
{
    router_id=$1
    if_index=$2
    isp=$3
    gateway=$4
    mac=$5
    vlantag=$6
    min_rate=$7
    max_rate=$8
    broadcast_min_rate=$9
    broadcast_max_rate=${10}

    vport_name=`check_wan_vport $router_id $if_index yes`
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name`
    vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`
    if [[ "$mac" != "00:00:00:00:00:00" && "$vport_mac" != "$mac" ]]; then
        vport_mac=$mac
        ovs-vsctl --timeout=10 -- set interface $vport_name "mac=\"$vport_mac\""
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
    fi
    ovs-vsctl --timeout=10 -- set port $vport_name tag=$vlantag

    isp_router_id=`get_isp_router_id $router_id $isp`
    isp_router_label=`get_isp_router_label $router_id $isp`
    cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    if ! ip rule ls | grep -w fwmark | grep -wqs "lookup $isp_router_label"; then
        pref=`ip_rule_find_min_pref`
        ip rule add fwmark $isp_router_id table $isp_router_label $pref
    fi
    # VGW-WAN-ENTRY-1:
    #   Used for WAN (ANY) flows from VGW WAN port to PHY or other VGW/VALVE WAN ports.
    # Resubmitted entry:
    #   (1) Match the learned entry of VGW-WAN-ENTRY-4 or VGW-WAN-ENTRY-5.
    #   (2) Match the entry VGW-WAN-ENTRY-2.
    # 'Deprecated by VGW-WAN-ENTRY-8 and VGW-WAN-ENTRY-9
    # ovs-ofctl add-flow $UPLINK_BR \
    #     cookie=$cookie,table=0,priority=20000,in_port=$vport_no,dl_src=$vport_mac,actions="
    #         mod_vlan_vid:$vlantag,resubmit(,1)" && \
    # '
    # VGW-WAN-ENTRY-2:
    #   Used for WAN (ANY) flows from VGW WAN port to PHY or other VGW/VALVE WAN ports (the
    #   same ISP).
    #     Note that, is this entry used only when no reversed entry is Learned
    #     via VGW-WAN-ENTRY-4 or VGW-WAN-ENTRY-5.
    #     Besides, this entry can avoid FLOOD, i.e., DUP.
    ovs-ofctl add-flow $UPLINK_BR \
        cookie=$cookie,table=1,priority=20000,in_port=$vport_no,dl_src=$vport_mac,actions="
            strip_vlan,normal" && \
    # VGW-WAN-ENTRY-3:
    #   Drop all irrelevant packets from VGW WAN port.
    ovs-ofctl add-flow $UPLINK_BR \
        cookie=$cookie,table=0,priority=19000,in_port=$vport_no,actions="drop"
    # Default entry:
    #   Table 0: normal
    #   Used for other common flows, such as local-nspbr1-IP <-> peer-nspbr1-IP
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    while [[ $# -ge 12 ]]; do
        ip=${11}
        netmask=${12}
        shift 2

        pref=`ip_rule_find_max_pref`
        ip rule add from $ip table $isp_router_label $pref
        ip addr add $ip/$netmask brd + dev $vport_name
        ip route add `ip_mask_to_prefix $ip $netmask` \
            table $isp_router_label dev $vport_name
        config_policy_rtable_for_local $ip $netmask $vport_name $isp_router_label
        if [[ "$isp_router_label" != "$router_id" ]]; then
            config_policy_rtable_for_local $ip $netmask $vport_name $router_id
        fi

        # VGW-WAN-ENTRY-4:
        #   Used for WAN ARP flows from PHY ports.
        # Learned entry:
        #   Used for reversed WAN (ANY) flows.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,arp,dl_vlan=$vlantag,arp_tpa=$ip,actions="
                learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=25000,
                    idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$vport_no,
                    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
                set_skb_mark:$isp_router_id,strip_vlan,$vport_no" && \
        # VGW-WAN-ENTRY-5:
        #   Used for WAN ARP flows from other VGW/VALVE WAN ports (any ISP).
        #     Note that, if dl_vlan is not designated in VGW-WAN-ENTRY-4 and VGW-WAN-ENTRY-5,
        #     then the inter-rack LAN ARP flows (e.g. intra VALVE) with arp_tpa=$ip
        #     from PATCH port can also be handled by mistake.
        # Learned entry:
        #   Used for reversed WAN (ANY) flows.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,arp,dl_vlan=0xffff,arp_spa=$ip/$netmask,arp_tpa=$ip,actions="
                learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=25000,
                    idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$vport_no,
                    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
                set_skb_mark:$isp_router_id,$vport_no" && \
        # VGW-WAN-ENTRY-6:
        #   Used for WAN IP flows from PHY ports.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,ip,dl_vlan=$vlantag,nw_dst=$ip,actions="
                set_skb_mark:$isp_router_id,strip_vlan,$vport_no" && \
        # VGW-WAN-ENTRY-7:
        #   Used for WAN IP flows from other VGW/VALVE WAN ports (any ISP).
        #     Note that, if dl_vlan is not designated in VGW-WAN-ENTRY-6 and VGW-WAN-ENTRY-7,
        #     then the inter-rack LAN IP flows (e.g. intra VGW/VALVE) with nw_dst=$ip
        #     from PATCH port can also be handled by mistake.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,ip,dl_vlan=0xffff,nw_src=$ip/$netmask,nw_dst=$ip,actions="
                set_skb_mark:$isp_router_id,$vport_no" && \
        # VGW-WAN-ENTRY-8:
        #   Used as VGW-WAN-ENTRY-1 for ARP flows against IP spoof
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=20000,in_port=$vport_no,arp,arp_spa=$ip,actions="
                mod_vlan_vid:$vlantag,resubmit(,1)" && \
        # VGW-WAN-ENTRY-9:
        #   Used as VGW-WAN-ENTRY-1 for IP flows against IP spoof
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=20000,in_port=$vport_no,ip,nw_src=$ip,actions="
                mod_vlan_vid:$vlantag,resubmit(,1)"
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
        /usr/local/livegate/script/net_ghost.py GARP 0 0 0 $ip $vport_mac - -
        if [[ $? -ne 0 ]]; then
            echo "`date +20'%y-%m-%d %H%M%S'` WARNING: execute" \
                "'/usr/local/livegate/script/net_ghost.py GARP 0 0 0 $ip $vport_mac - -'" \
                "failed" >> /var/log/livegate.log
        fi
    done

    # default route
    ip route del 0/0 table $isp_router_label >/dev/null 2>&1
    ip route add 0/0 via $gateway dev $vport_name table $isp_router_label

    # init INPUT chain
    check_iptables_chain filter INPUT $router_id

    config_interface_qos $vport_name $min_rate $max_rate true
    config_egress_broadcast_qos $router_id $if_index \
        $broadcast_min_rate $broadcast_max_rate

    nohup $LIVEGATE_SCRIPT_DIR/refresh_vgateway_mac.sh \
        $router_id $ROLE_VGATEWAY $if_index >/dev/null 2>&1 &
}

config_lan()
{
    router_id=$1
    if_index=$2
    mac=$3
    vlantag=$4
    min_rate=$5
    max_rate=$6

    vport_name=`check_lan_vport $router_id $if_index yes`
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name`
    vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`
    if [[ "$mac" != "00:00:00:00:00:00" && "$vport_mac" != "$mac" ]]; then
        vport_mac=$mac
        ovs-vsctl --timeout=10 -- set interface $vport_name "mac=\"$vport_mac\""
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
    fi
    ovs-vsctl --timeout=10 -- set port $vport_name tag=$vlantag

    isp_router_id=`get_isp_router_id $router_id 1`
    isp_router_label=`get_isp_router_label $router_id 1`
    cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    if ! ip rule ls | grep -w fwmark | grep -wqs "lookup $isp_router_label"; then
        pref=`ip_rule_find_min_pref`
        ip rule add fwmark $isp_router_id table $isp_router_label $pref
    fi
    # VGW-LAN-ENTRY-1:
    #   Used for LAN IP flows from PHY or PATCH ports to VGW LAN port.
    # Resubmitted entry:
    #   (1) Match the entry VGW-LAN-ENTRY-2.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=33000,ip,dl_vlan=$vlantag,dl_dst=$vport_mac,actions="
            set_skb_mark:$router_id,resubmit(,1)" && \
    # VGW-LAN-ENTRY-2:
    #   Used for LAN IP flows from PHY or PATCH ports to VGW LAN port.
    #     NOte that, this entry is also used by SNAT/DNAT/VPN LAN flows.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=1,priority=33000,ip,dl_vlan=$vlantag,dl_dst=$vport_mac,actions="
            strip_vlan,$vport_no" && \
    # VGW-LAN-ENTRY-3:
    #   Used for LAN (ANY) flows from VGW LAN port to PHY or PATCH ports.
    # Resubmitted entry:
    #   (1) Match the learned entry of VGW-LAN-ENTRY-6.
    #   (2) Match the entry VGW-LAN-ENTRY-4.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=31000,in_port=$vport_no,dl_src=$vport_mac,actions="
            mod_vlan_vid:$vlantag,resubmit(,1)" && \
    # VGW-LAN-ENTRY-4:
    #   Used for LAN (ANY) flows from VGW LAN port to PHY or PATCH ports.
    #     Note that, this entry can avoid FLOOD, i.e., DUP.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=1,priority=31000,in_port=$vport_no,dl_src=$vport_mac,actions="
            strip_vlan,normal" && \
    # VGW-LAN-ENTRY-5:
    #   Drop all irrelevant packets from VGW LAN port.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=30000,in_port=$vport_no,actions="drop"
    # Default entry:
    #   Table 0: normal
    #   Used for LAN (ANY) flows from PHY/PATCH ports to PATCH/PHY ports.
    #   Table 1: normal
    #   Used for LAN (ANY) flows from PATCH ports to PHY ports under SNAT/NDAT/VPN.
    if [[ $? -ne 0 ]]; then
        exit 1
    fi

    while [[ $# -ge 8 ]]; do
        ip=$7
        netmask=$8
        shift 2

        ip addr add $ip/$netmask brd + dev $vport_name

        ip_prefix=`ip_mask_to_prefix $ip $netmask`
        isp_router_label=`get_isp_router_label $router_id 1`
        ip route add $ip_prefix table $isp_router_label dev $vport_name
        config_policy_rtable_for_local $ip $netmask $vport_name $isp_router_label
        for isp in `seq 2 $MAX_ISP_ID`; do
            isp_router_label=`get_isp_router_label $router_id $isp`
            if ip rule ls | grep -w fwmark | grep -wqs "lookup $isp_router_label"; then
                ip route add $ip_prefix table $isp_router_label dev $vport_name
                config_policy_rtable_for_local $ip $netmask $vport_name $isp_router_label
            fi
        done

        # VGW-LAN-ENTRY-6:
        #   Used for LAN ARP flows from PHY or PATCH ports to VGW LAN port.
        # Learned entry:
        #   Used for reversed LAN (ANY) flows.
        ovs-ofctl add-flow $DATA_BR \
            cookie=$cookie,table=0,priority=33000,arp,dl_vlan=$vlantag,arp_tpa=$ip,actions="
                learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=33000,
                    idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$vport_no,
                    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
                set_skb_mark:$router_id,strip_vlan,$vport_no" && \
        # VGW-LAN-ENTRY-7:
        #   Used for LAN ARP flows from other VGW LAN ports to VGW LAN port.
        ovs-ofctl add-flow $DATA_BR \
            cookie=$cookie,table=1,priority=32000,arp,dl_vlan=$vlantag,arp_tpa=$ip,actions="
                set_skb_mark:$router_id,strip_vlan,$vport_no"
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
        /usr/local/livegate/script/net_ghost.py GARP 0 0 0 $ip $vport_mac - -
        if [[ $? -ne 0 ]]; then
            echo "`date +20'%y-%m-%d %H%M%S'` WARNING: execute" \
                "'/usr/local/livegate/script/net_ghost.py GARP 0 0 0 $ip $vport_mac - -'" \
                "failed" >> /var/log/livegate.log
        fi
    done

    # default route
    isp_router_label=`get_isp_router_label $router_id 1`
    chk=`ip route list exact 0/0 table $isp_router_label`
    if [[ -z "$chk" ]]; then
        ip route add unreachable 0/0 table $isp_router_label
    fi

    # init INPUT chain
    check_iptables_chain filter INPUT $router_id

    config_interface_qos $vport_name $min_rate $max_rate false

    nohup $LIVEGATE_SCRIPT_DIR/refresh_vgateway_mac.sh \
        $router_id $ROLE_VGATEWAY $if_index >/dev/null 2>&1 &
}

config_valve_wan()
{
    router_id=$1
    if_index=$2
    isp=$3
    gateway=$4
    mac=$5
    vlantag=$6
    min_rate=$7
    max_rate=$8
    broadcast_min_rate=$9
    broadcast_max_rate=${10}

    vport_name=`check_wan_vport $router_id $VALVE_WAN_IF_INDEX`
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name`
    vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`
    if [[ "$mac" != "00:00:00:00:00:00" && "$vport_mac" != "$mac" ]]; then
        vport_mac=$mac
        ovs-vsctl --timeout=10 -- set interface $vport_name "mac=\"$vport_mac\""
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
    fi
    ovs-vsctl --timeout=10 -- add port $vport_name trunks $vlantag

    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-router-type=$ROUTER_TYPE_VALVE
    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-router-isp-$if_index=$isp
    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-vlan-$if_index=$vlantag
    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-gateway-$if_index=$gateway
    ip -4 addr flush $vport_name 2> /dev/null

    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-valve-rate-$if_index="$min_rate $max_rate"
    rate=(`ovs-vsctl --bare get interface $vport_name \
        external_ids:lc-valve-rate 2> /dev/null | grep -Eo "[0-9]+"`)
    if [[ -n "$rate" ]]; then
        (( min_sum_rate = $min_rate + ${rate[0]} ))
        (( max_sum_rate = ($max_rate > ${rate[1]}) ? $max_rate : ${rate[1]} ))
    else
        min_sum_rate=$min_rate
        max_sum_rate=$max_rate
    fi
    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-valve-rate="$min_sum_rate $max_sum_rate"

    # Assume x Mbit ISP1 bandwidth (A yuan/Mbit), y Mbit ISP2 bandwidth (B yuan/Mbit), A>B.
    # TOTAL_PRICE = x*A+y*B
    # TOTAL_MAX_BW = x+y
    # TOTAL_MIN_BW = x+y
    #  ISP1_MAX_BW = x+(B/A)y
    #  ISP1_MIN_BW = x
    #  ISP2_MAX_BW = x+y
    #  ISP2_MIN_BW = y
    # It is possible that ISP1 IPs use full of ISP1_MAX_BW bandwidth, meanwhile
    # ISP2 IPs can also use the rest (TOTAL_MAX_BW - ISP1_MAX_BW) bandwidth
    # via valve if x<y, thus at this time the user obtains the extra free
    # (TOTAL_MAX_BW - ISP1_MAX_BW) bandwidth.
    # IF we can limit x>=y, or charge x*A+y*(2-B/A)B yuan for the valve, then
    # we will not suffer losses. The value of ISPX_XXX_BW is given by talker.
    # Final scheme:
    # TOTAL_PRICE = x*A+y*B
    # TOTAL_MAX_BW = x+(B/A)y
    # TOTAL_MIN_BW = x+(B/A)y
    #  ISP1_MAX_BW = x+(B/A)y
    #  ISP1_MIN_BW = x
    #  ISP2_MAX_BW = x+(B/A)y
    #  ISP2_MIN_BW = min{y, x+(B/A)y}
    egress_vport_name=$vport_name
    config_valve_interface_qos $egress_vport_name $min_sum_rate $max_sum_rate \
        $if_index $min_rate $max_rate
    ingress_vport_name=`check_lan_vport $router_id $VALVE_LAN_IF_INDEX`
    config_valve_interface_qos $ingress_vport_name $min_sum_rate $max_sum_rate \
        $if_index $min_rate $max_rate

    isp_router_id=`get_isp_router_id $router_id $isp`
    cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    # VALVE-WAN-ENTRY-1:
    #   Used for WAN (ANY) flows from VALVE WAN port to PHY or other VGW/VALVE WAN ports (the
    #   same ISP).
    #     Note that, because the VALVE WAN port use trunk mode, it cannot use strip_vlan
    #     before normal action.
    #     Besides, this entry can avoid FLOOD, i.e., DUP.
    ovs-ofctl add-flow $UPLINK_BR \
        cookie=$cookie,table=1,priority=20000,in_port=$vport_no,dl_vlan=$vlantag,actions="
            normal" && \
    # VALVE-WAN-ENTRY-2:
    #   Drop all irrelevant packets from VALVE WAN port.
    ovs-ofctl add-flow $UPLINK_BR \
        cookie=$cookie,table=0,priority=19000,in_port=$vport_no,actions="drop"
    # Default entry:
    #   Table 0: normal
    #   Used for other common flows, such as local-nspbr1-IP <-> peer-nspbr1-IP
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    isp_router_id=`get_isp_router_id $router_id $VALVE_WAN_ISP_ID`
    id=0
    while [[ $# -ge 12 ]]; do
        ip=${11}
        netmask=${12}
        shift 2

        prefix=`ip_mask_to_ip_masklen $ip $netmask`
        # VALVE-WAN-ENTRY-3:
        #   Drop WAN (ARP) flows from VALVE WAN port to VALVE WAN port (the same ISP).
        #     Note that, for the src IP and the dst IP intra the same VALVE and belong to the same ISP,
        #     they can connect intra LAN (due to the same VLAN), unnecessary to connect via WAN again,
        #     otherwise, DUP will occur.
        #     Besides, for the src IP and the dst IP intra the same VALVE but belong to different ISPs,
        #     they must connect via WAN, i.e., IP gateway, because the normal routes of the IPS
        #     from different ISPs do not allow direct connection without gateway,
        #     although in the same LAN.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=26000,in_port=$vport_no,arp,arp_spa=$prefix,arp_tpa=$ip,actions="
                drop" && \
        # VALVE-WAN-ENTRY-4:
        #   Drop WAN (IP) flows from VALVE WAN port to VALVE WAN port (the same ISP).
        #     The same as VALVE-WAN-ENTRY-3.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=26000,in_port=$vport_no,ip,nw_src=$prefix,nw_dst=$ip,actions="
                drop" && \
        # VALVE-WAN-ENTRY-5:
        #   Used for WAN ARP flows from PHY ports.
        # Learned entry:
        #   Used for reversed WAN (ANY) flows.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,arp,dl_vlan=$vlantag,arp_tpa=$ip,actions="
                learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=25000,
                    idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$vport_no,
                    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
                set_skb_mark=$isp_router_id,strip_vlan,$vport_no" && \
        # VALVE-WAN-ENTRY-6:
        #   Used for WAN ARP flows from other VGW/VALVE WAN ports (any ISP).
        #     Note that, if dl_vlan is not designated in VALVE-WAN-ENTRY-5 and VALVE-WAN-ENTRY-6,
        #     then the inter-rack LAN ARP flows (e.g. intra VALVE) with arp_tpa=$ip
        #     from PATCH port can also be handled by mistake.
        # Learned entry:
        #   Used for reversed WAN (ANY) flows.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,arp,dl_vlan=0xffff,arp_spa=$ip/$netmask,arp_tpa=$ip,actions="
                learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=25000,
                    idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$vport_no,
                    NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
                set_skb_mark=$isp_router_id,$vport_no" && \
        # VALVE-WAN-ENTRY-7:
        #   Used for WAN IP flows from PHY ports.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,ip,dl_vlan=$vlantag,nw_dst=$ip,actions="
                set_skb_mark=$isp_router_id,strip_vlan,$vport_no" && \
        # VALVE-WAN-ENTRY-8:
        #   Used for WAN IP flows from other VGW/VALVE WAN ports (any ISP).
        #     Note that, if dl_vlan is not designated in VALVE-WAN-ENTRY-7 and VALVE-WAN-ENTRY-8,
        #     then the inter-rack LAN IP flows (e.g. intra VGW/VALVE) with nw_dst=$ip
        #     from PATCH port can also be handled by mistake.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=25000,ip,dl_vlan=0xffff,nw_src=$ip/$netmask,nw_dst=$ip,actions="
                set_skb_mark=$isp_router_id,$vport_no" && \
        # VALVE-WAN-ENTRY-9:
        #   Used for WAN ARP flows from VALVE WAN port to PHY or other VGW/VALVE WAN ports.
        # Resubmitted entry:
        #   (1) Match the learned entry of VALVE-WAN-ENTRY-5 or VALVE-WAN-ENTRY-6.
        #   (2) Match the entry VGW-WAN-ENTRY-1.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=20000,in_port=$vport_no,arp,arp_spa=$ip,actions="
                mod_vlan_vid:$vlantag,resubmit(,1)" && \
        # VALVE-WAN-ENTRY-10:
        #   Used for WAN IP flows from VALVE WAN port to PHY or other VGW/VALVE WAN ports.
        #     Note that, this entry cannot combine with VALVE-WAN-ENTRY-9
        #     due to no MAC can be designated to replace IP.
        # Resubmitted entry:
        #   (1) Match the learned entry of VALVE-WAN-ENTRY-5 or VALVE-WAN-ENTRY-6.
        #   (2) Match the entry VGW-WAN-ENTRY-1.
        ovs-ofctl add-flow $UPLINK_BR \
            cookie=$cookie,table=0,priority=20000,in_port=$vport_no,ip,nw_src=$ip,actions="
                mod_vlan_vid:$vlantag,resubmit(,1)"
        if [[ $? -ne 0 ]]; then
            exit 1
        fi

        (( id += 1 ))
        ovs-vsctl --timeout=10 -- set interface $vport_name \
            external_ids:lc-ip-netmask-$if_index-$id="$prefix"
        if [[ $? -ne 0 ]]; then
            exit 1
        fi

        config_valve_interface_qos $egress_vport_name $min_sum_rate $max_sum_rate \
            $if_index $min_rate $max_rate $ip src
        config_valve_interface_qos $ingress_vport_name $min_sum_rate $max_sum_rate \
            $if_index $min_rate $max_rate $ip dst
    done

    # init FORWARD chain
    isp_router_id=`get_isp_router_id $router_id $VALVE_LAN_ISP_ID`
    check_ebtables_chain filter FORWARD $router_id $isp_router_id $vport_name

    config_egress_broadcast_qos $router_id $VALVE_WAN_IF_INDEX \
        $broadcast_min_rate $broadcast_max_rate
}

config_valve_lan()
{
    router_id=$1
    if_index=$2
    mac=$3
    vlantag=$4

    vport_name=`check_lan_vport $router_id $VALVE_LAN_IF_INDEX`
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name`
    vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`
    if [[ "$mac" != "00:00:00:00:00:00" && "$vport_mac" != "$mac" ]]; then
        vport_mac=$mac
        ovs-vsctl --timeout=10 -- set interface $vport_name "mac=\"$vport_mac\""
        if [[ $? -ne 0 ]]; then
            exit 1
        fi
    fi
    ovs-vsctl --timeout=10 -- set port $vport_name tag=$vlantag

    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-router-type=$ROUTER_TYPE_VALVE
    ovs-vsctl --timeout=10 -- set interface $vport_name \
        external_ids:lc-vlan-$if_index=$vlantag
    ip -4 addr flush $vport_name 2> /dev/null

    isp_router_id=`get_isp_router_id $router_id $VALVE_LAN_ISP_ID`
    cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    if ! ovs-vsctl list interface $LC_DATA_TUNL_PATCH_PORT > /dev/null 2>&1; then
        exit 1
    fi
    patch_port=`ovs-vsctl get interface $LC_DATA_TUNL_PATCH_PORT ofport`
    # VALVE-LAN-ENTRY-1:
    #   Used for LAN (ANY) flows from PATCH port to PHY or VALVE LAN ports.
    #     Note that, this entry can be saved if normal action are used instead of
    #     $vport_no for VALVE-LAN-ENTRY-2 and VALVE-LAN-ENTRY-3, but the affect that
    #     the flows from PATCH port are forced to send back to PATCH port is
    #     nondeterministic.
    #     Besides, this entry can be divided into two parts, where the one resubmits
    #     to table 1 can utilize the learned entry of VALVE-LAN-ENTRY-2. However,
    #     (1) this introduces another entry, and (2) in standard deployment VxLAN
    #     is implemented by ToR switch (rather than NSP server).
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=34000,in_port=$patch_port,dl_vlan=$vlantag,actions="
            set_skb_mark=$isp_router_id,normal" && \
    # VALVE-LAN-ENTRY-2:
    #   Used for LAN ARP flows from PHY ports.
    # Learned entry:
    #   Used for reversed LAN (ANY) flows.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=33000,arp,dl_vlan=$vlantag,actions="
            learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=33000,
                idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$vport_no,
                NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
            $patch_port,set_skb_mark=$isp_router_id,strip_vlan,$vport_no" && \
    # VALVE-LAN-ENTRY-3:
    #   Used for LAN IP flows from PHY ports.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=33000,ip,dl_vlan=$vlantag,actions="
            $patch_port,set_skb_mark=$isp_router_id,strip_vlan,$vport_no" && \
    # VALVE-LAN-ENTRY-4:
    #   Used for LAN (ANY) flows from VALVE LAN port to PATCH or PHY ports.
    # Resubmitted entry:
    #   (1) Match the learned entry of VGW-LAN-ENTRY-2.
    #   (2) Match the entry VGW-LAN-ENTRY-5.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=31000,in_port=$vport_no,dl_vlan=0xffff,actions="
            mod_vlan_vid:$vlantag,resubmit(,1)" && \
    # VALVE-LAN-ENTRY-5:
    #   Used for LAN (ANY) flows from VALVE LAN port to PATCH or PHY ports.
    #     Note that, this entry can avoid FLOOD, i.e., DUP.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=1,priority=31000,in_port=$vport_no,dl_vlan=$vlantag,actions="
            strip_vlan,normal" && \
    # VALVE-LAN-ENTRY-6:
    #   Drop all irrelevant packets from VALVE LAN port.
    ovs-ofctl add-flow $DATA_BR \
        cookie=$cookie,table=0,priority=30000,in_port=$vport_no,actions="drop"
    # Default entry:
    #   Table 0: normal
    #   Used for no chance.
    if [[ $? -ne 0 ]]; then
        exit 1
    fi

    # init FORWARD chain
    isp_router_id=`get_isp_router_id $router_id $VALVE_WAN_ISP_ID`
    check_ebtables_chain filter FORWARD $router_id $isp_router_id $vport_name
}

get_wan_isp()
{
    router_id=$1
    vport_name=$2

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_label=`get_isp_router_label $router_id $isp`
        chk=`ip route ls table $isp_router_label 0/0 dev $vport_name 2> /dev/null`
        if [[ -n "$chk" ]]; then
            echo $isp
            return 0
        fi
    done

    return 1
}

get_valve_wan_isp()
{
    router_id=$1
    vport_name=$2
    if_index=$3

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        chk=`ovs-vsctl --bare get interface $vport_name \
            external_ids:lc-router-isp-$if_index 2> /dev/null | grep -o $isp`
        if [[ -n "$chk" ]]; then
            echo $isp
            return 0
        fi
    done

    return 1
}

translate_qos()
{
    value=(`echo $1 | grep -Eo "[0-9]+|[GMKi]*bit"`)
    result=0
    if [[ -n "${value[0]}" && -n "${value[1]}" ]]; then
        case ${value[1]} in
            Kibit)
                (( result = ${value[0]} * 1024 ))
                ;;
            Mibit)
                (( result = ${value[0]} * 1024 * 1024 ))
                ;;
            Gibit)
                (( result = ${value[0]} * 1024 * 1024 * 1024 ))
                ;;
            bit)
                (( result = ${value[0]} ))
                ;;
        esac
    fi
    echo $result
}

get_qos()
{
    vport_name=$1

    qos_min=0
    qos_max=0
    qos=`tc -iec class show dev $vport_name classid 1:2`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        qos_max=`translate_qos $__qos_max`
    fi
    echo $qos_min $qos_max
}

get_valve_qos()
{
    vport_name=$1
    index=$2

    qos_min=0
    qos_max=0
    if [[ -n "$index" ]]; then
        (( index += 1 ))
    fi
    qos=`tc -iec class show dev $vport_name classid 1:$index`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        qos_max=`translate_qos $__qos_max`
    fi
    echo $qos_min $qos_max
}

get_wan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    isp=`get_wan_isp $router_id $vport_name`
    if [[ $? -ne 0 ]]; then
        exit 1
    fi
    isp_router_label=`get_isp_router_label $router_id $isp`

    gateway=`ip route ls table $isp_router_label 0/0 dev $vport_name 2> /dev/null | awk '{print $3}'`
    vlantag=`ovs-vsctl --bare get port $vport_name tag 2> /dev/null | grep -E "[0-9]+"`
    if [[ -z "$vlantag" || "$vlantag" == "[]" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`
    qos=(`get_qos $vport_name`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    json_hdr=`cat <<JSON_DATA
    {
      "IF_INDEX": $if_index,
      "STATE": "ATTACH",
      "ISP": $isp,
      "GATEWAY": "$gateway",
      "VLANTAG": $vlantag,
      "MAC": "$mac",
      "QOS": { "MIN_BANDWIDTH": $qos_min, "MAX_BANDWIDTH": $qos_max },
      "IPS": [
JSON_DATA`
    echo "$json_hdr"

    IPMS=(`ip -f inet -oneline addr show $vport_name 2> /dev/null | awk '{print $4}'`)
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -ne 0 ]]; then
            echo ","
        fi

        arr=(`ip_masklen_to_ip_mask $ipm`)
        json_ip=`cat <<JSON_DATA
        { "ADDRESS": "${arr[0]}", "NETMASK": "${arr[1]}" }
JSON_DATA`
        echo -n "$json_ip"

        (( i = i + 1 ))
    done

    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "      ]"
    echo "    }"
}

get_lan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    vlantag=`ovs-vsctl --bare get port $vport_name tag 2> /dev/null | grep -E "[0-9]+"`
    if [[ -z "$vlantag" || "$vlantag" == "[]" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`
    qos=(`get_qos $vport_name`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    json_hdr=`cat <<JSON_DATA
    {
      "IF_INDEX": $if_index,
      "STATE": "ATTACH",
      "VLANTAG": $vlantag,
      "MAC": "$mac",
      "QOS": { "MIN_BANDWIDTH": $qos_min, "MAX_BANDWIDTH": $qos_max },
      "IPS": [
JSON_DATA`
    echo "$json_hdr"

    IPMS=(`ip -f inet -oneline addr show $vport_name 2> /dev/null | awk '{print $4}'`)
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -ne 0 ]]; then
            echo ","
        fi

        arr=(`ip_masklen_to_ip_mask $ipm`)
        json_ip=`cat <<JSON_DATA
        { "ADDRESS": "${arr[0]}", "NETMASK": "${arr[1]}" }
JSON_DATA`
        echo -n "$json_ip"

        (( i = i + 1 ))
    done

    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "      ]"
    echo "    }"
}

get_valve_wan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${VALVE_WAN_IF_INDEX}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    isp=`get_valve_wan_isp $router_id $vport_name $if_index`
    if [[ $? -ne 0 ]]; then
        exit 1
    fi

    gateway=`ovs-vsctl --bare get interface $vport_name external_ids:lc-gateway-$if_index \
        2> /dev/null | grep -Eo "$IP_FORMAT"`
    vlantag=`ovs-vsctl --bare get interface $vport_name external_ids:lc-vlan-$if_index \
        2> /dev/null | grep -Eo "[0-9]+"`
    if [[ -z "$vlantag" || "$vlantag" == "[]" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`
    qos=(`get_valve_qos $vport_name $if_index`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    json_hdr=`cat <<JSON_DATA
    {
      "IF_INDEX": $if_index,
      "STATE": "ATTACH",
      "ISP": $isp,
      "GATEWAY": "$gateway",
      "VLANTAG": $vlantag,
      "MAC": "$mac",
      "QOS": { "MIN_BANDWIDTH": $qos_min, "MAX_BANDWIDTH": $qos_max },
      "IPS": [
JSON_DATA`
    echo "$json_hdr"

    IPMS=(`ovs-vsctl --bare get interface $vport_name external_ids \
        2> /dev/null | grep -Eo "lc-ip-netmask-$if_index-[^,}]+" |
        grep -Eo "$IP_FORMAT/[0-9]+"`)
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -ne 0 ]]; then
            echo ","
        fi

        arr=(`ip_masklen_to_ip_mask $ipm`)
        json_ip=`cat <<JSON_DATA
        { "ADDRESS": "${arr[0]}", "NETMASK": "${arr[1]}" }
JSON_DATA`
        echo -n "$json_ip"

        (( i = i + 1 ))
    done

    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "      ]"
    echo "    }"
}

get_valve_lan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    vlantag=`ovs-vsctl --bare get interface $vport_name external_ids:lc-vlan-$if_index \
        2> /dev/null | grep -Eo "[0-9]+"`
    if [[ -z "$vlantag" || "$vlantag" == "[]" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`
    qos=(`get_valve_qos $vport_name`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    json_hdr=`cat <<JSON_DATA
    {
      "IF_INDEX": $if_index,
      "STATE": "ATTACH",
      "VLANTAG": $vlantag,
      "MAC": "$mac",
      "QOS": { "MIN_BANDWIDTH": $qos_min, "MAX_BANDWIDTH": $qos_max },
      "IPS": []
JSON_DATA`
    echo "$json_hdr"

    echo "    }"
}

get_wan_vport_names()
{
    router_id=$1
    ovs-vsctl list-ports $UPLINK_BR | grep "^${router_id}-${WAN_VPORT_PREFIX}-"
}

get_lan_vport_names()
{
    router_id=$1
    ovs-vsctl list-ports $DATA_BR | grep "^${router_id}-${LAN_VPORT_PREFIX}-"
}

get_valve_wan_if_indices()
{
    router_id=$1
    vport_name=${router_id}-${WAN_VPORT_PREFIX}-${VALVE_WAN_IF_INDEX}
    ovs-vsctl --bare get interface $vport_name external_ids |
        grep -Eo "lc-router-isp-[0-9]+" | grep -Eo "[0-9]+"
}

get_valve_lan_if_indices()
{
    router_id=$1
    vport_name=${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}
    ovs-vsctl --bare get interface $vport_name external_ids |
        grep -Eo "lc-vlan-[0-9]+" | grep -Eo "[0-9]+"
}

get_router()
{
    router_id=$1

    echo "{"
    echo "  \"ID\": $router_id,"

    i=0
    echo "  \"WANS\": ["
    for vport_name in `get_wan_vport_names $router_id`; do
        if_index=${vport_name##*-}
        json=`get_wan $router_id $if_index`
        if [[ $? -eq 0 ]]; then
            if [[ $i -ne 0 ]]; then
                echo ","
            fi
            echo -n "$json"
            (( i = i + 1 ))
        fi
    done
    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "  ],"

    i=0
    echo "  \"LANS\": ["
    for vport_name in `get_lan_vport_names $router_id`; do
        if_index=${vport_name##*-}
        json=`get_lan $router_id $if_index`
        if [[ $? -eq 0 ]]; then
            if [[ $i -ne 0 ]]; then
                echo ","
            fi
            echo -n "$json"
            (( i = i + 1 ))
        fi
    done
    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "  ]"
    echo "}"
}

get_valve()
{
    router_id=$1

    echo "{"
    echo "  \"ID\": $router_id,"

    i=0
    echo "  \"WANS\": ["
    for if_index in `get_valve_wan_if_indices $router_id`; do
        json=`get_valve_wan $router_id $if_index`
        if [[ $? -eq 0 ]]; then
            if [[ $i -ne 0 ]]; then
                echo ","
            fi
            echo -n "$json"
            (( i = i + 1 ))
        fi
    done
    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "  ],"

    i=0
    echo "  \"LANS\": ["
    for if_index in `get_valve_lan_if_indices $router_id`; do
        json=`get_valve_lan $router_id $if_index`
        if [[ $? -eq 0 ]]; then
            if [[ $i -ne 0 ]]; then
                echo ","
            fi
            echo -n "$json"
            (( i = i + 1 ))
        fi
    done
    if [[ $i -ne 0 ]]; then
        echo ""
    fi
    echo "  ]"
    echo "}"
}

delete_policy_rtable_for_local()
{
    typeset ipm vport_name isp_router_label

    ipm=$1
    vport_name=$2
    isp_router_label=$3

    ip=`echo $ipm | grep -Eo "$IP_FORMAT"`
    mask_num=`echo $ipm | grep -Eo "[0-9]+$"`
    (( mask_num = 0xffffffff ^ ( (1 << (32 - mask_num)) - 1 ) ))
    netmask=`NUM2IP $mask_num`
    ip route del table $isp_router_label $ip dev $vport_name 2> /dev/null
    ip route del table $isp_router_label `ip_mask_to_broadcast_l $ip $netmask`
        dev $vport_name 2> /dev/null
    ip route del table $isp_router_label `ip_mask_to_broadcast_r $ip $netmask`
        dev $vport_name 2> /dev/null
}

delete_wan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"

    isp=`get_wan_isp $router_id $vport_name`
    if [[ $? -ne 0 ]]; then
        exit 0
    fi
    isp_router_id=`get_isp_router_id $router_id $isp`
    isp_router_label=`get_isp_router_label $router_id $isp`
    cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    # route
    ip route del 0/0 dev $vport_name table $isp_router_label > /dev/null 2>&1

    # flow
    ovs-ofctl del-flows $UPLINK_BR cookie=$cookie/-1

    # only flush address, postpone port deletion
    ip -4 addr flush $vport_name 2> /dev/null
    :
}

delete_lan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name`
    vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`

    cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
    IPMS=(`ip -f inet -oneline addr show $vport_name 2> /dev/null | awk '{print $4}'`)
    for ipm in ${IPMS[@]}; do
        for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
            isp_router_id=`get_isp_router_id $router_id $isp`
            isp_router_label=`get_isp_router_label $router_id $isp`

            # route
            pfx=`ip_masklen_to_prefix $ipm`
            ip route del $pfx table $isp_router_label dev $vport_name 2> /dev/null
            delete_policy_rtable_for_local $ipm $vport_name $isp_router_label
        done

        # ovs flow
        ip=(`echo $ipm | awk -F"/" '{print $1}'`)
        ovs-ofctl del-flows $DATA_BR cookie=$cookie/-1,arp,arp_tpa=$ip
    done
    ovs-ofctl del-flows $DATA_BR cookie=$cookie/-1,ip
    ovs-ofctl del-flows $DATA_BR cookie=$cookie/-1,in_port=$vport_no

    # only flush address, postpone port deletion
    ip -4 addr flush $vport_name 2> /dev/null
    :
}

delete_valve_wan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${VALVE_WAN_IF_INDEX}"

    isp=`get_valve_wan_isp $router_id $vport_name $if_index`
    if [[ $? -ne 0 ]]; then
        exit 0
    fi

    isp_router_id=`get_isp_router_id $router_id $isp`
    cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    # flow
    ovs-ofctl del-flows $UPLINK_BR cookie=$cookie/-1

    rate=(`ovs-vsctl --bare get interface $vport_name \
        external_ids:lc-valve-rate 2> /dev/null | grep -Eo "[0-9]+"`)
    if_rate=(`ovs-vsctl --bare get interface $vport_name \
        external_ids:lc-valve-rate-$if_index 2> /dev/null | grep -Eo "[0-9]+"`)
    ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids lc-valve-rate-$if_index
    if [[ -n "$rate" && -n "$if_rate" ]]; then
        (( min_rate = ${rate[0]} - ${if_rate[0]} ))
        (( min_rate = ($min_rate > 0) ? $min_rate : 0 ))
        if [[ ${rate[1]} -gt ${if_rate[1]} ]]; then
            max_rate=${rate[1]}
        else
            max_rate=`ovs-vsctl --bare get interface $vport_name external_ids |
                grep -Eo "lc-valve-rate-[^,}]+" | grep -Eo "[0-9]+\"$" | grep -Eo "[0-9]+" |
                sort -r | head -n 1`
            : ${max_rate:=0}
        fi
        ingress_vport_name="${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}"
        if [[ $min_rate -ne 0 ]]; then
            ovs-vsctl --timeout=10 -- set interface $vport_name \
                external_ids:lc-valve-rate="$min_rate $max_rate"
            delete_valve_interface_qos $vport_name $if_index
            config_valve_interface_qos $vport_name $min_rate $max_rate
            if ovs-vsctl list port $ingress_vport_name > /dev/null 2>&1; then
                delete_valve_interface_qos $ingress_vport_name $if_index
                config_valve_interface_qos $ingress_vport_name $min_rate $max_rate
            fi
        else
            ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids lc-valve-rate
            delete_valve_interface_qos $vport_name
            if ovs-vsctl list port $ingress_vport_name > /dev/null 2>&1; then
                delete_valve_interface_qos $ingress_vport_name
            fi
        fi
    fi
    ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids lc-router-isp-$if_index
    ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids lc-gateway-$if_index
    ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids lc-vlan-$if_index
    objs=`ovs-vsctl --bare get interface $vport_name external_ids |
        grep -Eo "lc-ip-netmask-$if_index-[0-9]+"`
    for obj in $objs; do
        ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids $obj
    done
    if [[ -n "`get_valve_wan_if_indices $router_id`" ]]; then
        return 0
    fi

    # ebtables
    isp_router_id=`get_isp_router_id $router_id $VALVE_LAN_ISP_ID`
    delete_ebtables_chain filter FORWARD $router_id $isp_router_id $vport_name

    # only flush address, postpone port deletion
    ip -4 addr flush $vport_name 2> /dev/null
    :
}

delete_valve_lan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}"

    cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    # flow
    ovs-ofctl del-flows $DATA_BR cookie=$cookie/-1

    ovs-vsctl --timeout=10 -- remove interface $vport_name external_ids lc-vlan-$if_index
    if [[ -n "`get_valve_lan_if_indices $router_id`" ]]; then
        return 0
    fi

    # ebtables
    isp_router_id=`get_isp_router_id $router_id $VALVE_WAN_ISP_ID`
    delete_ebtables_chain filter FORWARD $router_id $isp_router_id $vport_name

    # only flush address, postpone port deletion
    ip -4 addr flush $vport_name 2> /dev/null
    :
}

flush_vpn_conn_by_router_id()
{
    router_id=$1

    rm -f $STRONGSWAN_CONF_DIR/nsp_${router_id}_*.conf 2> /dev/null
    rm -f $STRONGSWAN_CONF_DIR/nsp_${router_id}_*.secrets 2> /dev/null
    flush_vpn_conn=false
    if strongswan status > /dev/null 2>&1; then
        if ls $STRONGSWAN_CONF_DIR/nsp_*.conf > /dev/null 2>&1; then
            strongswan reload > /dev/null 2>&1
            flush_vpn_conn=true
        else
            strongswan stop > /dev/null 2>&1
        fi
    fi

    if $flush_vpn_conn; then
        vpn_conns=`strongswan status 2> /dev/null | grep -Eo "^${router_id}_[^{[]+" | sort | uniq`
        for vpn_conn in $vpn_conns; do
            try=1
            while :; do
                if [[ -z "`strongswan down $vpn_conn 2> /dev/null`" || $try -ge 9 ]]; then
                    break
                fi
                (( try += 1 ))
            done
        done
        strongswan reload > /dev/null 2>&1
    fi
}

flush_vpn_conn_by_vpn_label()
{
    vpn_label=$1

    vpn_conns=`cat $STRONGSWAN_CONF_DIR/${vpn_label}.conf | grep ^conn | grep -Eo "[^ conn]+"`
    rm -f $STRONGSWAN_CONF_DIR/${vpn_label}.conf 2> /dev/null
    rm -f $STRONGSWAN_CONF_DIR/${vpn_label}.secrets 2> /dev/null
    flush_vpn_conn=false
    if strongswan status > /dev/null 2>&1; then
        if ls $STRONGSWAN_CONF_DIR/nsp_*.conf > /dev/null 2>&1; then
            strongswan reload > /dev/null 2>&1
            flush_vpn_conn=true
        else
            strongswan stop > /dev/null 2>&1
        fi
    fi

    if $flush_vpn_conn; then
        for vpn_conn in $vpn_conns; do
            try=1
            while :; do
                if [[ -z "`strongswan down $vpn_conn 2> /dev/null`" || $try -ge 9 ]]; then
                    break
                fi
                (( try += 1 ))
            done
        done
        strongswan reload > /dev/null 2>&1
    fi
}

refresh_vpn_conn_by_conn_name()
{
    vpn_conn_name=$1

    if ! strongswan status > /dev/null 2>&1; then
        strongswan start > /dev/null 2>&1
    else
        strongswan reload > /dev/null 2>&1
    fi

    # strongswan down must be executed 3 times
    seq 3 | xargs -i strongswan down $vpn_conn_name > /dev/null 2>&1
    strongswan reload > /dev/null 2>&1
}

delete_router()
{
    router_id=$1
    remove_vport=$2

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        isp_router_label=`get_isp_router_label $router_id $isp`
        wan_cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        snat_cookie=`echo $isp_router_id | awk -v fmt=$SNAT_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        dnat_cookie=`echo $isp_router_id | awk -v fmt=$DNAT_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        vpn_cookie=`echo $isp_router_id | awk -v fmt=$VPN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

        # route
        ip route flush table $isp_router_label
        ip rule | grep -w "lookup $isp_router_label" | awk '{print $2, $3, $4, $5, $6, $7}' | while read line; do
            if [[ -n "$line" ]]; then
                ip rule del $line
            fi
        done

        # flow
        ovs-ofctl del-flows $UPLINK_BR cookie=$wan_cookie/-1
        ovs-ofctl del-flows $DATA_BR cookie=$snat_cookie/-1
        ovs-ofctl del-flows $DATA_BR cookie=$dnat_cookie/-1
        ovs-ofctl del-flows $DATA_BR cookie=$vpn_cookie/-1
    done

    lan_cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
    ovs-ofctl del-flows $DATA_BR cookie=$lan_cookie/-1

    # iptables
    for chain in INPUT FORWARD OUTPUT; do
        if ! iptables -S ${chain}_${router_id} 1 > /dev/null 2>&1; then
           continue
        fi
        iptables -D $chain -m mark --mark $router_id/$SKB_MARK_MASK \
            -g ${chain}_${router_id} 2> /dev/null
        iptables -F ${chain}_${router_id} 2> /dev/null
        iptables -X ${chain}_${router_id} 2> /dev/null
    done
    for chain in PREROUTING INPUT OUTPUT POSTROUTING; do
        if ! iptables -t nat -S ${chain}_${router_id} 1 > /dev/null 2>&1; then
           continue
        fi
        iptables -t nat -D $chain -m mark --mark $router_id/$SKB_MARK_MASK \
            -g ${chain}_${router_id} 2> /dev/null
        iptables -t nat -F ${chain}_${router_id} 2> /dev/null
        iptables -t nat -X ${chain}_${router_id} 2> /dev/null
    done

    # vports
    if [[ "$remove_vport" = "1" ]]; then
        for vport_name in `get_wan_vport_names $router_id`; do
            delete_vport $vport_name
        done
        for vport_name in `get_lan_vport_names $router_id`; do
            delete_vport $vport_name
        done
    else
        for vport_name in `get_wan_vport_names $router_id`; do
            # Note that, tag must be removed
            ovs-vsctl --timeout=10 -- set port $vport_name tag=[]
            ip -4 addr flush $vport_name 2> /dev/null
        done
        for vport_name in `get_lan_vport_names $router_id`; do
            # Note that, tag must be removed
            ovs-vsctl --timeout=10 -- set port $vport_name tag=[]
            ip -4 addr flush $vport_name 2> /dev/null
        done
    fi

    # vpn
    flush_vpn_conn_by_router_id $router_id

    :
}

delete_valve()
{
    router_id=$1
    remove_vport=$2

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        wan_cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

        # flow
        ovs-ofctl del-flows $UPLINK_BR cookie=$wan_cookie/-1
    done

    # ebtables
    isp_router_id=`get_isp_router_id $router_id $VALVE_LAN_ISP_ID`
    delete_ebtables_chain filter FORWARD $router_id $isp_router_id

    lan_cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`

    #flow
    ovs-ofctl del-flows $DATA_BR cookie=$lan_cookie/-1

    # ebtables
    isp_router_id=`get_isp_router_id $router_id $VALVE_WAN_ISP_ID`
    delete_ebtables_chain filter FORWARD $router_id $isp_router_id

    br=$VALVE_BR_PREFIX$router_id
    ip link set dev $br down 2> /dev/null
    # vports
    if [[ "$remove_vport" = "1" ]]; then
        for vport_name in `get_wan_vport_names $router_id`; do
            delete_valve_vport $vport_name
        done
        for vport_name in `get_lan_vport_names $router_id`; do
            delete_valve_vport $vport_name
        done
        brctl delbr $br 2> /dev/null
    else
        for if_index in `get_valve_wan_if_indices $router_id`; do
            delete_valve_wan $router_id $if_index
        done
        for if_index in `get_valve_lan_if_indices $router_id`; do
            delete_valve_lan $router_id $if_index
        done
        for vport_name in `get_wan_vport_names $router_id`; do
            # Note that, tag must be removed
            ovs-vsctl --timeout=10 -- set port $vport_name trunks=[]
            delete_valve_interface_qos $vport_name
        done
        for vport_name in `get_lan_vport_names $router_id`; do
            # Note that, tag must be removed
            ovs-vsctl --timeout=10 -- set port $vport_name tag=[]
            delete_valve_interface_qos $vport_name
        done
    fi

    :
}

delete_all_routers()
{
    ebtables -P FORWARD DROP
    ebtables -F
    ebtables -X
    for br in `brctl show | grep -Ewo "^$VALVE_BR_PREFIX[0-9]+"`; do
        ip link set dev $br down
        brctl delbr $br
    done

    iptables -F
    iptables -t nat -F
    iptables -X
    iptables -t nat -X
    ip rule | grep -Ew "lookup [0-9]+" | awk '{print $2, $3, $4, $5, $6, $7}' | while read line; do
        if [[ -n "$line" ]]; then
            ip rule del $line
        fi
    done
    iptables -A INPUT -p icmp -m icmp --icmp-type 255 -j ACCEPT
    iptables -A INPUT -p udp -m udp --sport 500 -j ACCEPT
    iptables -A INPUT -p esp -j ACCEPT
    iptables -A INPUT -p tcp --dport 5666 -j ACCEPT # nagios nrpe plugins port 5666
    iptables -A INPUT -p udp --dport 161 -j ACCEPT # nagios snmp udp port 161

    ovs-ofctl add-flow $DATA_BR \
        cookie=$MAC_FLOOD_COOKIE,table=1,priority=18000,actions="normal"

    # delete all valves before routers
    ROUTER_IDS=(`ovs-vsctl --bare -- --columns=name find interface \
        external_ids:lc-router-type=$ROUTER_TYPE_VALVE |
        grep -E "^$VPORT_FORMAT$" | awk -F"-" '{print $1}' | sort | uniq`)
    for router_id in ${ROUTER_IDS[@]}; do
        delete_valve $router_id 1
    done

    ROUTER_IDS=(`ip -oneline link | awk -F": " '{print $2}' |
        grep -E "^$VPORT_FORMAT$" | awk -F"-" '{print $1}' | sort | uniq`)
    for router_id in ${ROUTER_IDS[@]}; do
        delete_router $router_id 1
    done
}

init_router_input_chain()
{
    table=$1
    router_chain=$2
    if [[ "$table" = "filter" && "$router_chain" = INPUT_* ]]; then
        iptables -D $router_chain -j DROP 2> /dev/null
        iptables -A $router_chain -j DROP
    fi
}

check_iptables_chain()
{
    table=$1
    chain=$2
    router_id=$3

    router_chain=${chain}_${router_id}

    if iptables -t $table -S $router_chain 1 > /dev/null 2>&1; then
        init_router_input_chain $table $router_chain
        return 0
    fi

    iptables -t $table -N $router_chain
    iptables -t $table -A $chain -m mark --mark $router_id/$SKB_MARK_MASK -g $router_chain
    init_router_input_chain $table $router_chain
}

get_ebtables_rule()
{
    typeset table chain

    table=$1
    chain=$2
    shift 2

    ebtables -t $table -L $chain 2> /dev/null | grep -E "^$*$"
}

find_ebtables_rule()
{
    [[ -n "`get_ebtables_rule $*`" ]]
}

check_ebtables_chain()
{
    table=$1
    chain=$2
    router_id=$3
    fwmark=0x`printf %x $4`
    vport_name=$5

    ebtables -t $table -P $chain DROP

    br=$VALVE_BR_PREFIX$router_id
    if [[ -z "`brctl show | grep -Ewo "^$br"`" ]]; then
        brctl addbr $br
    fi
    if [[ -z "`brctl show $br | grep -Ewo "$vport_name"`" ]]; then
        brctl addif $br $vport_name
    fi
    ip link set dev $br up

    valve_chain=${chain}_${router_id}
    ebtables -t $table -L $valve_chain > /dev/null 2>&1
    if [[ $? -ne 0 ]]; then
        ebtables -t $table -N $valve_chain -P DROP
    fi
    masked_fwmark=0x`printf %x $router_id`/$SKB_MARK_MASK
    rule="--mark $masked_fwmark -j $valve_chain"
    if ! find_ebtables_rule $table $chain $rule; then
        ebtables -t $table -A $chain $rule
    fi
    rule="-o $vport_name --mark $fwmark -j mark --mark-set 0x0 --mark-target ACCEPT"
    if ! find_ebtables_rule $table $valve_chain $rule; then
        ebtables -t $table -A $valve_chain $rule
    fi
}

delete_ebtables_chain()
{
    table=$1
    chain=$2
    router_id=$3
    fwmark=0x`printf %x $4`
    vport_name=$5

    valve_chain=${chain}_${router_id}
    if [[ -n "$vport_name" ]]; then
        vport_names=$vport_name
    else
        rule_fmt="-o $VPORT_FORMAT --mark $fwmark -j mark --mark-set 0x0 --mark-target ACCEPT"
        vport_names=`get_ebtables_rule $table $valve_chain $rule_fmt |
            grep -Ewo "$VPORT_FORMAT"`
    fi

    br=$VALVE_BR_PREFIX$router_id
    if [[ -n "`brctl show | grep -Ewo "^$br"`" ]]; then
        for vport_name in $vport_names; do
            brctl delif $br $vport_name 2> /dev/null
        done
        if [[ -z "`brctl show $br | grep -Ewo "$VPORT_FORMAT"`" ]]; then
            ip link set dev $br down
        fi
    fi

    for vport_name in $vport_names; do
        rule="-o $vport_name --mark $fwmark -j mark --mark-set 0x0 --mark-target ACCEPT"
        ebtables -t $table -D $valve_chain $rule 2> /dev/null
    done
    rule_fmt="-o $VPORT_FORMAT --mark 0x[0-9a-f]+ -j mark --mark-set 0x0 --mark-target ACCEPT"
    if ! find_ebtables_rule $table $valve_chain $rule_fmt; then
        masked_fwmark=0x`printf %x $router_id`/$SKB_MARK_MASK
        rule="--mark $masked_fwmark -j $valve_chain"
        ebtables -t $table -D $chain $rule 2> /dev/null
        ebtables -t $table -F $valve_chain 2> /dev/null
        ebtables -t $table -X $valve_chain 2> /dev/null
    fi
}

find_target_port_by_min_ip()
{
    typeset vport_name
    router_id=$1
    ip=$2

    for vport_name in `get_wan_vport_names $router_id`; do
        chk=`ip addr show $vport_name 2> /dev/null | grep -Eo "inet $IP_FORMAT/[0-9]+" |
            grep -Eo "$ip"`
        if [[ -n "$chk" ]]; then
            echo "$vport_name"
            return 0
        fi
    done

    return 1
}

config_nat()
{
    action=$1
    nat_type=$2
    router_id=$3
    rule_id=$4
    isp=$5
    protocol=$6
    match_if_type=$7
    match_if_index=$8
    match_min_ip=$9
    match_max_ip=${10}
    match_min_port=${11}
    match_max_port=${12}
    target_if_type=${13}
    target_if_index=${14}
    target_min_ip=${15}
    target_max_ip=${16}
    target_min_port=${17}
    target_max_port=${18}

    if [[ "$nat_type" = "SNAT" ]]; then
        chain="POSTROUTING"
        cookie_fmt=$SNAT_FLOW_COOKIE_FORMAT
    elif [[ "$nat_type" = "DNAT" ]]; then
        chain="PREROUTING"
        cookie_fmt=$DNAT_FLOW_COOKIE_FORMAT
    else
        return 1
    fi
    check_iptables_chain nat $chain $router_id
    router_chain=${chain}_${router_id}

    cmd="iptables -t nat"
    if [[ "$action" = "append" ]]; then
        cmd="$cmd -A $router_chain"
    elif [[ "$action" = "replace" ]]; then
        cmd="$cmd -R $router_chain $rule_id"
    else
        return 1
    fi
    if [[ $protocol -ne 0 ]]; then
        cmd="$cmd -p $protocol"
    fi

    if [[ "$nat_type" = "SNAT" ]]; then
        addr_prefix="-s"
        addr_range="--src-range"
        port_range="--sport"
    elif [[ "$nat_type" = "DNAT" ]]; then
        addr_prefix="-d"
        addr_range="--dst-range"
        port_range="--dport"
    fi
    if [[ "$match_if_type" = "WAN" ]]; then
        match_port="${router_id}-${WAN_VPORT_PREFIX}-${match_if_index}"
    elif [[ "$match_if_type" = "LAN" ]]; then
        match_port="${router_id}-${LAN_VPORT_PREFIX}-${match_if_index}"
    fi
    if [[ "$target_if_type" = "WAN" ]]; then
        target_port="${router_id}-${WAN_VPORT_PREFIX}-${target_if_index}"
    elif [[ "$target_if_type" = "LAN" ]]; then
        target_port="${router_id}-${LAN_VPORT_PREFIX}-${target_if_index}"
    fi

    if [[ "$match_if_type" != "ANY" ]]; then
        cmd="$cmd -i $match_port"
    fi
    if [[ "$match_min_ip" != "$MIN_IPV4" || "$match_max_ip" != "$MAX_IPV4" ]]; then
        if [[ "$match_min_ip" = "$match_max_ip" ]]; then
            cmd="$cmd $addr_prefix $match_min_ip/32"
        else
            pfx=`ip_range_to_prefix $match_min_ip $match_max_ip`
            if [[ -n "$pfx" ]]; then
                cmd="$cmd $addr_prefix $pfx"
            else
                cmd="$cmd -m iprange $addr_range $match_min_ip-$match_max_ip"
            fi
        fi
    fi
    if [[ $match_min_port -ne $MIN_PORT || $match_max_port -ne $MAX_PORT ]]; then
        if [[ $match_min_port -ne $match_max_port ]]; then
            cmd="$cmd $port_range $match_min_port:$match_max_port"
        else
            cmd="$cmd $port_range $match_min_port"
        fi
    fi

    if [[ "$nat_type" = "SNAT" ]]; then
        if [[ "$target_if_type" != "ANY" ]]; then
            cmd="$cmd -o $target_port -j MASQUERADE"
        else
            target_port=`find_target_port_by_min_ip $router_id $target_min_ip`
            if [[ -z "$target_port" ]]; then
                echo "ERROR: cannot find the out WAN port for SNAT IP $target_min_ip" >&2
                exit 1
            fi
            cmd="$cmd -o $target_port -j $nat_type --to-source $target_min_ip"
            if [[ "$target_min_ip" != "$target_max_ip" ]]; then
                cmd="$cmd-$target_max_ip"
            fi
        fi
    elif [[ "$nat_type" = "DNAT" ]]; then
        cmd="$cmd -j $nat_type --to-destination $target_min_ip"
        if [[ "$target_min_ip" != "$target_max_ip" ]]; then
            cmd="$cmd-$target_max_ip"
        fi
    fi
    if [[ $target_min_port -ne $MIN_PORT || $target_max_port -ne $MAX_PORT ]]; then
        if [[ $target_min_port -ne $match_min_port ||
              $target_max_port -ne $match_max_port ]]; then
            if [[ "$nat_type" = "SNAT" && "$target_if_type" != "ANY" ]]; then
                cmd="$cmd --to-ports $target_min_port"
            else
                cmd="$cmd:$target_min_port"
            fi
            if [[ $target_min_port -ne $target_max_port ]]; then
                cmd="$cmd-$target_max_port"
            fi
        fi
    fi

    echo "EXEC: $cmd"
    eval $cmd
    if [[ $? -ne 0 ]]; then
        exit 1
    fi

    # ovs flows
    if [[ "$nat_type" = "SNAT" ]]; then
        PFXS=`ip_range_to_prefix_array $match_min_ip $match_max_ip`
        priority=36000
    elif [[ "$nat_type" = "DNAT" ]]; then
        PFXS=`ip_range_to_prefix_array $target_min_ip $target_max_ip`
        priority=37000
    fi
    isp_router_id=`get_isp_router_id $router_id $isp`
    cookie=`echo $isp_router_id | awk -v fmt=$cookie_fmt '{printf fmt, $1}'`
    for p in ${PFXS[@]}; do
        for vport_name in `get_lan_vport_names $router_id`; do
            vport_vlan=`ovs-vsctl --bare -- --columns=tag find port name=$vport_name`
            vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`
            if [[ -n "$vport_vlan" ]]; then
                if [ "$p" != "0.0.0.0/0" ]; then
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$p,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)"
                else
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)"
                fi
                if [[ $? -ne 0 ]]; then
                    exit 1
                fi
            fi
        done
    done
}

delete_nat()
{
    echo "deprecated"
    return 1
}

flush_nat()
{
    nat_type=$1
    router_id=$2

    if [[ "$nat_type" = "SNAT" ]]; then
        chain="POSTROUTING"
        cookie_fmt=$SNAT_FLOW_COOKIE_FORMAT
    elif [[ "$nat_type" = "DNAT" ]]; then
        chain="PREROUTING"
        cookie_fmt=$DNAT_FLOW_COOKIE_FORMAT
    else
        return 1
    fi

    if ! iptables -t nat -S ${chain}_${router_id} 1 > /dev/null 2>&1; then
       continue
    fi
    iptables -t nat -D $chain -m mark --mark $router_id/$SKB_MARK_MASK \
        -g ${chain}_${router_id} 2> /dev/null
    iptables -t nat -F ${chain}_${router_id} 2> /dev/null
    iptables -t nat -X ${chain}_${router_id} 2> /dev/null

    # ovs flows
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        cookie=`echo $isp_router_id | awk -v fmt=$cookie_fmt '{printf fmt, $1}'`
        ovs-ofctl del-flows $DATA_BR cookie=$cookie/-1,table=0
    done

    :
}

config_acl()
{
    action=$1
    acl_type=$2
    router_id=$3
    rule_id=$4
    protocol=$5
    src_if_type=$6
    src_if_index=$7
    src_min_ip=$8
    src_max_ip=$9
    src_min_port=${10}
    src_max_port=${11}
    dst_if_type=${12}
    dst_if_index=${13}
    dst_min_ip=${14}
    dst_max_ip=${15}
    dst_min_port=${16}
    dst_max_port=${17}
    target=${18}

    if [[ "$acl_type" != "INPUT" && "$acl_type" != "OUTPUT" &&
        "$acl_type" != "FORWARD" ]]; then
        return 1
    fi
    chain=$acl_type
    check_iptables_chain filter $chain $router_id
    router_chain=${chain}_${router_id}

    cmd="iptables"
    if [[ "$action" = "append" ]]; then
        cmd="$cmd -A $router_chain"
    elif [[ "$action" = "replace" ]]; then
        cmd="$cmd -R $router_chain $rule_id"
    else
        return 1
    fi
    if [[ $protocol -ne 0 ]]; then
        cmd="$cmd -p $protocol"
    fi

    if [[ "$src_if_type" = "WAN" ]]; then
        src_port="${router_id}-${WAN_VPORT_PREFIX}-${src_if_index}"
    elif [[ "$src_if_type" = "LAN" ]]; then
        src_port="${router_id}-${LAN_VPORT_PREFIX}-${src_if_index}"
    fi
    if [[ "$dst_if_type" = "WAN" ]]; then
        dst_port="${router_id}-${WAN_VPORT_PREFIX}-${dst_if_index}"
    elif [[ "$dst_if_type" = "LAN" ]]; then
        dst_port="${router_id}-${LAN_VPORT_PREFIX}-${dst_if_index}"
    fi

    if [[ "$src_if_type" != "ANY" ]]; then
        cmd="$cmd -i $src_port"
    fi
    if [[ "$src_min_ip" != "$MIN_IPV4" || "$src_max_ip" != "$MAX_IPV4" ]]; then
        if [[ "$src_min_ip" = "$src_max_ip" ]]; then
            cmd="$cmd -s $src_min_ip/32"
        else
            pfx=`ip_range_to_prefix $src_min_ip $src_max_ip`
            if [[ -n "$pfx" ]]; then
                cmd="$cmd -s $pfx"
            else
                cmd="$cmd -m iprange --src-range $src_min_ip-$src_max_ip"
            fi
        fi
    fi
    if [[ $src_min_port -ne $MIN_PORT || $src_max_port -ne $MAX_PORT ]]; then
        if [[ $src_min_port -ne $src_max_port ]]; then
            cmd="$cmd --sport $src_min_port:$src_max_port"
        else
            cmd="$cmd --sport $src_min_port"
        fi
    fi

    if [[ "$dst_if_type" != "ANY" ]]; then
        cmd="$cmd -o $dst_port"
    fi
    if [[ "$dst_min_ip" != "$MIN_IPV4" || "$dst_max_ip" != "$MAX_IPV4" ]]; then
        if [[ "$dst_min_ip" = "$dst_max_ip" ]]; then
            cmd="$cmd -d $dst_min_ip/32"
        else
            pfx=`ip_range_to_prefix $dst_min_ip $dst_max_ip`
            if [[ -n "$pfx" ]]; then
                cmd="$cmd -d $pfx"
            else
                cmd="$cmd -m iprange --dst-range $dst_min_ip-$dst_max_ip"
            fi
        fi
    fi
    if [[ $dst_min_port -ne $MIN_PORT || $dst_max_port -ne $MAX_PORT ]]; then
        if [[ $dst_min_port -ne $dst_max_port ]]; then
            cmd="$cmd --dport $dst_min_port:$dst_max_port"
        else
            cmd="$cmd --dport $dst_min_port"
        fi
    fi

    cmd="$cmd -j $target"

    echo "EXEC: $cmd"
    eval $cmd
}

delete_acl()
{
    acl_type=$1
    router_id=$2
    rule_id=$3

    if [[ "$acl_type" != "INPUT" && "$acl_type" != "OUTPUT" &&
        "$acl_type" != "FORWARD" ]]; then
        return 1
    fi
    chain=$acl_type

    router_chain=${chain}_${router_id}
    cmd="iptables -D $router_chain $rule_id"

    echo "EXEC: $cmd"
    eval $cmd
}

flush_acl()
{
    acl_type=$1
    router_id=$2

    if [[ "$acl_type" != "INPUT" && "$acl_type" != "OUTPUT" &&
        "$acl_type" != "FORWARD" ]]; then
        return 1
    fi
    chain=$acl_type

    if [[ "$chain" = "INPUT" ]]; then
        # init INPUT chain
        iptables -F ${chain}_${router_id} 2> /dev/null
        check_iptables_chain filter $chain $router_id
    else
        iptables -D $chain -m mark --mark $router_id/$SKB_MARK_MASK \
            -g ${chain}_${router_id} 2> /dev/null
        iptables -F ${chain}_${router_id} 2> /dev/null
        iptables -X ${chain}_${router_id} 2> /dev/null
    fi

    :
}

config_route()
{
    action=$1
    router_id=$2
    dst_ip=$3
    dst_netmask=$4

    dst_pfx=`ip_mask_to_prefix $dst_ip $dst_netmask`

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_label=`get_isp_router_label $router_id $isp`
        if ip rule ls | grep -w fwmark | grep -wqs "lookup $isp_router_label"; then
            ip route del $dst_pfx table $isp_router_label 2> /dev/null
            # default route
            if [[ "$action" = "delete" && "$dst_pfx" = "0.0.0.0/0" ]]; then
                ip route add unreachable 0/0 table $isp_router_label
            fi
        fi
    done

    if [[ "$action" = "delete" ]]; then
        return 0
    fi
    next_hop=$5
    if_type=$6
    if_index=$7
    isp=$8

    if [[ "$if_type" = "WAN" ]]; then
        vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"
    elif [[ "$if_type" = "LAN" ]]; then
        vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"
    else
        return 1
    fi

    if [[ $isp -ne 0 ]]; then
        isp_router_label=`get_isp_router_label $router_id $isp`
        ip route add $dst_pfx via $next_hop dev $vport_name table $isp_router_label
    else
        for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
            isp_router_label=`get_isp_router_label $router_id $isp`
            if ip rule ls | grep -w fwmark | grep -wqs "lookup $isp_router_label"; then
                ip route add $dst_pfx via $next_hop dev $vport_name table $isp_router_label
                if [[ $? -ne 0 ]]; then
                    exit 1
                fi
            fi
        done
    fi
}

config_vpn()
{
    action=$1
    router_id=$2
    name=$3
    isp=$4
    left=$5
    lnet_addr=$6
    lnet_mask=$7
    right=$8
    rnet_addr=$9
    rnet_mask=${10}
    psk=${11}

    mkdir -p $STRONGSWAN_CONF_DIR

    vpn_label="nsp_${router_id}_${name}"
    if [[ "$action" = "delete" ]]; then
        flush_vpn_conn_by_vpn_label $vpn_label
        return
    fi

    lnet_prefix=`ip_mask_to_prefix $lnet_addr $lnet_mask`
    rnet_prefix=`ip_mask_to_prefix $rnet_addr $rnet_mask`
    isp_router_id=`get_isp_router_id $router_id $isp`
    vpn_conn_name="${router_id}_${left}_${lnet_addr}_${lnet_mask}_${right}_${rnet_addr}_${rnet_mask}"
    # Supported IKEv1 cipher suites
    #   https://wiki.strongswan.org/projects/strongswan/wiki/IKEv1CipherSuites
    cat << VPN_CONF > $STRONGSWAN_CONF_DIR/${vpn_label}.conf
#
conn $vpn_conn_name
    keyexchange=ikev1
    authby=psk
    aggressive=no
    type=tunnel
    keyingtries=%forever
    left=$left
    leftsubnet=$lnet_prefix
    mark=`echo $isp_router_id | awk '{printf "%#x", $1}'`
    right=$right
    rightsubnet=$rnet_prefix
    auto=route
VPN_CONF
    echo -e "#\n$left $right : PSK \"$psk\"" > $STRONGSWAN_CONF_DIR/${vpn_label}.secrets

    refresh_vpn_conn_by_conn_name $vpn_conn_name

    priority=38000
    isp_router_id=`get_isp_router_id $router_id $isp`
    cookie=`echo $isp_router_id | awk -v fmt=$VPN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
    for vport_name in `get_lan_vport_names $router_id`; do
        vport_vlan=`ovs-vsctl --bare -- --columns=tag find port name=$vport_name`
        vport_mac=`ip addr show $vport_name | grep "link/ether" | awk '{print $2}'`
        if [[ -n "$vport_vlan" ]]; then
            if [ "$lnet_prefix" != "0.0.0.0/0" ]; then
                if [ "$rnet_prefix" != "0.0.0.0/0" ]; then
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$lnet_prefix,nw_dst=$rnet_prefix,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)" && \
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$lnet_prefix,nw_dst=$right,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)"
                else
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$lnet_prefix,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)"
                fi
            else
                if [ "$rnet_prefix" != "0.0.0.0/0" ]; then
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_dst=$rnet_prefix,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)" && \
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_dst=$right,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)"
                else
                    ovs-ofctl add-flow $DATA_BR \
                        cookie=$cookie,table=0,priority=$priority,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,actions="
                            set_skb_mark:$isp_router_id,resubmit(,1)"
                fi
            fi
            if [[ $? -ne 0 ]]; then
                exit 1
            fi
        fi
    done
}

flush_vpn()
{
    router_id=$1

    flush_vpn_conn_by_router_id $router_id

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        cookie=`echo $isp_router_id | awk -v fmt=$VPN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        ovs-ofctl del-flows $DATA_BR cookie=$cookie/-1,table=0
    done

    :
}

clear_egress_broadcast_qos()
{
    router_id=$1
    if_index=$2

    # vport must exist
    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"
    if ! ip link show $vport_name > /dev/null 2>&1; then
        return
    fi

    tc filter del dev $vport_name protocol ip parent 1:0 prio $TC_CTRL_PRIO u32 \
        2> /dev/null
    tc class del dev $vport_name parent 1:0 classid 1:f001 2> /dev/null
    tc qdisc del dev $vport_name parent 1:f001 2> /dev/null

    :
}

config_egress_broadcast_qos()
{
    router_id=$1
    if_index=$2
    min_rate=$3
    max_rate=$4

    # vport must exist
    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"
    if ! ip link show $vport_name > /dev/null 2>&1; then
        echo "ERROR: $vport_name does not exist" >&2
        exit 1
    fi
    # no broadcast qos is configured
    if [[ $min_rate -eq 0 && $max_rate -eq 0 ]]; then
        return
    fi
    # detached WAN port
    if [[ ! "`tc qdisc show dev $vport_name | grep -o 'htb 1: root'`" ]]; then
        echo "ERROR: $vport_name is not attached" >&2
        exit 2
    fi
    # no parent class is found
    qos=`tc -iec class show dev $vport_name classid 1:0`
    if [[ -z "$qos" ]]; then
        echo "ERROR: $vport_name has no class 1:0 in tc" >&2
        exit 3
    fi
    # excessively allocated qos
    __max_qos=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
    max_qos=`translate_qos $__max_qos`
    if [[ $max_rate -gt $max_qos ]]; then
        echo "ERROR: $vport_name cannot add bandw $max_rate (> $max_qos)" >&2
        exit 4
    fi

    clear_egress_broadcast_qos $router_id $if_index

    (( min_rate = (min_rate < $BASIC_RATE) ? $BASIC_RATE : min_rate ))
    (( max_rate = (max_rate < min_rate) ? min_rate : max_rate ))
    (( burst = max_rate / $BASIC_RATE ))
    # broadcast qos queue class
    tc class replace dev $vport_name parent 1:0 classid 1:f001 \
        htb rate ${min_rate}bit ceil ${max_rate}bit \
        burst ${burst}b cburst ${burst}b
    # broadcast qos queue qdisc
    tc qdisc replace dev $vport_name parent 1:f001 sfq perturb 10
    # filter for multicast and broadcast traffic
    tc filter replace dev $vport_name protocol ip parent 1:0 prio $TC_CTRL_PRIO u32 \
        match u16 0x0100 0x0100 at -14 flowid 1:f001
}

debug_wan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    isp=`get_wan_isp $router_id $vport_name`
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    isp_router_label=`get_isp_router_label $router_id $isp`

    gateway=`ip route ls table $isp_router_label 0/0 dev $vport_name 2> /dev/null | awk '{print $3}'`
    vlantag=`ovs-vsctl --bare get port $vport_name tag 2> /dev/null | grep -E "[0-9]+"`
    if [[ -z "$vlantag" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`
    qos=(`get_qos $vport_name`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    IPMS=(`ip -f inet -oneline addr show $vport_name 2> /dev/null | awk '{print $4}'`)
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -eq 0 ]]; then
            echo $vport_no $if_index $isp $gateway $vlantag $mac $qos_min $qos_max | \
            awk '{printf "  %4s %3s %3s %15s %4s %17s %10s %10s", $1, $2, $3, $4, $5, $6, $7, $8}'
        else
            awk 'BEGIN {printf "  %4s %3s %3s %15s %4s %17s %10s %10s", "", "", "", "", "", "", "", ""}'
        fi
        (( i = i + 1 ))
        arr=(`ip_masklen_to_ip_mask $ipm`)
        echo ${arr[0]} ${arr[1]} | awk '{printf " %15s %15s\n", $1, $2}'
    done
}

debug_lan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    vlantag=`ovs-vsctl --bare get port $vport_name tag 2> /dev/null | grep -E "[0-9]+"`
    if [[ -z "$vlantag" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`

    qos=(`get_qos $vport_name`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    IPMS=(`ip -f inet -oneline addr show $vport_name 2> /dev/null | awk '{print $4}'`)
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -eq 0 ]]; then
            echo $vport_no $if_index $vlantag $mac $qos_min $qos_max | \
            awk '{printf "  %4s %3s %3s %15s %4s %17s %10s %10s", $1, $2, "", "", $3, $4, $5, $6}'
        else
            awk 'BEGIN {printf "  %4s %3s %3s %15s %4s %17s %10s %10s", "", "", "", "", "", "", "", ""}'
        fi
        (( i = i + 1 ))
        arr=(`ip_masklen_to_ip_mask $ipm`)
        echo ${arr[0]} ${arr[1]} | awk '{printf " %15s %15s\n", $1, $2}'
    done
}

debug_valve_wan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${VALVE_WAN_IF_INDEX}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    isp=`get_valve_wan_isp $router_id $vport_name $if_index`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    gateway=`ovs-vsctl --bare get interface $vport_name external_ids:lc-gateway-$if_index \
        2> /dev/null | grep -Eo "$IP_FORMAT"`
    vlantag=`ovs-vsctl --bare get interface $vport_name external_ids:lc-vlan-$if_index \
        2> /dev/null | grep -Eo "[0-9]+"`
    if [[ -z "$vlantag" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`
    qos=(`get_valve_qos $vport_name $if_index`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    IPMS=(`ovs-vsctl --bare get interface $vport_name external_ids \
        2> /dev/null | grep -Eo "lc-ip-netmask-$if_index-[^,}]+" |
        grep -Eo "$IP_FORMAT/[0-9]+"`)
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -eq 0 ]]; then
            echo $vport_no $if_index $isp $gateway $vlantag $mac $qos_min $qos_max | \
            awk '{printf "  %4s %3s %3s %15s %4s %17s %10s %10s", $1, $2, $3, $4, $5, $6, $7, $8}'
        else
            awk 'BEGIN {printf "  %4s %3s %3s %15s %4s %17s %10s %10s", "", "", "", "", "", "", "", ""}'
        fi
        (( i = i + 1 ))
        arr=(`ip_masklen_to_ip_mask $ipm`)
        echo ${arr[0]} ${arr[1]} | awk '{printf " %15s %15s\n", $1, $2}'
    done
}

debug_valve_lan()
{
    router_id=$1
    if_index=$2

    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}"
    vport_no=`ovs-vsctl --bare -- --columns=ofport find interface name=$vport_name 2> /dev/null`
    if [[ -z "$vport_no" ]]; then
        return 1
    fi

    vlantag=`ovs-vsctl --bare get interface $vport_name external_ids:lc-vlan-$if_index \
        2> /dev/null | grep -Eo "[0-9]+"`
    if [[ -z "$vlantag" ]]; then
        vlantag=0
    fi
    mac=`ip link show $vport_name 2> /dev/null | grep "link/ether" | awk '{print $2}'`

    qos=(`get_valve_qos $vport_name`)
    qos_min=${qos[0]}
    qos_max=${qos[1]}

    IPMS=("0.0.0.0/0")
    i=0
    for ipm in ${IPMS[@]}; do
        if [[ $i -eq 0 ]]; then
            echo $vport_no $if_index $vlantag $mac $qos_min $qos_max | \
            awk '{printf "  %4s %3s %3s %15s %4s %17s %10s %10s", $1, $2, "", "", $3, $4, $5, $6}'
        else
            awk 'BEGIN {printf "  %4s %3s %3s %15s %4s %17s %10s %10s", "", "", "", "", "", "", "", ""}'
        fi
        (( i = i + 1 ))
        arr=(`ip_masklen_to_ip_mask $ipm`)
        echo ${arr[0]} ${arr[1]} | awk '{printf " %15s %15s\n", $1, $2}'
    done
}

dump_flow_entry()
{
    echo $1 | awk '{
        printf " ";
        for (i=1; i<NF-2; ++i) printf " %s", $i;
        printf "\n    %s\n    %s\n", $(NF-1), $NF
    }'
}

debug_policy()
{
    router_id=$1

    echo "${wrap_pass}Forward Rules${wrap_over}"
    iptables -S FORWARD_$router_id 2> /dev/null | \
        grep -v -- "^-N" | awk '{print " ", $0}'

    echo "${wrap_pass}DNAT Rules${wrap_over}"
    iptables -t nat -S PREROUTING_$router_id 2> /dev/null | \
        grep -v -- "^-N" | awk '{print " ", $0}'

    echo "${wrap_pass}SNAT Rules${wrap_over}"
    iptables -t nat -S POSTROUTING_$router_id 2> /dev/null | \
        grep -v -- "^-N" | awk '{print " ", $0}'

    echo "${wrap_pass}VPN Configs${wrap_over}"
    cat /etc/strongswan/ipsec.d/nsp_${router_id}_*.conf 2> /dev/null | \
        grep "^conn " | awk -F"[_ ]" \
        '{printf "  %15s %15s/%-15s <--> %15s %15s/%-15s\n", $3, $4, $5, $6, $7, $8}'

    echo "${wrap_pass}Routing Tables${wrap_over}"
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_label=`get_isp_router_label $router_id $isp`
        chk=`ip rule ls | grep -w fwmark | grep -w "lookup $isp_router_label"`
        if [[ -n "$chk" ]]; then
            ip rule ls | grep -w "lookup $isp_router_label" | awk '{print " ", $0}'
            ip route ls table $isp_router_label | awk '{print "   ", $0}'
        fi
    done

    echo "${wrap_pass}WAN Flows${wrap_over}"
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        isp_router_label=`get_isp_router_label $router_id $isp`
        wan_cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        ovs-ofctl dump-flows $UPLINK_BR cookie=$wan_cookie/-1 \
            --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
            grep -v "NXST_FLOW reply" | \
            while read line; do dump_flow_entry "$line"; done
    done

    lan_cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
    echo "${wrap_pass}LAN Flows (ARP IN)${wrap_over}"
    ovs-ofctl dump-flows $DATA_BR cookie=$lan_cookie/-1,arp \
        --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
        grep -v "NXST_FLOW reply" | \
        while read line; do dump_flow_entry "$line"; done
    echo "${wrap_pass}LAN Flows (IP IN)${wrap_over}"
    ovs-ofctl dump-flows $DATA_BR cookie=$lan_cookie/-1,ip \
        --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
        grep -v "NXST_FLOW reply" | \
        while read line; do dump_flow_entry "$line"; done
    echo "${wrap_pass}LAN Flows (OUT)${wrap_over}"
    ovs-ofctl dump-flows $DATA_BR cookie=$lan_cookie/-1 \
        --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
        grep ",in_port=" | grep -v learn | \
        grep -v "NXST_FLOW reply" | \
        while read line; do dump_flow_entry "$line"; done

    echo "${wrap_pass}SNAT Flows${wrap_over}"
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        isp_router_label=`get_isp_router_label $router_id $isp`
        snat_cookie=`echo $isp_router_id | awk -v fmt=$SNAT_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        ovs-ofctl dump-flows $DATA_BR cookie=$snat_cookie/-1 \
            --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
            grep -v "NXST_FLOW reply" | \
            while read line; do dump_flow_entry "$line"; done
    done

    echo "${wrap_pass}DNAT Flows${wrap_over}"
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        isp_router_label=`get_isp_router_label $router_id $isp`
        dnat_cookie=`echo $isp_router_id | awk -v fmt=$DNAT_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        ovs-ofctl dump-flows $DATA_BR cookie=$dnat_cookie/-1 \
            --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
            grep -v "NXST_FLOW reply" | \
            while read line; do dump_flow_entry "$line"; done
    done

    echo "${wrap_pass}VPN Flows${wrap_over}"
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        isp_router_label=`get_isp_router_label $router_id $isp`
        vpn_cookie=`echo $isp_router_id | awk -v fmt=$VPN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        ovs-ofctl dump-flows $DATA_BR cookie=$vpn_cookie/-1 \
            --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
            grep -v "NXST_FLOW reply" | \
            while read line; do dump_flow_entry "$line"; done
    done
}

debug_valve_policy()
{
    router_id=$1

    echo "${wrap_pass}Linux Bridge Interfaces${wrap_over}"
    brctl show $VALVE_BR_PREFIX$router_id 2>/dev/null

    echo "${wrap_pass}Linux ebtables Rules${wrap_over}"
    ebtables -L FORWARD_$router_id 2> /dev/null | \
        grep -Ev "^$|Bridge" | awk '{print " ", $0}'

    echo "${wrap_pass}WAN Flows${wrap_over}"
    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_id=`get_isp_router_id $router_id $isp`
        wan_cookie=`echo $isp_router_id | awk -v fmt=$WAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
        ovs-ofctl dump-flows $UPLINK_BR cookie=$wan_cookie/-1 \
            --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
            grep -v "NXST_FLOW reply" | \
            while read line; do dump_flow_entry "$line"; done
    done

    lan_cookie=`echo $router_id | awk -v fmt=$LAN_FLOW_COOKIE_FORMAT '{printf fmt, $1}'`
    echo "${wrap_pass}LAN Flows (ARP IN)${wrap_over}"
    ovs-ofctl dump-flows $DATA_BR cookie=$lan_cookie/-1,arp \
        --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
        grep -v "NXST_FLOW reply" | \
        while read line; do dump_flow_entry "$line"; done
    echo "${wrap_pass}LAN Flows (IP IN)${wrap_over}"
    ovs-ofctl dump-flows $DATA_BR cookie=$lan_cookie/-1,ip \
        --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
        grep -v "NXST_FLOW reply" | \
        while read line; do dump_flow_entry "$line"; done
    echo "${wrap_pass}LAN Flows (OUT)${wrap_over}"
    ovs-ofctl dump-flows $DATA_BR cookie=$lan_cookie/-1 \
        --rsort=priority --sort=in_port --sort=dl_vlan --rsort=dl_type | \
        grep ",in_port=" | grep -v learn | \
        grep -v "NXST_FLOW reply" | \
        while read line; do dump_flow_entry "$line"; done
}

debug_system()
{
    echo "${wrap_pass}NSP Bridges${wrap_over}"
    local NSPBR=(`ovs-vsctl list-br`)
    printf "%s\t%s\t%-10s\t%s\n" "NAME" "EXTERNAL_IDS" "PIF" "PIF_LINK"
    for br in ${NSPBR[@]}
    do
        local BR_INFO_1="`
            ovs-vsctl --format=table --data=bare -- --columns=name,external_ids list bridge $br |
            grep -v name | grep -v '\-\-' | awk '{
                if ($2 == "is-bonding=1") print $1" "$3;
                else if ($2 == "") print $1" lc-br-id=-";
                else print $1" "$2;
            }'`"
        local PIF_LIST=(`ovs-vsctl list-ifaces $br | grep -E "eth"`)
        for l in ${PIF_LIST[@]}
        do
           ethtool $l | grep 'Link detected: yes' >/dev/null 2>&1 && local LINK_STATUS
           if [ $? -eq 0 ]; then
               LINK_STATUS=${LINK_STATUS}'!'
           else
               LINK_STATUS=${LINK_STATUS}'.'
           fi
        done
        echo "$BR_INFO_1 $BR_INFO_2 $LINK_STATUS" | awk '{printf("%s\t%s\t%-10s\t%s\n",$1,$2,$3,$4);}'
        unset LINK_STATUS
    done
    echo

    echo "${wrap_pass}NSP iptables${wrap_over}"
    iptables -S INPUT | awk '{if (NR == 1) print $0; else print "  ", $0}'
    iptables -S FORWARD | awk '{if (NR == 1) print $0; else print "  ", $0}'
    iptables -t nat -S PREROUTING | awk '{if (NR == 1) print $0; else print "  ", $0}'
    iptables -t nat -S POSTROUTING | awk '{if (NR == 1) print $0; else print "  ", $0}'
    echo
}

debug_vport()
{
    type=$1
    router_id=$2
    vport_name=$3

    chk=`ovs-vsctl --bare get interface $vport_name external_ids:lc-router-type \
        2> /dev/null | grep -o $ROUTER_TYPE_VALVE`
    if [[ -z "$chk" ]]; then
        if_index=${vport_name##*-}
        eval debug_$type $router_id $if_index
    else
        if_indices=`eval get_valve_${type}_if_indices $router_id`
        for if_index in $if_indices; do
            eval debug_valve_$type $router_id $if_index
        done
    fi
}

debug_router()
{
    router_id=$1
    vport_name=$2

    chk=`ovs-vsctl --bare get interface $vport_name external_ids:lc-router-type \
        2> /dev/null | grep -o $ROUTER_TYPE_VALVE`
    if [[ -z "$chk" ]]; then
        debug_policy $router_id
    else
        debug_valve_policy $router_id
    fi
}

do_command()
{
    action=$1
    router_id=$2
    if_type=$3
    if_index=$4
    source_ip=$5
    target_ip=$6
    interval=$7

    if [[ "$if_type" = "WAN" ]]; then
        vport_name="$router_id-w-$if_index"
    else
        vport_name="$router_id-l-$if_index"
    fi

    source_ip=`ip route get $target_ip oif $vport_name 2>$- |
        grep -Eo "src [0-9.]+" | awk '{print $2}' | head -n 1`
    target_ip=`echo $target_ip | grep -Eo "[0-9.]+"`
    mask_len=`ip a show dev $vport_name 2>$- |
        grep -Eo "$source_ip/[0-9]{1,2}" | awk -F"/" '{print $2}' | head -n 1`
    source_pfx=`ip_masklen_to_prefix $source_ip/$mask_len`
    target_pfx=`ip_masklen_to_prefix $target_ip/$mask_len`
    if [[ -z "$mask_len" || "$source_pfx" != "$target_pfx" ]]; then
        echo "Error: source ($source_ip) and target ($target_ip)" \
             "must in the same network"
        exit
    fi

    if [[ "$action" = "ping" ]]; then
        out=`$action -I $vport_name $target_ip -i $interval -c 5 -w 5 2>&1`
    else
        #out=`$action -I $vport_name -s $source_ip $target_ip -c 5 -w 5 2>&1`
        out=`$action -I $vport_name $target_ip -c 5 -w 5 2>&1`
    fi
    echo "$out" | sed "s/$vport_name/eth$if_index/g" |
        sed "/ Destination Host Unreachable$/d"
}

debug()
{
    router_id=$1

    if [[ -z "$router_id" ]]; then
        ROUTER_IDS=(`ip -oneline link | awk -F": " '{print $2}' |
            grep -E "^$VPORT_FORMAT$" | awk -F"-" '{print $1}' | sort | uniq`)
        debug_system
        for router_id in ${ROUTER_IDS[@]}; do
            echo "${wrap_pass}Router $router_id${wrap_over}"
            echo "PORT" "IDX" "ISP" "GATEWAY" "VLAN" "MAC" "QOS_MIN" "QOS_MAX" "IP" "NETMASK" | \
            awk '{printf "  %4s %3s %3s %15s %4s %17s %10s %10s %15s %15s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10}'

            for vport_name in `get_wan_vport_names $router_id`; do
                debug_vport wan $router_id $vport_name
            done
            for vport_name in `get_lan_vport_names $router_id`; do
                debug_vport lan $router_id $vport_name
            done

            echo
        done
    else
        echo "${wrap_pass}Router $router_id${wrap_over}"
        echo "PORT" "IDX" "ISP" "GATEWAY" "VLAN" "MAC" "QOS_MIN" "QOS_MAX" "IP" "NETMASK" | \
        awk '{printf "  %4s %3s %3s %15s %4s %17s %10s %10s %15s %15s\n", $1, $2, $3, $4, $5, $6, $7, $8, $9, $10}'

        for vport_name in `get_wan_vport_names $router_id`; do
            debug_vport wan $router_id $vport_name
        done
        for vport_name in `get_lan_vport_names $router_id`; do
            debug_vport lan $router_id $vport_name
        done
        debug_router $router_id $vport_name

        echo
    fi
}

update_vlantag()
{
    mac=$1
    vlantag=$2

    vport_name=`ovs-vsctl --timeout=10 --bare -- --columns=name \
        find interface "mac_in_use=\"$mac\"" 2>&1`
    if [[ -z $vport_name ]]; then
        echo "can not find vport_name for $mac" >&2
        exit 1
    fi

    ovs-vsctl --timeout=10 -- set port $vport_name tag=$vlantag
    if [[ $? -ne 0 ]]; then
        echo "set vlantag failed" >&2
        exit 1
    fi
}

action=$1
object=$2

__check_router_id()
{
    router_id=$1

    if [[ -n "$router_id" ]]; then
        for id in ${BLACK_ROUTER_IDS[@]}; do
            if [[ $router_id -eq $id ]]; then
                echo "ERROR: Operation of TABLE ID $id is not permitted (local:255, main:254, default:253)" >&2
                exit 1
            fi
        done
    fi
}

case $object in
    router | wan | lan | vpn | route | valve | valve-wan | valve-lan)
        __check_router_id $3
        ;;
    nat | acl)
        __check_router_id $4
        ;;
esac


if [[ "$action" = "add" && "$object" = "wan" && $# -ge 14 ]]; then
    shift 2
    config_wan $@
elif [[ "$action" = "add" && "$object" = "lan" && $# -ge 10 ]]; then
    shift 2
    config_lan $@
elif [[ "$action" = "get" && "$object" = "wan" && $# -ge 4 ]]; then
    shift 2
    get_wan $@
elif [[ "$action" = "get" && "$object" = "lan" && $# -ge 4 ]]; then
    shift 2
    get_lan $@
elif [[ "$action" = "get" && "$object" = "router" && $# -ge 3 ]]; then
    shift 2
    get_router $@
elif [[ "$action" = "delete" && "$object" = "wan" && $# -eq 4 ]]; then
    shift 2
    delete_wan $@
elif [[ "$action" = "delete" && "$object" = "lan" && $# -eq 4 ]]; then
    shift 2
    delete_lan $@
elif [[ "$action" = "delete" && "$object" = "router" && $# -eq 4 ]]; then
    shift 2
    delete_router $@
elif [[ "$action" = "add" && "$object" = "valve-wan" && $# -ge 14 ]]; then
    shift 2
    config_valve_wan $@
elif [[ "$action" = "add" && "$object" = "valve-lan" && $# -ge 6 ]]; then
    shift 2
    config_valve_lan $@
elif [[ "$action" = "get" && "$object" = "valve-wan" && $# -ge 4 ]]; then
    shift 2
    get_valve_wan $@
elif [[ "$action" = "get" && "$object" = "valve-lan" && $# -ge 4 ]]; then
    shift 2
    get_valve_lan $@
elif [[ "$action" = "get" && "$object" = "valve" && $# -ge 3 ]]; then
    shift 2
    get_valve $@
elif [[ "$action" = "delete" && "$object" = "valve-wan" && $# -eq 4 ]]; then
    shift 2
    delete_valve_wan $@
elif [[ "$action" = "delete" && "$object" = "valve-lan" && $# -eq 4 ]]; then
    shift 2
    delete_valve_lan $@
elif [[ "$action" = "delete" && "$object" = "valve" && $# -eq 4 ]]; then
    shift 2
    delete_valve $@
elif [[ "$action" = "delete" && "$object" = "all_routers" && $# -eq 2 ]]; then
    delete_all_routers
elif [[ "$action" = "append" && "$object" = "nat" && $# -eq 19 ]]; then
    shift 2
    config_nat $action $@
elif [[ "$action" = "replace" && "$object" = "nat" && $# -eq 19 ]]; then
    shift 2
    config_nat $action $@
elif [[ "$action" = "delete" && "$object" = "nat" && $# -eq 6 ]]; then
    shift 2
    delete_nat $@
elif [[ "$action" = "flush" && "$object" = "nat" && $# -eq 4 ]]; then
    shift 2
    flush_nat $@
elif [[ "$action" = "append" && "$object" = "acl" && $# -eq 19 ]]; then
    shift 2
    config_acl $action $@
elif [[ "$action" = "replace" && "$object" = "acl" && $# -eq 19 ]]; then
    shift 2
    config_acl $action $@
elif [[ "$action" = "delete" && "$object" = "acl" && $# -eq 5 ]]; then
    shift 2
    delete_acl $@
elif [[ "$action" = "flush" && "$object" = "acl" && $# -eq 4 ]]; then
    shift 2
    flush_acl $@
elif [[ "$action" = "add" && "$object" = "route" && $# -eq 9 ]]; then
    shift 2
    config_route $action $@
elif [[ "$action" = "delete" && "$object" = "route" && $# -eq 5 ]]; then
    shift 2
    config_route $action $@
elif [[ "$action" = "add" && "$object" = "vpn" && $# -eq 12 ]]; then
    shift 2
    config_vpn $action $@
elif [[ "$action" = "delete" && "$object" = "vpn" && $# -eq 4 ]]; then
    shift 2
    config_vpn $action $@
elif [[ "$action" = "flush" && "$object" = "vpn" && $# -eq 3 ]]; then
    shift 2
    flush_vpn $@
elif [[ "$action" = "add" && "$object" = "broadcast-qos" && $# -eq 6 ]]; then
    shift 2
    config_egress_broadcast_qos $@
elif [[ "$action" = "delete" && "$object" = "broadcast-qos" && $# -eq 4 ]]; then
    shift 2
    clear_egress_broadcast_qos $@
elif [[ "$action" = "add" && "$object" = "conntrack" ]]; then
    shift 2
    config_router_conntrack $@
elif [[ "$action" = "delete" && "$object" = "conntrack" ]]; then
    shift 2
    delete_router_conntrack $@
elif [[ "$action" = "get" && "$object" = "conntrack" ]]; then
    shift 2
    get_router_conntrack $@
elif [[ "$action" = "arping" || "$action" = "ping" ]] && [[ $# -ge 6 ]]; then
    shift 1
    do_command $action $@
elif [[ "$action" = "debug" && $# -ge 1 ]]; then
    shift 1
    debug $@
elif [[ "$action" = "update" && "$object" = "vlantag" && $# -eq 4 ]]; then
    shift 2
    update_vlantag $@
else
    if [[ $# -ne 0 ]]; then
        echo "unknown params: $@"
        echo
    fi
    print_usage
fi

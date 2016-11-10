#!/bin/sh

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh
alias iptables="iptables -w"

print_usage()
{
    echo "Usage: `basename $0` COMMAND PARAMS [OPTION] [ARGS] [OPTION] [ARGS] ..."
    echo
    echo "    COMMAND:          PARAMS:"
    echo "    router-wan-vport  <router_id> <if_index>"
    echo "    router-lan-vport  <router_id> <if_index>"
    echo "    valve-wan-vport   <valve_id> <if_index>"
    echo "    valve-lan-vport   <valve_id> <if_index>"
    echo "    server            <tunnel_protocol> [<peer_server_ip>] [<peer_server_ip>] ..."
    echo
    echo "    OPTION:           ARGS:"
    echo "    --state"
    echo "    --mac             <mac>"
    echo "    --mtu"
    echo "    --ip              <ip/masklen> [<ip/masklen>] [<ip/masklen>] ..."
    echo "    --gateway         <gateway_ip>"
    echo "    --isp             <isp_id>"
    echo "    --vlan            <vlantag>"
    echo "    --qos             <min_rate> <max_rate> <monitor_min_rate> <monitor_max_rate>" \
                                "<broadcast_min_rate> <broadcast_max_rate>"
    echo "    --policy"
    echo "    --snat            <protocol> <match_min_ip> <match_max_ip>" \
                                "<target_min_ip> <target_max_ip> <isp_id>"
    echo "    --dnat            <protocol> <match_min_ip> <match_max_ip>" \
                                "<match_min_port> <match_max_port>" \
                                "<target_min_ip> <target_max_ip>" \
                                "<target_min_port> <target_max_port> <isp_id>"
    echo "    --acl             <protocol> <src_if_type> <src_if_index>" \
                                "<src_min_ip> <src_max_ip>" \
                                "<src_min_port> <src_max_port>" \
                                "<dst_if_type> <dst_if_index>" \
                                "<dst_min_ip> <dst_max_ip>" \
                                "<dst_min_port> <dst_max_port> <target>"
    echo "    --vpn             <left> <lnet_addr> <lnet_mask>" \
                                "<right> <rnet_addr> <rnet_mask>" \
                                "<psk> <isp_id> <vpn_name>"
    echo "    --route           <dst_ip> <dst_netmask> <nexthop_ip> <isp_id>"
    echo "    --tunnel          <tunnel_id>"
}

get_br_name_from_id()
{
    br_id=$1

    br=`$OVS_VSCTL_BARE --columns=name find bridge external_ids:lc-br-idx=$br_id`
    if [ -n "$br" ]; then
        echo $br
        return 0
    fi

    br=`$OVS_VSCTL_BARE --columns=name find bridge external_ids:lc-br-id=$br_id`
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

br_of_ctrl()
{
    ctrl_br=`get_br_name_from_id $LC_CTRL_BR_ID`
    if [[ $? -ne 0 ]]; then
        # TODO handle br missing
        echo "nspbr0"
        return 1
    fi

    echo $ctrl_br
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

br_of_ulnk()
{
    ulnk_br=`get_br_name_from_id $LC_ULNK_BR_ID`
    if [[ $? -ne 0 ]]; then
        # TODO handle br missing
        echo "nspbr0"
        return 1
    fi

    echo $ulnk_br
    return 0
}

br_of_tunl()
{
    tunl_br=`get_br_name_from_id $LC_TUNL_BR_ID`
    if [[ $? -ne 0 ]]; then
        # TODO handle br missing
        echo "tunbr"
        return 1
    fi

    echo $tunl_br
    return 0
}

CTRL_BR=`br_of_ctrl`
DATA_BR=`br_of_data`
ULNK_BR=`br_of_ulnk`
TUNL_BR=`br_of_tunl`

NSPBR_LIST="$CTRL_BR $DATA_BR $TUNL_BR"

ip_masklen_to_ip_mask()
{
    ipml=$1
    arr=(`echo $ipml | awk -F'/' '{print $1, $2}'`)

    mask_num=${arr[1]}
    (( mask_num = 0xffffffff ^ ( (1 << (32 - mask_num)) - 1 ) ))
    mask=`NUM2IP $mask_num`
    echo -n "${arr[0]} $mask"
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

    (( isp_id -= 1 ))
    if [[ $isp_id -eq 0 ]]; then
        echo $router_id
    else
        echo $isp_id $router_id | awk '{printf "%d%08d", $1, $2}'
    fi
}

get_router_vport_gateway()
{
    router_id=$1
    vport_name=$2

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_label=`get_isp_router_label $router_id $isp`
        gateway=`ip route show table $isp_router_label 0/0 dev $vport_name \
                2> /dev/null | awk '{print $3}'`
        if [[ -n "$gateway" ]]; then
            echo $gateway
            return 0
        fi
    done

    echo 0.0.0.0
    return 1
}

get_router_vport_isp()
{
    router_id=$1
    vport_name=$2

    for isp in `seq $MIN_ISP_ID $MAX_ISP_ID`; do
        isp_router_label=`get_isp_router_label $router_id $isp`
        if [[ "`ip route show table $isp_router_label 0/0 dev $vport_name \
                2> /dev/null`" ]]; then
            echo $isp
            return 0
        fi
    done

    echo $INVALID_ISP_ID
    return 1
}

get_router_vport_cookie()
{
    echo $1 | awk -v fmt=$2 '{printf fmt, $1}'
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

get_router_vport_qos()
{
    vport=$1

    qos_min=0
    qos_max=0
    qos=`tc -iec class show dev $vport classid 1:2`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        qos_max=`translate_qos $__qos_max`
    fi
    mon_qos_min=$DEFAULT_RATE
    mon_qos_max=$DEFAULT_RATE
    qos=`tc -iec class show dev $vport classid 1:f000`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        mon_qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        mon_qos_max=`translate_qos $__qos_max`
    fi
    bdc_qos_min=0
    bdc_qos_max=0
    qos=`tc -iec class show dev $vport classid 1:f001`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        bdc_qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        bdc_qos_max=`translate_qos $__qos_max`
    fi
    echo $qos_min $qos_max $mon_qos_min $mon_qos_max $bdc_qos_min $bdc_qos_max
}

get_valve_vport_qos()
{
    vport=$1
    if_index=$2

    (( index = if_index + 1 ))
    qos_min=0
    qos_max=0
    qos=`tc -iec class show dev $vport classid 1:$index`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        qos_max=`translate_qos $__qos_max`
    fi
    mon_qos_min=0
    mon_qos_max=0
    qos=`tc -iec class show dev $vport classid 1:f000`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        mon_qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        mon_qos_max=`translate_qos $__qos_max`
    fi
    bdc_qos_min=0
    bdc_qos_max=0
    qos=`tc -iec class show dev $vport classid 1:f001`
    if [[ -n "$qos" ]]; then
        __qos_min=`echo $qos | grep -Eo "rate [^ ]+" | grep -Eo "[^ ]+$"`
        bdc_qos_min=`translate_qos $__qos_min`
        __qos_max=`echo $qos | grep -Eo "ceil [^ ]+" | grep -Eo "[^ ]+$"`
        bdc_qos_max=`translate_qos $__qos_max`
    fi
    echo $qos_min $qos_max $mon_qos_min $mon_qos_max $bdc_qos_min $bdc_qos_max
}

__check_router_vport_tc_qdisc()
{
    vport=$1
    use_vpn_bypass=$2
    use_egress_qos=$3
    qdisc=0
    if [[ ! "`tc qdisc show dev $vport |
            grep -E "htb 1: root .* default 2"`" ]]; then
        echo "ERROR: vport $vport root qdisc cannot be found."
        return 1
    else
        (( qdisc += 1 ))
    fi
    if [[ ! "`tc qdisc show dev $vport |
            grep -E "sfq [0-9a-f]+: parent 1:2"`" ]]; then
        echo "ERROR: vport $vport default qdisc cannot be found."
        return 1
    else
        (( qdisc += 1 ))
    fi
    if [[ ! "`tc qdisc show dev $vport |
            grep -E "sfq [0-9a-f]+: parent 1:f000"`" ]]; then
        echo "ERROR: vport $vport monitor qdisc cannot be found."
        return 1
    else
        (( qdisc += 1 ))
    fi
    if [[ "$use_egress_qos" && ! "`tc qdisc show dev $vport |
            grep -E "ingress ffff: parent ffff:fff1"`" ]]; then
        echo "ERROR: vport $vport ingress qdisc cannot be found."
        return 1
    else
        if [[ "$use_egress_qos" ]]; then
            (( qdisc += 1 ))
        fi
    fi
    if [[ "$use_egress_qos" > "0" && ! "`tc qdisc show dev $vport |
            grep -E "sfq [0-9a-f]+: parent 1:f001"`" ]]; then
        echo "ERROR: vport $vport broadcast qdisc cannot be found."
        return 1
    else
        if [[ "$use_egress_qos" > "0" ]]; then
            (( qdisc += 1 ))
        fi
    fi
    if $use_vpn_bypass; then
        (( qdisc += 1 ))
    fi
    if [[ $qdisc -ne `tc qdisc show dev $vport | wc -l` ]]; then
        echo "ERROR: vport $vport should not have excessive qdiscs."
        return 1
    fi
    return 0
}

__check_router_vport_tc_filter()
{
    vport=$1
    use_vpn_bypass=$2
    use_egress_qos=$3
    filter=0
    if [[ "$use_egress_qos" && 1 -ne `tc filter show dev $vport parent ffff: |
            grep -E "pref $TC_MIRR_PRIO .* flowid 1:1 " |
            wc -l` ]]; then
        echo "ERROR: vport $vport ingress filter cannot be found" \
                "or duplicates."
        return 1
    else
        if [[ "$use_egress_qos" ]]; then
            (( filter += 1 ))
        fi
    fi
    if [[ $filter -ne `tc filter show dev $vport parent ffff: |
            grep flowid | wc -l` ]]; then
        echo "ERROR: vport $vport should not have excessive" \
                "ingress filters."
        return 1
    fi
    filter=0
    if [[ 1 -ne `tc filter show dev $vport |
            grep -E "pref $TC_BASE_PRIO .* flowid 1:f000 " |
            wc -l` ]]; then
        echo "ERROR: vport $vport monitor filter cannot be found" \
                "or duplicates."
        return 1
    else
        (( filter += 1 ))
    fi
    if [[ "$use_egress_qos" > "0" && 1 -ne `tc filter show dev $vport |
            grep -E "pref $TC_CTRL_PRIO .* flowid 1:f001 " |
            wc -l` ]]; then
        echo "ERROR: vport $vport broadcast filter cannot be found" \
                "or duplicates."
        return 1
    else
        if [[ "$use_egress_qos" > "0" ]]; then
            (( filter += 1 ))
        fi
    fi
    if $use_vpn_bypass; then
        (( filter += 1 ))
    fi
    if [[ $filter -ne `tc filter show dev $vport |
            grep flowid | wc -l` ]]; then
        echo "ERROR: vport $vport should not have excessive filters."
        return 1
    fi
    return 0
}

check_router_wan_vport()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"
    if ! ip link show $vport_name > /dev/null 2>&1; then
        echo "ERROR: vport $vport_name does not exist."
        return 1
    fi
    vport_ifb="${router_id}-${IFB_VPORT_PREFIX}-${if_index}"
    if ! ip link show $vport_ifb > /dev/null 2>&1; then
        echo "ERROR: vport $vport_ifb does not exist."
        return 1
    fi

    case $param in
        state)
            vport_state=`ip link show $vport_name | grep -Eo "state [A-Z]+" |
                    awk '{print $2}'`
            if [[ "$vport_state" == "DOWN" ]]; then
                echo "ERROR: vport $vport_name state should not be DOWN."
                return 1
            fi
            vport_state=`ip link show $vport_ifb | grep -Eo "state [A-Z]+" |
                    awk '{print $2}'`
            if [[ "$vport_state" == "DOWN" ]]; then
                echo "ERROR: vport $vport_ifb state should not be DOWN."
                return 1
            fi
            ;;
        mac)
            expect_mac=$1
            vport_mac=`ip link show $vport_name | grep "link/ether" | awk '{print $2}'`
            if [[ "$vport_mac" != "$expect_mac" ]]; then
                echo "ERROR: vport $vport_name MAC $vport_mac does not match" \
                        "expected $expect_mac in DB."
                return 1
            fi
            ;;
        mtu)
            phy_port=`$OVS_VSCTL_BARE list-ifaces $ULNK_BR | grep -E "^eth[0-9]+" |
                    head -n 1`
            expect_mtu=`ip link show $phy_port | grep " mtu " | awk '{print $5}'`
            vport_mtu=`ip link show $vport_name | grep " mtu " | awk '{print $5}'`
            if [[ "$vport_mtu" != "$expect_mtu" ]]; then
                echo "ERROR: vport $vport_name MTU $vport_mtu does not match" \
                        "expected $expect_mtu in DB."
                return 1
            fi
            vport_mtu=`ip link show $vport_ifb | grep " mtu " | awk '{print $5}'`
            if [[ "$vport_mtu" != "$expect_mtu" ]]; then
                echo "ERROR: vport $vport_ifb MTU $vport_mtu does not match" \
                        "expected $expect_mtu in DB."
                return 1
            fi
            ;;
        ip)
            expect_ipmls=`echo $@ | sed "s/ /\n/g" | sort`
            vport_ipmls=`ip addr show $vport_name | grep " inet " | awk '{print $2}' | sort`
            if [[ "$vport_ipmls" != "$expect_ipmls" ]]; then
                echo "ERROR: vport $vport_name IPs ($vport_ipmls) does not match" \
                        "expected ($expect_ipmls) in DB."
                return 1
            fi
            ;;
        gateway)
            expect_gateway=$1
            vport_gateway=`get_router_vport_gateway $router_id $vport_name`
            if [[ "$vport_gateway" != "$expect_gateway" ]]; then
                echo "ERROR: vport $vport_name GW $vport_gateway does not match" \
                        "expected $expect_gateway in DB."
                return 1
            fi
            ;;
        isp)
            expect_isp=$1
            vport_isp=`get_router_vport_isp $router_id $vport_name`
            if [[ "$vport_isp" != "$expect_isp" ]]; then
                echo "ERROR: vport $vport_name ISP $vport_isp does not match" \
                        "expected $expect_isp in DB."
                return 1
            fi
            ;;
        vlan)
            expect_vlan=$1
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            if [[ "$vport_vlan" != "$expect_vlan" ]]; then
                echo "ERROR: vport $vport_name VLAN $vport_vlan does not match" \
                        "expected $expect_vlan in DB."
                return 1
            fi
            ;;
        qos)
            expect_egress_qos=$@
            vport_qos=`get_router_vport_qos $vport_name`
            if [[ "$vport_qos" != "$expect_egress_qos" ]]; then
                echo "ERROR: vport $vport_name egress QoS ($vport_qos)" \
                        "does not match expected ($expect_egress_qos) in DB."
                return 1
            fi
            expect_ingress_qos=`echo $expect_egress_qos |
                    awk '{print $1,$2,$3,$4,0,0}'`
            vport_qos=`get_router_vport_qos $vport_ifb`
            if [[ "$vport_qos" != "$expect_ingress_qos" ]]; then
                echo "ERROR: vport $vport_ifb ingress QoS ($vport_qos)" \
                        "does not match expected ($expect_ingress_qos) in DB."
                return 1
            fi
            egress_qos=`echo $expect_egress_qos | awk '{print $6}'`
            if ! __check_router_vport_tc_qdisc $vport_name false $egress_qos; then
                return 1
            fi
            if ! __check_router_vport_tc_qdisc $vport_ifb true; then
                return 1
            fi
            if ! __check_router_vport_tc_filter $vport_name false $egress_qos; then
                return 1
            fi
            if ! __check_router_vport_tc_filter $vport_ifb true; then
                return 1
            fi
            if [[ "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_rate`"  != "0" ||
                  "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_burst`" != "0" ||
                  "`$OVS_VSCTL_BARE get port $vport_name qos`" != "[]" ]]; then
                echo "ERROR: vport $vport_name should not configure QoS via OvS."
                return 1
            fi
            ;;
        policy)
            vport_ipmls=`ip addr show $vport_name | grep " inet " | awk '{print $2}'`
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            vport_no=`$OVS_VSCTL_BARE get interface $vport_name ofport`
            vport_isp=`get_router_vport_isp $router_id $vport_name`
            isp_router_id=`get_isp_router_id $router_id $vport_isp`
            isp_router_label=`get_isp_router_label $router_id $vport_isp`
            __check_router_wan_vport_rule()
            {
                fwmark=`printf "0x%x" $isp_router_id`
                if [[ ! "`ip rule show |
                        grep "from all fwmark $fwmark lookup $isp_router_label"`" ]]; then
                    echo "ERROR: vport $vport_name rule of fwmark $fwmark" \
                            "cannot be found."
                    return 1
                fi
                tables=`echo -e "$router_id\n$isp_router_label" | uniq`
                for vport_ipml in $vport_ipmls; do
                    vport_ip=`echo $vport_ipml | awk -F'/' '{print $1}'`
                    if [[ ! "`ip rule show |
                            grep "from $vport_ip lookup $isp_router_label"`" ]]; then
                        echo "ERROR: vport $vport_name rule of $vport_ip" \
                                "cannot be found."
                        return 1
                    fi
                    vport_masklen=`echo $vport_ipml | awk -F'/' '{print $2}'`
                    vport_bdc_l=`ip_mask_to_broadcast_l \
                            $(ip_masklen_to_ip_mask $vport_ipml)`
                    vport_bdc_r=`ip_mask_to_broadcast_r \
                            $(ip_masklen_to_ip_mask $vport_ipml)`
                    for table in $tables; do
                        if [[ ! "`ip route show table $table $vport_ip \
                                dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of $vport_ip" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                        if [[ ! "`ip route show table $table $vport_bdc_l \
                                dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of $vport_bdc_l" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                        if [[ ! "`ip route show table $table $vport_bdc_r \
                                dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of $vport_bdc_r" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                        if [[ "$table" == "$isp_router_label" &&
                                ! "`ip route show table $table \
                                $vport_bdc_l/$vport_masklen dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of" \
                                    "$vport_bdc_l/$vport_masklen" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                    done
                done
                return 0
            }
            if ! __check_router_wan_vport_rule; then
                return 1
            fi
            __check_router_wan_vport_flow()
            {
                cookie=`get_router_vport_cookie $isp_router_id \
                        $WAN_FLOW_COOKIE_FORMAT`
                skb_mark=`printf "0x%x" $isp_router_id`
                #if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                #        cookie=$cookie/-1,table=0,in_port=$vport_no,dl_src=$vport_mac |
                #        grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                #    then
                #    echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-1" \
                #            "(cookie=$cookie,table=0,in_port=$vport_no,dl_src=$vport_mac)."
                #    return 1
                #fi
                if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                        cookie=$cookie/-1,table=1,in_port=$vport_no,dl_src=$vport_mac |
                        grep "strip_vlan,NORMAL"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-2" \
                            "(cookie=$cookie,table=1,in_port=$vport_no,dl_src=$vport_mac)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                        cookie=$cookie/-1,table=0,in_port=$vport_no |
                        grep "drop"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-3" \
                            "(cookie=$cookie,table=0,in_port=$vport_no)."
                    return 1
                fi
                for vport_ipml in $vport_ipmls; do
                    vport_ip=`echo $vport_ipml | awk -F'/' '{print $1}'`
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip |
                            grep "set_skb_mark:$skb_mark,strip_vlan,output:$vport_no" |
                            grep -E "learn\([^)]+\),set_skb_mark"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-4" \
                                "(cookie=$cookie,table=0,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,arp,dl_vlan=0xffff,arp_spa=$vport_ipml,arp_tpa=$vport_ip |
                            grep "set_skb_mark:$skb_mark,output:$vport_no" |
                            grep -E "learn\([^)]+\),set_skb_mark"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-5" \
                                "(cookie=$cookie,table=0,arp,dl_vlan=0xffff,arp_spa=$vport_ipml,arp_tpa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,nw_dst=$vport_ip |
                            grep "set_skb_mark:$skb_mark,strip_vlan,output:$vport_no"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-6" \
                                "(cookie=$cookie,table=0,ip,dl_vlan=$vport_vlan,nw_dst=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,ip,dl_vlan=0xffff,nw_src=$vport_ipml,nw_dst=$vport_ip |
                            grep "set_skb_mark:$skb_mark,output:$vport_no"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-7" \
                                "(cookie=$cookie,table=0,ip,dl_vlan=0xffff,nw_src=$vport_ipml,nw_dst=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,in_port=$vport_no,arp,arp_spa=$vport_ip |
                            grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-8" \
                                "(cookie=$cookie,table=0,in_port=$vport_no,arp,arp_spa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,in_port=$vport_no,ip,nw_src=$vport_ip |
                            grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VGW-WAN-ENTRY-9" \
                                "(cookie=$cookie,table=0,in_port=$vport_no,ip,nw_src=$vport_ip)."
                        return 1
                    fi
                done
                return 0
            }
            if ! __check_router_wan_vport_flow; then
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
    return 0
}

check_router_lan_vport()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"
    if ! ip link show $vport_name > /dev/null 2>&1; then
        echo "ERROR: vport $vport_name does not exist."
        return 1
    fi
    vport_ifb="${router_id}-${IFB_VPORT_PREFIX}-${if_index}"
    if ! ip link show $vport_ifb > /dev/null 2>&1; then
        echo "ERROR: vport $vport_ifb does not exist."
        return 1
    fi

    case $param in
        conn_limit)
            expect_conn_max=$1
            expect_new_conn_per_sec=$2
            table="filter"
            chain="FORWARD"
            router_chain="${chain}_${KEY_CHAIN_CONN}_${router_id}"

            check_conn_max=""
            check_new_conn_per_sec=""
            check_set_mark=""
            check_return=""
            check_chain=`iptables -t $table -S $chain | grep -w "$router_chain"`
            if [ "$check_chain" != "" ]; then
                check_conn_max=`iptables -t $table -S $router_chain |
                        grep -Po "(?<=--connlimit-above )[0-9]+" 2>/dev/null`
                check_new_conn_per_sec=`iptables -t $table -S $router_chain |
                        grep -Po "(?<=--hashlimit-above )[0-9]+" 2>/dev/null`
                check_return=`iptables -t $table -S $router_chain |
                        tail -n1 | grep RETURN 2>/dev/null`
                check_set_mark=`iptables -t $table -S $router_chain |
                        grep "\--set-xmark" 2>/dev/null`
            fi
            if [[ ("$expect_conn_max" = "-1" || "$expect_new_conn_per_sec" = "-1")
                    && -n "$check_chain" ]]; then
                echo "ERROR: The conn limit for vgw $router_id" \
                    "should NOT be set."
                return 1
            elif [[ "$expect_conn_max" = "0" && -n "$check_conn_max" ]]; then
                echo "ERROR: The conn_max limit for vgw $router_id" \
                    "should NOT be set."
                return 1
            elif [[ "$expect_new_conn_per_sec" = "0"
                    && -n "$check_new_conn_per_sec" ]]; then
                echo "ERROR: The new_conn_per_sec limit for vgw $router_id" \
                    "should NOT be set."
                return 1
            elif [[ "$expect_new_conn_per_sec" = "0"
                    && "$expect_conn_max" = "0" ]]; then
                if [[ -n "$check_new_conn_per_sec" || -n "$check_conn_max" ]]; then
                    echo "ERROR: The conn_max and new_conn_per_sec limit for vgw $router_id" \
                        "should NOT be set."
                    return 1
                fi
            elif [[ "$expect_new_conn_per_sec" != "$check_new_conn_per_sec"
                    || "$expect_conn_max" != "$check_conn_max" ]]; then
                echo "ERROR: The conn_max and new_conn_per_sec limit for vgw $router_id" \
                    "are NOT right."
                return 1
            elif [[ -z "$check_return" ]]; then
                echo "ERROR: The RETURN is LOST in chain $router_chain."
                return 1
            elif [[ -z "$check_set_mark" ]]; then
                echo "ERROR: The set_mark rule is NOT found in chain $router_chain."
                return 1
            fi
            ;;
        state)
            vport_state=`ip link show $vport_name | grep -Eo "state [A-Z]+" |
                    awk '{print $2}'`
            if [[ "$vport_state" == "DOWN" ]]; then
                echo "ERROR: vport $vport_name state should not be DOWN."
                return 1
            fi
            vport_state=`ip link show $vport_ifb | grep -Eo "state [A-Z]+" |
                    awk '{print $2}'`
            if [[ "$vport_state" == "DOWN" ]]; then
                echo "ERROR: vport $vport_ifb state should not be DOWN."
                return 1
            fi
            ;;
        mac)
            expect_mac=$1
            vport_mac=`ip link show $vport_name | grep "link/ether" | awk '{print $2}'`
            if [[ "$vport_mac" != "$expect_mac" ]]; then
                echo "ERROR: vport $vport_name MAC $vport_mac does not match" \
                        "expected $expect_mac in DB."
                return 1
            fi
            ;;
        mtu)
            phy_port=`$OVS_VSCTL_BARE list-ifaces $DATA_BR | grep -E "^eth[0-9]+" |
                    head -n 1`
            expect_mtu=`ip link show $phy_port | grep " mtu " | awk '{print $5}'`
            vport_mtu=`ip link show $vport_name | grep " mtu " | awk '{print $5}'`
            if [[ "$vport_mtu" != "$expect_mtu" ]]; then
                echo "ERROR: vport $vport_name MTU $vport_mtu does not match" \
                        "expected $expect_mtu in DB."
                return 1
            fi
            vport_mtu=`ip link show $vport_ifb | grep " mtu " | awk '{print $5}'`
            if [[ "$vport_mtu" != "$expect_mtu" ]]; then
                echo "ERROR: vport $vport_ifb MTU $vport_mtu does not match" \
                        "expected $expect_mtu in DB."
                return 1
            fi
            ;;
        ip)
            expect_ipmls=`echo $@ | sed "s/ /\n/g" | sort`
            vport_ipmls=`ip addr show $vport_name | grep " inet " | awk '{print $2}' | sort`
            if [[ "$vport_ipmls" != "$expect_ipmls" ]]; then
                echo "ERROR: vport $vport_name IPs ($vport_ipmls) does not match" \
                        "expected ($expect_ipmls) in DB."
                return 1
            fi
            ;;
        vlan)
            expect_vlan=$1
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            if [[ "$vport_vlan" != "$expect_vlan" ]]; then
                echo "ERROR: vport $vport_name VLAN $vport_vlan does not match" \
                        "expected $expect_vlan in DB."
                return 1
            fi
            ;;
        qos)
            expect_qos=$@
            vport_qos=`get_router_vport_qos $vport_name`
            if [[ "$vport_qos" != "$expect_qos" ]]; then
                echo "ERROR: vport $vport_name egress QoS ($vport_qos)" \
                        "does not match expected ($expect_qos) in DB."
                return 1
            fi
            vport_qos=`get_router_vport_qos $vport_ifb`
            if [[ "$vport_qos" != "$expect_qos" ]]; then
                echo "ERROR: vport $vport_ifb ingress QoS ($vport_qos)" \
                        "does not match expected ($expect_qos) in DB."
                return 1
            fi
            egress_qos=0
            if ! __check_router_vport_tc_qdisc $vport_name false $egress_qos; then
                return 1
            fi
            if ! __check_router_vport_tc_qdisc $vport_ifb false; then
                return 1
            fi
            if ! __check_router_vport_tc_filter $vport_name false $egress_qos; then
                return 1
            fi
            if ! __check_router_vport_tc_filter $vport_ifb false; then
                return 1
            fi
            if [[ "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_rate`"  != "0" ||
                  "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_burst`" != "0" ||
                  "`$OVS_VSCTL_BARE get port $vport_name qos`" != "[]" ]]; then
                echo "ERROR: vport $vport_name should not configure QoS via OvS."
                return 1
            fi
            ;;
        policy)
            vport_mac=`ip link show $vport_name | grep "link/ether" | awk '{print $2}'`
            vport_ipmls=`ip addr show $vport_name | grep " inet " | awk '{print $2}'`
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            vport_no=`$OVS_VSCTL_BARE get interface $vport_name ofport`
            isp_router_id=`get_isp_router_id $router_id 1`
            isp_router_label=`get_isp_router_label $router_id 1`
            __check_router_lan_vport_rule()
            {
                fwmark=`printf "0x%x" $isp_router_id`
                if [[ ! "`ip rule show |
                        grep "from all fwmark $fwmark lookup $isp_router_label"`" ]]; then
                    echo "ERROR: vport $vport_name rule of fwmark $fwmark" \
                            "cannot be found."
                    return 1
                fi
                tables=$router_id
                for isp in `seq 2 $MAX_ISP_ID`; do
                    isp_router_label=`get_isp_router_label $router_id $isp`
                    if ip rule show | grep -w fwmark |
                            grep -wqs "lookup $isp_router_label"; then
                        tables=$tables" $isp_router_label"
                    fi
                done
                for vport_ipml in $vport_ipmls; do
                    vport_ip=`echo $vport_ipml | awk -F'/' '{print $1}'`
                    vport_masklen=`echo $vport_ipml | awk -F'/' '{print $2}'`
                    vport_bdc_l=`ip_mask_to_broadcast_l \
                            $(ip_masklen_to_ip_mask $vport_ipml)`
                    vport_bdc_r=`ip_mask_to_broadcast_r \
                            $(ip_masklen_to_ip_mask $vport_ipml)`
                    for table in $tables; do
                        if [[ ! "`ip route show table $table $vport_ip \
                                dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of $vport_ip" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                        if [[ ! "`ip route show table $table $vport_bdc_l \
                                dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of $vport_bdc_l" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                        if [[ ! "`ip route show table $table $vport_bdc_r \
                                dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of $vport_bdc_r" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                        if [[ ! "`ip route show table $table \
                                $vport_bdc_l/$vport_masklen dev $vport_name`" ]]; then
                            echo "ERROR: vport $vport_name route of" \
                                    "$vport_bdc_l/$vport_masklen" \
                                    "cannot be found in table $table."
                            return 1
                        fi
                    done
                done
                return 0
            }
            if ! __check_router_lan_vport_rule; then
                return 1
            fi
            __check_router_lan_vport_flow()
            {
                cookie=`get_router_vport_cookie $router_id \
                        $LAN_FLOW_COOKIE_FORMAT`
                patch_port=`$OVS_VSCTL_BARE get interface $LC_DATA_TUNL_PATCH_PORT ofport`
                skb_mark=`printf "0x%x" $isp_router_id`
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac |
                        grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-1" \
                            "(cookie=$cookie,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=1,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac |
                        grep "strip_vlan,output:$vport_no"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-2" \
                            "(cookie=$cookie,table=1,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,in_port=$vport_no,dl_src=$vport_mac |
                        grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-3" \
                            "(cookie=$cookie,table=0,in_port=$vport_no,dl_src=$vport_mac)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=1,in_port=$vport_no,dl_src=$vport_mac |
                        grep "strip_vlan,NORMAL"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-4" \
                            "(cookie=$cookie,table=1,in_port=$vport_no,dl_src=$vport_mac)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,in_port=$vport_no |
                        grep "drop"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-5" \
                            "(cookie=$cookie,table=0,in_port=$vport_no)."
                    return 1
                fi
                for vport_ipml in $vport_ipmls; do
                    vport_ip=`echo $vport_ipml | awk -F'/' '{print $1}'`
                    if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                            cookie=$cookie/-1,table=0,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip |
                            grep "set_skb_mark:$skb_mark,strip_vlan,output:$vport_no" |
                            grep -E "learn\([^)]+\),set_skb_mark"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-6" \
                                "(cookie=$cookie,table=0,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                            cookie=$cookie/-1,table=1,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip |
                            grep "set_skb_mark:$skb_mark,strip_vlan,output:$vport_no"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $DATA_BR flow VGW-LAN-ENTRY-7" \
                                "(cookie=$cookie,table=1,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip)."
                        return 1
                    fi
                done
                return 0
            }
            if ! __check_router_lan_vport_flow; then
                return 1
            fi
            if ! iptables -t filter -L INPUT_$router_id > /dev/null 2>&1; then
                echo "ERROR: vport $vport_name does not have iptables chain" \
                        "INPUT_$router_id"
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
    return 0
}

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

get_wan_vport_names()
{
    router_id=$1
    $OVS_VSCTL_BARE list-ports $ULNK_BR | grep "^${router_id}-${WAN_VPORT_PREFIX}-"
}

get_lan_vport_names()
{
    router_id=$1
    $OVS_VSCTL_BARE list-ports $DATA_BR | grep "^${router_id}-${LAN_VPORT_PREFIX}-"
}

translate_proto()
{
    proto=$1

    case $proto in
        0)
            proto=all
            ;;
        1)
            proto=icmp
            ;;
        6)
            proto=tcp
            ;;
        17)
            proto=udp
            ;;
        50)
            proto=esp
            ;;
        51)
            proto=ah
            ;;
        132)
            proto=sctp
            ;;
        136)
            proto=udplite
            ;;
        *)
            : ${proto:=-1}
            ;;
    esac
    echo $proto
}

check_router_wan_vport_advanced()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"

    case $param in
        snat)
            expect_proto=`translate_proto $1`
            match_min_ip=$2; match_max_ip=$3
            target_min_ip=$4; target_max_ip=$5
            expect_isp=$6
            chain=POSTROUTING_$router_id
            masked_skb_mark=`printf "0x%x" $router_id`/$SKB_MARK_MASK
            if [[ ! "`iptables -t nat -nvL POSTROUTING |
                grep "$chain .* all .* mark match $masked_skb_mark"`" ]]; then
                echo "ERROR: vport $vport_name does not have SNAT POSTROUTING" \
                        "entry ($chain,$masked_skb_mark)."
                return 1
            fi
            if ! iptables -t nat -nvL $chain > /dev/null 2>&1; then
                echo "ERROR: vport $vport_name does not have SNAT $chain."
                return 1
            fi
            nat_type="SNAT"
            if [[ "$match_min_ip" == "$match_max_ip" ]]; then
                expect_ip="$match_min_ip"
            else
                expect_ip=`ip_range_to_prefix $match_min_ip $match_max_ip`
                if [[ -z "$expect_ip" ]]; then
                    expect_ip="$match_min_ip-$match_max_ip"
                fi
            fi
            if [[ "$target_min_ip" == "$target_max_ip" ]]; then
                expect_target_ip="to:$target_min_ip"
            elif [[ "$target_min_ip" == "0.0.0.0" &&
                    "$target_max_ip" == "255.255.255.255" ]]; then
                expect_target_ip=""
                nat_type="MASQUERADE"
            else
                expect_target_ip="to:$target_min_ip-$target_max_ip"
            fi
            if [[ ! "`iptables -t nat -nvL $chain |
                    grep -E "$nat_type.+$expect_proto.+$vport_name.+$expect_ip" |
                    grep -E "$expect_target_ip"`" ]]; then
                echo "ERROR: vport $vport_name does not have SNAT $chain entry" \
                        "($nat_type,$expect_proto,$vport_name,$expect_ip" \
                        "$expect_target_ip)."
                return 1
            fi
            # flow
            isp_router_id=`get_isp_router_id $router_id $expect_isp`
            cookie=`get_router_vport_cookie $isp_router_id \
                    $SNAT_FLOW_COOKIE_FORMAT`
            skb_mark=`printf "0x%x" $isp_router_id`
            PFXS=`ip_range_to_prefix_array $match_min_ip $match_max_ip`
            for p in ${PFXS[@]}; do
                for vport in `get_lan_vport_names $router_id`; do
                    vport_vlan=`$OVS_VSCTL_BARE get port $vport tag | grep -Eo "[0-9]+"`
                    vport_mac=`ip link show $vport | grep "link/ether" | awk '{print $2}'`
                    if [[ -n "$vport_vlan" ]]; then
                        if [ "$p" != "0.0.0.0/0" ]; then
                            if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                                    cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$p |
                                    grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                                then
                                echo "ERROR: vport $vport_name does not have $DATA_BR SNAT flow" \
                                        "(cookie=$cookie,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$p)."
                                return 1
                            fi
                        else
                            if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                                    cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac |
                                    grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                                then
                                echo "ERROR: vport $vport_name does not have $DATA_BR SNAT flow" \
                                        "(cookie=$cookie,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac)."
                                return 1
                            fi
                        fi
                    fi
                done
            done
            ;;
        dnat)
            expect_proto=`translate_proto $1`
            match_min_ip=$2; match_max_ip=$3
            match_min_port=$4; match_max_port=$5
            target_min_ip=$6; target_max_ip=$7
            target_min_port=$8; target_max_port=$9
            expect_isp=${10}
            chain=PREROUTING_$router_id
            if [[ ! "`iptables -t nat -nvL PREROUTING |
                grep "$chain .* all .* mark match $masked_skb_mark"`" ]]; then
                echo "ERROR: vport $vport_name does not have DNAT PREROUTING" \
                        "entry ($chain,$masked_skb_mark)."
                return 1
            fi
            if ! iptables -t nat -nvL $chain > /dev/null 2>&1; then
                echo "ERROR: vport $vport_name does not have DNAT $chain."
                return 1
            fi
            nat_type="DNAT"
            if [[ "$match_min_ip" == "$match_max_ip" ]]; then
                expect_ip="$match_min_ip"
            else
                expect_ip=`ip_range_to_prefix $match_min_ip $match_max_ip`
                if [[ -z "$expect_ip" ]]; then
                    expect_ip="$match_min_ip-$match_max_ip"
                fi
            fi
            if [[ $match_min_port -ne $match_max_port ]]; then
                if [[ $match_min_port -eq 1 && $match_max_port -eq 65535 ]]; then
                    expect_port=""
                else
                    expect_port="dpts:$match_min_port:$match_max_port"
                fi
            else
                expect_port="dpt:$match_min_port"
            fi
            if [[ "$target_min_ip" == "$target_max_ip" ]]; then
                expect_target_ip="to:$target_min_ip"
            else
                expect_target_ip="to:$target_min_ip-$target_max_ip"
            fi
            if [[ $target_min_port -ne $target_max_port ]]; then
                if [[ $target_min_port -eq 1 && $target_max_port -eq 65535 ]]; then
                    expect_target_port=""
                else
                    expect_target_port=":$target_min_port-$target_max_port"
                fi
            else
                expect_target_port=":$target_min_port"
            fi
            if [[ $target_min_port -eq $match_min_port &&
                  $target_max_port -eq $match_max_port ]]; then
                expect_target_port=""
            fi
            if [[ ! "`iptables -t nat -nvL $chain |
                    grep -E "$nat_type.+$expect_proto.+$vport_name.+$expect_ip.+$expect_port" |
                    grep -E "$expect_target_ip$expect_target_port"`" ]]; then
                echo "ERROR: vport $vport_name does not have DNAT $chain entry" \
                        "($nat_type,$expect_proto,$vport_name,$expect_ip,$expect_port" \
                        "$expect_target_ip,$expect_target_port)."
                return 1
            fi
            # flow
            isp_router_id=`get_isp_router_id $router_id $expect_isp`
            cookie=`get_router_vport_cookie $isp_router_id \
                    $DNAT_FLOW_COOKIE_FORMAT`
            skb_mark=`printf "0x%x" $isp_router_id`
            PFXS=`ip_range_to_prefix_array $target_min_ip $target_max_ip`
            for p in ${PFXS[@]}; do
                for vport in `get_lan_vport_names $router_id`; do
                    vport_vlan=`$OVS_VSCTL_BARE get port $vport tag | grep -Eo "[0-9]+"`
                    vport_mac=`ip link show $vport | grep "link/ether" | awk '{print $2}'`
                    if [[ -n "$vport_vlan" ]]; then
                        if [ "$p" != "0.0.0.0/0" ]; then
                            if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                                    cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$p |
                                    grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                                then
                                echo "ERROR: vport $vport_name does not have $DATA_BR DNAT flow" \
                                        "(cookie=$cookie,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$p)."
                                return 1
                            fi
                        else
                            if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                                    cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac |
                                    grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                                then
                                echo "ERROR: vport $vport_name does not have $DATA_BR DNAT flow" \
                                        "(cookie=$cookie,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac)."
                                return 1
                            fi
                        fi
                    fi
                done
            done
            ;;
        vpn)
            left=$1; lnet_addr=$2; lnet_mask=$3
            right=$4; rnet_addr=$5; rnet_mask=$6
            psk=$7; expect_isp=$8; name=$9
            vpn_label="nsp_${router_id}_${name}"
            if [[ ! "`find $STRONGSWAN_CONF_DIR -name "$vpn_label.conf"`" ]]; then
                echo "ERROR: vport $vport_name does not have $vpn_label.conf."
                return 1
            fi
            if [[ ! "`find $STRONGSWAN_CONF_DIR -name "$vpn_label.secrets"`" ]]; then
                echo "ERROR: vport $vport_name does not have $vpn_label.secrets."
                return 1
            fi
            vpn_conn_name="${router_id}_${left}_${lnet_addr}_${lnet_mask}_${right}_${rnet_addr}_${rnet_mask}"
            if [[ ! "`grep "^conn $vpn_conn_name" \
                    $STRONGSWAN_CONF_DIR/$vpn_label.conf`" ]]; then
                echo "ERROR: vport $vport_name conn $vpn_conn_name" \
                        "does not found in $vpn_label.conf."
                return 1
            fi
            if ! strongswan status > /dev/null 2>&1; then
                echo "ERROR: vport $vport_name strongswan is not running."
                return 1
            fi
            lnet_prefix=`ip_mask_to_prefix $lnet_addr $lnet_mask`
            rnet_prefix=`ip_mask_to_prefix $rnet_addr $rnet_mask`
            isp_router_id=`get_isp_router_id $router_id $expect_isp`
            vpn_mark=`echo $isp_router_id | awk '{printf "%#x", $1}'`
            if [[ ! "`cat $STRONGSWAN_CONF_DIR/$vpn_label.conf |
                    grep "left=$left"`"   ||
                  ! "`cat $STRONGSWAN_CONF_DIR/$vpn_label.conf |
                    grep "leftsubnet=$lnet_prefix"`"  ||
                  ! "`cat $STRONGSWAN_CONF_DIR/$vpn_label.conf |
                    grep "right=$right"`" ||
                  ! "`cat $STRONGSWAN_CONF_DIR/$vpn_label.conf |
                    grep "rightsubnet=$rnet_prefix"`" ||
                  ! "`cat $STRONGSWAN_CONF_DIR/$vpn_label.conf |
                    grep "mark=$vpn_mark"`" ]]; then
                echo "ERROR: vport $vport_name conn $vpn_conn_name" \
                        "($left,$lnet_prefix,$right,$rnet_prefix,$vpn_mark)" \
                        "does not configure right in $vpn_label.conf."
                return 1
            fi
            if [[ ! "`cat $STRONGSWAN_CONF_DIR/$vpn_label.secrets |
                    grep -E "$left $right : PSK .$psk."`" ]]; then
                echo "ERROR: vport $vport_name conn $vpn_conn_name" \
                        "($left,$right,$psk)" \
                        "does not configure right in $vpn_label.secrets."
                return 1
            fi
            isp_router_id=`get_isp_router_id $router_id $expect_isp`
            cookie=`get_router_vport_cookie $isp_router_id \
                    $VPN_FLOW_COOKIE_FORMAT`
            skb_mark=`printf "0x%x" $isp_router_id`
            for vport in `get_lan_vport_names $router_id`; do
                vport_vlan=`$OVS_VSCTL_BARE get port $vport tag | grep -Eo "[0-9]+"`
                vport_mac=`ip link show $vport | grep "link/ether" | awk '{print $2}'`
                if [[ -n "$vport_vlan" ]]; then
                    if [ "$lnet_prefix" != "0.0.0.0/0" ]; then
                        if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                                cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$lnet_prefix |
                                grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                            then
                            echo "ERROR: vport $vport_name does not have $DATA_BR VPN flow" \
                                    "(cookie=$cookie,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac,nw_src=$lnet_prefix)."
                            return 1
                        fi
                    else
                        if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                                cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac |
                                grep "set_skb_mark:$skb_mark,resubmit(,1)"`" ]];
                            then
                            echo "ERROR: vport $vport_name does not have $DATA_BR VPN flow" \
                                    "(cookie=$cookie,ip,dl_vlan=$vport_vlan,dl_dst=$vport_mac)."
                            return 1
                        fi
                    fi
                fi
            done
            ;;
        route)
            expect_prefix=`ip_mask_to_prefix $1 $2`
            expect_nexthop=$3; expect_isp=$4
            isp_router_label=`get_isp_router_label $router_id $expect_isp`
            table=$isp_router_label
            if [[ ! "`ip route show table $table \
                    $expect_prefix via $expect_nexthop dev $vport_name`" ]]; then
                echo "ERROR: vport $vport_name does not have route" \
                        "($expect_prefix via $expect_nexthop dev $vport_name)" \
                        "in table $table."
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
}

check_router_lan_vport_advanced()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"

    case $param in
        acl)
            expect_proto=`translate_proto $1`
            src_if_type=$2; src_if_index=$3
            src_min_ip=$4; src_max_ip=$5
            src_min_port=$6; src_max_port=$7
            dst_if_type=$8; dst_if_index=$9
            dst_min_ip=${10}; dst_max_ip=${11}
            dst_min_port=${12}; dst_max_port=${13}
            expect_action=${14}
            chain=FORWARD_$router_id
            if [[ ! "`iptables -t filter -nvL FORWARD |
                grep "$chain .* all .* mark match $masked_skb_mark"`" ]]; then
                echo "ERROR: vport $vport_name does not have ACL FORWARD" \
                        "entry ($chain,$masked_skb_mark)."
                return 1
            fi
            if ! iptables -t filter -nvL $chain > /dev/null 2>&1; then
                echo "ERROR: vport $vport_name does not have ACL $chain."
                return 1
            fi
            if [[ "$src_if_type" = "WAN" ]]; then
                expect_in="${router_id}-${WAN_VPORT_PREFIX}-${src_if_index}"
            elif [[ "$src_if_type" = "LAN" ]]; then
                expect_in="${router_id}-${LAN_VPORT_PREFIX}-${src_if_index}"
            else
                expect_in="\*"
            fi
            if [[ "$dst_if_type" = "WAN" ]]; then
                expect_out="${router_id}-${WAN_VPORT_PREFIX}-${dst_if_index}"
            elif [[ "$dst_if_type" = "LAN" ]]; then
                expect_out="${router_id}-${LAN_VPORT_PREFIX}-${dst_if_index}"
            else
                expect_out="\*"
            fi
            if [[ "$src_min_ip" == "$src_max_ip" ]]; then
                expect_src_ip="$src_min_ip"
            elif [[ "$src_min_ip" == "0.0.0.0" &&
                    "$src_max_ip" == "255.255.255.255" ]]; then
                expect_src_ip="0.0.0.0/0"
            else
                expect_src_ip=`ip_range_to_prefix $src_min_ip $src_max_ip`
                if [[ -z "$expect_src_ip" ]]; then
                    expect_src_ip="$src_min_ip-$src_max_ip"
                fi
            fi
            if [[ $src_min_port -ne $src_max_port ]]; then
                if [[ $src_min_port -eq 1 && $src_max_port -eq 65535 ]]; then
                    expect_src_port=""
                else
                    expect_src_port="spts:$src_min_port:$src_max_port"
                fi
            else
                expect_src_port="spt:$src_min_port"
            fi
            if [[ "$dst_min_ip" == "$dst_max_ip" ]]; then
                expect_dst_ip="$dst_min_ip"
            elif [[ "$dst_min_ip" == "0.0.0.0" &&
                    "$dst_max_ip" == "255.255.255.255" ]]; then
                expect_dst_ip="0.0.0.0/0"
            else
                expect_dst_ip=`ip_range_to_prefix $dst_min_ip $dst_max_ip`
                if [[ -z "$expect_dst_ip" ]]; then
                    expect_dst_ip="$dst_min_ip-$dst_max_ip"
                fi
            fi
            if [[ $dst_min_port -ne $dst_max_port ]]; then
                if [[ $dst_min_port -eq 1 && $dst_max_port -eq 65535 ]]; then
                    expect_dst_port=""
                else
                    expect_dst_port="dpts:$dst_min_port:$dst_max_port"
                fi
            else
                expect_dst_port="dpt:$dst_min_port"
            fi
            if [[ ! "`iptables -t filter -nvL $chain |
                    grep -E "$expect_action.+$expect_proto.+$expect_in.+$expect_out" |
                    grep -E "$expect_src_ip.*$expect_src_port" |
                    grep -E "$expect_dst_ip.*$expect_dst_port"`" ]]; then
                echo "ERROR: vport $vport_name does not have ACL $chain entry" \
                        "($expect_action,$expect_proto,$expect_in,$expect_out" \
                        "$expect_src_ip,$expect_src_port,$expect_dst_ip,$expect_dst_port)."
                return 1
            fi
            ;;
        route)
            expect_prefix=`ip_mask_to_prefix $1 $2`
            expect_nexthop=$3; expect_isp=$4
            isp_router_label=`get_isp_router_label $router_id $expect_isp`
            tables="$router_id"
            for isp in `seq 2 $MAX_ISP_ID`; do
                isp_router_label=`get_isp_router_label $router_id $isp`
                if [[ "`ip rule show | grep "lookup $isp_router_label"`" ]]; then
                    tables=$tables" $isp_router_label"
                fi
            done
            for table in $tables; do
                if [[ ! "`ip route show table $table \
                        $expect_prefix via $expect_nexthop`" ]]; then
                    echo "ERROR: vport $vport_name does not have route" \
                            "($expect_prefix via $expect_nexthop)" \
                            "in table $table."
                    return 1
                fi
            done
            ;;
        tunnel)
            expect_tunid=$1
            vport_mac=`ip link show $vport_name | grep "link/ether" | awk '{print $2}'`
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            patch_port=`$OVS_VSCTL_BARE get interface $LC_TUNL_DATA_PATCH_PORT ofport`
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,tun_id=$expect_tunid,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 |
                    grep "mod_vlan_vid:$vport_vlan,output:$patch_port" |
                    grep -E "learn\([^)]+\),mod_vlan_vid"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vl2 flow" \
                        "(table=0,tun_id=$expect_tunid,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00)."
                return 1
            fi
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,tun_id=$expect_tunid,dl_dst=$vport_mac |
                    grep "mod_vlan_vid:$vport_vlan,output:$patch_port" |
                    grep -E "learn\([^)]+\),mod_vlan_vid"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(table=0,tun_id=$expect_tunid,dl_dst=$vport_mac)."
                return 1
            fi
            expect_tunid=`printf "0x%x" $expect_tunid`
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,in_port=$patch_port,dl_vlan=$vport_vlan,dl_src=$vport_mac |
                    grep "strip_vlan,set_tunnel:$expect_tunid,resubmit(,1)"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(table=0,in_port=$patch_port,dl_vlan=$vport_vlan,dl_src=$vport_mac)."
                return 1
            fi
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,dl_src=$vport_mac | grep "drop"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(table=0,dl_src=$vport_mac)."
                return 1
            fi
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    cookie=$MAC_FLOOD_COOKIE/-1,table=1,in_port=$patch_port |
                    grep "NORMAL"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(cookie=$MAC_FLOOD_COOKIE/-1,table=1,in_port=$patch_port)."
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
}

__check_valve_vport_tc_qdisc()
{
    vport=$1
    use_egress_qos=$2
    (( index = if_index + 1 ))
    if [[ ! "`tc qdisc show dev $vport |
            grep -E "htb 1: root .* default 1"`" ]]; then
        echo "ERROR: vport $vport root qdisc cannot be found."
        return 1
    fi
    if [[ ! "`tc qdisc show dev $vport |
            grep -E "sfq [0-9a-f]+: parent 1:$index"`" ]]; then
        echo "ERROR: vport $vport default qdisc cannot be found."
        return 1
    fi
    if [[ ! "`tc qdisc show dev $vport |
            grep -E "sfq [0-9a-f]+: parent 1:f000"`" ]]; then
        echo "ERROR: vport $vport monitor qdisc cannot be found."
        return 1
    fi
    if [[ "$use_egress_qos" > "0" && ! "`tc qdisc show dev $vport |
            grep -E "sfq [0-9a-f]+: parent 1:f001"`" ]]; then
        echo "ERROR: vport $vport broadcast qdisc cannot be found."
        return 1
    fi
    if [[ "`tc qdisc show dev $vport |
            grep -E "ingress ffff: parent ffff:fff1"`" ]]; then
        echo "ERROR: vport $vport ingress qdisc should not be configured."
        return 1
    fi
    return 0
}

__check_valve_vport_tc_filter()
{
    vport=$1
    use_egress_qos=$2
    (( index = if_index + 1 ))
    vport_ips=`$OVS_VSCTL_BARE get interface $vport_name external_ids |
            grep -Eo "lc-ip-netmask-$if_index-[0-9]+[^,]+" |
            awk -F'"' '{print $3}' | awk -F'/' '{print $1}' | sort`
    if [[ "$vport_ips" != "`tc -p filter show dev $vport |
            grep -A 1 -E "pref $TC_BASE_PRIO .* flowid 1:$index " |
            grep match | awk '{print $4}' | awk -F'/' '{print $1}' |
            sort`" ]]; then
        echo "ERROR: vport $vport ($vport_ips) filter cannot be found."
        return 1
    fi
    if [[ 1 -ne `tc filter show dev $vport |
            grep -E "pref $TC_BASE_PRIO .* flowid 1:f000 " |
            wc -l` ]]; then
        echo "ERROR: vport $vport monitor filter cannot be found" \
                "or duplicates."
        return 1
    fi
    if [[ "$use_egress_qos" > "0" && 1 -ne `tc filter show dev $vport |
            grep -E "pref $TC_CTRL_PRIO .* flowid 1:f001 " |
            wc -l` ]]; then
        echo "ERROR: vport $vport broadcast filter cannot be found" \
                "or duplicates."
        return 1
    fi
    return 0
}

check_valve_wan_vport()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${VALVE_WAN_IF_INDEX}"
    if ! ip link show $vport_name > /dev/null 2>&1; then
        echo "ERROR: vport $vport_name does not exist."
        return 1
    fi
    vport_lan="${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}"
    if ! ip link show $vport_lan > /dev/null 2>&1; then
        echo "ERROR: vport $vport_lan does not exist as pair of vport $vport_name."
        return 1
    fi

    case $param in
        state)
            vport_state=`ip link show $vport_name | grep -Eo "state [A-Z]+" |
                    awk '{print $2}'`
            if [[ "$vport_state" == "DOWN" ]]; then
                echo "ERROR: vport $vport_name state should not be DOWN."
                return 1
            fi
            ;;
        mtu)
            phy_port=`$OVS_VSCTL_BARE list-ifaces $ULNK_BR | grep -E "^eth[0-9]+" |
                    head -n 1`
            expect_mtu=`ip link show $phy_port | grep " mtu " | awk '{print $5}'`
            vport_mtu=`ip link show $vport_name | grep " mtu " | awk '{print $5}'`
            if [[ "$vport_mtu" != "$expect_mtu" ]]; then
                echo "ERROR: vport $vport_name MTU $vport_mtu does not match" \
                        "expected $expect_mtu in DB."
                return 1
            fi
            ;;
        ip)
            expect_ipmls=`echo $@ | sed "s/ /\n/g" | sort`
            vport_ipmls=`$OVS_VSCTL_BARE get interface $vport_name external_ids |
                    grep -Eo "lc-ip-netmask-$if_index-[0-9]+[^,]+" |
                    awk -F'"' '{print $3}' | sort`
            if [[ "$vport_ipmls" != "$expect_ipmls" ]]; then
                echo "ERROR: vport $vport_name IPs ($vport_ipmls) does not match" \
                        "expected ($expect_ipmls) in DB."
                return 1
            fi
            ;;
        gateway)
            expect_gateway=$1
            vport_gateway=`$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-gateway-$if_index | awk -F'"' '{print $2}'`
            if [[ "$vport_gateway" != "$expect_gateway" ]]; then
                echo "ERROR: vport $vport_name GW $vport_gateway does not match" \
                        "expected $expect_gateway in DB."
                return 1
            fi
            ;;
        isp)
            expect_isp=$1
            vport_isp=`$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-router-isp-$if_index | awk -F'"' '{print $2}'`
            if [[ "$vport_isp" != "$expect_isp" ]]; then
                echo "ERROR: vport $vport_name ISP $vport_isp does not match" \
                        "expected $expect_isp in DB."
                return 1
            fi
            ;;
        vlan)
            expect_vlan=$1
            vport_vlan=`$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-vlan-$if_index | awk -F'"' '{print $2}'`
            if [[ "$vport_vlan" != "$expect_vlan" ]]; then
                echo "ERROR: vport $vport_name VLAN $vport_vlan does not match" \
                        "expected $expect_vlan in DB."
                return 1
            fi
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name trunks | grep -o $expect_vlan`
            if [[ "$vport_vlan" != "$expect_vlan" ]]; then
                echo "ERROR: vport $vport_name trunks VLAN does not have" \
                        "expected $expect_vlan in DB."
                return 1
            fi
            ;;
        qos)
            expect_egress_qos=$@
            vport_qos=`get_router_vport_qos $vport_name`
            if [[ "$vport_qos" != "$expect_egress_qos" ]]; then
                echo "ERROR: vport $vport_name egress QoS ($vport_qos)" \
                        "does not match expected ($expect_egress_qos) in DB."
                return 1
            fi
            expect_ingress_qos=`echo $expect_egress_qos |
                    awk '{print $1,$2,$3,$4,0,0}'`
            vport_qos=`get_router_vport_qos $vport_lan`
            if [[ "$vport_qos" != "$expect_ingress_qos" ]]; then
                echo "ERROR: vport $vport_lan ingress QoS ($vport_qos)" \
                        "does not match expected ($expect_ingress_qos) in DB."
                return 1
            fi
            egress_qos=`echo $expect_egress_qos | awk '{print $6}'`
            if ! __check_valve_vport_tc_qdisc $vport_name $egress_qos; then
                return 1
            fi
            if ! __check_valve_vport_tc_qdisc $vport_lan; then
                return 1
            fi
            if ! __check_valve_vport_tc_filter $vport_name $egress_qos; then
                return 1
            fi
            if ! __check_valve_vport_tc_filter $vport_lan; then
                return 1
            fi
            if [[ "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_rate`"  != "0" ||
                  "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_burst`" != "0" ||
                  "`$OVS_VSCTL_BARE get port $vport_name qos`" != "[]" ]]; then
                echo "ERROR: vport $vport_name should not configure QoS via OvS."
                return 1
            fi
            ;;
        policy)
            vport_ipmls=`$OVS_VSCTL_BARE get interface $vport_name external_ids |
                    grep -Eo "lc-ip-netmask-$if_index-[0-9]+[^,]+" |
                    awk -F'"' '{print $3}'`
            vport_vlan=`$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-vlan-$if_index | awk -F'"' '{print $2}'`
            vport_no=`$OVS_VSCTL_BARE get interface $vport_name ofport`
            vport_isp=`$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-router-isp-$if_index | awk -F'"' '{print $2}'`
            if [[ `$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-router-type 2> /dev/null |
                    awk -F'"' '{print $2}'` -ne $ROUTER_TYPE_VALVE ]]; then
                echo "ERROR: vport $vport_name type is not valve."
                return 1
            fi
            __check_valve_wan_vport_rule()
            {
                isp_router_id=`get_isp_router_id $router_id $VALVE_LAN_ISP_ID`
                skb_mark=`printf "0x%x" $isp_router_id`
                masked_skb_mark=`printf "0x%x" $router_id`/$SKB_MARK_MASK
                br=$VALVE_BR_PREFIX$router_id
                if ! brctl show $br > /dev/null 2>&1; then
                    echo "ERROR: vport $vport_name bridge $br does not exist."
                    return 1
                fi
                if [[ ! "`brctl show $br | grep -o $vport_name`" ]]; then
                    echo "ERROR: vport $vport_name does not connect to bridge $br."
                    return 1
                fi
                if [[ "`ip link show $br | grep -Eo "state [A-Z]+" |
                        awk '{print $2}'`" == "DOWN" ]]; then
                    echo "ERROR: vport $vport_name bridge $br state should not be DOWN."
                    return 1
                fi
                chain=FORWARD_$router_id
                if [[ ! "`ebtables -t filter -L FORWARD |
                        grep "policy: DROP"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables FORWARD policy is not DROP."
                    return 1
                fi
                if [[ ! "`ebtables -t filter -L FORWARD |
                        grep "^--mark $masked_skb_mark -j $chain"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables FORWARD entry" \
                            "(--mark $masked_skb_mark -j $chain)" \
                            "cannot be found."
                    return 1
                fi
                if [[ ! "`ebtables -t filter -L $chain 2> /dev/null |
                        grep "policy: DROP"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables $chain policy is not DROP."
                    return 1
                fi
                if [[ ! "`ebtables -t filter -L $chain |
                        grep "^-o $vport_name --mark $skb_mark -j mark --mark-set 0x0" |
                        grep "mark-set 0x0 --mark-target ACCEPT"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables $chain entry" \
                            "(-o $vport_name --mark $skb_mark -j mark --mark-set 0x0)" \
                            "cannot be found."
                    return 1
                fi
            }
            if ! __check_valve_wan_vport_rule; then
                return 1
            fi
            __check_valve_wan_vport_flow()
            {
                isp_router_id=`get_isp_router_id $router_id $vport_isp`
                cookie=`get_router_vport_cookie $isp_router_id \
                        $WAN_FLOW_COOKIE_FORMAT`
                if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                        table=1,in_port=$vport_no,dl_vlan=$vport_vlan |
                        grep "NORMAL"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-1" \
                            "(table=1,in_port=$vport_no,dl_vlan=$vport_vlan)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                        table=0,in_port=$vport_no |
                        grep "drop"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-2" \
                            "(table=0,in_port=$vport_no)."
                    return 1
                fi
                isp_router_id=`get_isp_router_id $router_id $VALVE_WAN_ISP_ID`
                skb_mark=`printf "0x%x" $isp_router_id`
                for vport_ipml in $vport_ipmls; do
                    vport_ip=`echo $vport_ipml | awk -F'/' '{print $1}'`
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,in_port=$vport_no,arp,arp_tpa=$vport_ip |
                            grep "drop"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-3" \
                                "(cookie=$cookie,table=0,in_port=$vport_no,arp,arp_tpa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,in_port=$vport_no,ip,nw_dst=$vport_ip |
                            grep "drop"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-4" \
                                "(cookie=$cookie,table=0,in_port=$vport_no,ip,nw_dst=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip |
                            grep "set_skb_mark:$skb_mark,strip_vlan,output:$vport_no" |
                            grep -E "learn\([^)]+\),set_skb_mark"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-5" \
                                "(cookie=$cookie,table=0,arp,dl_vlan=$vport_vlan,arp_tpa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,arp,dl_vlan=0xffff,arp_spa=$vport_ipml,arp_tpa=$vport_ip |
                            grep "set_skb_mark:$skb_mark,output:$vport_no" |
                            grep -E "learn\([^)]+\),set_skb_mark"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-6" \
                                "(cookie=$cookie,table=0,arp,dl_vlan=0xffff,arp_spa=$vport_ipml,arp_tpa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan,nw_dst=$vport_ip |
                            grep "set_skb_mark:$skb_mark,strip_vlan,output:$vport_no"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-7" \
                                "(cookie=$cookie,table=0,ip,dl_vlan=$vport_vlan,nw_dst=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,ip,dl_vlan=0xffff,nw_src=$vport_ipml,nw_dst=$vport_ip |
                            grep "set_skb_mark:$skb_mark,output:$vport_no"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-8" \
                                "(cookie=$cookie,table=0,ip,dl_vlan=0xffff,nw_src=$vport_ipml,nw_dst=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,in_port=$vport_no,arp,arp_spa=$vport_ip |
                            grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-9" \
                                "(cookie=$cookie,table=0,in_port=$vport_no,arp,arp_spa=$vport_ip)."
                        return 1
                    fi
                    if [[ ! "`ovs-ofctl dump-flows $ULNK_BR \
                            cookie=$cookie/-1,table=0,in_port=$vport_no,ip,nw_src=$vport_ip |
                            grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                        then
                        echo "ERROR: vport $vport_name does not have $ULNK_BR flow VALVE-WAN-ENTRY-10" \
                                "(cookie=$cookie,table=0,in_port=$vport_no,ip,nw_src=$vport_ip)."
                        return 1
                    fi
                done
                return 0
            }
            if ! __check_valve_wan_vport_flow; then
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
    return 0
}

check_valve_lan_vport()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${VALVE_LAN_IF_INDEX}"
    if ! ip link show $vport_name > /dev/null 2>&1; then
        echo "ERROR: vport $vport_name does not exist."
        return 1
    fi

    case $param in
        state)
            vport_state=`ip link show $vport_name | grep -Eo "state [A-Z]+" |
                    awk '{print $2}'`
            if [[ "$vport_state" == "DOWN" ]]; then
                echo "ERROR: vport $vport_name state should not be DOWN."
                return 1
            fi
            ;;
        mtu)
            phy_port=`$OVS_VSCTL_BARE list-ifaces $DATA_BR | grep -E "^eth[0-9]+" |
                    head -n 1`
            expect_mtu=`ip link show $phy_port | grep " mtu " | awk '{print $5}'`
            vport_mtu=`ip link show $vport_name | grep " mtu " | awk '{print $5}'`
            if [[ "$vport_mtu" != "$expect_mtu" ]]; then
                echo "ERROR: vport $vport_name MTU $vport_mtu does not match" \
                        "expected $expect_mtu in DB."
                return 1
            fi
            ;;
        vlan)
            expect_vlan=$1
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            if [[ "$vport_vlan" != "$expect_vlan" ]]; then
                echo "ERROR: vport $vport_name VLAN $vport_vlan does not match" \
                        "expected $expect_vlan in DB."
                return 1
            fi
            ;;
        qos)
            expect_qos=$@
            vport_qos="0 0 0 0 0 0"
            if [[ "$vport_qos" != "$expect_qos" ]]; then
                echo "ERROR: vport $vport_name egress QoS ($vport_qos)" \
                        "does not match expected ($expect_qos) in DB."
                return 1
            fi
            if [[ "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_rate`"  != "0" ||
                  "`$OVS_VSCTL_BARE get interface $vport_name \
                    ingress_policing_burst`" != "0" ||
                  "`$OVS_VSCTL_BARE get port $vport_name qos`" != "[]" ]]; then
                echo "ERROR: vport $vport_name should not configure QoS via OvS."
                return 1
            fi
            ;;
        policy)
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            vport_no=`$OVS_VSCTL_BARE get interface $vport_name ofport`
            if [[ `$OVS_VSCTL_BARE get interface $vport_name \
                    external_ids:lc-router-type 2> /dev/null |
                    awk -F'"' '{print $2}'` -ne $ROUTER_TYPE_VALVE ]]; then
                echo "ERROR: vport $vport_name type is not valve."
                return 1
            fi
            __check_valve_lan_vport_rule()
            {
                isp_router_id=`get_isp_router_id $router_id $VALVE_WAN_ISP_ID`
                skb_mark=`printf "0x%x" $isp_router_id`
                masked_skb_mark=`printf "0x%x" $router_id`/$SKB_MARK_MASK
                br=$VALVE_BR_PREFIX$router_id
                if ! brctl show $br > /dev/null 2>&1; then
                    echo "ERROR: vport $vport_name bridge $br does not exist."
                    return 1
                fi
                if [[ ! "`brctl show $br | grep -o $vport_name`" ]]; then
                    echo "ERROR: vport $vport_name does not connect to bridge $br."
                    return 1
                fi
                if [[ "`ip link show $br | grep -Eo "state [A-Z]+" |
                        awk '{print $2}'`" == "DOWN" ]]; then
                    echo "ERROR: vport $vport_name bridge $br state should not be DOWN."
                    return 1
                fi
                chain=FORWARD_$router_id
                if [[ ! "`ebtables -t filter -L FORWARD |
                        grep "policy: DROP"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables FORWARD policy is not DROP."
                    return 1
                fi
                if [[ ! "`ebtables -t filter -L FORWARD |
                        grep "^--mark $masked_skb_mark -j $chain"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables FORWARD entry" \
                            "(--mark $masked_skb_mark -j $chain)" \
                            "cannot be found."
                    return 1
                fi
                if [[ ! "`ebtables -t filter -L $chain 2> /dev/null |
                        grep "policy: DROP"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables $chain policy is not DROP."
                    return 1
                fi
                if [[ ! "`ebtables -t filter -L $chain |
                        grep "^-o $vport_name --mark $skb_mark -j mark --mark-set 0x0" |
                        grep "mark-set 0x0 --mark-target ACCEPT"`" ]]; then
                    echo "ERROR: vport $vport_name ebtables $chain entry" \
                            "(-o $vport_name --mark $skb_mark -j mark --mark-set 0x0)" \
                            "cannot be found."
                    return 1
                fi
            }
            if ! __check_valve_lan_vport_rule; then
                return 1
            fi
            __check_valve_lan_vport_flow()
            {
                isp_router_id=`get_isp_router_id $router_id 1`
                cookie=`get_router_vport_cookie $isp_router_id \
                        $LAN_FLOW_COOKIE_FORMAT`
                isp_router_id=`get_isp_router_id $router_id $VALVE_LAN_ISP_ID`
                patch_port=`$OVS_VSCTL_BARE get interface $LC_DATA_TUNL_PATCH_PORT ofport`
                skb_mark=`printf "0x%x" $isp_router_id`
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,in_port=$patch_port,dl_vlan=$vport_vlan |
                        grep "set_skb_mark:$skb_mark,NORMAL"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VALVE-LAN-ENTRY-1" \
                            "(cookie=$cookie,in_port=$patch_port,dl_vlan=$vport_vlan)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,arp,dl_vlan=$vport_vlan |
                        grep "output:$patch_port,set_skb_mark:$skb_mark,strip_vlan,output:$vport_no" |
                        grep -E "learn\([^)]+\),output"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VALVE-LAN-ENTRY-2" \
                            "(cookie=$cookie,arp,dl_vlan=$vport_vlan)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,ip,dl_vlan=$vport_vlan |
                        grep "output:$patch_port,set_skb_mark:$skb_mark,strip_vlan,output:$vport_no"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VALVE-LAN-ENTRY-3" \
                            "(cookie=$cookie,ip,dl_vlan=$vport_vlan)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,in_port=$vport_no,dl_vlan=0xffff |
                        grep "mod_vlan_vid:$vport_vlan,resubmit(,1)"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VALVE-LAN-ENTRY-4" \
                            "(cookie=$cookie,table=0,in_port=$vport_no,dl_vlan=0xffff)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=1,in_port=$vport_no,dl_vlan=$vport_vlan |
                        grep "strip_vlan,NORMAL"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VALVE-LAN-ENTRY-5" \
                            "(cookie=$cookie,table=1,in_port=$vport_no,dl_vlan=$vport_vlan)."
                    return 1
                fi
                if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
                        cookie=$cookie/-1,table=0,in_port=$vport_no |
                        grep "drop"`" ]];
                    then
                    echo "ERROR: vport $vport_name does not have $DATA_BR flow VALVE-LAN-ENTRY-6" \
                            "(cookie=$cookie,table=0,in_port=$vport_no)."
                    return 1
                fi
                return 0
            }
            if ! __check_valve_lan_vport_flow; then
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
    return 0
}

check_valve_wan_vport_advanced()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${WAN_VPORT_PREFIX}-${if_index}"

    echo "INFO: vport $vport_name $param is OK."
}

check_valve_lan_vport_advanced()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    vport_name="${router_id}-${LAN_VPORT_PREFIX}-${if_index}"

    case $param in
        tunnel)
            expect_tunid=$1
            vport_vlan=`$OVS_VSCTL_BARE get port $vport_name tag`
            patch_port=`$OVS_VSCTL_BARE get interface $LC_TUNL_DATA_PATCH_PORT ofport`
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,tun_id=$expect_tunid,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00 |
                    grep "mod_vlan_vid:$vport_vlan,output:$patch_port" |
                    grep -E "learn\([^)]+\),mod_vlan_vid"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vl2 flow" \
                        "(table=0,tun_id=$expect_tunid,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00)."
                return 1
            fi
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,tun_id=$expect_tunid |
                    grep "priority=50004," |
                    grep "mod_vlan_vid:$vport_vlan,output:$patch_port" |
                    grep -E "learn\([^)]+\),mod_vlan_vid"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(table=0,tun_id=$expect_tunid)."
                return 1
            fi
            expect_tunid=`printf "0x%x" $expect_tunid`
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    table=0,in_port=$patch_port,dl_vlan=$vport_vlan |
                    grep "priority=50003," |
                    grep "strip_vlan,set_tunnel:$expect_tunid,resubmit(,1)"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(table=0,in_port=$patch_port,dl_vlan=$vport_vlan)."
                return 1
            fi
            if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
                    cookie=$MAC_FLOOD_COOKIE/-1,table=1,in_port=$patch_port |
                    grep "NORMAL"`" ]];
                then
                echo "ERROR: vport $vport_name does not have $TUNL_BR vif flow" \
                        "(cookie=$MAC_FLOOD_COOKIE/-1,table=1,in_port=$patch_port)."
                return 1
            fi
            ;;
    esac
    echo "INFO: vport $vport_name $param is OK."
}

check_phy_port()
{
    type=$1
    param=$2
    br=$3
    mtu=$4
    expect_type_ports=`cat $LIVECLOUD_CONF_DIR/nspbr_config.conf |
            grep -Eo "$param eth[0-9]+(,eth[0-9]+)*" | grep -Eo "eth[0-9]+" | sort`
    num=`echo $expect_type_ports | wc -w`
    if [[ $num -lt 1 || $num -gt 2 ]]; then
        echo "ERROR: server ${type}-plane phy ports ($expect_type_ports)" \
                "in nspbr_config.conf are not legal".
        return 1
    fi
    server_type_port=`$OVS_VSCTL_BARE list-ports $br | grep -E "eth[0-9]+"`
    num=`echo $server_type_port | wc -w`
    if [[ $num -ne 1 ]]; then
        echo "ERROR: server ${type}-plane phy port ($server_type_port)" \
                "in $br is not unique".
        return 1
    fi
    server_type_ports=`echo $server_type_port | grep -Eo "eth[0-9]+" | sort`
    if [[ "$server_type_ports" != "$expect_type_ports" ]]; then
        echo "ERROR: server ${type}-plane phy ports ($server_type_ports)" \
                "in $br does not match expected ($expect_type_ports)" \
                "in nspbr_config.conf".
        return 1
    fi
    if [[ `echo $server_type_ports | wc -w` -eq 2 ]]; then
        type_bond_mode=`$OVS_VSCTL_BARE get port $server_type_port bond_mode`
        if [[ -z "$bond_mode" ]]; then
            echo "ERROR: server does not set bond_mode ($expect_bond_mode)" \
                    "in nspbr_config.conf".
            return 1
        fi
        if [[ "$type_bond_mode" != "$expect_bond_mode" ]]; then
            echo "ERROR: server ${type}-plane bond port ($server_type_port)" \
                    "in $br bond_mode ($type_bond_mode)" \
                    "is not expected ($expect_bond_mode)".
            return 1
        fi
    fi
    for port in $server_type_ports; do
        output=`ip link show dev $port | grep "state UP"`
        if [[ -z "$output" ]]; then
            echo "ERROR: server ${type}-plane phy port $port is not UP".
            return 1
        fi
        output=`ip addr show dev $port | grep " inet "`
        if [[ -n "$output" ]]; then
            echo "ERROR: server ${type}-plane phy port $port cannot set IP" \
                    "($output)".
            return 1
        fi
    done
    output=`echo "$server_type_ports" | xargs -I {} ethtool {} |
            grep Speed | awk '{print $2}' | uniq | wc -l`
    if [[ $output -ne 1 ]]; then
        echo "ERROR: server ${type}-plane phy ports have different speed".
        return 1
    fi
    output=`echo "$server_type_ports" | xargs -I {} ip link show dev {} |
            grep -Eo "mtu [0-9]+" | uniq`
    if [[ `echo "$output" | wc -l` -ne 1 ]]; then
        echo "ERROR: server ${type}-plane phy ports have different MTU".
        return 1
    fi
    if [[ "`echo "$output" | grep -Eo "[0-9]+"`" != "$mtu" ]]; then
        echo "ERROR: server ${type}-plane phy ports MTU is not $mtu".
        return 1
    fi
    # check GRO/LRO/GSO/TSO/UFO for ctrl port: used to avoid kernel skb_warn_bad_offload error
    funcs=("generic-receive-offload" "large-receive-offload"
           "generic-segmentation-offload"
           "tcp-segmentation-offload" "udp-fragmentation-offload")
    if [[ "$type" == "ctrl" ]]; then
        for port in $CTRL_BR; do
            for func in ${funcs[@]}; do
                status=`ethtool -k $port | grep "$func" | awk '{print $2}'`
                if [[ "$status" == "on" ]]; then
                    echo "ERROR: server ${type}-plane port $port cannot close $func".
                    return 1
                fi
            done
        done
    fi
    # check GRO/LRO only for NSP data port: used for VxLAN
    funcs=("generic-receive-offload" "large-receive-offload")
    if [[ "$type" == "data" ]]; then
        for port in $server_type_ports; do
            for func in ${funcs[@]}; do
                status=`ethtool -k $port | grep "$func" | awk '{print $2}'`
                if [[ "$status" == "on" ]]; then
                    echo "ERROR: server ${type}-plane port $port cannot close $func".
                    return 1
                fi
            done
        done
    fi
    :
}

check_server()
{
    tunl_proto=`echo $1 | tr '[A-Z]' '[a-z]' | grep -Eo "^[a-z]{3}"`
    shift 1
    peer_servers=$@
    # kernel
    if [[ -z "`grep "$KERN_INFO" $KERN_DMESG`" ]]; then
        echo "ERROR: server kernel is not $KERN_INFO."
        return 1
    fi
    if [[ `rpm -qa | grep "kernel-debuginfo" | wc -l` -lt 2 ]]; then
        echo "ERROR: server does not have kernel-debuginfo packages."
        return 1
    fi
    # service
    if [[ "`systemctl is-enabled openvswitch 2>$-`" != "enabled" ]]; then
        echo "ERROR: server service openvswitch is not enabled."
        return 1
    fi
    if [[ "`systemctl is-enabled NetworkManager 2>$-`" != "disabled" ]]; then
        echo "ERROR: server service NetworkManager is not disabled."
        return 1
    fi
    if [[ "`systemctl is-enabled firewalld 2>$-`" != "disabled" ]]; then
        echo "ERROR: server service firewalld is not disabled."
        return 1
    fi
    # bridge
    expect_brs="`echo $NSPBR_LIST | sed "s/ /\n/g" | sort | uniq`"
    server_brs="`$OVS_VSCTL_BARE list-br | sort`"
    if [[ "$server_brs" != "$expect_brs" ]]; then
        server_brs=($server_brs)
        expect_brs=($expect_brs)
        echo "ERROR: server bridges (${server_brs[@]}) does not match" \
                "expected (${expect_brs[@]})."
        return 1
    fi
    # nspbr_config.conf
    if [[ ! -e $LIVECLOUD_CONF_DIR/nspbr_config.conf ]]; then
        echo "ERROR: server nspbr_config.conf cannot be found."
        return 1
    fi
    expect_bond_mode=balance-slb
    bond_mode=`cat $LIVECLOUD_CONF_DIR/nspbr_config.conf |
            grep -Eo "\\-m $expect_bond_mode"`
    # ctrl port
    check_phy_port ctrl \\-c $CTRL_BR $LC_CTRL_BR_MTU
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    # data port
    check_phy_port data \\-d $DATA_BR $LC_DATA_BR_MTU
    if [[ $? -ne 0 ]]; then
        return 1
    fi
    # tunl port
    expect_tunl=`cat $LIVECLOUD_CONF_DIR/nspbr_config.conf |
            grep -Eo "\\-u DATA"`
    if [[ -z "$expect_tunl" ]]; then
        echo "ERROR: server tunl-plane bridge is not set in nspbr_config.conf".
        return 1
    fi
    tunltag=`$OVS_VSCTL_BARE get port $LC_TUNL_PORT tag 2>$-`
    if [[ -n "$tunltag" ]]; then
        expect_tunltag=`cat $LIVECLOUD_CONF_DIR/nspbr_config.conf |
                grep -Eo "\\-t [0-9]+" | awk '{print $2}'`
        : ${expect_tunltag:="[]"}
        if [[ "$tunltag" != "$expect_tunltag" && "$tunltag" != "0" ]]; then
            echo "ERROR: server tunnel port $LC_TUNL_PORT vlantag $tunltag" \
                    "does not match expected $expect_tunltag".
            return 1
        fi
    fi
    patch_port=`$OVS_VSCTL_BARE list-ports $DATA_BR | grep $LC_DATA_TUNL_PATCH_PORT`
    if [[ -z "$patch_port" ]]; then
        echo "ERROR: server patch port $LC_DATA_TUNL_PATCH_PORT" \
                "cannot be found in $DATA_BR".
        return 1
    fi
    patch_port=`$OVS_VSCTL_BARE list-ports $TUNL_BR | grep $LC_TUNL_DATA_PATCH_PORT`
    if [[ -z "$patch_port" ]]; then
        echo "ERROR: server patch port $LC_TUNL_DATA_PATCH_PORT" \
                "cannot be found in $TUNL_BR".
        return 1
    fi
    patch_port=`$OVS_VSCTL_BARE get interface $LC_DATA_TUNL_PATCH_PORT ofport`
    # flow
    if [[ ! "`ovs-ofctl dump-flows $DATA_BR \
            cookie=$MAC_FLOOD_COOKIE/-1,table=1 |
            grep -E "priority=18000.*NORMAL"`" ]];
        then
        echo "ERROR: server bridge $DATA_BR does not have default NORMAL" \
                "flow entry (cookie=$MAC_FLOOD_COOKIE/-1,table=1)".
        return 1
    fi
    if [[ ! "`ovs-ofctl dump-flows $TUNL_BR \
            cookie=$DEF_DROP_COOKIE/-1,table=0 |
            grep -E "priority=1.*drop"`" ]];
        then
        echo "ERROR: server bridge $TUNL_BR does not have default DROP" \
                "flow entry (cookie=$DEF_DROP_COOKIE/-1,table=0)".
        return 1
    fi
    # policy
    if [[ -n "`ip route show table local | grep -Ev \
            "$CTRL_BR|$DATA_BR|$ULNK_BR|$TUNL_BR|$LC_TUNL_PORT|lo"`" ]]; then
        echo "ERROR: server local route table should not have excessive entries."
        return 1
    fi
    # sysctl
    if [[ ! "`sysctl -A | grep 'net.ipv4.ip_forward = 1'`" ]];
        then
        echo "ERROR: server ip_forward is not configured as 1."
        return 1
    fi
    if [[ ! "`sysctl -A | grep 'net.ipv4.conf.all.rp_filter = 0'`" \
       || ! "`sysctl -A | grep 'net.ipv4.conf.default.rp_filter = 0'`" ]];
        then
        echo "ERROR: server rp_filter is not configured as 0."
        return 1
    fi
    if [[ ! "`sysctl -A | grep 'net.ipv4.conf.all.src_valid_mark = 1'`" \
       || ! "`sysctl -A | grep 'net.ipv4.conf.default.src_valid_mark = 1'`" ]];
        then
        echo "ERROR: server src_valid_mark is not configured as 1."
        return 1
    fi
    if [[ ! "`sysctl -A | grep 'net.ipv4.conf.all.arp_ignore = 1'`" \
       || ! "`sysctl -A | grep 'net.ipv4.conf.default.arp_ignore = 1'`" ]];
        then
        echo "ERROR: server arp_ignore is not configured as 1."
        return 1
    fi
    if [[ ! "`sysctl -A | grep 'net.ipv4.conf.all.arp_filter = 0'`" \
       || ! "`sysctl -A | grep 'net.ipv4.conf.default.arp_filter = 0'`" ]];
        then
        echo "ERROR: server arp_filter is not configured as 0."
        return 1
    fi
    if [[ ! "`sysctl -A | grep 'net.ipv4.conf.all.arp_announce = 2'`" \
       || ! "`sysctl -A | grep 'net.ipv4.conf.default.arp_announce = 2'`" ]];
        then
        echo "ERROR: server arp_announce is not configured as 2."
        return 1
    fi
    # tunnel
    for peer_server in $peer_servers; do
        tunnel_port=$tunl_proto`echo $peer_server | awk '{split($0, dec, "."); \
                printf "%03d%03d%03d%03d\n", dec[1], dec[2], dec[3], dec[4]}'`
        if [[ ! "`$OVS_VSCTL_BARE list-ports $TUNL_BR | grep $tunnel_port`" ]]; then
            echo "ERROR: server tunnel port $tunnel_port cannot be found" \
                    "in bridge $TUNL_BR."
            return 1
        fi
        if [[ ! "`$OVS_VSCTL_BARE get interface $tunnel_port options |
                grep -E "in_key=flow, out_key=flow, remote_ip=.$peer_server."`" ]]; then
            echo "ERROR: server tunnel port $tunnel_port options are not correct."
            return 1
        fi
        if [[ ! "`$OVS_VSCTL_BARE get interface $tunnel_port status |
                grep -E "tunnel_egress_iface=[^,]+, tunnel_egress_iface_carrier=up"`" ]]; then
            echo "ERROR: server tunnel port $tunnel_port status are not correct."
            return 1
        fi
    done
    # dfi
    DFI_VER="4.1"
    if [[ `lsmod | grep -w ^dfi | grep -v grep | wc -l` -ne 1 \
       || "`modinfo dfi | grep -w version | awk '{print $2}'`" != "$DFI_VER" ]]; then
        echo "ERROR: DFI kernel is not running or version is not correct."
        return 1
    fi
    if [[ `ps aux | grep -w ovs-dfi-agent | grep -v grep | wc -l` -ne 1 \
       || "`ovs-aclctl -v 2>&1 | grep -Eo 'v[0-9]+\.[0-9]+(\.\w+)*'`" != "v$DFI_VER" ]]; then
        echo "ERROR: DFI agent is not running or version is not correct."
        return 1
    fi
    echo "INFO: server is OK."
}

get_param()
{
    param=`echo $params | awk '{print $1}' | grep -Ew "[0-9]+"`
    if [[ -n "$param" ]]; then
        params=${params:${#param}}
        return 0
    fi
    print_usage
    exit 1
}

get_param_opt()
{
    param=`echo $params | grep -Eo "\--(.?[^-])+" | head -n 1`
    if [[ -n "$param" ]]; then
        params=${params:${#param}}
        return 0
    fi
    return 1
}

__check_param_num()
{
    param=$1
    num=$2

    case $param in
        state | mtu | policy)
            [[ $num -eq 0 ]]
            ;;
        mac | gw | isp | vlan | tunnel)
            [[ $num -eq 1 ]]
            ;;
        ip | server)
            [[ $num -ge 1 ]]
            ;;
        qos | snat)
            [[ $num -eq 6 ]]
            ;;
        dnat)
            [[ $num -eq 10 ]]
            ;;
        acl)
            [[ $num -eq 14 ]]
            ;;
        vpn)
            [[ $num -eq 9 ]]
            ;;
        route)
            [[ $num -eq 4 ]]
            ;;
    esac
}

check_router_wan_vport_full()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    param=${param##--}
    case $param in
        state | mac | mtu | ip | gateway | isp | vlan | qos | policy)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_router_wan_vport $router_id $if_index $param $@
            ;;
        snat | dnat | vpn | route)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_router_wan_vport_advanced $router_id $if_index $param $@
            ;;
        *)
            echo "ERROR: unsupported OPTION --$param for router-wan-vport."
            return 1
            ;;
    esac
}

check_router_lan_vport_full()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    param=${param##--}
    case $param in
        state | mac | mtu | ip | vlan | qos | policy | conn_limit)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_router_lan_vport $router_id $if_index $param $@
            ;;
        acl | route | tunnel)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_router_lan_vport_advanced $router_id $if_index $param $@
            ;;
        *)
            echo "ERROR: unsupported OPTION --$param for router-lan-vport."
            return 1
            ;;
    esac
}

check_valve_wan_vport_full()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    param=${param##--}
    case $param in
        state | mtu | ip | gateway | isp | vlan | qos | policy)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_valve_wan_vport $router_id $if_index $param $@
            ;;
        *)
            echo "ERROR: unsupported OPTION --$param for valve-wan-vport."
            return 1
            ;;
    esac
}

check_valve_lan_vport_full()
{
    router_id=$1
    if_index=$2
    param=$3

    shift 3
    param=${param##--}
    case $param in
        state | mtu | vlan | qos | policy)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_valve_lan_vport $router_id $if_index $param $@
            ;;
        tunnel)
            if ! __check_param_num $param $#; then
                echo "ERROR: incorrect parameter number for OPTION --$param."
                return 1
            fi
            check_valve_lan_vport_advanced $router_id $if_index $param $@
            ;;
        *)
            echo "ERROR: unsupported OPTION --$param for valve-lan-vport."
            return 1
            ;;
    esac
}

check_server_full()
{
    if ! __check_param_num server $#; then
        echo "ERROR: incorrect parameter number for server."
        return 1
    fi
    check_server $@
}

cmd=$1
shift 1
params=$@

ret=0
case $cmd in
    router-wan-vport | router-lan-vport | valve-wan-vport | valve-lan-vport)
        get_param; router_id=$param
        get_param; if_index=$param
        if [[ $router_id -lt $ROUTER_ID_FLOOR ]]; then
            echo "WARNING: vgateway/valve ID should not be smaller than $ROUTER_ID_FLOOR."
        fi
        while get_param_opt; do
            eval check_`echo $cmd | sed "s/-/_/g"`_full $router_id $if_index $param
            (( ret += $? ))
        done
        ;;
    server)
        check_server_full $params
        (( ret += $? ))
        ;;
    *)
        print_usage
        ;;
esac
exit $ret

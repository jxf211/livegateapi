#!/bin/bash

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh

print_usage()
{
    echo "$0 Usage:"
    echo "    $0 UPLINK <ip> <netmask> <gateway>"
    echo "    $0 CHECK_SYSTEM_BOOTUP"
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

br_of_uplink()
{
    uplink_br=`get_br_name_from_id $LC_ULNK_BR_ID`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    echo $uplink_br
    return 0
}

br_of_ctrl()
{
    ctrl_br=`get_br_name_from_id $LC_CTRL_BR_ID`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    echo $ctrl_br
    return 0
}

config_uplink()
{
    ip=$1
    mask=$2
    gateway=$3

    uplink_br=`br_of_uplink`
    if [[ "$uplink_br" = "" ]]; then
        return 1
    else
        ctrl_br=`br_of_ctrl`
        if [[ "$uplink_br" = "$ctrl_br" ]]; then
            uplink_br="nspbr1"
            ovs-vsctl --timeout=10 -- --may-exist add-port \
                $ctrl_br $uplink_br -- set interface $uplink_br type=internal \
            2> /dev/null
            vlantag=`cat /usr/local/livecloud/conf/nspbr_config.conf \
                2> /dev/null | grep -Eo "\\-t [0-9]+" | awk '{print $2}'`
            if [[ -z "$vlantag" ]]; then
                ovs-vsctl --timeout=10 -- set port $uplink_br tag=[]
            else
                ovs-vsctl --timeout=10 -- set port $uplink_br tag=$vlantag
            fi
        fi
        if [[ "$ip" = "0.0.0.0" ]]; then
            ip link set dev $uplink_br down 2> /dev/null
            ip addr flush dev $uplink_br 2> /dev/null
            ip route del 0/0 2> /dev/null
            return 0
        else
            ip route del 0/0 2> /dev/null
            ip link set dev $uplink_br up && \
            ip addr flush dev $uplink_br && \
            ip addr add $ip/$mask brd + dev $uplink_br
            if [[ $? -ne 0 ]]; then
                return 1
            fi

            # refresh default gateway
            ip route add 0/0 via $gateway dev $uplink_br
            if [[ $? -ne 0 ]]; then
                return 1
            fi

            # make sure link-local route in uplink-br has the highest priority
            ip route change `ip_mask_to_prefix $ip $mask` dev $uplink_br scope link src $ip
            if [[ $? -ne 0 ]]; then
                return 1
            fi

            return 0
        fi
    fi
}

check_system_bootup()
{
    uptime=`cat /tmp/uptime 2> /dev/null | awk -F"[. ]" '{print $1}'`
    echo "$uptime"
}

action=$1

if [[ "$1" = "UPLINK" && $# -eq 4 ]]; then
    ip=$2
    mask=$3
    gateway=$4

    config_uplink $ip $mask $gateway
    exit $?

elif [[ "$1" = "CHECK_SYSTEM_BOOTUP" && $# -eq 1 ]]; then
    check_system_bootup
    exit $?

fi

print_usage
exit 1

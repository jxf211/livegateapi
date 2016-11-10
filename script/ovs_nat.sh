#!/bin/sh

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh

usage()
{
    echo "usage: $0 add-nat <bridge> <ip> <port> <mac> <targetip> <targetport> <targetmac>"
    echo "       $0 del-nat <bridge> <targetip> <targetport>"
    echo "bridge: CTRL | DATA | UPLINK | TUNNEL"
    return 0
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

add_nat(){
    bridge=$1
    port=$2
    ip=$3
    mac=$4
    targetport=$5
    targetip=$6
    targetmac=$7

    if [[ "$bridge" = "CTRL" ]]; then
        br=`get_br_name_from_id $LC_CTRL_BR_ID`
    elif [[ "$bridge" = "DATA" ]]; then
        br=`get_br_name_from_id $LC_DATA_BR_ID`
    elif [[ "$bridge" = "UPLINK" ]]; then
        br=`get_br_name_from_id $LC_ULNK_BR_ID`
    elif [[ "$bridge" = "TUNNEL" ]]; then
        br=`get_br_name_from_id $LC_TUNL_BR_ID`
    else
        exit 1
    fi

    # TODO 2.4->3.0 ISSU delete flows with cookie=0xFFFFEFFFF1$port/-1
    ip_num=`IP2NUM $targetip`
    cookie_a=`echo $ip_num $targetport | awk -v fmt=$OVSNAT_FLOW_COOKIE_FORMAT_1 '{printf fmt, $1, $2}'`
    cookie_b=`echo $ip_num $targetport | awk -v fmt=$OVSNAT_FLOW_COOKIE_FORMAT_2 '{printf fmt, $1, $2}'`

    ovs-ofctl add-flow $br "cookie=$cookie_a,table=0,ip,tcp,priority=61000,nw_dst=$ip,tp_dst=$port,actions=mod_nw_dst:$targetip,mod_tp_dst:$targetport,mod_dl_dst:$targetmac,NORMAL"
    ovs-ofctl add-flow $br "cookie=$cookie_b,table=0,ip,tcp,priority=61001,nw_src=$targetip,tp_src=$targetport,actions=mod_nw_src:$ip,mod_tp_src:$port,mod_dl_src:$mac,NORMAL"
}

del_nat(){
    bridge=$1
    targetport=$2
    targetip=$3

    if [[ "$bridge" = "CTRL" ]]; then
        br=`get_br_name_from_id $LC_CTRL_BR_ID`
    elif [[ "$bridge" = "DATA" ]]; then
        br=`get_br_name_from_id $LC_DATA_BR_ID`
    elif [[ "$bridge" = "UPLINK" ]]; then
        br=`get_br_name_from_id $LC_ULNK_BR_ID`
    elif [[ "$bridge" = "TUNNEL" ]]; then
        br=`get_br_name_from_id $LC_TUNL_BR_ID`
    else
        exit 1
    fi

    # TODO 2.4->3.0 ISSU delete flows with cookie=0xFFFFEFFFF1$port/-1
    ip_num=`IP2NUM $targetip`
    cookie_a=`echo $ip_num $targetport | awk -v fmt=$OVSNAT_FLOW_COOKIE_FORMAT_1 '{printf fmt, $1, $2}'`
    cookie_b=`echo $ip_num $targetport | awk -v fmt=$OVSNAT_FLOW_COOKIE_FORMAT_2 '{printf fmt, $1, $2}'`
    ovs-ofctl del-flows $br cookie=$cookie_a/-1
    ovs-ofctl del-flows $br cookie=$cookie_b/-1
}

if [ "$1" = "add-nat" ]; then
    if [ $# -ge 8 ]; then
        shift
        add_nat $*
    else
        usage
        exit 1
    fi
elif [ "$1" = "del-nat" ]; then
    if [ $# -ge 4 ]; then
        shift
        del_nat $*
    else
        usage
        exit 1
    fi
else
    usage
    exit 1
fi

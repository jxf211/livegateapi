#!/bin/bash

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh

print_usage()
{
    echo "$0 Usage:"
    echo "    $0 set-qos <min-rate (bps)> <max-rate (bps)>"
    echo "    $0 clear-qos"
    echo "    $0 add-tunnel <tunnel-protocol> <peer-ip> <ovs-key>"
    echo "    $0 del-tunnel <peer-ip>"
    echo "    $0 set-vif-policy <cookie> <tun-id> <vlantag> <vif-mac>"
    echo "    $0 set-vl2-policy <cookie> <tun-id> <vlantag>"
    echo "    $0 set-isp-ingress <cookie> <isp-cookie> <tun-id> <ip>"
    echo "    $0 set-isp-egress <cookie> <isp-cookie> <tun-id> <ip>"
    echo "    $0 clear-policy [ DATA | UPLINK | TUNNEL ] <cookie> <cookie-mask>"
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
        echo "nspbr0"
        return 1
    fi

    echo $uplink_br
    return 0
}

br_of_data()
{
    data_br=`get_br_name_from_id $LC_DATA_BR_ID`
    if [[ $? -ne 0 ]]; then
        echo "nspbr0"
        return 1
    fi

    echo $data_br
    return 0
}

pif_of_uplink()
{
    uplink_br=$1

    # get PIF name (i.e., ethX, bondX, ...) of uplink bridge
    pif=`ovs-vsctl list-ports $uplink_br | grep -E "$BOND_NAME_PFX-$PIF_NAME_PFX[0-9]+-$PIF_NAME_PFX[0-9]+|$PIF_NAME_PFX[0-9]+"`
    echo $pif

    if [[ -z "$pif" ]]; then
        return 1
    else
        return 0
    fi
}

delete_gre_qos_and_queue()
{
    pif=$1

    ovs-vsctl clear port $pif qos

    qosuuid=`ovs-vsctl --bare -- --columns=_uuid find qos external_ids:name=tunnel`
    if [[ $? -eq 0 ]]; then
        for qu in $qosuuid; do
            ovs-vsctl --bare -- --columns=name find port qos=$qu | xargs -I {} ovs-vsctl clear port {} qos
            ovs-vsctl destroy qos $qu
        done
    fi

    queueuuid=`ovs-vsctl --bare -- --columns=_uuid find queue external_ids:name=tunnel`
    if [[ $? -eq 0 ]]; then
        for qu in $queueuuid; do
            ovs-vsctl destroy queue $qu
        done
    fi

    return 0
}

set_qos()
{
    min_rate=$1
    max_rate=$2

: <<'COMMENT'
    uplink_br=`br_of_uplink`
    pif=`pif_of_uplink $uplink_br`
    if [[ "$pif" = "" || "$pif" = '""' ]]; then
        return 1
    fi

    # add qos and queue for PIF port

    ovs-vsctl set port $pif qos=@pif-qos \
        -- --id=@pif-qos create qos external_ids:name="tunnel" \
           type=linux-htb queues=$GRE_QUEUE_ID=@q1 \
        -- --id=@q1 create queue external_ids:name="tunnel" \
           other_config:min-rate=$min_rate other_config:max-rate=$max_rate
    if [[ $? -ne 0 ]]; then
        delete_gre_qos_and_queue $pif
        return 1
    fi

    # add policy for GRE traffic

    ovs-ofctl del-flows $uplink_br cookie=$GRE_POLICY_COOKIE/-1
    ovs-ofctl add-flow $uplink_br \
      "cookie=$GRE_POLICY_COOKIE,table=0,priority=$GRE_POLICY_PRIORITY,
      ip,in_port=local,nw_proto=$GRE_PROTO_ID,actions=set_queue:$GRE_QUEUE_ID,NORMAL"
    pif_ofport=`ovs-vsctl --bare -- --columns=ofport list interface $pif`
COMMENT

    ((burst=max_rate/10))
    ovs-vsctl set interface patch-data-tunl ingress_policing_rate=$max_rate
    ovs-vsctl set interface patch-data-tunl ingress_policing_burst=$burst
    ovs-vsctl set interface patch-tunl-data ingress_policing_rate=$max_rate
    ovs-vsctl set interface patch-tunl-data ingress_policing_burst=$burst

    return 0
}

clear_qos()
{
    uplink_br=`br_of_uplink`
    pif=`pif_of_uplink $uplink_br`
    if [[ "$pif" = "" || "$pif" = '""' ]]; then
        return 1
    fi

: <<'COMMENT'
    delete_gre_qos_and_queue $pif
    ovs-ofctl del-flows $uplink_br cookie=$GRE_POLICY_COOKIE/-1
COMMENT

    ovs-vsctl set interface patch-data-tunl ingress_policing_rate=0
    ovs-vsctl set interface patch-data-tunl ingress_policing_burst=0
    ovs-vsctl set interface patch-tunl-data ingress_policing_rate=0
    ovs-vsctl set interface patch-tunl-data ingress_policing_burst=0

    return 0
}

add_tunnel()
{
    tun_proto=$1
    peer=$2
    key=$3

    port_name=`echo $peer | awk '{split($0, dec, "."); printf "%03d%03d%03d%03d\n", dec[1], dec[2], dec[3], dec[4]}'`
    if [[ "$tun_proto" = "GRE" ]]; then
        ovs-vsctl -- --if-exists del-port $LC_TUNL_BR_NAME "vxl$port_name"
        ovs-vsctl -- --may-exist add-port $LC_TUNL_BR_NAME "gre$port_name" \
            -- set interface "gre$port_name" type=gre options:remote_ip="$peer" \
            options:in_key="$key" options:out_key="$key"
    elif [[ "$tun_proto" = "VXLAN" ]]; then
        ovs-vsctl -- --if-exists del-port $LC_TUNL_BR_NAME "gre$port_name"
        ovs-vsctl -- --may-exist add-port $LC_TUNL_BR_NAME "vxl$port_name" \
            -- set interface "vxl$port_name" type=vxlan options:remote_ip="$peer" \
            options:in_key="$key" options:out_key="$key"
    else
        return 1
    fi
    return $?
}

del_tunnel()
{
    peer=$1

    port_name=`echo $peer | awk '{split($0, dec, "."); printf "%03d%03d%03d%03d\n", dec[1], dec[2], dec[3], dec[4]}'`
    ovs-ofctl del-flows tunbr cookie=$MAC_ENTRY_COOKIE/-1,table=1
    ovs-vsctl -- --if-exists del-port $LC_TUNL_BR_NAME "gre$port_name"
    ovs-vsctl -- --if-exists del-port $LC_TUNL_BR_NAME "vxl$port_name"
    return $?
}

be_valve_vif()
{
    vifmac=$1
    vifname=`ovs-vsctl --bare -- --columns=name find interface \
        mac_in_use=\"$vifmac\"`
    viftype=`ovs-vsctl --bare get interface $vifname \
        external_ids:lc-router-type 2> /dev/null | grep -Eo '[0-9]+'`
    [[ -n "$vifname" && "$viftype" == "$ROUTER_TYPE_VALVE" ]]
}

set_vif_policy()
{
    cookie=$1
    tunid=$2
    vlantag=$3
    vifmac=$4

    patch_ofport=`ovs-vsctl get interface $LC_TUNL_DATA_PATCH_PORT ofport`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1

    # table 1: mac learning table
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50004,tun_id=$tunid,
      dl_dst=$vifmac,actions=learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=50004,
            idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$patch_ofport,
            NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
      mod_vlan_vid:$vlantag,output:$patch_ofport" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50003,in_port=$patch_ofport,dl_vlan=$vlantag,
      dl_src=$vifmac,actions=strip_vlan,set_tunnel:$tunid,resubmit(,1)" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50002,
      tun_id=$tunid,dl_src=$vifmac,actions=drop" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$MAC_FLOOD_COOKIE,table=1,priority=50000,in_port=$patch_ofport,
      actions=NORMAL"
    if [[ $? -ne 0 ]]; then
        ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1
        return 1
    fi

    if be_valve_vif $vifmac; then
      ovs-ofctl add-flow $LC_TUNL_BR_NAME \
        "cookie=$cookie,table=0,priority=50004,tun_id=$tunid,
        actions=learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=50004,
              idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$patch_ofport,
              NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
        mod_vlan_vid:$vlantag,output:$patch_ofport" && \
      ovs-ofctl add-flow $LC_TUNL_BR_NAME \
        "cookie=$cookie,table=0,priority=50003,in_port=$patch_ofport,dl_vlan=$vlantag,
        actions=strip_vlan,set_tunnel:$tunid,resubmit(,1)"
      if [[ $? -ne 0 ]]; then
          ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1
          return 1
      fi
    fi

    return 0
}

set_vl2_policy()
{
    cookie=$1
    tunid=$2
    vlantag=$3

    patch_ofport=`ovs-vsctl get interface $LC_TUNL_DATA_PATCH_PORT ofport`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1

    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50001,tun_id=$tunid,
      dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,
      actions=learn(cookie=$MAC_ENTRY_COOKIE,table=1,priority=50004,
            idle_timeout=$MAC_ENTRY_DEFAULT_IDLE_TIME,in_port=$patch_ofport,
            NXM_OF_ETH_DST[]=NXM_OF_ETH_SRC[],output:NXM_OF_IN_PORT[]),
      mod_vlan_vid:$vlantag,output:$patch_ofport"
    if [[ $? -ne 0 ]]; then
        ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1
        return 1
    fi
    return 0
}

set_isp_ingress()
{
    cookie=$1
    ispcookie=$2
    ingress_tunnel_id=$3
    egress_tunnel_id=$4
    ip=$5

    uplink_br=`br_of_uplink` && \
    data_br=`br_of_data` && \
    tunl_ulnk_ofport=`ovs-vsctl get interface $LC_TUNL_ULNK_PATCH_PORT ofport` && \
    data_tunl_ofport=`ovs-vsctl get interface $LC_DATA_TUNL_PATCH_PORT ofport`

    if [[ $? -ne 0 ]]; then
        return 1
    fi

    ovs-ofctl del-flows $uplink_br cookie=$cookie/-1
    ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1
    ovs-ofctl del-flows $data_br cookie=$cookie/-1

    # guard
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50100,in_port=$data_tunl_ofport,arp,nw_src=$ip,
      actions=drop" && \
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50101,in_port=$data_tunl_ofport,ip,nw_src=$ip,
      actions=drop"
    if [[ $? -ne 0 ]]; then
        return 2
    fi

    # out (ip -> isp) & in (isp -> ip) packets
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50100,in_port=$tunl_ulnk_ofport,arp,nw_src=$ip,
      actions=set_tunnel:$ingress_tunnel_id,NORMAL" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50101,in_port=$tunl_ulnk_ofport,ip,nw_src=$ip,
      actions=set_tunnel:$ingress_tunnel_id,NORMAL" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50102,tun_id=$egress_tunnel_id,arp,nw_dst=$ip,
      actions=output:$tunl_ulnk_ofport" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50103,tun_id=$egress_tunnel_id,ip,nw_dst=$ip,
      actions=output:$tunl_ulnk_ofport"
    if [[ $? -ne 0 ]]; then
        return 3
    fi

    return 0
}

set_isp_egress()
{
    cookie=$1
    ispcookie=$2
    ingress_tunnel_id=$3
    egress_tunnel_id=$4
    ip=$5

    uplink_br=`br_of_uplink` && \
    data_br=`br_of_data` && \
    tunl_ulnk_ofport=`ovs-vsctl get interface $LC_TUNL_ULNK_PATCH_PORT ofport` && \
    data_tunl_ofport=`ovs-vsctl get interface $LC_DATA_TUNL_PATCH_PORT ofport`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    ovs-ofctl del-flows $uplink_br cookie=$cookie/-1
    ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1
    ovs-ofctl del-flows $data_br cookie=$cookie/-1

    # guard
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50100,in_port=$data_tunl_ofport,arp,nw_dst=$ip,
      actions=drop" && \
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50101,in_port=$data_tunl_ofport,ip,nw_dst=$ip,
      actions=drop"
    if [[ $? -ne 0 ]]; then
        return 2
    fi

    # in (isp -> ip) & out (ip -> isp) packets
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50100,in_port=$tunl_ulnk_ofport,arp,nw_dst=$ip,
      actions=set_tunnel:$egress_tunnel_id,NORMAL" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50101,in_port=$tunl_ulnk_ofport,ip,nw_dst=$ip,
      actions=set_tunnel:$egress_tunnel_id,NORMAL" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50102,tun_id=$ingress_tunnel_id,arp,nw_src=$ip,
      actions=output:$tunl_ulnk_ofport" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50103,tun_id=$ingress_tunnel_id,ip,nw_src=$ip,
      actions=output:$tunl_ulnk_ofport"
    if [[ $? -ne 0 ]]; then
        return 3
    fi

    return 0
}

set_isp_relay()
{
    cookie=$1
    ispcookie=$2
    ingress_tunnel_id=$3
    egress_tunnel_id=$4
    ingress2_tunnel_id=$5
    egress2_tunnel_id=$6
    ip=$7

    uplink_br=`br_of_uplink` && \
    data_br=`br_of_data` && \
    tunl_ulnk_ofport=`ovs-vsctl get interface $LC_TUNL_ULNK_PATCH_PORT ofport` && \
    data_tunl_ofport=`ovs-vsctl get interface $LC_DATA_TUNL_PATCH_PORT ofport`
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    ovs-ofctl del-flows $uplink_br cookie=$cookie/-1
    ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/-1
    ovs-ofctl del-flows $data_br cookie=$cookie/-1

    # guard
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50100,in_port=$data_tunl_ofport,arp,nw_dst=$ip,
      actions=drop" && \
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50101,in_port=$data_tunl_ofport,ip,nw_dst=$ip,
      actions=drop" && \
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50100,in_port=$data_tunl_ofport,arp,nw_src=$ip,
      actions=drop" && \
    ovs-ofctl add-flow $data_br \
      "cookie=$cookie,table=0,priority=50101,in_port=$data_tunl_ofport,ip,nw_src=$ip,
      actions=drop"
    if [[ $? -ne 0 ]]; then
        return 2
    fi

    # in (isp -> ip) & out (ip -> isp) packets
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50102,tun_id=$egress2_tunnel_id,arp,nw_dst=$ip,
      actions=set_tunnel:$egress_tunnel_id,NORMAL" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50103,tun_id=$egress2_tunnel_id,ip,nw_dst=$ip,
      actions=set_tunnel:$egress_tunnel_id,NORMAL"
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50102,tun_id=$ingress_tunnel_id,arp,nw_src=$ip,
      actions=set_tunnel:$ingress2_tunnel_id,NORMAL" && \
    ovs-ofctl add-flow $LC_TUNL_BR_NAME \
      "cookie=$cookie,table=0,priority=50103,tun_id=$ingress_tunnel_id,ip,nw_src=$ip,
      actions=set_tunnel:$ingress2_tunnel_id,NORMAL"
    if [[ $? -ne 0 ]]; then
        return 3
    fi

    return 0
}

clear_policy()
{
    bridge=$1
    cookie=$2
    cookie_mask=$3

    if [[ "$bridge" = "DATA" ]]; then
        data_br=`br_of_data` && \
        ovs-ofctl del-flows $data_br cookie=$cookie/$cookie_mask
        return $?

    elif [[ "$bridge" = "UPLINK" ]]; then
        uplink_br=`br_of_uplink` && \
        ovs-ofctl del-flows $uplink_br cookie=$cookie/$cookie_mask
        return $?

    elif [[ "$bridge" = "TUNNEL" ]]; then
        ovs-ofctl del-flows $LC_TUNL_BR_NAME cookie=$cookie/$cookie_mask
        return $?

    else
        return 1

    fi
}

action=$1

if [[ "$1" = "set-qos" && $# -eq 3 ]]; then
    min_rate=$2
    max_rate=$3
    clear_qos
    set_qos $min_rate $max_rate
    exit $?

elif [[ "$1" = "clear-qos" && $# -eq 1 ]]; then
    clear_qos
    exit $?

elif [[ "$1" = "add-tunnel" && $# -eq 4 ]]; then
    tun_proto=$2
    peer=$3
    key=$4
    add_tunnel $tun_proto $peer $key
    exit $?

elif [[ "$1" = "del-tunnel" && $# -eq 2 ]]; then
    peer=$2
    del_tunnel $peer
    exit $?

elif [[ "$1" = "set-vif-policy" && $# -eq 5 ]]; then
    cookie=$2
    tunid=$3
    vlantag=$4
    vifmac=$5
    set_vif_policy $cookie $tunid $vlantag $vifmac
    exit $?

elif [[ "$1" = "set-vl2-policy" && $# -eq 4 ]]; then
    cookie=$2
    tunid=$3
    vlantag=$4
    set_vl2_policy $cookie $tunid $vlantag
    exit $?

elif [[ "$1" = "set-isp-ingress" && $# -eq 6 ]]; then
    cookie=$2
    ispcookie=$3
    ingress_tunnel_id=$4
    egress_tunnel_id=$5
    ip=$6
    set_isp_ingress $cookie $ispcookie $ingress_tunnel_id $egress_tunnel_id $ip
    exit $?

elif [[ "$1" = "set-isp-egress" && $# -eq 6 ]]; then
    cookie=$2
    ispcookie=$3
    ingress_tunnel_id=$4
    egress_tunnel_id=$5
    ip=$6
    set_isp_egress $cookie $ispcookie $ingress_tunnel_id $egress_tunnel_id $ip
    exit $?

elif [[ "$1" = "clear-policy" && $# -eq 4 ]]; then
    bridge=$2
    cookie=$3
    cookie_mask=$4
    clear_policy $bridge $cookie $cookie_mask
    exit $?

fi

print_usage
exit 1

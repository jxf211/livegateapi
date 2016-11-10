#!/bin/sh
# In KVM/XEN: /usr/local/livecloud/pyagexec/script/trace.sh
# In NSP:     /usr/local/livegate/script/trace.sh

if [[ $# -ne 1 ]]; then
    echo "Usage: `basename $0` <dst_mac>"
    echo "Output: VmName Bridge BridgeType InIF OutIFType(PHYSICAL|VIRTUAL) OutPort OutIF TxBps/ErrErr"
    echo "Example: vm-64-1-wangkai-5emahRbc08rzWadl nspbr1 DATA vnet31 PHYSICAL bond-eth25-eth27 eth25 0.0M/0"
    exit 1
fi

mac=$1
br_types=(CTRL DATA 2 TUNL STOR)
traffic_script="`dirname $0`/get_traffic_rate.sh"
port_names=`ovs-dpctl show`

# get iface from datapath flows

dp_ifaces=""
action_list=`ovs-dpctl dump-flows | grep -i "dst=$mac" | grep -Eo "(in_port\([0-9]+\))|(actions:.+)"`
action_list=${action_list//in_port(/in_port(0}
port_pair_list=`echo $action_list" " |
    grep -Eo "(,|actions:|in_port\()[0-9]+[, \)]" |
    grep -Eo "[0-9]+" |
    awk '{
        if (substr($1, 1, 1) == "0") in_po=substr($1, 2)
        else printf "%s-%s\n", in_po, $1
    }' | sort | uniq`

for pp in ${port_pair_list[@]}; do
    in_po=${pp%%-*}
    out_po=${pp##*-}
    in_iface=`echo "$port_names" | grep -Eow "port $in_po: .+" | awk '{print $3}'`
    out_iface=`echo "$port_names" | grep -Eow "port $out_po: .+" | awk '{print $3}'`

    if [[ "${out_iface:0:5}" = "nspbr" || "${out_iface:0:5}" = "xenbr" ]]; then
        iface_br=$out_iface
    else
        iface_br=`ovs-vsctl iface-to-br $out_iface`
    fi

    br_id=`ovs-vsctl br-get-external-id $iface_br lc-br-idx 2> /dev/null`
    if [[ -z "$br_id" ]]; then
        br_id=`ovs-vsctl br-get-external-id $iface_br lc-br-id 2> /dev/null`
    fi
    : ${br_id:="-1"}
    if [[ $br_id -ge 0 && $br_id -le ${#br_types[@]} ]]; then
        br_type=${br_types[br_id]}
    fi

    if [[ "${out_iface:0:3}" = "eth" ]]; then
        out_iface_uuid=`ovs-vsctl get interface $out_iface _uuid`
        out_port=`ovs-vsctl --bare -- --columns=name find port "interfaces{>=}$out_iface_uuid"`
        out_type='PHYSICAL'
        if [[ "${in_iface:0:4}" = "vnet" ]]; then
            dom_uuid=`ovs-vsctl get interface $in_iface external_ids:vm-id 2> /dev/null`
            dom_name=`virsh domname ${dom_uuid:1:36} 2> /dev/null | grep -Eo ".+"`
        fi
    else
        out_port=$out_iface
        out_type='VIRTUAL'
        if [[ "${out_iface:0:4}" = "vnet" ]]; then
            dom_uuid=`ovs-vsctl get interface $out_iface external_ids:vm-id 2> /dev/null`
            dom_name=`virsh domname ${dom_uuid:1:36} 2> /dev/null | grep -Eo ".+"`
        fi
    fi
    : ${dom_name:="?"}
    out_rate=`$traffic_script $out_iface 1 1 |
              tail -n 1 | awk '{printf "%.1lfM/%d", $7/1048576, $9+$10}'`
    echo "$dom_name" $iface_br $br_type $in_iface $out_type $out_port $out_iface $out_rate
    dp_ifaces="$dp_ifaces $out_iface"
done

# get iface from fdb

ovs_version=`ovs-vsctl --version | grep ovs-vsctl | awk '{print $NF}'`

ovs-vsctl list-br | while read br; do
    br_id=`ovs-vsctl br-get-external-id $br lc-br-idx 2> /dev/null`
    if [[ -z "$br_id" ]]; then
        br_id=`ovs-vsctl br-get-external-id $br lc-br-id 2> /dev/null`
    fi
    : ${br_id:="-1"}
    if [[ $br_id -ge 0 && $br_id -le ${#br_types[@]} ]]; then
        br_type=${br_types[br_id]}
    fi

    port_nos=(`ovs-appctl fdb/show $br | grep -i $mac | awk '{print $1}'`)
    for out_po in ${port_nos[@]}; do
        if [[ "$out_po" = "LOCAL" ]]; then
            out_po=65534
        fi
        if [[ "$ovs_version" = "1.11.0" ]]; then
            ifaces=(`echo "$port_names" | grep -Eow "port $out_po: .+" | awk '{print $3}'`)  # ovs 1.11
        else
            ifaces=(`ovs-vsctl --bare -- --columns=name find interface ofport=$out_po`)  # ovs 2.3
        fi
        for iface in ${ifaces[@]}; do
            if `echo $dp_ifaces | grep -qsw $iface`; then
                continue
            fi
            if [[ "${iface:0:5}" = "nspbr" || "${iface:0:5}" = "xenbr" ]]; then
                iface_br=$iface
            else
                iface_br=`ovs-vsctl iface-to-br $iface`
            fi
            if [[ "$iface_br" = "$br" ]]; then
                if [[ "${iface:0:3}" = "eth" ]]; then
                    iface_uuid=`ovs-vsctl get interface $iface _uuid`
                    port=`ovs-vsctl --bare -- --columns=name find port "interfaces{>=}$iface_uuid"`
                    type='PHYSICAL'
                else
                    port=$iface
                    type='VIRTUAL'
                    if [[ "${iface:0:4}" = "vnet" ]]; then
                        dom_uuid=`ovs-vsctl get interface $iface external_ids:vm-id 2> /dev/null`
                        dom_name=`virsh domname ${dom_uuid:1:36} 2> /dev/null | grep -Eo ".+"`
                    fi
                fi
                : ${dom_name:="?"}
                out_rate=`$traffic_script $iface 1 1 |
                          tail -n 1 | awk '{printf "%.1lfM/%d", $7/1048576, $9+$10}'`
                echo "$dom_name" $br $br_type "?" $type $port $iface $out_rate
            fi
        done
    done
done

#!/bin/sh

LIVEGATE="/usr/local/livegate"
source $LIVEGATE/script/const.sh

get_lc_br_traffic()
{
    ctrl_as_data_bridge=`ovs-vsctl --bare -- --columns=name \
        find bridge external_ids:lc-br-idx=$LC_DATA_BR_ID`
    if [[ -z "$ctrl_as_data_bridge" ]]; then
        for br in {0..1}; do
            ovs-vsctl --bare -- --columns=name find bridge external_ids:lc-br-id=$br |
                xargs -i ovs-vsctl list-ifaces {} | grep -Eo "eth[0-9]+" |
                xargs -i ovs-vsctl get interface {} \
                statistics:rx_bytes statistics:rx_packets \
                statistics:tx_bytes statistics:tx_packets 2> /dev/null |
                awk '{printf "%s ", $1; if (NR % 4 == 0) printf "\n";}' |
                awk -v brname=lc_br$br 'BEGIN {
                    sum_rxb = 0; sum_rxp = 0; sum_txb = 0; sum_txp = 0;
                } {
                    sum_rxb += $1
                    sum_rxp += $2
                    sum_txb += $3
                    sum_txp += $4
                } END {
                    printf "%s: %s %s 0 0 0 0 0 0 %s %s 0 0 0 0 0 0\n",
                        brname, sum_rxb, sum_rxp, sum_txb, sum_txp
                }'
        done

    else
        tmp=(`ovs-vsctl --bare -- --columns=name find bridge \
            external_ids:lc-br-id=$LC_CTRL_BR_ID |
            xargs -i ovs-vsctl get interface {} \
            statistics:rx_bytes statistics:rx_packets \
            statistics:tx_bytes statistics:tx_packets 2> /dev/null |
            awk '{printf "%s ", $1; if (NR % 4 == 0) printf "\n";}' |
            awk -v brname=$CTRL_IF_NICK_NAME 'BEGIN {
                sum_rxb = 0; sum_rxp = 0; sum_txb = 0; sum_txp = 0;
            } {
                sum_rxb += $1
                sum_rxp += $2
                sum_txb += $3
                sum_txp += $4
            } END {
                printf "%s: %s %s 0 0 0 0 0 0 %s %s 0 0 0 0 0 0\n",
                    brname, sum_rxb, sum_rxp, sum_txb, sum_txp
            }'`)
        echo "${tmp[@]}"

        ctrl_rxb=${tmp[2]}
        ctrl_rxp=${tmp[3]}
        ctrl_txb=${tmp[10]}
        ctrl_txp=${tmp[11]}

        ovs-vsctl --bare -- --columns=name find bridge \
            external_ids:lc-br-idx=$LC_DATA_BR_ID |
            xargs -i ovs-vsctl list-ifaces {} | grep -Eo "eth[0-9]+" |
            xargs -i ovs-vsctl get interface {} \
            statistics:rx_bytes statistics:rx_packets \
            statistics:tx_bytes statistics:tx_packets 2> /dev/null |
            awk '{printf "%s ", $1; if (NR % 4 == 0) printf "\n";}' |
            awk -v brname=$DATA_IF_NICK_NAME -v rxb=$ctrl_rxb \
                -v rxp=$ctrl_rxp -v txb=$ctrl_txb -v txp=$ctrl_txp 'BEGIN {
                sum_rxb = 0; sum_rxp = 0; sum_txb = 0; sum_txp = 0;
            } {
                sum_rxb += $1
                sum_rxp += $2
                sum_txb += $3
                sum_txp += $4
            } END {
                if (sum_rxb >= rxb) sum_rxb -= rxb
                if (sum_rxp >= rxp) sum_rxp -= rxp
                if (sum_txb >= txb) sum_txb -= txb
                if (sum_txp >= txp) sum_txp -= txp
                printf "%s: %s %s 0 0 0 0 0 0 %s %s 0 0 0 0 0 0\n",
                    brname, sum_rxb, sum_rxp, sum_txb, sum_txp
            }'

    fi

    ovs-vsctl get interface patch-data-tunl \
        statistics:rx_bytes statistics:rx_packets \
        statistics:tx_bytes statistics:tx_packets 2> /dev/null |
        awk '{printf "%s ", $1}' |
        awk '{
            printf "lc_br3: %s %s 0 0 0 0 0 0 %s %s 0 0 0 0 0 0\n",
                $1, $2, $3, $4
        }'
}

print_traffic_stat()
{
    prev=$1
    curr=$2
    interval=$3
    obj_type=$4

    cat $NET_STAT$prev $NET_STAT$curr | awk -v it=$interval -v ot=$obj_type '
    BEGIN { prev_router = 0; prev_if_type = ""; } {
        if (NF == 17 &&
               ((ot == "ROUTER" && match($1, "[0-9]+-[wl]-[0-9]+")) ||
                (ot == "HOST" && match($1, "lc_br[0-3]")))) {
            if (buf[$1] == 0) {
                buf[$1] = $2 " " $3 " " $10 " " $11
            } else {
                if (ot == "ROUTER") {
                    split($1, arr, "-")
                    if (arr[1] == prev_router) {
                        if (arr[2] != prev_if_type) {
                            printf "\n      ],\n      \"WANS\": [\n"
                            prev_if_type = arr[2]
                        } else {
                            printf ",\n"
                        }
                    } else {
                        if (prev_router == 0) {
                            printf "    {\n"
                        } else {
                            printf "\n      ]\n    }, {\n"
                        }
                        printf "      \"ROUTER_ID\":" arr[1] ",\n"
                        printf "      \"LANS\": [\n"
                        prev_router = arr[1]
                        prev_if_type = arr[2]
                    }
                    if_index = arr[3]
                    gsub(":", "", if_index)
                } else {
                    if_index = substr($1, 6, 1)
                    if (if_index != 0) {
                        printf ",\n"
                    }
                }

                split(buf[$1], stats, " ")
                printf "        {\n"
                printf "          \"IF_INDEX\":%d,\n", if_index
                printf "          \"RX_BYTES\":%d, \"RX_PACKETS\":%d,", $2, $3
                printf          " \"TX_BYTES\":%d, \"TX_PACKETS\":%d,\n", $10, $11
                printf "          \"RX_BPS\":%d,", (($2  - stats[1]) * 8 / it)
                printf          " \"RX_PPS\":%d,", (($3  - stats[2]) / it)
                printf          " \"TX_BPS\":%d,", (($10 - stats[3]) * 8 / it)
                printf          " \"TX_PPS\":%d\n", (($11 - stats[4]) / it)
                printf "        }"
            }
        }
    } END {
        if (ot == "HOST") {
            printf "\n"
        } else if (prev_router != 0) {
            printf "\n      ]\n    }\n"
        }
    }'
}

print_cpu_stat()
{
    prev=$1
    curr=$2
    interval=$3
    obj_type=$4

    cat $CPU_STAT$prev $CPU_STAT$curr | awk -v it=$interval -v ot=$obj_type '
    BEGIN { prev_cpu = -1; } {
        if (ot == "HOST" && match($1, "cpu[0-9]+")) {
            total = ($2 + $3 + $4 + $5 + $6 + $7 + $8)
            if (buf[$1] == 0) {
                buf[$1] = $5 " " total
            } else {
                cpu = substr($1, 4)
                split(buf[$1], stats, " ")

                if (prev_cpu != -1) {
                    printf ",\n"
                }
                prev_cpu = cpu

                printf "    {"
                printf " \"CPU_ID\":%d,", cpu
                printf " \"LOAD\":%d", 100 - ($5 - stats[1]) * 100 / (total - stats[2])
                printf " }"
            }
        }
    } END {
        if (ot == "HOST") {
            printf "\n"
        }
    }'
}

print_mem_stat()
{
    curr=$1

    cat $MEM_STAT$curr | awk 'BEGIN {total = 0; free = 0;} {
        if (NR == 1) {
            total = $2
        } else if (NR == 2) {
            free = $2
        }
    } END {
        printf "    \"TOTAL\": %d,\n    \"FREE\": %d\n", total, free
    }'
}

stat()
{
    realtime=$1

    if [[ $realtime -eq 1 ]]; then
        file_name_tag="r"
        expire=$REALTIME_STAT_EXPIRE
    else
        file_name_tag="m"
        expire=$GENERAL_STAT_EXPIRE
    fi

    echo "{"

    if [[ -f "${NET_STAT}.${file_name_tag}.1" &&
          -f "${CPU_STAT}.${file_name_tag}.1" &&
          -f "${MEM_STAT}.${file_name_tag}.1" ]]; then
        prev=".${file_name_tag}.1"
        curr=".${file_name_tag}.2"
    elif [[ -f "${NET_STAT}.${file_name_tag}.2" &&
            -f "${CPU_STAT}.${file_name_tag}.2" &&
            -f "${MEM_STAT}.${file_name_tag}.2" ]]; then
        prev=".${file_name_tag}.2"
        curr=".${file_name_tag}.1"
    fi

    if [[ -n "$prev" ]]; then
        cat /proc/net/dev 2> /dev/null | grep -Eo "[^ ]+.+[^ ]+" | sort -k1,1 > $NET_STAT$curr
        get_lc_br_traffic >> $NET_STAT$curr
        grep -E "^cpu[0-9]+ " /proc/stat 2> /dev/null > $CPU_STAT$curr
        head -n 2 /proc/meminfo 2> /dev/null > $MEM_STAT$curr
        prev_t=`ls $NET_STAT$prev --time-style=+%s -cl | awk '{print $6}'`
        curr_t=`ls $NET_STAT$curr --time-style=+%s -cl | awk '{print $6}'`
        if (( curr_t - prev_t > expire )); then
            tmp=$prev
            prev=$curr
            curr=$tmp
            sleep 1
            cat /proc/net/dev 2> /dev/null | grep -Eo "[^ ]+.+[^ ]+" | sort -k1,1 > $NET_STAT$curr
            get_lc_br_traffic >> $NET_STAT$curr
            prev_t=$curr_t
            curr_t=`ls $NET_STAT$curr --time-style=+%s -cl | awk '{print $6}'`
        fi
    else
        prev=".${file_name_tag}.2"
        curr=".${file_name_tag}.1"
        cat /proc/net/dev 2> /dev/null | grep -Eo "[^ ]+.+[^ ]+" | sort -k1,1 > $NET_STAT$prev
        get_lc_br_traffic >> $NET_STAT$prev
        grep -E "^cpu[0-9]+ " /proc/stat 2> /dev/null > $CPU_STAT$prev
        sleep 1
        cat /proc/net/dev 2> /dev/null | grep -Eo "[^ ]+.+[^ ]+" | sort -k1,1 > $NET_STAT$curr
        get_lc_br_traffic >> $NET_STAT$curr
        grep -E "^cpu[0-9]+ " /proc/stat 2> /dev/null > $CPU_STAT$curr
        head -n 2 /proc/meminfo 2> /dev/null > $MEM_STAT$curr
        prev_t=`ls $NET_STAT$prev --time-style=+%s -cl | awk '{print $6}'`
        curr_t=`ls $NET_STAT$curr --time-style=+%s -cl | awk '{print $6}'`
    fi

    if [[ $curr_t -le $prev_t ]]; then
        (( curr_t = prev_t + 1 ))
    fi
    (( interval = curr_t - prev_t ))

    echo "  \"ROUTER_TRAFFICS\": ["
    print_traffic_stat $prev $curr $interval "ROUTER"
    echo "  ],"
    echo "  \"HOST_TRAFFICS\": ["
    print_traffic_stat $prev $curr $interval "HOST"
    echo "  ],"
    echo "  \"HOST_CPUS\": ["
    print_cpu_stat $prev $curr $interval "HOST"
    echo "  ],"
    echo "  \"HOST_MEMORY\": {"
    print_mem_stat $curr
    echo "  }"

    rm -f $NET_STAT$prev
    rm -f $CPU_STAT$prev
    rm -f $MEM_STAT$prev

    echo "}"
}

if [[ $# -eq 1 && $1 = 'general' ]]; then
    stat 0
elif [[ $# -eq 1 && $1 = 'realtime' ]]; then
    stat 1
else
    exit 1
fi

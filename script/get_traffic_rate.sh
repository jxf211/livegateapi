#!/bin/sh

usage()
{
    echo "Usage: `basename $0` <nic-name> <interval> [round]"
    echo "  i.e: `basename $0` eth0 1"
    echo "  i.e: `basename $0` eth0 1 10"
}

if [[ $# -ne 2 && $# -ne 3 ]]; then
    usage
    exit 1
fi

nic=$1
interval=$2
round=$3

old=(`cat /proc/net/dev | grep $nic | awk -F":" '{print $2}'`)
i=0
while : ; do
    sleep $interval
    new=(`cat /proc/net/dev | grep $nic | awk -F":" '{print $2}'`)
    #echo "${old[@]}"
    #echo "${new[@]}"
    (( rx_bps = (new[0] - old[0]) * 8 / interval ))
    (( rx_pps = (new[1] - old[1]) / interval ))
    (( rx_err = (new[2] - old[2]) / interval ))
    (( rx_drp = (new[3] - old[3]) / interval ))
    (( tx_bps = (new[8] - old[8]) * 8 / interval ))
    (( tx_pps = (new[9] - old[9]) / interval ))
    (( tx_err = (new[10] - old[10]) / interval ))
    (( tx_drp = (new[11] - old[11]) / interval ))
    old=(${new[@]})

    ((i += 1))
    (( fold = i % 28 ))
    if [[ $fold -eq 1 ]]; then
        awk 'BEGIN{printf "%20s %10s %10s %10s %10s  /  %10s %10s %10s %10s\n", "TIME", "RX_BPS", "RX_PPS", "RX_ERR", "RX_DROP", "TX_BPS", "TX_PPS", "TX_ERR", "TX_DROP"}'
    fi
    echo `date +%y-%m-%d.%H:%M:%S` $rx_bps $rx_pps $rx_err $rx_drp $tx_bps $tx_pps $tx_err $tx_drp | awk '{printf "%20s %10d %10d %10d %10d  /  %10d %10d %10d %10d\n", $1, $2, $3, $4, $5, $6, $7, $8, $9}'

    if [[ -n "$round" && "$i" -ge "$round" ]]; then
        break
    fi
done

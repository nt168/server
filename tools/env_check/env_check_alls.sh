#!/bin/bash
chkfil=$1
function check_cmd {
        if ! [ -x "$(command -v $1)" ]; then
                echo "$1|no"
        else
                echo "$1|yes"
        fi
}

function check_kernel_config {
        if [ "$(cat /proc/sys/kernel/perf_event_paranoid)" -ne -1 ]; then
                echo "perf(non-root)|no"
        else
                echo "perf(non-root)|yes"
        fi

        if [ "$(cat /proc/sys/kernel/kptr_restrict)" -ne 0 ]; then
                echo "kallsyms(non-root)|no"
        else
                echo "kallsyms(non-root)|yes"
        fi
}

function check_cputp {
        cputpstr=`cat /sys/devices/system/cpu/cpu0/regs/identification/midr_el1`
    last_8=$(echo $cputpstr | tail -c 9)
        format=$last_8
        output="0x${format}"
        echo "cputp|${output}"
}

function check_events {
	for ev in $(echo $1 | tr "," "\n")
	do
		if ! $(echo "$2" | grep -q "$ev"); then
			return 1
			break
		fi
	done
	return 0
}

function check_l3 {
	for ev in $(echo $1 | tr "," "\n")
	do
                if ! $(echo "$2" | grep -q "$ev"); then
			return 1
			break
                else
                        output=$(perf stat -e $ev --timeout 100 2>&1)
                        if echo "$output" | grep -q "perf_event_paranoid"; then
			       return 1
			       break
                        else
                                count=$(echo "$output" | grep "$ev" | awk '{print $1}')
                                count=$(echo $count | cut -d',' -f1)
                                if [ "$count" -eq 0 ]; then
                                        return 1
                                        break
                                else
                                        return 0
                                fi
                        fi
		fi
	done
	return 0
}


function check_supported_metrics {
	memaccess_support=""
	l1_evlist="L1-dcache-loads,L1-dcache-load-misses,L1-icache-loads,L1-icache-load-misses"
	output=$(perf list | grep L1)
	if check_events "$l1_evlist" "$output"; then
		memaccess_support+="L1,"
	fi
	l2_evlist="l2d_cache,l2d_cache_refill"
	output=$(perf list | grep l2)
	if check_events "$l2_evlist" "$output"; then
                memaccess_support+="L2,"
        fi
	tlb_evlist="l1d_tlb,l1d_tlb_refill,l1i_tlb,l1i_tlb_refill,l2d_tlb,l2d_tlb_refill"
	output=$(perf list | grep tlb)
        if check_events "$tlb_evlist" "$output"; then
                memaccess_support+="TLB,"
        fi
	l3_evlist="l3d_cache,l3d_cache_refill"
        output=$(perf list | grep l3)
        if check_l3 "$l3_evlist" "$output"; then
                memaccess_support+="L3,"
        fi
	ddr_output=$(perf list | grep 'ddr.*rxdat\|ddr.*txdat\|ddr.*cycles' | awk '{print $1}' | tr '\n' ',' | sed 's/,$//')
	if [ ! -z "$ddr_output" ]; then
		memaccess_support+="DDR,"
	fi
	if [ ! -z "$memaccess_support" ]; then
		memaccess_support=$(echo $memaccess_support | sed 's/,$//')
                echo "support_metrics|$memaccess_support"
        fi
}

check_cmd perf
check_cmd python3
check_cmd expect
check_kernel_config
check_cputp
check_supported_metrics

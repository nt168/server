#!/bin/bash
chkfil=$1
function check_cmd {
	if ! [ -x "$(command -v $1)" ]; then
#		echo "WARN: $1 is not installed." >&2
		echo "$1|no" >> $chkfil
	else
		echo "$1|yes" >> $chkfil
	fi
}

function check_kernel_config {
	if [ "$(cat /proc/sys/kernel/perf_event_paranoid)" -ne -1 ]; then
#		echo "WARN: perf not full allowed for non-root."
		echo "perf(non-root)|no" >> $chkfil
	else
		echo "perf(non-root)|yes" >> $chkfil 
	fi
	
	if [ "$(cat /proc/sys/kernel/kptr_restrict)" -ne 0 ]; then
#               echo "WARN: kallsyms not allowed for non-root."
		echo "kallsyms(non-root)|no" >> $chkfil
	else
		echo "kallsyms(non-root)|yes" >> $chkfil	
        fi
}

function check_cputp {
	cputpstr=`cat /sys/devices/system/cpu/cpu0/regs/identification/midr_el1`
    last_8=$(echo $cputpstr | tail -c 9)
#	format=$(echo $last_8 | sed -r 's/(..)(.)(.)(...)(.)/\1-\2-\3-\4-\5/' )
	format=$last_8
	output="0x${format}"
	echo "cputp|${output}" >> $chkfil	
}

check_cmd expect
check_cmd perf
check_cmd ssh
check_cmd scp
check_cmd python3
check_kernel_config
check_cputp

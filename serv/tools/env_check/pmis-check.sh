#!/bin/bash

function check_kernel_config {
	if [ "$(cat /proc/sys/kernel/perf_event_paranoid)" -ne -1 ]; then
		echo "WARN: perf not full allowed for non-root."
	fi
	
	if [ "$(cat /proc/sys/kernel/kptr_restrict)" -ne 0 ]; then
                echo "WARN: kallsyms not allowed for non-root."
        fi
}

check_kernel_config


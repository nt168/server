#!/bin/bash
function check_cmd {
	if ! [ -x "$(command -v $1)" ]; then
		echo "WARN: $1 is not installed." >&2
	fi
}

check_cmd expect
check_cmd perf
check_cmd ssh
check_cmd scp
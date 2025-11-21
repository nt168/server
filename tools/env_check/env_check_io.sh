#!/bin/bash
chkfil=$1
function check_cmd {
        if ! [ -x "$(command -v $1)" ]; then
                echo "$1|no"
        else
                echo "$1|yes"
        fi
}


function check_config {
        config_file="/boot/config-$(uname -r)"
        if [ -f "$config_file" ]; then
                set_out=$(cat $config_file | grep $1)
                if echo "$set_out" | grep -q "=y"; then
                        check_cmd blktrace
                        # check_cmd fio
                else
                        echo "$1|no"
                fi
        else
                flag=false
                files=$(ls /boot/config-*)
                for file in $files
                do
                        out=$(cat $file | grep $1)
                        if echo "$out" | grep -q "=y"; then
                                flag=true
                        else
                                flga=false     
                        fi
                done
                if [ "$flag" = "true" ]; then
                        check_cmd blktrace
                        # check_cmd fio
                else
                        echo "$1|no"
                fi
        fi

} 


check_cmd python3
check_config CONFIG_BLK_DEV_IO_TRACE
check_cmd strace

#!/usr/bin/expect
set timeout -1 
if {$argc < 2} {
    send_user "usage: $argv0 src_file username ip dest_file password\n"
    exit
}
set src_file [lindex $argv 0]
set username [lindex $argv 1]
set host_ip [lindex $argv 2]
set dest_file [lindex $argv 3]
set password [lindex $argv 4]

spawn scp -pr $src_file $username@$host_ip:$dest_file
expect {
    "*yes/no*" {send "yes\r";exp_continue}
    "password" {send "$password\r";exp_continue}
}
exit
EOF

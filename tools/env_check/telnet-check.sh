#!/bin/bash
 
Server_ip=(10.31.94.35 10.10.240.15 10.31.94.34 10.10.70.220 10.31.94.36)
Server_port=$1 #测试端口号
echo -n "">./pd.txt #清空测试记录
 
#开始测试
for i in "${Server_ip[@]}" #遍历服务器ip
do
echo "测试连接服务器端口$i $Server_port"
qq=`(sleep 1;) | telnet $i $Server_port|grep "]"|wc -l` #判断连通性命令
if [ $qq -eq 0 ]; #输出结果
then echo "连接失败";echo "服务器$i端口$Server_port连接失败" >> ./pd.txt;
else
echo "连接成功";echo "服务器$i端口$Server_port连接成功" >> ./pd.txt;
fi
 
done
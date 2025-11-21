#!/bin/bash
#
#获取当前时间
datetimevar=`date "+%Y-%m-%d %H:%M:%S"`
#读取IP列表行数
lineNumber=`cat iplist.txt |wc -l`
#设置计数参数
count=0
#循环读取IP并测试
for i in `cat ./iplist.txt`    
	do        
	#计数器        
	count=$((count+1))        
	#控制台打印当前进度        
	echo "${i} ${count}/${lineNumber}"        
	#PING并保留丢包数        
	p=`ping -c 1 $i|grep loss|awk '{print $6}'|awk -F "%" '{print $1}'`            
		#因为只PING一次，丢包数为0则表示成功，否则失败            
		if [ $p -eq 0 ]                
	then                    
		echo "${datetimevar}|${i}|true" >> ./ipcheckdown.txt                
	else                    
		echo "${datetimevar}|${i}|fail" >> ./ipcheckdown.txt            
		fi    
	done

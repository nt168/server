#!/bin/bash

input=$1
output=$2
output1=$3

echo "{" > $output
current_stage=""
current_group=""
metric_lines=""

while IFS= read -r line; do
    if [[ $line =~ Stage[[:space:]]+[0-9]+ ]]; then
        # 结束前一个阶段（如果存在）
        if [[ -n $current_stage && -n $current_group ]]; then
            if [[ -n $metric_lines ]]; then
                echo -e "$metric_lines" >> $output
                metric_lines=""
            fi
            echo "        }" >> $output # 结束前一个分组
            echo "    }," >> $output # 结束前一个阶段
        fi
        current_stage=$(echo "$line" | awk -F ' \\(' '{print $1 " (" $2}')
        echo "    \"$current_stage\": {" >> $output
        current_group=""
    elif [[ $line =~ \[([^\]]+)\] ]]; then
#	echo 2---------------- $line
        # 结束前一个分组（如果存在）
        if [[ -n $metric_lines ]]; then
            echo -e "$metric_lines" >> $output
            metric_lines=""
        fi
        if [[ -n $current_group ]]; then
            echo "        }," >> $output
        fi
        current_group="${BASH_REMATCH[1]}"
        echo "        \"$current_group\": {" >> $output
    elif [[ ! $line =~ \[|\]|\Stage|\(|\) ]] && [[ $line =~ [[:space:]]+[0-9] ]]; then #[[ $line =~ ([^\.]+)(\.\.\.+|\s+)(.+) ]]; then
#	echo 3---------------- $line
<<'COMMENTS'
	# 使用正则表达式提取所需的部分
	if [[ $line =~ ^([^\0-9]+)([0-9]+\.[0-9]+[%].+)$ ]]; then
    	# 第一部分：匹配到的字符串，去除点号
    		metric_name="${BASH_REMATCH[1]//./}"

    	# 第二部分：匹配到的字符串，去除前导空格
    		metric_value_and_unit="${BASH_REMATCH[2]}"
    		metric_value_and_unit="${metric_value_and_unit# }" # 去除前导空格
	fi
COMMENTS

<<'COMMENTS'
	# 使用正则表达式提取所需的部分
    	if [[ $line =~ ^([^\0-9]+)[[:space:]]([0-9]+(\.[0-9]+)?%?([,0-9]*[[:space:]]?.*)$) ]]; then
        # 第一部分：匹配到的字符串，去除点号
        	metric_name="${BASH_REMATCH[1]//./}"
        # 第二部分：匹配到的字符串，保留
        	metric_value_and_unit="${BASH_REMATCH[2]}"
    	fi
COMMENTS

<<'COMMENTS'
	if [[ $line =~ ^([^.]+)\.*[[:space:]]([0-9,%]+.*$) ]]; then
        # 第一部分：匹配到的字符串，去除点号
        	metric_name="${BASH_REMATCH[1]}"
        	metric_name="${metric_name//./}"

        # 第二部分：匹配到的字符串，不需要额外处理
   	     	metric_value_and_unit="${BASH_REMATCH[2]}"
        fi
COMMENTS
	position=$(echo "$line" | grep -o -b -P '(\s\d)' | awk -F: 'NR==1 {print $1}')

	# 截取字符串
        metric_name=${line:0:$position}
        metric_value_unit=${line:$position}

        metric_name="${metric_name//./}"
        metric_value_unit="${metric_value_unit# }"

        # 使用 grep 提取从开头到第一个空格之间的数字部分
        value=$(echo "$metric_value_unit" | grep -oE '^[0-9,]*\.?[0-9]*%?')

        # 使用 sed 删除数字部分来提取单位
	units=$(echo "$metric_value_unit" | sed "s/$value//")

	echo "-metric_name $metric_name"
	echo "-metric_value_unit $metric_value_unit"
	echo "--value $value"
	echo "--unit $units"

	metric_line="\"$metric_name\": \"$value $units\"" # 保留数值和单位之间的一个空格
        if [[ -n $metric_lines ]]; then
        	metric_lines+=",\n            $metric_line"
        else
                metric_lines="            $metric_line"
        fi


<<'COMMENTS'	
	# 提取度量值及其单位
        if [[ $metric_value_and_unit =~ ([0-9]+(\.[0-9]+)?%?)\s*(.*) ]]; then
#            metric_value="${BASH_REMATCH[1]}"
	    metric_value=$(echo "$metric_value_and_unit" | grep -oE '^[0-9,]*\.?[0-9]*%?')
	    metric_unit=$(echo "$metric_value_and_unit" | sed "s/$metric_value//")
#            metric_unit="${BASH_REMATCH[3]}"
            metric_unit=$(echo "$metric_unit" | sed 's/^[ \t]*//;s/[ \t]*$//') # 移除两端的空格
	    echo "--metric_value $metric_value"
	    echo "--metiic_unit $metric_unit"
            metric_line="\"$metric_name\": \"$metric_value $metric_unit\"" # 保留数值和单位之间的一个空格
            if [[ -n $metric_lines ]]; then
                metric_lines+=",\n            $metric_line"
            else
                metric_lines="            $metric_line"
            fi
        fi
COMMENTS
    fi
done < "$input"

# 输出最后的度量数据和结束分组/阶段
if [[ -n $metric_lines ]]; then
    echo -e "$metric_lines" >> $output
fi
if [[ -n $current_group ]]; then
    echo "        }" >> $output # 结束最后一个分组
fi
if [[ -n $current_stage ]]; then
    echo "    }" >> $output # 结束最后一个阶段
fi

echo "}" >> $output

#sed 's/"Stage 1 .*"/"1.001100987"/g' $output > 文件名2
#sed 's/"Stage 2 .*"/"2.649975772"/g' $output > 文件名2

sed 's/"Stage 1 .*"/"1.001100987"/g' $output | sed 's/"Stage 2 .*"/"2.649975772"/g' > $output1

#将Stage关键字的内容替换成1、2、3...
count=1
# 使用grep定位包含"Stage"的行，然后对这些行进行处理
grep -n '\"Stage' "$output" | cut -f1 -d: | while read -r lineno; do
    # 为每个匹配的行构造一个sed替换命令
    sed -i "${lineno}s/\"Stage [^\"]*\"/\"${count}\"/" "$output"
    ((count++))
done

echo "JSON 文件已创建: $output"

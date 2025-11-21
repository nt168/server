#!/bin/bash

# 输入和输出文件路径
input=$1
output1=$2
output=$3

# 开始转换
echo "{" > $output
awk -F, '{
    if (NR == 1) { next } # 跳过标题行
    if ($1 == "" || $4 == "" || $5 == "") { next } # 跳过任何关键字段为空的行
    if (last_time != $1) {
        if (NR != 2) {
            print last_line >> "'$output'" # 添加前一个分组的最后一项
            print "        }" >> "'$output'" # 结束前一个分组
            print "    }," >> "'$output'" # 结束前一个时间戳
        }
        print "    \""$1"\":  {" >> "'$output'" # 开始新的时间戳
        last_group=""
    }
    if (last_group != "" && last_group != $4) {
        print last_line >> "'$output'" # 添加前一个分组的最后一项
        print "        }," >> "'$output'" # 结束前一个分组
    }
    if (last_group != $4) {
        print "        \""$4"\": {" >> "'$output'" # 开始新的分组
    } else {
        print last_line "," >> "'$output'" # 在上一行末尾添加逗号
    }
    last_line="            \""$5"\": \""$6" "$7"\"" # 保存当前行
    last_time=$1
    last_group=$4
} END {
    print last_line >> "'$output'" # 添加最后一个分组的最后一项
    print "        }" >> "'$output'" # 结束最后一个分组
    print "    }" >> "'$output'" # 结束最后一个时间戳
    print "}" >> "'$output'" # 结束整个 JSON 对象
}' $input
sed -i 's/\r//' $output

#去除行头行尾的‘ ’符
#sed -i 's/^[[:space:]]*//;s/[[:space:]]*$//' $output

#填充‘_’
sed -i -E 's/"([^"]+)":/"\1":/g; :a s/("([^"]+)) ([^:"]+":)/\1_\3/; ta' $output

count=1
:<<!
while IFS= read -r line
do
    # Use grep to check if the line contains a number within quotes
    if grep -o '"[0-9]\+\(\.[0-9]*\)\?"' <<< "$line" > /dev/null; then
        # Extract the number within quotes and replace it with count
        newline=$(echo "$line" | sed -E 's/"[0-9]+(\.[0-9]+)?"/"'"$count"'"/')
        echo "$newline" >> "$output1"
        ((count++))
    else
        # If no number in quotes, just write the line as is
        echo "$line" >> "$output1"
    fi
done < "$output"
!

#找到纯数字(包括小数)字符串 然后替换成 1、2、3...
# 使用while循环逐行读取输入文件
while IFS= read -r line; do
    # 使用grep搜索符合条件的字符串
    matches=$(grep -oP '"\K[0-9]+(\.[0-9]+)?(?=")' <<< "$line")
    for match in $matches; do
        # 对于每个匹配的字符串，使用sed进行替换
        line=$(sed "s/\"$match\"/\"$count\"/" <<< "$line")
        ((count++))
    done
    echo "$line"
done < "$output" > "$output1"

echo "JSON文件已创建: $output"

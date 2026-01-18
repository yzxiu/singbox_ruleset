#!/bin/bash

# 编译合并后的规则集

# 编译规则集的函数
compile_ruleset_dir() {
    local base_dir=$1
    
    # 遍历指定文件夹下的每个子文件夹
    for dir in "$base_dir"/*/; do
        # 检查目录是否存在
        if [[ ! -d "$dir" ]]; then
            continue
        fi
        
        # 查找目录下的所有 JSON 文件
        for json_file in "$dir"/*.json; do
            # 检查文件是否存在（避免通配符未匹配的情况）
            if [[ ! -f "$json_file" ]]; then
                continue
            fi
            
            # 获取 JSON 文件名（不含路径和扩展名）
            json_filename=$(basename "$json_file" .json)
            
            # 构建输出文件名 (与 JSON 相同，用 .srs 结尾)
            output_file="$dir/$json_filename.srs"
            
            # 执行 sing-box 命令
            sing-box rule-set compile --output "$output_file" "$json_file"
            
            # 输出处理信息
            echo "Processed: $json_file -> $output_file"
        done
    done
}

# 编译 my_rule 目录下的规则集
if [[ -d "my_rule" ]]; then
    echo "Compiling my_rule directory..."
    compile_ruleset_dir "my_rule"
else
    echo "Warning: my_rule directory not found"
fi

echo "Merged rule-set compilation complete!"


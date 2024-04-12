use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Data {
    key: String,
    value: Vec<String>,
}

/**
 * 这个代码的作用，将rules_file_vec向量中的文件内容，按程序逻辑拼接成clash的rules的规则内容。（5个代理组）
 */
fn main() {
    let rules_file_vec = vec![
        "rules/direct.txt",  // 🎯 全球直连
        "rules/private.txt", // 🎯 全球直连
        "rules/lancidr.txt", // 🎯 全球直连
        "rules/reject.txt",  // 🛑 全球拦截
        "rules/gfw.txt",     // 🔰 节点选择
        "rules/proxy.txt",   // 🔰 节点选择
    ]; // 不在这些规则里面的，则走🐟 漏网之鱼
    let mut rules_item_set = HashSet::new();
    for rules_file in rules_file_vec {
        let proxy_type = if rules_file.contains("reject") {
            "🛑 全球拦截".to_owned()
        } else if rules_file.contains("gfw") || rules_file.contains("proxy") {
            "🔰 节点选择".to_owned()
        } else {
            "🎯 全球直连".to_owned()
        };

        let mut file = File::open(rules_file).unwrap();
        let mut contents = String::new();
        file.read_to_string(&mut contents).unwrap();

        let yaml: Value = serde_yaml::from_str(&contents).unwrap();
        let values = yaml["payload"].as_sequence().unwrap();

        for value in values {
            let value_str = value.as_str().unwrap();
            let processed_value = if value_str.starts_with("+.") {
                format!(
                    "DOMAIN-SUFFIX,{},{}",
                    value_str.replace("+.", ""),
                    proxy_type
                )
            } else if value_str.starts_with("www.") {
                format!("DOMAIN,{},{}", value_str.replace("www.", ""), proxy_type)
            } else if value_str.contains("0/") || value_str.contains("::/") {
                format!(
                    "IP-CIDR,{},{},no-resolve",
                    value_str.to_string(),
                    proxy_type
                )
            } else {
                format!("DOMAIN,{},{}", value_str.to_string(), proxy_type)
            };
            // 直接插入到 HashSet 中，如果元素已经存在，那么插入操作不会有任何效果
            rules_item_set.insert(processed_value);
        }
    }

    // 将HashSet转换为Vec
    let mut rules_item_vec: Vec<_> = rules_item_set.into_iter().collect();

    // 对Vec进行排序
    rules_item_vec.sort();
    rules_item_vec.push("DOMAIN-KEYWORD,-cn,🎯 全球直连".to_owned());
    // rules_item_vec.push("GEOIP,CN,🎯 全球直连".to_owned());
    // rules_item_vec.push("MATCH,🐟 漏网之鱼".to_owned());
    // 创建一个新的HashMap，并添加键值对
    let mut data = HashMap::new();
    data.insert("rules", rules_item_vec);

    // 将HashMap转换为YAML格式的字符串
    let yaml_string = serde_yaml::to_string(&data).unwrap();
    // 分割字符串为行，然后在第二行及以后的每行前面添加两个空格，最后再把它们连接起来
    let mut indented_yaml_string = yaml_string
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 0 {
                line.to_string()
            } else {
                format!("  {}", line)
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    // 添加新规则
    indented_yaml_string = format!("{}\n  - GEOIP,CN,🎯 全球直连\n  - MATCH,🐟 漏网之鱼",indented_yaml_string);
    // 将字符串写入到新的YAML文件
    std::fs::write("rules/clash_rules.yaml", indented_yaml_string).unwrap();
}

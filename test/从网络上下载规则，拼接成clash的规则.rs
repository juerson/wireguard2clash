use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::Path,
    sync::{Arc, Mutex},
};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Data {
    key: String,
    value: Vec<String>,
}

/**
 * 这个代码的作用，将urls中下载下来的文件内容，按程序逻辑拼接成clash的rules的规则内容。（5个代理组）
 */
#[tokio::main]
async fn main() {
    // 下面的链接来源于https://github.com/Loyalsoldier/clash-rules
    let urls = vec![
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt", // 🎯 全球直连
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt", // 🎯 全球直连
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt", // 🎯 全球直连
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt", // 🛑 全球拦截
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt",    // 🔰 节点选择
        "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt",  // 🔰 节点选择
    ]; // 不在这些规则里面的，则走🐟 漏网之鱼

    let mut handles = vec![];

    // 使用 Arc 和 Mutex 来共享 HashSet 并确保线程安全，如此才能保证插入数据不会报错，后面也能读取到共享的数据
    let results: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    for url in urls {
        let results = Arc::clone(&results);
        let handle = tokio::spawn(async move {
            match fetch_url(url).await {
                Ok(content) => {
                    let mut results = results.lock().unwrap();
                    let proxy_type = if url.contains("reject") {
                        "🛑 全球拦截".to_owned()
                    } else if url.contains("gfw") || url.contains("proxy") {
                        "🔰 节点选择".to_owned()
                    } else {
                        "🎯 全球直连".to_owned()
                    };
                    let yaml: Value = serde_yaml::from_str(&content).unwrap();
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
                        results.insert(processed_value);
                    }
                }
                Err(e) => println!("Error fetching {}: {:?}", url, e),
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
    // 锁定 Mutex 以访问最终的 HashSet
    let results = results.lock().unwrap();
    // 转换为Vec
    let mut rules_item_vec: Vec<String> = results.clone().into_iter().collect();
    // 打乱顺序
    rules_item_vec.sort();
    // 加入一些其它规则
    rules_item_vec.push("DOMAIN-KEYWORD,-cn,🎯 全球直连".to_owned());
    rules_item_vec.push("GEOIP,CN,🎯 全球直连".to_owned());
    rules_item_vec.push("MATCH,🐟 漏网之鱼".to_owned());

    // 创建一个新的HashMap，并添加键值对
    let mut data = HashMap::new();
    data.insert("rules", rules_item_vec);

    // 将HashMap转换为YAML格式的字符串
    let yaml_string = serde_yaml::to_string(&data).unwrap();
    // 分割字符串为行，然后在第二行及以后的每行前面添加两个空格，最后再把它们连接起来
    let rules_result = yaml_string
        .lines()
        .enumerate()
        .map(|(i, line)| {
            if i == 0 {
                line.to_string()
            } else {
                format!("  {}", line)
            }
        })
        .collect::<Vec<String>>()
        .join("\n");
    create_folder_if_not_exists("./rules");
    let output_file = "rules/clash_rules.yaml";
    // 将字符串写入到新的YAML文件
    std::fs::write(output_file, rules_result).unwrap();
    println!("规则已经写入到文件{}中！", output_file);
}

async fn fetch_url(url: &str) -> Result<String, reqwest::Error> {
    let response = reqwest::get(url).await?;
    let body = response.text().await?;
    Ok(body)
}

fn create_folder_if_not_exists(folder_path: &str) {
    let path = Path::new(folder_path);

    if !path.exists() {
        fs::create_dir_all(path).expect("Failed to create folder");
    }
}

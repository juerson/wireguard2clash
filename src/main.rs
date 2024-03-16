mod clash_config;
mod clash_rules2;

use clash_config::BASIC_INFO;
use clash_rules2::RULES;
use ipnetwork::IpNetwork;
use serde_json::json;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Write},
    str::FromStr,
};

const PROXY_GROUPS1: &str = r#"proxy-groups:
  - name: 🔰 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🎯 全球直连
"#;
const PROXY_GROUPS2: &str = r#"  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 1000
    proxies:
"#;
const PROXY_GROUPS3: &str = r#"  - name: 🛑 全球拦截
    type: select
    proxies:
      - REJECT
      - DIRECT
"#;
const PROXY_GROUPS4: &str = r#"  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT
"#;
const PROXY_GROUPS5: &str = r#"  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;
fn main() -> io::Result<()> {
    /* 删除目录中所有文件 */
    let dir_path = "./output"; //指定目录
    delete_files_in_dir(dir_path)?;

    let wg_conf_file = "wg-config.conf";
    let param = read_wireguard_key_parameters(wg_conf_file);
    // 远端公钥
    let peer_public_key = param.get("PublicKey").unwrap().trim();
    // 本机私钥
    let private_key = param.get("PrivateKey").unwrap().trim();

    // 本机组网IP
    let addresses = param
        .get("Address")
        .map(|address| {
            if let [ipv4, ipv6] = address.split(',').collect::<Vec<&str>>().as_slice() {
                (*ipv4, Some(*ipv6))
            } else {
                (address.trim(), None)
            }
        })
        .unwrap_or_else(|| ("", None));

    let ipv4 = addresses.0.split('/').next().unwrap().trim();
    let ipv6 = addresses.1.unwrap_or("").split('/').next().unwrap().trim();

    // clash中，wireguard协议的节点（json数据结构）
    let json_data = json!({"name": "wg", "type": "wireguard", "private-key": private_key,
        "server": "162.159.195.251", "port": 946, "ip": ipv4, "public-key": peer_public_key, "udp": true});
    let cidr_ranges = vec![
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
    ];

    // 从"wg-config.conf"文件中，分离出Endpoint的端口
    let wg_port = param.get("PORT").unwrap().trim();
    let ports = vec![wg_port];

    // let ports = vec![
    //     854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955,
    //     968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138,
    //     3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
    //     8854, 8886, 2408, 500, 4500, 1701,
    // ];

    // 定义一个计数器来计算content写入的个数(也就是proxies中最多写多少个节点)
    let mut content_count = 0;
    let mut max_content_per_file: usize = ports.len() * 22; // 指定每个文件最多的 content 数量（这个是22个IP乘以端口向量的总数）
    if max_content_per_file < 1024 {
        max_content_per_file = 1024;
    }

    // 对于每个 CIDR，创建一个单独的文件，并写入相应内容
    for cidr in cidr_ranges {
        let ip_network: IpNetwork = match IpNetwork::from_str(&cidr) {
            Ok(network) => network,
            Err(err) => {
                eprintln!("Error parsing CIDR {}: {}", cidr, err);
                continue;
            }
        };
        let mut unique_ips: HashSet<String> = HashSet::new();
        match ip_network {
            IpNetwork::V4(network) => {
                for ip in network.iter() {
                    unique_ips.insert(ip.to_string());
                }
            }
            IpNetwork::V6(_) => {
                println!("IPv6地址暂不支持");
                continue;
            }
        }

        let cidr_prefix = cidr.split('/').next().unwrap_or(&cidr); // 获取斜杠之前的部分作为文件名的一部分

        let mut file_count = 1; // 文件编号从1开始
        let mut proxy_name_vec: Vec<String> = Vec::new();
        // 将unique_ips写入文件中
        // 将 HashSet 转换为 Vec
        let ips: Vec<&str> = unique_ips.iter().map(|s| s.as_str()).collect::<Vec<&str>>();
        let last_ip = ips[ips.len() - 1];
        for ip in ips {
            for port in &ports {
                let mut new_json_data: Value = json_data.clone();
                new_json_data["server"] = json!(ip);
                new_json_data["port"] = json!(port);
                let proxy_name = format!("{}:{}", ip, port);
                proxy_name_vec.push(proxy_name.clone());
                new_json_data["name"] = json!(proxy_name);
                if !ipv6.is_empty() {
                    new_json_data["ipv6"] = json!(ipv6);
                }
                let content = format!("  - {}", serde_json::to_string(&new_json_data).unwrap());
                println!("{}", content);

                if content_count >= max_content_per_file {
                    content_count = 0; // 重置计数器
                    file_count += 1; // 切换到下一个文件
                }

                let mut file_name = format!("{}/{}", dir_path, cidr_prefix);
                if file_count > 1 {
                    // 如果file_count大于1，则添加文件后缀编号
                    file_name.push_str(&format!("_{}", file_count));
                } else {
                    // 如果file_count等于1，则默认1为文件后缀编号
                    file_name.push_str(&format!("_{}", "1"));
                }

                let file_path = format!("{}.yaml", file_name);

                // 检查文件是否存在
                let file_exists = fs::metadata(&file_path).is_ok();

                let mut file = match fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(file_exists) // 只在文件存在时追加写入
                    .open(&file_path)
                {
                    Ok(file) => file,
                    Err(err) => {
                        eprintln!("Error opening file: {}", err);
                        continue;
                    }
                };
                // 写入初始内容（如果是第一个文件）
                if !file_exists {
                    if let Err(err) = writeln!(&mut file, "{}", BASIC_INFO) {
                        eprintln!("Error writing to file: {}", err);
                        continue;
                    }
                }

                if let Err(err) = writeln!(&mut file, "{}", content) {
                    eprintln!("Error writing to file: {}", err);
                    continue;
                }
                if content_count == max_content_per_file
                    || ((last_ip == ip || content_count == max_content_per_file - 1)
                        && port == &ports[ports.len() - 1])
                {
                    // 将向量中的元素连接成一个字符串
                    let joined_string = proxy_name_vec
                        .iter() // 使用迭代器
                        .map(|s| format!("      - {}{}", s, "\n")) // 在每个元素前添加 " - "，并在后面添加 "\n"
                        .collect::<String>();
                    let groxy_group_and_rules = format!(
                        "{}{}{}{}{}{}{}{}",
                        PROXY_GROUPS1,
                        joined_string,
                        PROXY_GROUPS2,
                        joined_string,
                        PROXY_GROUPS3,
                        PROXY_GROUPS4,
                        PROXY_GROUPS5,
                        RULES
                    );
                    if let Err(err) = writeln!(&mut file, "{}", groxy_group_and_rules) {
                        eprintln!("Error writing to file: {}", err);
                        continue;
                    }
                    proxy_name_vec.clear(); // 清空字符串向量，防止出现节点名和代理组中的节点不匹配
                }
                // 每写入一个 content，增加 content 计数
                content_count += 1;
            }
        }
        // 处理完一个 CIDR 后，重置 content_count
        content_count = 0;
    }
    Ok(())
}

fn delete_files_in_dir(dir_path: &str) -> io::Result<()> {
    // 如果目录不存在，则创建目录
    if !fs::metadata(dir_path).is_ok() {
        fs::create_dir_all(dir_path)?;
    }
    // 获取目录中的所有条目
    let entries = fs::read_dir(dir_path)?;

    // 遍历目录中的所有条目
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        // 检查条目是否为文件
        if path.is_file() {
            // 删除文件
            fs::remove_file(path)?;
        }
    }

    Ok(())
}

fn read_wireguard_key_parameters(file: &str) -> HashMap<String, String> {
    let mut wireguard_param = HashMap::new();
    let contents = fs::read_to_string(file).expect("无法读取文件");
    let lines: Vec<&str> = contents.lines().collect();
    let mut addresses = Vec::new();
    for line in lines {
        if line.starts_with("PrivateKey") {
            wireguard_param.insert(
                "PrivateKey".to_string(),
                line.replace(" ", "").replace("PrivateKey=", "").to_string(),
            );
        } else if line.starts_with("PublicKey") {
            wireguard_param.insert(
                "PublicKey".to_string(),
                line.replace(" ", "").replace("PublicKey=", "").to_string(),
            );
        } else if line.starts_with("Address") {
            let cleaned_line = line.replace(" ", "").replace("Address=", "");
            addresses.push(cleaned_line);
        } else if line.starts_with("MTU") {
            wireguard_param.insert(
                "MTU".to_string(),
                line.replace(" ", "").replace("MTU=", "").to_string(),
            );
        } else if line.starts_with("Endpoint") {
            let mut parts = line.trim().rsplitn(2, ':'); // 从Endpoint中切割出端口
            if let Some(port) = parts.next() {
                wireguard_param.insert("PORT".to_string(), port.to_string());
            } else {
                wireguard_param.insert("PORT".to_string(), "2408".to_string()); // 没有获取到端口，就设置一个默认的端口
            };
        }
    }
    // 将 addresses 合并成一个字符串，以逗号分隔
    let combined_addresses = addresses.join(",");
    wireguard_param.insert("Address".to_string(), combined_addresses);

    wireguard_param
}

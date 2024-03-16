mod clash_config;
mod clash_rules;
mod proxy_groups;

use clash_config::BASIC_INFO;
use clash_rules::RULES;
use ipnetwork::IpNetwork;
use proxy_groups::PROXY_GROUPS1; // 这个代理组需要添加节点的名称
use proxy_groups::PROXY_GROUPS2; // 这个代理组不需要添加节点的名称
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Write},
    str::FromStr,
};

fn main() -> io::Result<()> {
    /* 删除output目录中的所有文件 */
    let dir_path = "./output"; //指定目录
    delete_files_in_dir(dir_path)?;

    /* 读取wg-config.conf文件中的参数 */
    let wg_conf_file = "wg-config.conf";
    let param = read_wireguard_key_parameters(wg_conf_file);

    // 提取wg-config.conf文件中的远端公钥
    let peer_public_key = param.get("PublicKey").unwrap().trim();
    // 提取wg-config.conf文件中的本机私钥
    let private_key = param.get("PrivateKey").unwrap().trim();
    // 提取wg-config.conf文件中的本机组网IP(IPv4和IPv6)
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
    // 截取"/"前面的字符
    let ipv4 = addresses.0.split('/').next().unwrap().trim();
    let ipv6 = addresses.1.unwrap_or("").split('/').next().unwrap().trim(); // 如果没有ipv6的地址，则返回空字符串

    // clash中，wireguard协议的节点（json数据结构）
    let json_data = json!({"name": "wg", "type": "wireguard", "private-key": private_key,
        "server": "162.159.192.1", "port": 2408, "ip": ipv4, "public-key": peer_public_key, "udp": true});

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

    // 定义一个计数器来计算 node_info 写入的个数
    let mut write_count = 0;
    // 指定每个文件最多的 node_info 数量(这里硬性限制最多540个节点)
    let mut max_nodes_per_file: usize = ports.len() * 10;
    if max_nodes_per_file < 512 && ports.len() > 0 {
        max_nodes_per_file = 512;
    } else if ports.len() == 0 {
        println!("ports为空，无法生成Clash配置文件");
        return Ok(());
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
        // 获取斜杠之前的部分作为文件名的一部分
        let cidr_prefix = cidr.split('/').next().unwrap_or(&cidr);
        // 文件编号从1开始
        let mut file_no = 1;
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
                new_json_data["name"] = json!(proxy_name);
                proxy_name_vec.push(proxy_name.clone());
                if !ipv6.is_empty() {
                    new_json_data["ipv6"] = json!(ipv6);
                }
                // 节点信息（clash配置文件中，proxies:后面的节点信息）
                let node_info = format!("  - {}", serde_json::to_string(&new_json_data).unwrap());
                println!("{}", node_info);

                //如果write_count超过max_nodes_per_file(您设置的单个文件写入的上限)的数值，则切换到下一个文件，并清空proxy_name_vec向量的数据
                if write_count >= max_nodes_per_file {
                    write_count = 0; // 重置计数器
                    proxy_name_vec = Vec::new();
                    file_no += 1; // 切换到下一个文件
                }
                // 写入文件的文件名，假如该cidr内生成的节点太多，一个文件写不完，就酌情在文件名后面添加编号
                let mut file_name = format!("{}/{}", dir_path, cidr_prefix);
                // 这个条件用于判断写入的节点数量超过设置的单个文件写入的上限，则采用里面的编号
                if max_nodes_per_file > 512 && ports.len() <= 540 {
                    // 这里设置的值，是跟前面max_nodes_per_file设置的值有关
                    if file_no > 1 {
                        // 如果file_no大于1，则添加文件后缀编号
                        file_name.push_str(&format!("_{}", file_no));
                    } else {
                        // 如果file_no等于1，则默认1为文件后缀编号
                        file_name.push_str(&format!("_{}", "1"));
                    }
                }
                let file_path = format!("{}.yaml", file_name);

                // 检查文件是否存在
                let file_exists = fs::metadata(&file_path).is_ok();

                let mut file = match fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .append(file_exists) // 追加写入
                    .open(&file_path)
                {
                    Ok(file) => file,
                    Err(err) => {
                        eprintln!("Error opening file: {}", err);
                        continue;
                    }
                };

                // 写入clash基本配置信息(也就是BASIC_INFO)，注意：只有当文件不存在时，才写入BASIC_INFO
                if !file_exists {
                    if let Err(err) = writeln!(&mut file, "{}", BASIC_INFO) {
                        eprintln!("Error writing to file: {}", err);
                        continue;
                    }
                }
                // 正式将node_info(节点信息)写入文件中
                if let Err(err) = writeln!(&mut file, "{}", node_info) {
                    eprintln!("Error writing to file: {}", err);
                    continue; // 写入失败就不要执行后面的代码了
                }

                if write_count == max_nodes_per_file
                    || ((last_ip == ip || write_count == max_nodes_per_file - 1)
                        && port == &ports[ports.len() - 1])
                {
                    // 构建新的节点名称（在节点名称前面添加" - "，以及在节点名称后面换行）
                    let joined_node_string = proxy_name_vec
                        .iter() // 使用迭代器
                        .map(|s| format!("      - {}{}", s, "\n")) // 在每个元素前添加 " - "，并在后面添加 "\n"
                        .collect::<String>();

                    // proxy_groups1中，每个元素都在它的后面添加节点名称（这个分组才能选择节点）
                    let new_proxy_groups1: Vec<String> = PROXY_GROUPS1
                        .iter()
                        .map(|s| format!("{}{}", s, joined_node_string))
                        .collect();

                    // 将两个分组Vec连接起来
                    let joined_string =
                        format!("{}{}", new_proxy_groups1.join(""), PROXY_GROUPS2.join(""));

                    let groxy_groups_and_rules =
                        format!("proxy-groups:\n{}{}", joined_string, RULES);
                    // 将代理组和规则写入yaml文件中
                    if let Err(err) = writeln!(&mut file, "{}", groxy_groups_and_rules) {
                        eprintln!("Error writing to file: {}", err);
                        continue;
                    }
                    // 清空要写入"proxy-groups"的节点名称向量，防止出现proxies的节点名称跟代理组中的节点名称不匹配
                    proxy_name_vec.clear(); //也可以使用proxy_name_vec = Vec::new();
                }
                // 每写入一个 node_info ，就增加 write_count 计数
                write_count += 1;
            }
        }
        // 处理完一个 CIDR 后，重置 write_count
        write_count = 0;
    }
    Ok(())
}

/* 检查output文件是否存在，不存在就创建，如果存在，发现里面有文件就删除里面的所有文件 */
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

/* 读取wg-config.conf文件中的参数，选择性提取关键参数，返回一个HashMap */
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

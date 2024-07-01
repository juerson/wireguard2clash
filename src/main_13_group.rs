mod utils;

use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Write},
};

fn main() -> io::Result<()> {
    /* 删除目录中所有文件 */
    let dir_path: &str = "./output"; //指定目录
    utils::delete::delete_files_and_dir(dir_path)?;

    let wg_conf_file = "wg-config.conf";
    let param = utils::wireguard::get_parameters(wg_conf_file);
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
    let peer_public_key = param.get("PublicKey").unwrap().trim();
    let private_key = param.get("PrivateKey").unwrap().trim();

    // --------------------------------------------------------------------------------------------
    println!("——————————————————————————————————————————————————————————————————————————————");
    println!("选择 IPv4 CIDR，还是选择 IPv6 CIDR，生成Clash配置文件？");
    println!("——————————————————————————————————————————————————————————————————————————————");
    println!("1: IPv4 CIDR");
    println!("2: IPv6 CIDR");
    let ipv4_cidrs = vec![
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
    ];
    let ipv6_cidrs = vec!["2606:4700:d0::/48", "2606:4700:d1::/48"];
    let cidr_ranges = utils::vector::select_vector(&ipv4_cidrs, &ipv6_cidrs);
    // --------------------------------------------------------------------------------------------
    println!("——————————————————————————————————————————————————————————————————————————————");
    println!("选择Cloudflare的其中一个端口(UDP)，还是全部端口(共54个)，生成Clash配置文件？");
    println!("——————————————————————————————————————————————————————————————————————————————");
    println!("1: 单端口(端口由配置文件指定)");
    println!("2: 全端口(54个)");
    let single_ports: Vec<i32> = vec![param.get("PORT").unwrap().parse().unwrap()];
    let all_ports: Vec<i32> = vec![
        854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955,
        968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138,
        3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
        8854, 8886, 2408, 500, 4500, 1701,
    ];
    let ports = utils::vector::select_vector(&single_ports, &all_ports);
    // --------------------------------------------------------------------------------------------

    // clash中，wireguard协议的节点（json数据结构）
    let json_data = json!({"name": "wg", "type": "wireguard", "server": "162.159.192.1", "port": 2408, "ip": ipv4, "public-key": peer_public_key, "private-key": private_key, "udp": true, "mtu":1280});

    let ports_len = ports.len();
    let mut max_nodes: usize = ports_len * 5;
    // 限制每个clahs配置文件最大只能容纳300个节点
    if max_nodes <= 300 && ports_len > 0 {
        max_nodes = 300;
    } else if ports_len == 0 {
        println!("ports为空，无法生成Clash配置文件");
        return Ok(());
    }

    println!("——————————————————————————————————————————————————————————————————————————————");

    let endpoints = utils::ips::generate_ip_with_port(cidr_ranges.clone(), ports);

    let mut proxy_name_vec: Vec<String> = Vec::new();
    let mut nodes_count = 1; // 当前的节点数，计算节点数是否达到max_nodes的上限
    let mut file_count = 1; // 文件编号从1开始，当节点数达到max_nodes的上限时，切换到下一个文件

    // 最后一个元素，前提是endpoints不为空
    let last_endpoint = &endpoints[endpoints.len() - 1];

    for (ip, port) in endpoints.clone() {
        // 当前节点数达到max_nodes数的上限，则切换到下一个文件，并重置nodes_count的计数器
        if nodes_count > max_nodes {
            file_count += 1; // 切换到下一个文件
            nodes_count = 1; // 重置计数器
        }

        let mut new_json_data: Value = json_data.clone();

        /*
         * 将代理名称添加的proxy_name_vec中，
         */
        if ip.chars().filter(|&c| c == ':').count() > 4 {
            let mut parts = ip.splitn(3, ":");
            parts.next(); // 跳过第一个
            parts.next(); // 跳过第二个
            let part3_str = parts
                .next()
                .unwrap_or("")
                .splitn(2, ":")
                .next()
                .unwrap_or("");
            let proxy_name: String = format!("warp-ipv6-{}-{:03}", part3_str, nodes_count);
            new_json_data["name"] = json!(proxy_name);
            if !proxy_name_vec.contains(&proxy_name) {
                proxy_name_vec.push(proxy_name.clone());
            } else {
                continue;
            }
        } else {
            let proxy_name = format!("warp-{}:{}", ip.clone(), port.clone());
            new_json_data["name"] = json!(proxy_name);
            if !proxy_name_vec.contains(&proxy_name) {
                proxy_name_vec.push(proxy_name.clone());
            } else {
                continue;
            }
        }
        new_json_data["server"] = json!(ip);
        new_json_data["port"] = json!(port);
        if !ipv6.is_empty() {
            new_json_data["ipv6"] = json!(ipv6);
        }
        // 节点信息（clash配置文件中，proxies:后面的节点信息）
        let node_info = format!("  - {}", serde_json::to_string(&new_json_data).unwrap());
        /*
         * 写入文件的路径
         */
        let file_path = rename_file(dir_path, file_count);
        // 检查文件是否存在
        let file_exists = fs::metadata(&file_path).is_ok();
        // 文件句柄
        let mut file = match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(file_exists) // 文件存在就追加写入
            .open(&file_path)
        {
            Ok(file) => file,
            Err(_) => continue,
        };
        /*
         * 如果是新创建的文件，则先写入clash配置文件的基本信息（clash头部信息）
         */
        if !file_exists {
            if let Err(err) = writeln!(&mut file, "{}", utils::base::BASIC_INFO) {
                eprintln!("Error writing to file: {}", err);
                continue;
            }
        }
        /*
         * 写入clash的节点信息
         */
        if let Err(err) = writeln!(&mut file, "{}", node_info) {
            eprintln!("Error writing to file: {}", err);
            continue;
        }
        /*
         * nodes_count达到最大节点数，或者当前节点为最后一个节点就写入剩下的clash内容(代理组和规则)
         */
        if nodes_count == max_nodes || (ip, port) == *last_endpoint {
            // 将proxy_name_vec中的节点名称插入代理组，构建成新的代理组和规则
            let groxy_groups_and_rules = build_proxy_group_and_rules(&proxy_name_vec);
            println!("写入文件\"{}\"成功！", file_path);
            // 将代理组和规则写入yaml文件中
            if let Err(err) = writeln!(&mut file, "{}", groxy_groups_and_rules) {
                eprintln!("Error writing to file: {}", err);
                continue;
            }
            // 清空要写入"proxy-groups"的proxy_name_vec，防止出现proxies的节点名称跟代理组中的节点名称不匹配
            proxy_name_vec.clear(); //也可以使用proxy_name_vec = Vec::new();
        }
        nodes_count += 1;
    }

    Ok(())
}

fn build_proxy_group_and_rules(proxy_name_vec: &Vec<String>) -> String {
    // 构建新的节点名称（在节点名称前面添加" - "，以及在节点名称后面换行）
    let joined_node_string = proxy_name_vec
        .iter() // 使用迭代器
        .map(|s| format!("      - {}{}", s, "\n")) // 在每个元素前添加 " - "，并在后面添加 "\n"
        .collect::<String>();

    let groxy_groups_and_rules = format!(
        "proxy-groups:\n{}{}{}",
        utils::config::PROXY_GROUPS1
            .iter()
            .map(|s| format!("{}{}", s, joined_node_string))
            .collect::<Vec<String>>()
            .join(""),
        utils::config::PROXY_GROUPS2.join(""),
        utils::config::RULES
    );
    groxy_groups_and_rules
}

fn rename_file(dir_path: &str, file_count: i32) -> String {
    let mut file_name = format!("{}/warp", dir_path);
    if file_count > 1 {
        // 如果file_count大于1，则添加文件后缀编号
        file_name.push_str(&format!("-{:03}", file_count));
    } else {
        // 如果file_count等于1，则默认1为文件后缀编号
        file_name.push_str(&format!("-{}", "001"));
    }

    let file_path = format!("{}.yaml", file_name);

    file_path
}

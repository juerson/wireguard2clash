mod utils;

use serde_json::{json, Value};
use std::{
    error::Error,
    fs,
    io::{self, Write},
    process,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    /* 获取丢包率为0%，延迟小于500ms的数据 */
    let file_path = "result.csv";
    let filter_delay = input()?; // 默认 500ms
    let endpoints: Vec<String> = utils::csv::get_endpoints(file_path, filter_delay);
    let endpoints_len = endpoints.len();

    /*
     * 删除output目录中的所有文件、文件夹
     */
    let dir_path = "./output"; //指定目录
    utils::delete::delete_files_and_dir(dir_path)?;

    // csv文件中，没有读取到数据，强行终止程序并退出
    if endpoints_len == 0 {
        process::exit(1);
    }

    // ——————————————————————————————————————————————————————————————————————————————————————————
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
    /*
     * 获取ipv4、ipv6、peer_public_key、private_key
     */
    let ipv4 = addresses.0.split('/').next().unwrap().trim();
    let ipv6 = addresses.1.unwrap_or("").split('/').next().unwrap().trim(); // 如果没有ipv6的地址，则返回空字符串
    let peer_public_key = param.get("PublicKey").unwrap().trim();
    let private_key = param.get("PrivateKey").unwrap().trim();
    // ——————————————————————————————————————————————————————————————————————————————————————————

    // clash中，wireguard协议的节点（json数据结构）
    let json_data: Value = json!({"name": "wg", "type": "wireguard", "server": "162.159.192.1", "port": 2408, "ip": ipv4, "public-key": peer_public_key, "private-key": private_key, "udp": true, "mtu":1280});

    let mut proxy_name_vec: Vec<String> = Vec::new();
    let max_nodes: usize = 300; // 每个文件最大节点数
    let mut nodes_count = 1; // 当前的节点数，计算节点数是否达到max_nodes的上限
    let mut file_count = 1; // 文件编号从1开始，当节点数达到max_nodes的上限时，切换到下一个文件
    
    println!("——————————————————————————————————————————————————————————————————————————————————");

    // 最后一个元素，前提是endpoints不为空
    let last_endpoint = &endpoints[endpoints_len - 1];
    for endpoint in endpoints.clone() {
        // 当前节点数达到max_nodes数的上限，则切换到下一个文件，并重置nodes_count的计数器
        if nodes_count > max_nodes {
            file_count += 1; // 切换到下一个文件
            nodes_count = 1; // 重置计数器
        }

        let (ip, port) = split_ip_and_port(&endpoint); // 分割IP和PORT
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
            let proxy_name: String = format!("warp-ipv6-{}-{}", part3_str, nodes_count);
            new_json_data["name"] = json!(proxy_name);
            if !proxy_name_vec.contains(&proxy_name) {
                proxy_name_vec.push(proxy_name.clone());
            } else {
                continue;
            }
        } else {
            let proxy_name = format!("warp-{}", endpoint.clone());
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
         * 写入文件中
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
        if nodes_count == max_nodes || endpoint == last_endpoint.to_string() {
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

fn input() -> Result<u16, Box<dyn Error>> {
    print!("请输入最大延迟数，当延迟小于这个数才保留(单位：ms，留空或非数字情况默认为500)：");
    io::stdout().flush().expect("Failed to flush stdout");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();
    let filter_delay = match input.parse::<u16>() {
        Ok(n) => n,
        Err(_) if input.is_empty() || !input.chars().all(|c| c.is_digit(10)) => 500,
        Err(e) => return Err(e.into()),
    };
    Ok(filter_delay)
}

// 将节点名称添加到指定的代理组中，然后跟规则合并起来，以字符串形式返回
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

// 分割出IP和PORT,支持合法的IPv6:PORT分割出IP和PORT，并返回IP和PORT
fn split_ip_and_port(endpoint: &str) -> (&str, i32) {
    let mut parts = endpoint.rsplitn(2, ':');
    // 端口
    let port = parts
        .next()
        .unwrap_or("2408")
        .parse()
        .unwrap_or_else(|_| 2408);
    // IP地址
    let ip = parts
        .next()
        .unwrap_or("")
        .trim_start_matches('[')
        .trim_end_matches(']');

    (ip, port)
}

fn rename_file(dir_path: &str, file_count: i32) -> String {
    let mut file_name = format!("{}/warp", dir_path);
    if file_count > 1 {
        // 如果file_count大于1，则添加文件后缀编号
        file_name.push_str(&format!("-csv-{:03}", file_count));
    } else {
        // 如果file_count等于1，则默认1为文件后缀编号
        file_name.push_str(&format!("-csv-{}", "001"));
    }
    let file_path = format!("{}.yaml", file_name);

    file_path
}

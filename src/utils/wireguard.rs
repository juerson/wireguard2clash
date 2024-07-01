use std::collections::HashMap;
use std::fs;

#[allow(dead_code)]
pub fn get_parameters(file: &str) -> HashMap<String, String> {
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

use ipnetwork::{IpNetwork, Ipv6Network};
use rand::{seq::SliceRandom, thread_rng, Rng};
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::net::Ipv6Addr;
use std::str::FromStr;

#[allow(dead_code)]
pub fn generate_ip_with_port(cidrs: Vec<&str>, ports: Vec<i32>) -> Vec<(String, i32)> {
    let mut datas: BTreeSet<(String, i32)> = BTreeSet::new();
    let ipv6_address_count = 500; // 生成500个IPv6地址
    for cidr in cidrs {
        let ip_network: IpNetwork = match IpNetwork::from_str(&cidr) {
            Ok(network) => network,
            Err(_) => continue,
        };
        let mut unique_ips: HashSet<String> = HashSet::new();
        match ip_network {
            IpNetwork::V4(network) => {
                for ip in network.iter() {
                    unique_ips.insert(ip.to_string());
                }
            }
            IpNetwork::V6(network) => {
                while unique_ips.len() < ipv6_address_count {
                    let ip = generate_random_ipv6_addresses(&network);
                    unique_ips.insert(ip.to_string());
                }
            }
        }
        let ips: Vec<String> = unique_ips.into_iter().collect();
        for ip in ips.clone() {
            for port in ports.clone() {
                datas.insert((ip.clone(), port));
            }
        }
    }
    // 将 BTreeSet 转换为 Vec
    let mut endpoints: Vec<(String, i32)> = datas.clone().into_iter().collect();
    let mut rng = thread_rng();
    endpoints.shuffle(&mut rng);

    endpoints
}

// 使用IPv6 CIDR生成随机的IPv6地址(这里只生成一个IPv6地址)
fn generate_random_ipv6_addresses(network: &Ipv6Network) -> Ipv6Addr {
    let mut rng = rand::thread_rng();
    let prefix_len = network.prefix();
    let network_addr = network.network().octets();

    let mut ip_addr = [0u8; 16];

    // 复制网络地址中的前缀部分
    let bytes_to_copy = (prefix_len / 8) as usize;
    ip_addr[..bytes_to_copy].copy_from_slice(&network_addr[..bytes_to_copy]);

    // 随机排列剩余部分，确保只有最后4个部分被随机化
    for i in bytes_to_copy..16 {
        if i >= 8 {
            ip_addr[i] = rng.gen();
        } else {
            ip_addr[i] = network_addr[i];
        }
    }

    Ipv6Addr::from(ip_addr)
}
use std::{
    fmt::Display,
    io::{self, Write},
};

fn main() {
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
    println!("1: IPv4 CIDR");
    println!("2: IPv6 CIDR");
    let selected_cidrs_vec: Vec<&str> = select_vector(&ipv4_cidrs, &ipv6_cidrs);
    println!("最终选择的CIDRs Vector: {:?}", selected_cidrs_vec);

    let ports: Vec<i32> = vec![2048];
    let all_ports: Vec<i32> = vec![
        854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955,
        968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138,
        3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742,
        8854, 8886, 2408, 500, 4500, 1701,
    ];
    println!("1: 单端口(端口由配置文件指定)");
    println!("2: 全端口(54个)");
    let selected_ports_vec: Vec<i32> = select_vector(&ports, &all_ports);
    println!("最终选择的PORTs Vector: {:?}", selected_ports_vec);
}

fn select_vector<'a, T: Display>(vec1: &'a Vec<T>, vec2: &'a Vec<T>) -> Vec<T>
where
    T: Clone,
{
    loop {
        print!("选择菜单的选项：");
        io::stdout().flush().expect("Failed to flush stdout");
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read line");

        let input = input.trim();

        match input {
            "1" => return vec1.clone(),
            "2" => return vec2.clone(),
            _ => {}
        }
    }
}

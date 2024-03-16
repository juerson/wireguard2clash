const NODE_SELECTION: &str = r#"  - name: 🔰 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - 🎯 全球直连
"#;

const AUTO_SELECTION: &str = r#"  - name: ♻️ 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    proxies:
"#;

const NETFLIX: &str = r#"  - name: 🎥 NETFLIX
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;

const TELEGRAM: &str = r#"  - name: 📲 电报信息
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;

const MICROSOFT_SERVICES: &str = r#"  - name: Ⓜ️ 微软服务
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;

const APPLE_SERVICES: &str = r#"  - name: 🍎 苹果服务
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;

const FOREIGN_MEDIA: &str = r#"  - name: 🌍 国外媒体
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;

const HOMELESS_EXILE: &str = r#"  - name: 🐟 漏网之鱼
    type: select
    proxies:
      - 🔰 节点选择
      - 🎯 全球直连
      - ♻️ 自动选择
"#;

// 以下不用添加节点

const NATIONAL_MEDIA: &str = r#"  - name: 🌏 国内媒体
    type: select
    proxies:
      - 🎯 全球直连
      - 🔰 节点选择
"#;

const OPERATION_HIJACKING: &str = r#"  - name: 🚫 运营劫持
    type: select
    proxies:
      - 🛑 全球拦截
      - 🎯 全球直连
      - 🔰 节点选择
"#;

const ADBLOCK: &str = r#"  - name: ⛔️ 广告拦截
    type: select
    proxies:
      - 🛑 全球拦截
      - 🎯 全球直连
      - 🔰 节点选择
"#;

const GLOBAL_INTERCEPTION: &str = r#"  - name: 🛑 全球拦截
    type: select
    proxies:
      - REJECT
      - DIRECT
"#;

const GLOBAL_DIRECT: &str = r#"  - name: 🎯 全球直连
    type: select
    proxies:
      - DIRECT
"#;

pub const PROXY_GROUPS1: [&str; 8] = [
    NODE_SELECTION,
    AUTO_SELECTION,
    NETFLIX,
    TELEGRAM,
    MICROSOFT_SERVICES,
    APPLE_SERVICES,
    HOMELESS_EXILE,
    FOREIGN_MEDIA,
];

pub const PROXY_GROUPS2: [&str; 5] = [
    NATIONAL_MEDIA,
    ADBLOCK,
    OPERATION_HIJACKING,
    GLOBAL_INTERCEPTION,
    GLOBAL_DIRECT,
];

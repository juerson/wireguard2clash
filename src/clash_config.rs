pub const BASIC_INFO: &str = r#"port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
global-client-fingerprint: chrome
dns:
  enable: true
  listen: :53
  prefer-h3: true
  ipv6: true
  default-nameserver: ["223.5.5.5","180.184.1.1"]
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - localhost.ptlogin2.qq.com
    - +.srv.nintendo.net
    - +.stun.playstation.net
    - +.msftconnecttest.com
    - +.msftncsi.com
    - +.xboxlive.com
    - msftconnecttest.com
    - xbox.*.microsoft.com
    - "*.battlenet.com.cn"
    - "*.battlenet.com"
    - "*.blzstatic.cn"
    - "*.battle.net"
  nameserver-policy:
    '+.baidu.com': '180.76.76.76'
    '+.apple.com,+.icloud.com,+.bing.com': '8.8.8.8'
    'geosite:geolocation-cn': ['https://dns.alidns.com/dns-query','https://doh.pub/dns-query','https://doh.360.cn/dns-query']
    'geosite:geolocation-!cn': ['tls://8.8.8.8', 'https://1.0.0.1/dns-query']
    'www.baidu.com,+.google.cn': ['https://doh.pub/dns-query','https://dns.alidns.com/dns-query']
    'geosite:private,apple': https://dns.alidns.com/dns-query
  nameserver: ['https://doh.pub/dns-query','https://dns.alidns.com/dns-query']
  fallback: ['tls://1.0.0.1','tls://8.8.4.4']
  proxy-server-nameserver: ['https://doh.pub/dns-query','tls://1.0.0.1']
  fallback-filter:
    geoip: true
    geoip-code: CN
    geosite: ['gfw']
    ipcidr: ['240.0.0.0/4','0.0.0.0/32']
    domain: ["+.google.com","+.facebook.com","+.youtube.com"]
proxies:"#;

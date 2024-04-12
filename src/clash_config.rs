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
  default-nameserver: [223.5.5.5, 119.29.29.29]
  ipv6: false
  enhanced-mode: fake-ip
  fake-ip-filter: ["*.n.n.srv.nintendo.net", +.stun.playstation.net, xbox.*.*.microsoft.com, "*.msftncsi.com", "*.msftconnecttest.com", WORKGROUP, "*.lan", stun.*.*.*, stun.*.*, time.windows.com, time.nist.gov, time.apple.com, time.asia.apple.com, "*.ntp.org.cn", "*.openwrt.pool.ntp.org", time1.cloud.tencent.com, time.ustc.edu.cn, pool.ntp.org, ntp.ubuntu.com, "*.*.xboxlive.com", speedtest.cros.wr.pvp.net]
  nameserver: [tls://223.5.5.5:853, https://223.6.6.6/dns-query, https://120.53.53.53/dns-query]
  nameserver-policy: {+.tmall.com: 223.5.5.5, +.taobao.com: 223.5.5.5, +.alicdn.com: 223.5.5.5, +.aliyun.com: 223.5.5.5, +.alipay.com: 223.5.5.5, +.alibaba.com: 223.5.5.5, +.qq.com: 119.29.29.29, +.tencent.com: 119.29.29.29, +.weixin.com: 119.29.29.29, +.qpic.cn: 119.29.29.29, +.jd.com: 119.29.29.29, +.bilibili.com: 119.29.29.29, +.hdslb.com: 119.29.29.29, +.163.com: 119.29.29.29, +.126.com: 119.29.29.29, +.126.net: 119.29.29.29, +.127.net: 119.29.29.29, +.netease.com: 119.29.29.29, +.baidu.com: 223.5.5.5, +.bdstatic.com: 223.5.5.5, +.bilivideo.+: 119.29.29.29, +.iqiyi.com: 119.29.29.29, +.douyinvod.com: 180.184.1.1, +.douyin.com: 180.184.1.1, +.douyincdn.com: 180.184.1.1, +.douyinpic.com: 180.184.1.1, +.feishu.cn: 180.184.1.1}
  fallback: [tls://101.101.101.101:853,https://101.101.101.101/dns-query, https://public.dns.iij.jp/dns-query, https://208.67.220.220/dns-query]
  fallback-filter: {geoip: true, ipcidr: [240.0.0.0/4, 0.0.0.0/32, 127.0.0.1/32], domain: [+.google.com, +.facebook.com, +.twitter.com, +.youtube.com, +.xn--ngstr-lra8j.com, +.google.cn, +.googleapis.cn, +.googleapis.com, +.gvt1.com, +.paoluz.com, +.paoluz.link, +.paoluz.xyz, +.sodacity-funk.xyz, +.nloli.xyz, +.jsdelivr.net, +.proton.me]}
proxies:"#;
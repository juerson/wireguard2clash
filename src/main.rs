use ipnetwork::IpNetwork;
use serde_json::json;
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Write},
    str::FromStr,
};

const BASIC_INFO: &str = r#"port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: :9090
dns:
  enabled: true
  nameserver:
    - 119.29.29.29
    - 223.5.5.5
  fallback:
    - 8.8.8.8
    - 8.8.4.4
    - tls://1.0.0.1:853
    - tls://dns.google:853
proxies:"#;
const PROXY_GROUPS1: &str = r#"proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - 自动选择
      - DIRECT
"#;
const PROXY_GROUPS2: &str = r#"  - name: 自动选择
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 1000
    tolerance: 50
    proxies:
"#;
const RULES: &str = r#"rules:
  - DOMAIN-SUFFIX,1password.com,DIRECT
  - DOMAIN-SUFFIX,vultr.com,DIRECT
  - DOMAIN-SUFFIX,mb3admin.com,DIRECT
  - DOMAIN-SUFFIX,rixcloud.io,DIRECT
  - DOMAIN-SUFFIX,tempestapp.io,DIRECT
  - DOMAIN-SUFFIX,baidu-int.com,DIRECT
  - DOMAIN-SUFFIX,erebor.douban.com,DIRECT
  - DOMAIN,mtalk.google.com,DIRECT
  - DOMAIN,alt1-mtalk.google.com,DIRECT
  - DOMAIN,alt2-mtalk.google.com,DIRECT
  - DOMAIN,alt3-mtalk.google.com,DIRECT
  - DOMAIN,alt4-mtalk.google.com,DIRECT
  - DOMAIN,alt5-mtalk.google.com,DIRECT
  - DOMAIN,alt6-mtalk.google.com,DIRECT
  - DOMAIN,alt7-mtalk.google.com,DIRECT
  - DOMAIN,alt8-mtalk.google.com,DIRECT
  - DOMAIN,alt9-mtalk.google.com,DIRECT
  - DOMAIN-SUFFIX,cibntv.net,DIRECT
  - DOMAIN-SUFFIX,cdn.bcebos.com,DIRECT
  - DOMAIN-SUFFIX,mmstat.com,DIRECT
  - DOMAIN-SUFFIX,hitv.com,DIRECT
  - DOMAIN-SUFFIX,mgtv.com,DIRECT
  - DOMAIN-SUFFIX,miguvideo.com,DIRECT
  - DOMAIN-SUFFIX,docin.com,DIRECT
  - DOMAIN-SUFFIX,iqiyipic.com,DIRECT
  - DOMAIN,captive.apple.com,DIRECT
  - DOMAIN,time-ios.apple.com,DIRECT
  - DOMAIN-SUFFIX,gateway.push-apple.com.akadns.net,DIRECT
  - DOMAIN-SUFFIX,12306.cn,DIRECT
  - DOMAIN-SUFFIX,12306.com,DIRECT
  - DOMAIN-SUFFIX,126.net,DIRECT
  - DOMAIN-SUFFIX,163.com,DIRECT
  - DOMAIN-SUFFIX,360.cn,DIRECT
  - DOMAIN-SUFFIX,360.com,DIRECT
  - DOMAIN-SUFFIX,360buy.com,DIRECT
  - DOMAIN-SUFFIX,360buyimg.com,DIRECT
  - DOMAIN-SUFFIX,36kr.com,DIRECT
  - DOMAIN-SUFFIX,51ym.me,DIRECT
  - DOMAIN-SUFFIX,58.com,DIRECT
  - DOMAIN-SUFFIX,8686c.com,DIRECT
  - DOMAIN-SUFFIX,abercrombie.com,DIRECT
  - DOMAIN-SUFFIX,acfun.tv,DIRECT
  - DOMAIN-SUFFIX,adobesc.com,DIRECT
  - DOMAIN-SUFFIX,air-matters.com,DIRECT
  - DOMAIN-SUFFIX,air-matters.io,DIRECT
  - DOMAIN-SUFFIX,aixifan.com,DIRECT
  - DOMAIN-SUFFIX,akadns.net,DIRECT
  - DOMAIN-SUFFIX,alibabacloud.com,DIRECT
  - DOMAIN-SUFFIX,alicdn.com,DIRECT
  - DOMAIN-SUFFIX,alipay.com,DIRECT
  - DOMAIN-SUFFIX,alipayobjects.com,DIRECT
  - DOMAIN-SUFFIX,aliyun.com,DIRECT
  - DOMAIN-SUFFIX,aliyuncs.com,DIRECT
  - DOMAIN-SUFFIX,amap.com,DIRECT
  - DOMAIN-SUFFIX,appshike.com,DIRECT
  - DOMAIN-SUFFIX,appstore.com,DIRECT
  - DOMAIN-SUFFIX,autonavi.com,DIRECT
  - DOMAIN-SUFFIX,aweme.snssdk.com,DIRECT
  - DOMAIN-SUFFIX,bababian.com,DIRECT
  - DOMAIN-SUFFIX,baidu.com,DIRECT
  - DOMAIN-SUFFIX,baidupcs.com,DIRECT
  - DOMAIN-SUFFIX,baiducotent.com,DIRECT
  - DOMAIN-SUFFIX,baidustatic.com,DIRECT
  - DOMAIN-SUFFIX,bcebos.com,DIRECT
  - DOMAIN-SUFFIX,gshifen.com,DIRECT
  - DOMAIN-SUFFIX,popin.cc,DIRECT
  - DOMAIN-SUFFIX,shifen.com,DIRECT
  - DOMAIN-SUFFIX,wshifen.com,DIRECT
  - DOMAIN-SUFFIX,bdimg.com,DIRECT
  - DOMAIN-SUFFIX,bdstatic.com,DIRECT
  - DOMAIN-SUFFIX,beatsbydre.com,DIRECT
  - DOMAIN-SUFFIX,bet365.com,DIRECT
  - DOMAIN-SUFFIX,broadcasthe.net,DIRECT
  - DOMAIN-SUFFIX,caiyunapp.com,DIRECT
  - DOMAIN-SUFFIX,ccgslb.com,DIRECT
  - DOMAIN-SUFFIX,ccgslb.net,DIRECT
  - DOMAIN-SUFFIX,chinacache.net,DIRECT
  - DOMAIN-SUFFIX,chunbo.com,DIRECT
  - DOMAIN-SUFFIX,chunboimg.com,DIRECT
  - DOMAIN-SUFFIX,clashroyaleapp.com,DIRECT
  - DOMAIN-SUFFIX,clouddn.com,DIRECT
  - DOMAIN-SUFFIX,cloudsigma.com,DIRECT
  - DOMAIN-SUFFIX,cloudxns.net,DIRECT
  - DOMAIN-SUFFIX,cmct.tv,DIRECT
  - DOMAIN-SUFFIX,cmfu.com,DIRECT
  - DOMAIN-SUFFIX,cnbeta.com,DIRECT
  - DOMAIN-SUFFIX,cnbetacdn.com,DIRECT
  - DOMAIN-SUFFIX,chdbits.co,DIRECT
  - DOMAIN-SUFFIX,cnlang.org,DIRECT
  - DOMAIN-SUFFIX,cz88.net,DIRECT
  - DOMAIN-SUFFIX,dct-cloud.com,DIRECT
  - DOMAIN-SUFFIX,didialift.com,DIRECT
  - DOMAIN-SUFFIX,digicert.com,DIRECT
  - DOMAIN-SUFFIX,douban.com,DIRECT
  - DOMAIN-SUFFIX,doubanio.com,DIRECT
  - DOMAIN-SUFFIX,douyin.com,DIRECT
  - DOMAIN-SUFFIX,douyu.com,DIRECT
  - DOMAIN-SUFFIX,douyu.tv,DIRECT
  - DOMAIN-SUFFIX,douyutv.com,DIRECT
  - DOMAIN-SUFFIX,duokan.com,DIRECT
  - DOMAIN-SUFFIX,duoshuo.com,DIRECT
  - DOMAIN-SUFFIX,dytt8.net,DIRECT
  - DOMAIN-SUFFIX,easou.com,DIRECT
  - DOMAIN-SUFFIX,ecitic.com,DIRECT
  - DOMAIN-SUFFIX,ecitic.net,DIRECT
  - DOMAIN-SUFFIX,eudic.net,DIRECT
  - DOMAIN-SUFFIX,ewqcxz.com,DIRECT
  - DOMAIN-SUFFIX,feng.com,DIRECT
  - DOMAIN-SUFFIX,fir.im,DIRECT
  - DOMAIN-SUFFIX,firefox.com,DIRECT
  - DOMAIN-SUFFIX,frdic.com,DIRECT
  - DOMAIN-SUFFIX,fresh-ideas.cc,DIRECT
  - DOMAIN-SUFFIX,gameloft.com,DIRECT
  - DOMAIN-SUFFIX,geetest.com,DIRECT
  - DOMAIN-SUFFIX,godic.net,DIRECT
  - DOMAIN-SUFFIX,goodread.com,DIRECT
  - DOMAIN-SUFFIX,gtimg.com,DIRECT
  - DOMAIN-SUFFIX,haibian.com,DIRECT
  - DOMAIN-SUFFIX,hao123.com,DIRECT
  - DOMAIN-SUFFIX,haosou.com,DIRECT
  - DOMAIN-SUFFIX,hdchina.org,DIRECT
  - DOMAIN-SUFFIX,hdcmct.org,DIRECT
  - DOMAIN-SUFFIX,hkserversolution.com,DIRECT
  - DOMAIN-SUFFIX,hollisterco.com,DIRECT
  - DOMAIN-SUFFIX,hongxiu.com,DIRECT
  - DOMAIN-SUFFIX,hxcdn.net,DIRECT
  - DOMAIN-SUFFIX,icedropper.com,DIRECT
  - DOMAIN-SUFFIX,iciba.com,DIRECT
  - DOMAIN-SUFFIX,ifeng.com,DIRECT
  - DOMAIN-SUFFIX,ifengimg.com,DIRECT
  - DOMAIN-SUFFIX,images-amazon.com,DIRECT
  - DOMAIN-SUFFIX,img4me.com,DIRECT
  - DOMAIN-SUFFIX,ithome.com,DIRECT
  - DOMAIN-SUFFIX,ixdzs.com,DIRECT
  - DOMAIN-SUFFIX,jd.com,DIRECT
  - DOMAIN-SUFFIX,jd.hk,DIRECT
  - DOMAIN-SUFFIX,jianshu.com,DIRECT
  - DOMAIN-SUFFIX,jianshu.io,DIRECT
  - DOMAIN-SUFFIX,jianshuapi.com,DIRECT
  - DOMAIN-SUFFIX,jiathis.com,DIRECT
  - DOMAIN-SUFFIX,jomodns.com,DIRECT
  - DOMAIN-SUFFIX,jsboxbbs.com,DIRECT
  - DOMAIN-SUFFIX,knewone.com,DIRECT
  - DOMAIN-SUFFIX,kuaidi100.com,DIRECT
  - DOMAIN-SUFFIX,kugou.com,DIRECT
  - DOMAIN-SUFFIX,lecloud.com,DIRECT
  - DOMAIN-SUFFIX,lemicp.com,DIRECT
  - DOMAIN-SUFFIX,letv.com,DIRECT
  - DOMAIN-SUFFIX,letvcloud.com,DIRECT
  - DOMAIN-SUFFIX,liyuans.com,DIRECT
  - DOMAIN-SUFFIX,lizhi.io,DIRECT
  - DOMAIN-SUFFIX,localizecdn.com,DIRECT
  - DOMAIN-SUFFIX,lucifr.com,DIRECT
  - DOMAIN-SUFFIX,luoo.net,DIRECT
  - DOMAIN-SUFFIX,lxdns.com,DIRECT
  - DOMAIN-SUFFIX,mai.tn,DIRECT
  - DOMAIN-SUFFIX,meizu.com,DIRECT
  - DOMAIN-SUFFIX,metatrader4.com,DIRECT
  - DOMAIN-SUFFIX,metatrader5.com,DIRECT
  - DOMAIN-SUFFIX,mi.com,DIRECT
  - DOMAIN-SUFFIX,miaopai.com,DIRECT
  - DOMAIN-SUFFIX,miui.com,DIRECT
  - DOMAIN-SUFFIX,miwifi.com,DIRECT
  - DOMAIN-SUFFIX,mob.com,DIRECT
  - DOMAIN-SUFFIX,moji.com,DIRECT
  - DOMAIN-SUFFIX,moke.com,DIRECT
  - DOMAIN-SUFFIX,mxhichina.com,DIRECT
  - DOMAIN-SUFFIX,myqcloud.com,DIRECT
  - DOMAIN-SUFFIX,myunlu.com,DIRECT
  - DOMAIN-SUFFIX,ngabbs.com,DIRECT
  - DOMAIN-SUFFIX,netease.com,DIRECT
  - DOMAIN-SUFFIX,nfoservers.com,DIRECT
  - DOMAIN-SUFFIX,nssurge.com,DIRECT
  - DOMAIN-SUFFIX,nuomi.com,DIRECT
  - DOMAIN-SUFFIX,ourbits.club,DIRECT
  - DOMAIN-SUFFIX,ourdvs.com,DIRECT
  - DOMAIN-SUFFIX,passthepopcorn.me,DIRECT
  - DOMAIN-SUFFIX,pgyer.com,DIRECT
  - DOMAIN-SUFFIX,pniao.com,DIRECT
  - DOMAIN-SUFFIX,privatehd.to,DIRECT
  - DOMAIN-SUFFIX,pstatp.com,DIRECT
  - DOMAIN-SUFFIX,qbox.me,DIRECT
  - DOMAIN-SUFFIX,qcloud.com,DIRECT
  - DOMAIN-SUFFIX,qdaily.com,DIRECT
  - DOMAIN-SUFFIX,qdmm.com,DIRECT
  - DOMAIN-SUFFIX,qhimg.com,DIRECT
  - DOMAIN-SUFFIX,qidian.com,DIRECT
  - DOMAIN-SUFFIX,qihucdn.com,DIRECT
  - DOMAIN-SUFFIX,qin.io,DIRECT
  - DOMAIN-SUFFIX,qingmang.me,DIRECT
  - DOMAIN-SUFFIX,qingmang.mobi,DIRECT
  - DOMAIN-SUFFIX,qiniucdn.com,DIRECT
  - DOMAIN-SUFFIX,qiniudn.com,DIRECT
  - DOMAIN-SUFFIX,qq.com,DIRECT
  - DOMAIN-SUFFIX,qqurl.com,DIRECT
  - DOMAIN-SUFFIX,rarbg.to,DIRECT
  - DOMAIN-SUFFIX,redacted.ch,DIRECT
  - DOMAIN-SUFFIX,rrmj.tv,DIRECT
  - DOMAIN-SUFFIX,ruguoapp.com,DIRECT
  - DOMAIN-SUFFIX,sandai.net,DIRECT
  - DOMAIN-SUFFIX,sf-express.com,DIRECT
  - DOMAIN-SUFFIX,sinaapp.com,DIRECT
  - DOMAIN-SUFFIX,sinaimg.cn,DIRECT
  - DOMAIN-SUFFIX,sinaimg.com,DIRECT
  - DOMAIN-SUFFIX,sm.ms,DIRECT
  - DOMAIN-SUFFIX,smzdm.com,DIRECT
  - DOMAIN-SUFFIX,snssdk.com,DIRECT
  - DOMAIN-SUFFIX,snwx.com,DIRECT
  - DOMAIN-SUFFIX,so.com,DIRECT
  - DOMAIN-SUFFIX,sogou.com,DIRECT
  - DOMAIN-SUFFIX,sogoucdn.com,DIRECT
  - DOMAIN-SUFFIX,sohu.com,DIRECT
  - DOMAIN-SUFFIX,soku.com,DIRECT
  - DOMAIN-SUFFIX,soso.com,DIRECT
  - DOMAIN-SUFFIX,sspai.com,DIRECT
  - DOMAIN-SUFFIX,startssl.com,DIRECT
  - DOMAIN-SUFFIX,suning.com,DIRECT
  - DOMAIN-SUFFIX,symcd.com,DIRECT
  - DOMAIN-SUFFIX,taobao.com,DIRECT
  - DOMAIN-SUFFIX,tawk.link,DIRECT
  - DOMAIN-SUFFIX,tawk.to,DIRECT
  - DOMAIN-SUFFIX,tenpay.com,DIRECT
  - DOMAIN-SUFFIX,tietuku.com,DIRECT
  - DOMAIN-SUFFIX,tmall.com,DIRECT
  - DOMAIN-SUFFIX,tmzvps.com,DIRECT
  - DOMAIN-SUFFIX,trello.com,DIRECT
  - DOMAIN-SUFFIX,trellocdn.com,DIRECT
  - DOMAIN-SUFFIX,totheglory.im,DIRECT
  - DOMAIN-SUFFIX,ttmeiju.com,DIRECT
  - DOMAIN-SUFFIX,tudou.com,DIRECT
  - DOMAIN-SUFFIX,udache.com,DIRECT
  - DOMAIN-SUFFIX,umengcloud.com,DIRECT
  - DOMAIN-SUFFIX,upaiyun.com,DIRECT
  - DOMAIN-SUFFIX,upyun.com,DIRECT
  - DOMAIN-SUFFIX,uxengine.net,DIRECT
  - DOMAIN-SUFFIX,wandoujia.com,DIRECT
  - DOMAIN-SUFFIX,weather.bjango.com,DIRECT
  - DOMAIN-SUFFIX,weather.com,DIRECT
  - DOMAIN-SUFFIX,webqxs.com,DIRECT
  - DOMAIN-SUFFIX,weibo.cn,DIRECT
  - DOMAIN-SUFFIX,weibo.com,DIRECT
  - DOMAIN-SUFFIX,weico.cc,DIRECT
  - DOMAIN-SUFFIX,weiphone.com,DIRECT
  - DOMAIN-SUFFIX,weiphone.net,DIRECT
  - DOMAIN-SUFFIX,wenku8.net,DIRECT
  - DOMAIN-SUFFIX,werewolf.53site.com,DIRECT
  - DOMAIN-SUFFIX,wkcdn.com,DIRECT
  - DOMAIN-SUFFIX,xdrig.com,DIRECT
  - DOMAIN-SUFFIX,xhostfire.com,DIRECT
  - DOMAIN-SUFFIX,xiami.com,DIRECT
  - DOMAIN-SUFFIX,xiami.net,DIRECT
  - DOMAIN-SUFFIX,xiaojukeji.com,DIRECT
  - DOMAIN-SUFFIX,xiaomi.com,DIRECT
  - DOMAIN-SUFFIX,xiaomi.net,DIRECT
  - DOMAIN-SUFFIX,xiaomicp.com,DIRECT
  - DOMAIN-SUFFIX,ximalaya.com,DIRECT
  - DOMAIN-SUFFIX,xitek.com,DIRECT
  - DOMAIN-SUFFIX,xmcdn.com,DIRECT
  - DOMAIN-SUFFIX,xslb.net,DIRECT
  - DOMAIN-SUFFIX,yach.me,DIRECT
  - DOMAIN-SUFFIX,yeepay.com,DIRECT
  - DOMAIN-SUFFIX,yhd.com,DIRECT
  - DOMAIN-SUFFIX,yinxiang.com,DIRECT
  - DOMAIN-SUFFIX,yixia.com,DIRECT
  - DOMAIN-SUFFIX,ykimg.com,DIRECT
  - DOMAIN-SUFFIX,youdao.com,DIRECT
  - DOMAIN-SUFFIX,youku.com,DIRECT
  - DOMAIN-SUFFIX,yunjiasu-cdn.net,DIRECT
  - DOMAIN-SUFFIX,zealer.com,DIRECT
  - DOMAIN-SUFFIX,zgslb.net,DIRECT
  - DOMAIN-SUFFIX,zhihu.com,DIRECT
  - DOMAIN-SUFFIX,zhimg.com,DIRECT
  - DOMAIN-SUFFIX,zimuzu.tv,DIRECT
  - DOMAIN-SUFFIX,zmz002.com,DIRECT
  - DOMAIN-SUFFIX,www.88dmw.com,DIRECT
  - DOMAIN-SUFFIX,tanx.com,DIRECT
  - DOMAIN-SUFFIX,alibaba.com,DIRECT
  - DOMAIN-SUFFIX,iqiyi.com,DIRECT
  - DOMAIN-SUFFIX,gdtimg.com,DIRECT
  - DOMAIN-SUFFIX,gtimg.cn,DIRECT
  - DOMAIN-SUFFIX,tencent.com,DIRECT
  - DOMAIN-KEYWORD,github,节点选择
  - DOMAIN-SUFFIX,github.com,节点选择
  - DOMAIN-SUFFIX,googleapis.cn,节点选择
  - DOMAIN,ip.skk.moe,节点选择
  - DOMAIN,ip.sb,节点选择
  - DOMAIN-SUFFIX,challenges.cloudflare.com,节点选择
  - DOMAIN-SUFFIX,tiktok.com,节点选择
  - DOMAIN-SUFFIX,bytecdn.cn,节点选择
  - DOMAIN-SUFFIX,byted.org,节点选择
  - DOMAIN-SUFFIX,bytedanceapi.com,节点选择
  - DOMAIN-SUFFIX,byteoversea.com,节点选择
  - DOMAIN-SUFFIX,byteoversea.net,节点选择
  - DOMAIN-SUFFIX,ibytedtos.com,节点选择
  - DOMAIN-SUFFIX,ibyteimg.com,节点选择
  - DOMAIN-SUFFIX,isnssdk.com,节点选择
  - DOMAIN-SUFFIX,muscdn.com,节点选择
  - DOMAIN-SUFFIX,musemuse.cn,节点选择
  - DOMAIN-SUFFIX,musical.ly,节点选择
  - DOMAIN-SUFFIX,sgsnssdk.com,节点选择
  - DOMAIN-SUFFIX,tiktokcdn-in.com,节点选择
  - DOMAIN-SUFFIX,tiktokv.com,节点选择
  - DOMAIN-SUFFIX,tiktokcdn.com,节点选择
  - DOMAIN-SUFFIX,ttoversea.net,节点选择
  - DOMAIN-SUFFIX,worldfcdn.com,节点选择
  - DOMAIN-SUFFIX,wsdvs.com,节点选择
  - DOMAIN-SUFFIX,chat.openai.com,节点选择
  - DOMAIN-SUFFIX,auth0.openai.com,节点选择
  - DOMAIN-SUFFIX,cdn.openai.com,节点选择
  - DOMAIN-SUFFIX,openai.com,节点选择
  - DOMAIN-SUFFIX,client.crisp.chat,节点选择
  - DOMAIN-SUFFIX,msxiaobing.com,节点选择
  - DOMAIN-SUFFIX,bing.com,节点选择
  - DOMAIN-SUFFIX,bing123.com,节点选择
  - DOMAIN-SUFFIX,bing135.com,节点选择
  - DOMAIN-SUFFIX,bing4.com,节点选择
  - DOMAIN-SUFFIX,bing.com.bo,节点选择
  - DOMAIN-SUFFIX,bing.com.co,节点选择
  - DOMAIN-SUFFIX,bing.com.cy,节点选择
  - DOMAIN-SUFFIX,bing.com.gt,节点选择
  - DOMAIN-SUFFIX,bing.jp,节点选择
  - DOMAIN-SUFFIX,bing.cn,节点选择
  - DOMAIN-SUFFIX,bing.net,节点选择
  - DOMAIN-SUFFIX,bingapis.com,节点选择
  - DOMAIN-SUFFIX,bingforbusiness.com,节点选择
  - GEOIP,CN,DIRECT
  - MATCH,节点选择"#;
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
    let json_data = json!({"name": "wg", "type": "wireguard", "private-key": private_key, "server": "162.159.195.251", "port": 946, 
                                "ip": ipv4, "public-key": peer_public_key, "udp": true});
    let cidr_ranges = vec![
        "188.114.96.0/24",
        "188.114.97.0/24",
        "188.114.98.0/24",
        "188.114.99.0/24",
        "162.159.192.0/24",
        "162.159.193.0/24",
        "162.159.195.0/24",
    ];
    let ports = vec![2408];
    // let ports = vec![
    //     500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946,
    //     955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408,
    //     2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281,
    //     7559, 8319, 8742, 8854, 8886,
    // ];

    // 定义一个计数器来计算content写入的个数(也就是proxies中最多写多少个节点)
    let mut content_count = 0;
    let mut max_content_per_file: usize = ports.len() * 22; // 指定每个文件最多的 content 数量（这个是22个IP乘以端口向量的总数）
    if max_content_per_file < 1000 {
        max_content_per_file = 1000;
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
                        "{}{}{}{}{}",
                        PROXY_GROUPS1, joined_string, PROXY_GROUPS2, joined_string, RULES
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
        }
    }
    // 将 addresses 合并成一个字符串，以逗号分隔
    let combined_addresses = addresses.join(",");
    wireguard_param.insert("Address".to_string(), combined_addresses);

    wireguard_param
}

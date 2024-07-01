use csv::ReaderBuilder;
use serde::Deserialize;
use std::fs::File;

#[derive(Debug, Deserialize)]
struct Record {
    #[serde(rename = "IP:PORT")]
    endpoint: String,
    #[serde(rename = "LOSS")]
    loss: String,
    #[serde(rename = "DELAY")]
    delay: String,
}

#[allow(dead_code)]
pub fn get_endpoints(file_path: &str, delay_number: u16) -> Vec<String> {
    let file = File::open(file_path);
    if file.is_err() {
        return Vec::new();
    }
    let file = file.unwrap();
    // trim(csv::Trim::All)：去除字段名和数据项两端的所有空格
    let mut rdr = ReaderBuilder::new().trim(csv::Trim::All).from_reader(file);
    let mut endpoints = Vec::new();
    for result in rdr.deserialize::<Record>() {
        if let Ok(record) = result {
            // 丢包率等于0%且延迟小于delay_number的endpoint添加到endpoints中
            if record.loss == "0.00%" {
                if let Some(ms_value) = record.delay.strip_suffix(" ms") {
                    if let Ok(ms) = ms_value.parse::<u16>() {
                        // 延迟delay_number（延迟，单位：ms）
                        if ms < delay_number.into() {
                            endpoints.push(record.endpoint);
                        }
                    }
                }
            }
        }
    }

    endpoints
}

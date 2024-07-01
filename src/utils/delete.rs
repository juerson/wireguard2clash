use std::{fs, io};

/* 检查output文件是否存在，不存在就创建，如果存在，发现里面有文件就删除里面的所有文件，包括里面的目录 */
#[allow(dead_code)]
pub fn delete_files_and_dir(dir_path: &str) -> io::Result<()> {
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
        if path.is_file() {
            fs::remove_file(path)?;
        } else if path.is_dir() {
            fs::remove_dir_all(path)?;
        }
    }

    Ok(())
}

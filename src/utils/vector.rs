use std::fmt::Display;
use std::io::{self, Write};

#[allow(dead_code)]
pub fn select_vector<'a, T: Display>(vec1: &'a Vec<T>, vec2: &'a Vec<T>) -> Vec<T>
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

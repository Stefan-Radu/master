use std::fs::read_to_string;

fn map_digit(c: char) -> Option<u8> {
    match c {
        '_' => None,
        ch => Some(ch.to_digit(10).unwrap() as u8)
    }
}

pub fn read_from_file(path: &str) -> Vec<Option<u8>> {
    read_to_string(path).unwrap().lines().flat_map(|line| line.chars()).map(map_digit).collect::<Vec<_>>()
}

use anyhow::Result;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
};

pub fn get_reader(input: &str) -> Result<Box<dyn Read>> {
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(std::io::stdin())
    } else {
        Box::new(File::open(input)?)
    };
    Ok(reader)
}

pub fn get_writer(output: &str) -> Result<Box<dyn Write>> {
    let writer: Box<dyn Write> = if output == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(OpenOptions::new().create(true).open(output)?)
    };
    Ok(writer)
}

pub fn get_content(input: &str) -> Result<Vec<u8>> {
    let mut reader = get_reader(input)?;
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

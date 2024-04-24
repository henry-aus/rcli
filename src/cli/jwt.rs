use anyhow::{bail, Result};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use jsonwebtoken::get_current_timestamp;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{process_genjwt, process_verifyjwt, CmdExector};

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum JwtSubCommand {
    #[command(about = "Generate a jwt token")]
    Sign(JWTSignOpts),
    #[command(about = "Verify the generated token ")]
    Verify(JWTVerifyOpts),
}

#[derive(Debug, Parser, PartialEq, Serialize, Deserialize)]
pub struct JWTSignOpts {
    #[arg(short, long)]
    pub sub: String,
    #[arg(short, long)]
    pub aud: String,
    #[arg(short, long, value_parser = parse_exp, default_value = "1d")]
    pub exp: usize,
}

#[derive(Debug, Parser, PartialEq, Serialize, Deserialize)]
pub struct JWTVerifyOpts {
    #[arg(short, long)]
    pub token: String,
}

fn parse_exp(value: &str) -> Result<usize> {
    let re = Regex::new(r"(\d+)((?i)[smhd])$")?;
    if let Some(caps) = re.captures(value) {
        let num: &u64 = &caps[1].parse::<u64>()?;
        let unit = &caps[2].to_lowercase();
        let current = get_current_timestamp();
        let result: u64 = match unit.as_str() {
            "s" => *num + current,
            "m" => *num * 60 + current,
            "h" => *num * 60 * 60 + current,
            "d" => *num * 24 * 60 * 60 + current,
            &_ => bail!("Not valid unit"),
        };
        Ok(result as usize)
    } else {
        bail!("Bad format of exp {}", value)
    }
}

impl CmdExector for JWTVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let result = process_verifyjwt(&self)?;
        println!("Verified = {}", result);
        Ok(())
    }
}

impl CmdExector for JWTSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let token = process_genjwt(&self)?;
        println!("Token = {}", token);

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use anyhow::Result;

    #[test]
    fn test_parse_exp() -> Result<()> {
        let result = parse_exp("22d");
        assert!(result.is_ok());
        Ok(())
    }
}

use crate::{JWTSignOpts, JWTVerifyOpts};
use anyhow::Result;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};

const SHARED_SECRET: &str = "secret_to_share";

pub fn process_genjwt(opts: &JWTSignOpts) -> Result<String> {
    let token = encode(
        &Header::default(),
        opts,
        &EncodingKey::from_secret(SHARED_SECRET.as_ref()),
    )?;
    Ok(token)
}

pub fn process_verifyjwt(opts: &JWTVerifyOpts) -> Result<bool> {
    let mut validation = Validation::default();
    validation.validate_aud = false;
    match decode::<JWTSignOpts>(
        &opts.token,
        &DecodingKey::from_secret(SHARED_SECRET.as_ref()),
        &validation,
    ) {
        Ok(_) => Ok(true),
        Err(e) => {
            println!("Verification failed: {}", e);
            Ok(false)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{JWTSignOpts, JWTVerifyOpts};

    #[test]
    fn test_process_genjwt() {
        let opts = JWTSignOpts {
            sub: "acme".to_string(),
            aud: "device1".to_string(),
            exp: 1715171079,
        };
        let result = process_genjwt(&opts);
        assert!(result.is_ok())
    }

    #[test]
    fn test_process_verifyjwt() {
        let opts = JWTVerifyOpts {
            token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhY21lIiwiYXVkIjoiZGV2aWNlMSIsImV4cCI6MTcxNTE3MTA3OX0.Ndb5CdE6mQ31Ds0WoJbZISmPFSOTVD0aYuGM60WDBIw".to_string()
        };
        let result = process_verifyjwt(&opts).unwrap();
        assert!(result)
    }
}

//! TruthLinked native token denomination helpers.
//!
//! The native coin is displayed as TLKD. Its smallest unit is displayed as
//! xiom and uses the same nine-decimal base-unit scale that earlier internal
//! code names still refer to as `ONE_TRTH`.

use crate::constants::{TOKEN_DECIMALS, TOKEN_NAME, TOKEN_SUBUNIT, TOKEN_SYMBOL, TOTAL_SUPPLY};
use serde::{Deserialize, Serialize};
use truthlinked_core::constants::ONE_TRTH;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub subunit: String,
    pub total_supply: u128,
    pub circulating_supply: u128,
}

impl TokenInfo {
    pub fn new() -> Self {
        Self {
            name: TOKEN_NAME.to_string(),
            symbol: TOKEN_SYMBOL.to_string(),
            decimals: TOKEN_DECIMALS,
            subunit: TOKEN_SUBUNIT.to_string(),
            total_supply: TOTAL_SUPPLY,
            circulating_supply: 0,
        }
    }
}

pub fn format_amount(amount: u128) -> String {
    let whole = amount / ONE_TRTH;
    let fractional = amount % ONE_TRTH;

    if fractional == 0 {
        format!("{} {}", whole, TOKEN_SYMBOL)
    } else {
        let frac_str = format!("{:09}", fractional)
            .trim_end_matches('0')
            .to_string();
        format!("{}.{} {}", whole, frac_str, TOKEN_SYMBOL)
    }
}

pub fn format_links(amount: u128) -> String {
    format!("{} {}", amount, TOKEN_SUBUNIT)
}

pub fn parse_amount(s: &str) -> Result<u128, String> {
    let s = s.trim();
    if let Some(raw) = s.strip_suffix(TOKEN_SUBUNIT) {
        let raw = raw.trim();
        let links: u128 = raw.parse().map_err(|_| "Invalid amount")?;
        return Ok(links);
    }
    let s = s.trim_end_matches(TOKEN_SYMBOL).trim();

    if let Some((whole, frac)) = s.split_once('.') {
        let whole: u128 = whole.parse().map_err(|_| "Invalid amount")?;
        if frac.is_empty() {
            return Err("Missing fractional amount".to_string());
        }
        if frac.len() > TOKEN_DECIMALS as usize {
            return Err(format!(
                "TLKD amounts support at most {} decimal places",
                TOKEN_DECIMALS
            ));
        }
        if !frac.bytes().all(|b| b.is_ascii_digit()) {
            return Err("Invalid fractional amount".to_string());
        }
        let frac_padded = format!("{:0<9}", frac);
        let frac: u128 = frac_padded
            .parse()
            .map_err(|_| "Invalid fractional amount")?;

        Ok(whole * ONE_TRTH + frac)
    } else {
        let whole: u128 = s.parse().map_err(|_| "Invalid amount")?;
        Ok(whole * ONE_TRTH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_total_supply() {
        assert_eq!(TOTAL_SUPPLY, 1_000_000_000 * ONE_TRTH);
    }

    #[test]
    fn test_format_amount() {
        assert_eq!(format_amount(ONE_TRTH), "1 TLKD");
        assert_eq!(format_amount(ONE_TRTH * 100), "100 TLKD");
        assert_eq!(format_amount(ONE_TRTH + 500_000_000), "1.5 TLKD");
        assert_eq!(format_amount(123_456_789), "0.123456789 TLKD");
        assert_eq!(format_links(123_456_789), "123456789 xiom");
    }

    #[test]
    fn test_parse_amount() {
        assert_eq!(parse_amount("1").unwrap(), ONE_TRTH);
        assert_eq!(parse_amount("100").unwrap(), 100 * ONE_TRTH);
        assert_eq!(parse_amount("1.5").unwrap(), ONE_TRTH + 500_000_000);
        assert_eq!(parse_amount("0.123456789").unwrap(), 123_456_789);
        assert_eq!(parse_amount("0.000000001").unwrap(), 1);
        assert_eq!(parse_amount("1 TLKD").unwrap(), ONE_TRTH);
        assert_eq!(parse_amount("123456789 xiom").unwrap(), 123_456_789);
        assert!(parse_amount("0.0000000001").is_err());
        assert!(parse_amount("1.").is_err());
        assert!(parse_amount("1.a").is_err());
    }
}

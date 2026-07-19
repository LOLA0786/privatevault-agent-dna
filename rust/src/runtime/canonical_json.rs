//! Canonical JSON — byte-identical to CPython's
//! json.dumps(obj, sort_keys=True, separators=(",", ":"))
//!
//! This is THE hash preimage serializer. Every divergence from
//! CPython here is a silent chain fork between the Python and Rust
//! runtimes. Three divergences exist in stock serde_json and are
//! fixed here:
//!   1. ensure_ascii: CPython escapes every char > 0x7E as \uXXXX
//!      (astral planes as UTF-16 surrogate pairs); serde_json emits
//!      raw UTF-8.
//!   2. float repr: CPython repr -> "1.0", "1e+17", "1e-05";
//!      serde_json/ryu -> "1.0", "1e17", "1e-5".
//!   3. NaN/Infinity: CPython would emit them (invalid JSON);
//!      serde_json errors. We REJECT them -- fail-closed, a record
//!      that cannot canonicalize cannot seal.
//!
//! Key ordering: BTreeMap iteration = UTF-8 byte order = Unicode
//! code-point order = CPython sort_keys order for str keys.

use serde_json::Value;

#[derive(Debug)]
pub enum CanonError {
    NonFinite,
    Internal(String),
}

impl std::fmt::Display for CanonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CanonError::NonFinite => {
                write!(f, "non-finite float cannot be canonicalized")
            }
            CanonError::Internal(e) => write!(f, "canonicalization fault: {e}"),
        }
    }
}

/// CPython float repr (format_float_short, mode 'r', ADD_DOT_0).
/// Fixed notation while -4 < decpt <= 16, else scientific with a
/// signed, >=2-digit exponent.
pub fn py_float_repr(x: f64) -> Result<String, CanonError> {
    if !x.is_finite() {
        return Err(CanonError::NonFinite);
    }
    if x == 0.0 {
        return Ok(if x.is_sign_negative() { "-0.0" } else { "0.0" }.to_string());
    }

    // Rust {:e} is shortest-round-trip: "d[.ddd]e[-]X"
    let s = format!("{:e}", x);
    let (mant, exp_s) = s
        .split_once('e')
        .ok_or_else(|| CanonError::Internal(format!("no exponent in {s:?}")))?;
    let exp: i32 = exp_s
        .parse()
        .map_err(|_| CanonError::Internal(format!("bad exponent in {s:?}")))?;

    let neg = mant.starts_with('-');
    let mant = mant.trim_start_matches('-');
    let digits: String = mant.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1; // decimal point position within `digits`

    let body = if decpt <= -4 || decpt > 16 {
        // scientific: first digit, optional fraction, e, sign, >=2-digit exp
        let sci_exp = decpt - 1;
        let sign = if sci_exp < 0 { '-' } else { '+' };
        let frac = if digits.len() > 1 {
            format!(".{}", &digits[1..])
        } else {
            String::new()
        };
        format!("{}{}e{}{:02}", &digits[..1], frac, sign, sci_exp.abs())
    } else if decpt <= 0 {
        // 0.000ddd
        format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
    } else if (decpt as usize) < digits.len() {
        // dd.ddd
        format!(
            "{}.{}",
            &digits[..decpt as usize],
            &digits[decpt as usize..]
        )
    } else {
        // ddd000.0  (ADD_DOT_0: integral floats keep ".0")
        format!("{}{}.0", digits, "0".repeat(decpt as usize - digits.len()))
    };

    Ok(if neg { format!("-{body}") } else { body })
}

/// CPython ensure_ascii string escaping.
fn py_escape_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        let cp = ch as u32;
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            _ if cp < 0x20 => {
                out.push_str(&format!("\\u{:04x}", cp));
            }
            _ if cp < 0x7F => out.push(ch),
            _ if cp <= 0xFFFF => {
                out.push_str(&format!("\\u{:04x}", cp));
            }
            _ => {
                // astral plane -> UTF-16 surrogate pair, like CPython
                let v = cp - 0x10000;
                let hi = 0xD800 + (v >> 10);
                let lo = 0xDC00 + (v & 0x3FF);
                out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
            }
        }
    }
    out.push('"');
}

fn write_value(v: &Value, out: &mut String) -> Result<(), CanonError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else if let Some(f) = n.as_f64() {
                out.push_str(&py_float_repr(f)?);
            } else {
                return Err(CanonError::Internal("unrepresentable number".into()));
            }
        }
        Value::String(s) => py_escape_str(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // serde_json without preserve_order: BTreeMap, already
            // sorted by code point -- same order as CPython sort_keys.
            out.push('{');
            for (i, (k, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                py_escape_str(k, out);
                out.push(':');
                write_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// Serialize a Value exactly as CPython json.dumps(v, sort_keys=True,
/// separators=(",", ":")) would.
pub fn canonical(value: &Value) -> Result<String, CanonError> {
    let mut out = String::with_capacity(256);
    write_value(value, &mut out)?;
    Ok(out)
}

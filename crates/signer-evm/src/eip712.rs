//! EIP-712 typed structured data hashing.

use alloc::collections::{BTreeMap, BTreeSet};
#[cfg(not(feature = "std"))]
use alloc::string::ToString;
use alloc::{format, string::String, vec::Vec};

use sha3::{Digest, Keccak256};

use crate::Error;

/// Compute the EIP-712 hash from a JSON string.
///
/// Returns the 32-byte digest: `keccak256("\x19\x01" || domainSeparator || structHash)`.
pub fn hash_typed_data_json(json: &str) -> Result<[u8; 32], Error> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::InvalidMessage(e.to_string()))?;

    let types_val = v
        .get("types")
        .ok_or_else(|| Error::InvalidMessage("missing 'types'".into()))?;
    let primary_type = v
        .get("primaryType")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::InvalidMessage("missing 'primaryType'".into()))?;
    let domain = v
        .get("domain")
        .ok_or_else(|| Error::InvalidMessage("missing 'domain'".into()))?;
    let message = v
        .get("message")
        .ok_or_else(|| Error::InvalidMessage("missing 'message'".into()))?;

    let types = parse_types(types_val)?;

    let domain_hash = hash_struct("EIP712Domain", domain, &types)?;
    let message_hash = hash_struct(primary_type, message, &types)?;

    let mut buf = Vec::with_capacity(66);
    buf.extend_from_slice(&[0x19, 0x01]);
    buf.extend_from_slice(&domain_hash);
    buf.extend_from_slice(&message_hash);
    Ok(Keccak256::digest(&buf).into())
}

type TypeDefs = BTreeMap<String, Vec<(String, String)>>; // name → [(field_name, field_type)]

fn parse_types(val: &serde_json::Value) -> Result<TypeDefs, Error> {
    let obj = val
        .as_object()
        .ok_or_else(|| Error::InvalidMessage("'types' must be object".into()))?;
    let mut types = BTreeMap::new();
    for (name, fields) in obj {
        let arr = fields
            .as_array()
            .ok_or_else(|| Error::InvalidMessage(format!("{name}: expected array")))?;
        let mut parsed = Vec::new();
        for f in arr {
            let n = f
                .get("name")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::InvalidMessage("field missing 'name'".into()))?;
            let t = f
                .get("type")
                .and_then(|v| v.as_str())
                .ok_or_else(|| Error::InvalidMessage("field missing 'type'".into()))?;
            parsed.push((n.to_string(), t.to_string()));
        }
        types.insert(name.clone(), parsed);
    }
    Ok(types)
}

fn hash_struct(
    type_name: &str,
    data: &serde_json::Value,
    types: &TypeDefs,
) -> Result<[u8; 32], Error> {
    let th = type_hash(type_name, types)?;
    let encoded = encode_data(type_name, data, types)?;
    let mut buf = Vec::with_capacity(32 + encoded.len());
    buf.extend_from_slice(&th);
    buf.extend_from_slice(&encoded);
    Ok(Keccak256::digest(&buf).into())
}

fn type_hash(type_name: &str, types: &TypeDefs) -> Result<[u8; 32], Error> {
    let s = encode_type(type_name, types)?;
    Ok(Keccak256::digest(s.as_bytes()).into())
}

fn encode_type(type_name: &str, types: &TypeDefs) -> Result<String, Error> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| Error::InvalidMessage(format!("unknown type: {type_name}")))?;
    let mut deps = BTreeSet::new();
    collect_deps(type_name, types, &mut deps);
    deps.remove(type_name);

    let mut result = format_struct(type_name, fields);
    for dep in &deps {
        if let Some(f) = types.get(dep.as_str()) {
            result.push_str(&format_struct(dep, f));
        }
    }
    Ok(result)
}

fn format_struct(name: &str, fields: &[(String, String)]) -> String {
    let params: Vec<String> = fields.iter().map(|(n, t)| format!("{t} {n}")).collect();
    format!("{name}({})", params.join(","))
}

fn collect_deps(type_name: &str, types: &TypeDefs, out: &mut BTreeSet<String>) {
    if let Some(fields) = types.get(type_name) {
        for (_, t) in fields {
            let base = base_type(t);
            if types.contains_key(base) && !out.contains(base) {
                out.insert(base.to_string());
                collect_deps(base, types, out);
            }
        }
    }
}

fn base_type(t: &str) -> &str {
    t.find('[').map_or(t, |i| &t[..i])
}

fn encode_data(
    type_name: &str,
    data: &serde_json::Value,
    types: &TypeDefs,
) -> Result<Vec<u8>, Error> {
    let fields = types
        .get(type_name)
        .ok_or_else(|| Error::InvalidMessage(format!("unknown type: {type_name}")))?;
    let obj = data
        .as_object()
        .ok_or_else(|| Error::InvalidMessage(format!("expected object for {type_name}")))?;

    let mut out = Vec::new();
    for (name, type_str) in fields {
        let val = obj.get(name).unwrap_or(&serde_json::Value::Null);
        out.extend_from_slice(&encode_value(type_str, val, types)?);
    }
    Ok(out)
}

fn encode_value(
    type_name: &str,
    value: &serde_json::Value,
    types: &TypeDefs,
) -> Result<[u8; 32], Error> {
    if type_name.ends_with(']') {
        let base = base_type(type_name);
        let arr = value
            .as_array()
            .ok_or_else(|| Error::InvalidMessage(format!("expected array for {type_name}")))?;
        let mut inner = Vec::new();
        for item in arr {
            inner.extend_from_slice(&encode_value(base, item, types)?);
        }
        return Ok(Keccak256::digest(&inner).into());
    }
    if types.contains_key(type_name) {
        return hash_struct(type_name, value, types);
    }
    encode_atomic(type_name, value)
}

#[allow(clippy::many_single_char_names)]
fn encode_atomic(ty: &str, value: &serde_json::Value) -> Result<[u8; 32], Error> {
    let mut w = [0u8; 32];
    match ty {
        "address" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::InvalidMessage("address must be string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b =
                hex::decode(s).map_err(|e| Error::InvalidMessage(format!("bad address: {e}")))?;
            if b.len() != 20 {
                return Err(Error::InvalidMessage(format!(
                    "address: expected 20 bytes, got {}",
                    b.len()
                )));
            }
            w[12..].copy_from_slice(&b);
            Ok(w)
        }
        "bool" => {
            if value.as_bool().unwrap_or(false) {
                w[31] = 1;
            }
            Ok(w)
        }
        "string" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::InvalidMessage("string must be string".into()))?;
            Ok(Keccak256::digest(s.as_bytes()).into())
        }
        "bytes" => {
            let s = value
                .as_str()
                .ok_or_else(|| Error::InvalidMessage("bytes must be hex string".into()))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b = hex::decode(s).map_err(|e| Error::InvalidMessage(format!("bad bytes: {e}")))?;
            Ok(Keccak256::digest(&b).into())
        }
        t if t.starts_with("bytes") => {
            let n: usize = t[5..]
                .parse()
                .map_err(|_| Error::InvalidMessage(format!("invalid type: {t}")))?;
            if !(1..=32).contains(&n) {
                return Err(Error::InvalidMessage("bytesN: N must be 1..32".to_string()));
            }
            let s = value
                .as_str()
                .ok_or_else(|| Error::InvalidMessage(format!("{t} must be hex string")))?;
            let s = s.strip_prefix("0x").unwrap_or(s);
            let b = hex::decode(s).map_err(|e| Error::InvalidMessage(format!("bad {t}: {e}")))?;
            if b.len() != n {
                return Err(Error::InvalidMessage(format!(
                    "{t}: expected {n} bytes, got {}",
                    b.len()
                )));
            }
            w[..n].copy_from_slice(&b);
            Ok(w)
        }
        t if t.starts_with("uint") => {
            let bits: usize = t[4..]
                .parse()
                .map_err(|_| Error::InvalidMessage(format!("invalid type: {t}")))?;
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(Error::InvalidMessage(format!("bad uint width: {bits}")));
            }
            let b = parse_uint(value)?;
            let len = b.len().min(32);
            w[32 - len..].copy_from_slice(&b[b.len() - len..]);
            Ok(w)
        }
        t if t.starts_with("int") => {
            let bits: usize = t[3..]
                .parse()
                .map_err(|_| Error::InvalidMessage(format!("invalid type: {t}")))?;
            if bits == 0 || bits > 256 || !bits.is_multiple_of(8) {
                return Err(Error::InvalidMessage(format!("bad int width: {bits}")));
            }
            parse_int(value)
        }
        _ => Err(Error::InvalidMessage(format!(
            "unsupported EIP-712 type: {ty}"
        ))),
    }
}

fn parse_uint(value: &serde_json::Value) -> Result<Vec<u8>, Error> {
    if let Some(n) = value.as_u64() {
        return Ok(n.to_be_bytes().to_vec());
    }
    if let Some(s) = value.as_str() {
        if let Some(h) = s.strip_prefix("0x") {
            return hex::decode(h).map_err(|e| Error::InvalidMessage(format!("bad uint hex: {e}")));
        }
        let n: u128 = s
            .parse()
            .map_err(|_| Error::InvalidMessage(format!("uint '{s}' out of range; use 0x hex")))?;
        return Ok(n.to_be_bytes().to_vec());
    }
    Err(Error::InvalidMessage(
        "uint must be number or string".into(),
    ))
}

fn parse_int(value: &serde_json::Value) -> Result<[u8; 32], Error> {
    let mut w = [0u8; 32];
    if let Some(n) = value.as_i64() {
        let fill = if n < 0 { 0xff } else { 0x00 };
        w[..24].fill(fill);
        w[24..].copy_from_slice(&n.to_be_bytes());
        return Ok(w);
    }
    if let Some(s) = value.as_str() {
        if let Some(h) = s.strip_prefix("0x") {
            let b =
                hex::decode(h).map_err(|e| Error::InvalidMessage(format!("bad int hex: {e}")))?;
            w[32 - b.len()..].copy_from_slice(&b);
            return Ok(w);
        }
        if let Some(neg) = s.strip_prefix('-') {
            let n: u128 = neg
                .parse()
                .map_err(|e| Error::InvalidMessage(format!("bad int: {e}")))?;
            w[16..].copy_from_slice(&n.to_be_bytes());
            negate_twos_complement(&mut w);
            return Ok(w);
        }
        let n: u128 = s
            .parse()
            .map_err(|e| Error::InvalidMessage(format!("bad int: {e}")))?;
        w[16..].copy_from_slice(&n.to_be_bytes());
        return Ok(w);
    }
    Err(Error::InvalidMessage("int must be number or string".into()))
}

fn negate_twos_complement(bytes: &mut [u8; 32]) {
    for b in bytes.iter_mut() {
        *b = !*b;
    }
    let mut carry = 1u16;
    for b in bytes.iter_mut().rev() {
        let sum = u16::from(*b) + carry;
        *b = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EIP712_EXAMPLE: &str = r#"{
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"}
            ],
            "Person": [
                {"name": "name", "type": "string"},
                {"name": "wallet", "type": "address"}
            ],
            "Mail": [
                {"name": "from", "type": "Person"},
                {"name": "to", "type": "Person"},
                {"name": "contents", "type": "string"}
            ]
        },
        "primaryType": "Mail",
        "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
        },
        "message": {
            "from": {"name": "Cow", "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"},
            "to": {"name": "Bob", "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"},
            "contents": "Hello, Bob!"
        }
    }"#;

    #[test]
    fn full_eip712_hash() {
        let hash = hash_typed_data_json(EIP712_EXAMPLE).unwrap();
        assert_eq!(
            hex::encode(hash),
            "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );
    }

    #[test]
    fn rejects_invalid_json() {
        assert!(hash_typed_data_json("not json").is_err());
    }
}

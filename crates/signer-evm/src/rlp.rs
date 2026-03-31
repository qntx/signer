//! Minimal RLP encoding for EVM signed transaction construction.
//!
//! Only the subset needed to append `(v, r, s)` to an unsigned
//! EIP-1559 / EIP-2930 transaction list.

/// RLP-encode a byte string.
#[must_use]
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.len() == 1 && data[0] < 0x80 {
        return data.to_vec();
    }
    let mut out = encode_length(data.len(), 0x80);
    out.extend_from_slice(data);
    out
}

/// RLP-encode a list from already-encoded concatenated items.
#[must_use]
pub fn encode_list(items: &[u8]) -> Vec<u8> {
    let mut out = encode_length(items.len(), 0xc0);
    out.extend_from_slice(items);
    out
}

/// Strip leading zeros from a big-endian scalar.
#[must_use]
pub fn strip_leading_zeros(data: &[u8]) -> &[u8] {
    let start = data.iter().position(|&b| b != 0).unwrap_or(data.len());
    &data[start..]
}

/// Append `(v, r, s)` to an unsigned typed transaction.
///
/// Input:  `type_byte || RLP([…fields])`
/// Output: `type_byte || RLP([…fields, v, r, s])`
pub fn encode_signed_typed_tx(
    unsigned_tx: &[u8],
    v: u8,
    r: &[u8; 32],
    s: &[u8; 32],
) -> Result<Vec<u8>, &'static str> {
    if unsigned_tx.is_empty() {
        return Err("empty transaction");
    }
    let type_byte = unsigned_tx[0];
    if type_byte != 0x01 && type_byte != 0x02 {
        return Err("unsupported transaction type (expected 0x01 or 0x02)");
    }

    let rlp_data = &unsigned_tx[1..];
    let (payload_offset, payload_length) = decode_length(rlp_data)?;
    if rlp_data.len() < payload_offset + payload_length {
        return Err("truncated RLP payload");
    }

    let items = &rlp_data[payload_offset..payload_offset + payload_length];

    let v_enc = encode_bytes(strip_leading_zeros(&[v]));
    let r_enc = encode_bytes(strip_leading_zeros(r));
    let s_enc = encode_bytes(strip_leading_zeros(s));

    let mut new_items = items.to_vec();
    new_items.extend_from_slice(&v_enc);
    new_items.extend_from_slice(&r_enc);
    new_items.extend_from_slice(&s_enc);

    let mut result = vec![type_byte];
    result.extend_from_slice(&encode_list(&new_items));
    Ok(result)
}

#[allow(clippy::cast_possible_truncation)] // guarded: len < 56 and len_bytes.len() <= 8
fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len < 56 {
        vec![offset + len as u8]
    } else {
        let len_bytes = be_bytes(len);
        let mut out = vec![offset + 55 + len_bytes.len() as u8];
        out.extend_from_slice(&len_bytes);
        out
    }
}

fn be_bytes(val: usize) -> Vec<u8> {
    if val == 0 {
        return vec![0];
    }
    let bytes = val.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

fn decode_length(data: &[u8]) -> Result<(usize, usize), &'static str> {
    if data.is_empty() {
        return Err("empty input");
    }
    let prefix = data[0];
    match prefix {
        0x00..=0x7f => Ok((0, 1)),
        0x80..=0xb7 => Ok((1, (prefix - 0x80) as usize)),
        0xb8..=0xbf => {
            let n = (prefix - 0xb7) as usize;
            if data.len() < 1 + n {
                return Err("truncated length");
            }
            Ok((1 + n, read_be(&data[1..=n])))
        }
        0xc0..=0xf7 => Ok((1, (prefix - 0xc0) as usize)),
        0xf8..=0xff => {
            let n = (prefix - 0xf7) as usize;
            if data.len() < 1 + n {
                return Err("truncated length");
            }
            Ok((1 + n, read_be(&data[1..=n])))
        }
    }
}

fn read_be(bytes: &[u8]) -> usize {
    bytes.iter().fold(0usize, |acc, &b| (acc << 8) | b as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_single_byte() {
        assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
    }

    #[test]
    fn encode_empty() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn v_zero_is_rlp_integer_zero() {
        assert_eq!(encode_bytes(strip_leading_zeros(&[0])), vec![0x80]);
    }

    #[test]
    fn rejects_legacy_tx() {
        assert!(encode_signed_typed_tx(&[0xc0], 0, &[0; 32], &[0; 32]).is_err());
    }

    #[test]
    fn roundtrip_eip1559() {
        let items: Vec<u8> = [
            encode_bytes(&[1]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_bytes(&[]),
            encode_list(&[]),
        ]
        .concat();
        let mut unsigned = vec![0x02];
        unsigned.extend_from_slice(&encode_list(&items));

        let signed = encode_signed_typed_tx(&unsigned, 1, &[0; 32], &[0; 32]).unwrap();
        assert_eq!(signed[0], 0x02);
    }
}

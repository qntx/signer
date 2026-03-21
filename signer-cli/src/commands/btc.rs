//! Bitcoin signing CLI commands.

use clap::{Args, Subcommand, ValueEnum};
use signer_btc::{Address, AddressType, Network, NetworkKind, Signer};

use crate::output::{self, AddressOutput, NamedAddress, PsbtOutput, SignOutput, VerifyOutput};

/// Bitcoin signing operations.
#[derive(Args)]
pub struct BtcCommand {
    #[command(subcommand)]
    command: BtcSubcommand,
}

#[derive(Subcommand)]
enum BtcSubcommand {
    /// Sign a message (BIP-137).
    SignMessage {
        /// Private key in WIF or hex format.
        #[arg(short, long)]
        key: String,

        /// Message to sign.
        #[arg(short, long)]
        message: String,

        /// Address type for the BIP-137 flag byte.
        #[arg(short, long, value_enum, default_value = "native-segwit")]
        address_type: CliAddressType,

        /// Use testnet.
        #[arg(short, long)]
        testnet: bool,
    },

    /// Verify a BIP-137 signed message.
    VerifyMessage {
        /// Base64-encoded signature.
        #[arg(short, long)]
        signature: String,

        /// Message that was signed.
        #[arg(short, long)]
        message: String,

        /// Expected Bitcoin address.
        #[arg(short, long)]
        address: String,

        /// Use testnet.
        #[arg(short, long)]
        testnet: bool,
    },

    /// Sign a raw 32-byte hash with ECDSA.
    SignEcdsa {
        /// Private key in WIF or hex format.
        #[arg(short, long)]
        key: String,

        /// 32-byte hash in hex.
        #[arg(short, long)]
        hash: String,

        /// Use testnet.
        #[arg(short, long)]
        testnet: bool,
    },

    /// Sign a raw 32-byte hash with BIP-340 Schnorr.
    SignSchnorr {
        /// Private key in WIF or hex format.
        #[arg(short, long)]
        key: String,

        /// 32-byte hash in hex.
        #[arg(short = 'x', long)]
        hash: String,

        /// Use testnet.
        #[arg(short, long)]
        testnet: bool,
    },

    /// Sign all applicable inputs in a PSBT.
    SignPsbt {
        /// Private key in WIF or hex format.
        #[arg(short, long)]
        key: String,

        /// Base64-encoded PSBT.
        #[arg(short, long)]
        psbt: String,

        /// Use testnet.
        #[arg(short, long)]
        testnet: bool,
    },

    /// Show addresses and public key for a private key.
    Address {
        /// Private key in WIF or hex format.
        #[arg(short, long)]
        key: String,

        /// Use testnet.
        #[arg(short, long)]
        testnet: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum CliAddressType {
    /// Legacy P2PKH
    Legacy,
    /// `SegWit` P2SH-P2WPKH
    Segwit,
    /// Native `SegWit` P2WPKH
    NativeSegwit,
}

impl From<CliAddressType> for AddressType {
    fn from(val: CliAddressType) -> Self {
        match val {
            CliAddressType::Legacy => Self::P2pkh,
            CliAddressType::Segwit => Self::P2shP2wpkh,
            CliAddressType::NativeSegwit => Self::P2wpkh,
        }
    }
}

const fn network(testnet: bool) -> Network {
    if testnet {
        Network::Testnet
    } else {
        Network::Bitcoin
    }
}

const fn network_str(net: NetworkKind) -> &'static str {
    match net {
        NetworkKind::Main => "mainnet",
        NetworkKind::Test => "testnet",
    }
}

fn load_signer(key: &str, testnet: bool) -> Result<Signer, Box<dyn std::error::Error>> {
    let net = network(testnet);
    Signer::from_wif(key)
        .or_else(|_| Signer::from_hex(key, net))
        .map_err(|e| format!("invalid private key: {e}").into())
}

impl BtcCommand {
    pub fn execute(self, json: bool) -> Result<(), Box<dyn std::error::Error>> {
        match self.command {
            BtcSubcommand::SignMessage {
                key,
                message,
                address_type,
                testnet,
            } => {
                let signer = load_signer(&key, testnet)?;
                let addr_type = AddressType::from(address_type);
                let sig = signer.sign_message_with_type(&message, addr_type)?;
                let net = network(testnet);
                let addr = match addr_type {
                    AddressType::P2pkh => signer.p2pkh_address(net),
                    AddressType::P2shP2wpkh => signer.p2sh_p2wpkh_address(net),
                    AddressType::P2wpkh => signer.p2wpkh_address(net),
                };
                let out = SignOutput {
                    chain: "bitcoin",
                    operation: "BIP-137 message",
                    address: Some(addr.to_string()),
                    signature: sig,
                    message: Some(message),
                };
                output::render_sign(&out, json)?;
            }
            BtcSubcommand::VerifyMessage {
                signature,
                message,
                address,
                testnet,
            } => {
                let net = network(testnet);
                let addr: Address = address
                    .parse::<Address<_>>()
                    .map_err(|e| format!("invalid address: {e}"))?
                    .require_network(net)
                    .map_err(|e| format!("network mismatch: {e}"))?;
                let valid =
                    Signer::verify_message(&message, &signature, &addr, net).unwrap_or(false);
                let out = VerifyOutput {
                    chain: "bitcoin",
                    valid,
                    address: Some(address),
                    message: Some(message),
                };
                output::render_verify(&out, json)?;
            }
            BtcSubcommand::SignEcdsa { key, hash, testnet } => {
                let signer = load_signer(&key, testnet)?;
                let digest = parse_hash32(&hash)?;
                let msg = signer_btc::secp256k1::Message::from_digest(digest);
                let sig = signer.sign_ecdsa(&msg);
                let out = SignOutput {
                    chain: "bitcoin",
                    operation: "ECDSA",
                    address: None,
                    signature: sig.to_string(),
                    message: Some(hash),
                };
                output::render_sign(&out, json)?;
            }
            BtcSubcommand::SignSchnorr { key, hash, testnet } => {
                let signer = load_signer(&key, testnet)?;
                let digest = parse_hash32(&hash)?;
                let msg = signer_btc::secp256k1::Message::from_digest(digest);
                let sig = signer.sign_schnorr(&msg);
                let out = SignOutput {
                    chain: "bitcoin",
                    operation: "BIP-340 Schnorr",
                    address: None,
                    signature: sig.to_string(),
                    message: Some(hash),
                };
                output::render_sign(&out, json)?;
            }
            BtcSubcommand::SignPsbt { key, psbt, testnet } => {
                let signer = load_signer(&key, testnet)?;
                let mut psbt: signer_btc::Psbt =
                    psbt.parse().map_err(|e| format!("invalid PSBT: {e}"))?;
                signer.sign_psbt(&mut psbt)?;
                let out = PsbtOutput {
                    chain: "bitcoin",
                    operation: "PSBT",
                    psbt: psbt.to_string(),
                };
                output::render_psbt(&out, json)?;
            }
            BtcSubcommand::Address { key, testnet } => {
                let signer = load_signer(&key, testnet)?;
                let net = network(testnet);
                let cpk = signer.compressed_public_key();
                let primary = Address::p2wpkh(&cpk, net);
                let out = AddressOutput {
                    chain: "bitcoin",
                    network: Some(network_str(signer.network_kind())),
                    address: primary.to_string(),
                    public_key: cpk.to_string(),
                    addresses: vec![
                        NamedAddress {
                            kind: "P2WPKH",
                            address: signer.p2wpkh_address(net).to_string(),
                        },
                        NamedAddress {
                            kind: "P2TR",
                            address: signer.p2tr_address(net).to_string(),
                        },
                        NamedAddress {
                            kind: "P2SH-P2WPKH",
                            address: signer.p2sh_p2wpkh_address(net).to_string(),
                        },
                        NamedAddress {
                            kind: "P2PKH",
                            address: signer.p2pkh_address(net).to_string(),
                        },
                    ],
                };
                output::render_address(&out, json)?;
            }
        }
        Ok(())
    }
}

fn parse_hash32(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "hash must be exactly 32 bytes")?;
    Ok(arr)
}

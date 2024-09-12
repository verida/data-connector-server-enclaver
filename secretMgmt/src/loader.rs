use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng, Payload},
    ChaCha20Poly1305,
};
use clap::Parser;
use libsodium_sys::crypto_sign_ed25519_pk_to_curve25519;
use std::{error::Error, fs};
use std::fs::File;
use std::io::Read;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use x25519_dalek::x25519;
use hyper::{client::Client, Uri};

mod verifier;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ip address of the secret manager server http://<ip:port>
    #[clap(short, long, value_parser)]
    ip_addr: String,

    /// path to private key file
    #[arg(short, long)]
    secret: String,

    /// path to message file
    #[arg(short, long)]
    message: String,

    /// endpoint of the attestation server http://<ip:port>
    #[clap(short, long, value_parser)]
    endpoint: String,

    /// expected pcr0
    #[arg(long)]
    pcr0: String,

    /// expected pcr1
    #[arg(long)]
    pcr1: String,

    /// expected pcr2
    #[arg(long)]
    pcr2: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // verify attestation
    let pcrs = vec![cli.pcr0, cli.pcr1, cli.pcr2];
    let client = Client::new();
    let res = client.get(cli.endpoint.parse::<Uri>()?).await?;
    let buf = hyper::body::to_bytes(res).await?;
    let attestation_doc = buf.to_vec();
    let cert = include_bytes!("./aws.cert").to_vec();

    let pub_key = verifier::verify(attestation_doc, cert, pcrs)?;
    println!("verification successful with pubkey: {:?}", pub_key);

    // encrypt and send message
    println!("secret: {}", cli.secret);

    let mut file = File::open(cli.secret)?;
    let mut secret = [0u8; 32];
    file.read_exact(&mut secret)?;

    let mut ed25519_app = pub_key;
    let mut app = [0; 32];
    if unsafe { crypto_sign_ed25519_pk_to_curve25519(app.as_mut_ptr(), ed25519_app.as_mut_ptr()) } != 0 {
        return Err("failed to convert ed25519 public key to x25519".into());
    }

    let app_shared = x25519(secret, app);
    let app_cipher = ChaCha20Poly1305::new(&app_shared.into());

    let msg = fs::read(cli.message).unwrap();
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let buf = app_cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &msg,
                aad: &[0],
            },
        )
        .unwrap();

    let outbound = TcpStream::connect(cli.ip_addr).await?;
    let (mut ro, mut wo) = tokio::io::split(outbound);
    wo.write_all(nonce.as_slice()).await?;
    wo.write_all(buf.as_slice()).await?;
    wo.shutdown().await?;

    let mut resp = String::with_capacity(1000);
    ro.read_to_string(&mut resp).await?;

    println!("Repsonse: {}", resp);

    Ok(())
}
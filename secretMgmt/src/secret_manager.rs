use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use clap::Parser;
use libsodium_sys::crypto_sign_ed25519_sk_to_curve25519;
use std::error::Error;
use std::fs::File;
use std::io::Read;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use x25519_dalek::x25519;
use std::process::Command;
use std::{thread, time::Duration};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// ip address of the server <ip:port>
    #[clap(short, long, value_parser)]
    ip_addr: String,

    /// path to private key file
    #[arg(short, long)]
    private_key: String,

    /// path to loader public key file
    #[arg(short, long)]
    loader: String,

    /// path to output file
    #[arg(short, long)]
    output: String,

    /// service to restart after writing data (optional)
    #[arg(short, long)]
    service: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    println!(
        "secret: {}, loader: {}, output: {}",
        cli.private_key, cli.loader, cli.output
    );

    let mut file = File::open(cli.private_key)?;
    let mut ed25519_secret = [0; 64];
    file.read_exact(&mut ed25519_secret)?;

    let mut secret = [0; 32];
    if unsafe { crypto_sign_ed25519_sk_to_curve25519(secret.as_mut_ptr(), ed25519_secret.as_mut_ptr()) } != 0 {
        return Err("failed to convert ed25519 secret to x25519".into());
    }

    let mut file = File::open(cli.loader)?;
    let mut loader = [0; 32];
    file.read_exact(&mut loader)?;

    let loader_shared = x25519(secret, loader);
    let loader_cipher = ChaCha20Poly1305::new(&loader_shared.into());

    println!("Listening on: {}", cli.ip_addr);

    let listener = TcpListener::bind(cli.ip_addr).await?;

    let mut data: Vec<u8> = vec![0, 0];
    while let Ok((inbound, _)) = listener.accept().await {
        let mut buf: Vec<u8> = Vec::with_capacity(1000);
        let (mut ri, mut wi) = tokio::io::split(inbound);
        let len = ri.read_to_end(&mut buf).await?;

        data = loader_cipher
            .decrypt(
                buf[0..12].into(),
                Payload {
                    msg: &buf[12..len],
                    aad: &[0],
                },
            )
            .map_err(|e| "Decrypt failed: ".to_owned() + &e.to_string())?;

        println!("Data received and decrypted");

        std::fs::write(cli.output.as_str(), data.clone()).expect("Unable to write file");
        if !data.is_empty() {
            wi.write_all(b"Data write suceeded!").await?;
            if cli.service.is_none() { 
                break; 
            }
            let service = cli.service.clone().unwrap();
            let command = format!("/app/supervisord ctl stop {} and /app/supervisord ctl start {}", service, service);
            print!("Executing commands: {}", command);
            let mut child = Command::new("/app/supervisord")
                .arg("ctl")
                .arg("stop")
                .arg(&service)
                .spawn()
                .expect("failed to stop service");
            let ecode = child.wait().expect("failed to stop the service");
            if !ecode.success() { continue };

            let mut child = Command::new("/app/supervisord")
                .arg("ctl")
                .arg("start")
                .arg(&service)
                .spawn()
                .expect("failed to start service");
            let ecode = child.wait().expect("failed to start the service");
            if !ecode.success() { continue };
            break;
        }
        wi.write_all(b"No data to write!").await?;
    }

    Ok(())
}
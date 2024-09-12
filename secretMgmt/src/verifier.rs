use aws_nitro_enclaves_cose::{crypto::Openssl, crypto::SigningPublicKey, CoseSign1};
use hex;
use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::x509::{X509VerifyResult, X509};
use serde_cbor::{self, value, value::Value};
use std::collections::BTreeMap;
use std::error::Error;
use tokio;

fn get_all_certs(cert: X509, cabundle: Vec<Value>) -> Result<Vec<X509>, ErrorStack> {
    let mut all_certs = Vec::new();
    all_certs.push(cert);
    for cert in cabundle {
        let intermediate_certificate = match cert {
            Value::Bytes(b) => b,
            _ => unreachable!(),
        };
        let intermediate_certificate = X509::from_der(&intermediate_certificate)?;
        all_certs.push(intermediate_certificate);
    }
    Ok(all_certs)
}

fn verify_cert_chain(
    cert: X509,
    cabundle: Vec<Value>,
    root_cert_pem: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let certs = get_all_certs(cert, cabundle)?;
    let mut i = 0;
    while i < certs.len() - 1 {
        let pubkey = certs[i + 1].public_key()?;
        let x = certs[i].verify(&pubkey)?;
        if !x {
            return Err("signature verification failed".into());
        }
        let x = certs[i + 1].issued(&certs[i]);
        if x != X509VerifyResult::OK {
            return Err("certificate issuer and subject verification failed".into());
        }
        let current_time = Asn1Time::days_from_now(0)?;
        if certs[i].not_after() < current_time || certs[i].not_before() > current_time {
            return Err("certificate timestamp expired/not valid".into());
        }
        i += 1;
    }
    let root_cert = X509::from_pem(&root_cert_pem)?;
    if &root_cert != certs.last().unwrap() {
        return Err("root certificate mismatch".into());
    }
    Ok(())
}

pub fn verify(
    attestion_doc_cbor: Vec<u8>,
    root_cert_pem: Vec<u8>,
    pcrs: Vec<String>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let cosesign1 = CoseSign1::from_bytes(&attestion_doc_cbor)?;
    let payload = cosesign1.get_payload::<Openssl>(None as Option<&dyn SigningPublicKey>)?;
    let mut attestation_doc: BTreeMap<Value, Value> =
        value::from_value(serde_cbor::from_slice::<Value>(&payload)?)?;
    let document_pcrs_arr = attestation_doc
        .remove(&value::to_value("pcrs").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "pcrs key not found in attestation doc",
        ))?;
    let mut document_pcrs_arr: BTreeMap<Value, Value> = value::from_value(document_pcrs_arr)?;
    for i in 0..3 {
        let pcr = document_pcrs_arr
            .remove(&value::to_value(i).unwrap())
            .ok_or(Box::<dyn Error>::from(format!("pcr{i} not found")))?;
        let pcr = match pcr {
            Value::Bytes(b) => b,
            _ => unreachable!(),
        };
        if hex::encode(pcr) != pcrs[i] {
            return Err(format!("pcr{i} match failed").into());
        }
    }
    let enclave_certificate = attestation_doc
        .remove(&value::to_value("certificate").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "certificate key not found in attestation doc",
        ))?;
    let enclave_certificate = match enclave_certificate {
        Value::Bytes(b) => b,
        _ => unreachable!(),
    };
    let enclave_certificate = X509::from_der(&enclave_certificate)?;
    let pub_key = enclave_certificate.public_key()?;
    let verify_result = cosesign1.verify_signature::<Openssl>(&pub_key)?;

    if !verify_result {
        return Err("cose signature verfication failed".into());
    }

    let cabundle = attestation_doc
        .remove(&value::to_value("cabundle").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "cabundle key not found in attestation doc",
        ))?;

    let mut cabundle: Vec<Value> = value::from_value(cabundle)?;
    cabundle.reverse();

    verify_cert_chain(enclave_certificate, cabundle, root_cert_pem)?;

    let public_key = attestation_doc
        .remove(&value::to_value("public_key").unwrap())
        .ok_or(Box::<dyn Error>::from(
            "public key not found in attestation doc",
        ))?;
    let public_key = match public_key {
        Value::Bytes(b) => b,
        _ => unreachable!(),
    };

    Ok(public_key)
}
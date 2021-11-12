// Copyright (c) 2021 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_modules::{KbcCheckInfo, KbcInterface};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ISECL KBS annotation packet
#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    pub key_url: String,
    pub wrapped_key: Vec<u8>,
    pub wrap_type: String,
}

pub struct IseclKbc {
    kbs_info: HashMap<String, String>,
}

impl KbcInterface for IseclKbc {
    fn check(&self) -> Result<KbcCheckInfo> {
        Ok(KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
            //FIXME : Add some form of protocol versioning with keyproxy
        })
    }

    fn decrypt_payload(&mut self, annotation: &str) -> Result<Vec<u8>> {
        // FIXME : Handle error in parsing.
        let annotation_packet: AnnotationPacket = serde_json::from_str(annotation)?;

        let wrapped_key: Vec<u8> = annotation_packet.wrapped_key;
        let key_url: String = annotation_packet.key_url;
        println!("KBS URL Decrypt Payload  : {:?}", self.kbs_info);
        println!("Key URL Decrypt Payload  : {:?}", key_url);
        let plain_text = decrypt(&wrapped_key, &key_url)?;

        Ok(plain_text)
    }
}

impl IseclKbc {
    pub fn new(kbs_uri: String) -> IseclKbc {
        let mut kbs_info: HashMap<String, String> = HashMap::new();
        kbs_info.insert("kbs_uri".to_string(), kbs_uri);
        println!("KBS URL : {:?}", kbs_info);
        IseclKbc { kbs_info: kbs_info }
    }
}

fn decrypt(wrapped_key: &[u8], key_url: &String) -> Result<Vec<u8>> {
    let plain_text: String = "DecryptedKey".to_string();
    Ok(plain_text.into_bytes())
}

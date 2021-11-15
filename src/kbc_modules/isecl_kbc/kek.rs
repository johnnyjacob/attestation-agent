// Copyright (c) 2021 Intel
//
// SPDX-License-Identifier: Apache-2.0
//

// Module to generate Key Encryption public/private key pair.

use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};

pub struct Key {
    pub public: RsaPublicKey,
    private: RsaPrivateKey,
}

impl Key {
    // Fixme : Should take key size. And fallback to a default.
    pub fn new() -> Key {
        let mut rng = OsRng;
        let bits = 2048;
        let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
        let public_key = RsaPublicKey::from(&private_key);

        Key {
            public: public_key,
            private: private_jey,
        }
    }
}

pub fn unwrap(kek: Key) -> String {}

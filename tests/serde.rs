use cbor_smol::{cbor_deserialize, cbor_serialize_bytes};
use core::fmt::Debug;
use cosey::{EcdhEsHkdf256PublicKey, Ed25519PublicKey, P256PublicKey};
use heapless_bytes::Bytes;
use quickcheck::{Arbitrary, Gen};
use serde::{de::DeserializeOwned, Serialize};

#[derive(Clone, Debug)]
struct Input(Bytes<32>);

impl Arbitrary for Input {
    fn arbitrary(g: &mut Gen) -> Self {
        let mut data = vec![0; 32];
        data.fill_with(|| u8::arbitrary(g));
        Self(Bytes::from_slice(&data).unwrap())
    }
}

fn test_serde<T: Serialize + DeserializeOwned + PartialEq>(data: T) -> bool {
    let serialized: Bytes<1024> = cbor_serialize_bytes(&data).unwrap();
    let deserialized: T = cbor_deserialize(&serialized).unwrap();
    data == deserialized
}

fn test_de<T: DeserializeOwned + Debug + PartialEq>(s: &str, data: T) {
    let serialized = hex::decode(s).unwrap();
    let deserialized: T = cbor_deserialize(&serialized).unwrap();
    assert_eq!(data, deserialized);
}

#[test]
fn de_p256() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let y = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = P256PublicKey { x, y };
    test_de("a5010203262001215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff225820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", key);
}

#[test]
fn de_ecdh() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let y = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = EcdhEsHkdf256PublicKey { x, y };
    test_de("a501020338182001215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff225820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", key);
}

#[test]
fn de_ecdh_order() {
    // fields in a different order, see https://github.com/solokeys/ctap-types/issues/7
    let serialized = hex::decode("a42001215820babc05993673d3d9745712333373cc6da964b4814d0cd666ce97c5ffef8befa522582029ebc161c05e3ba0f702a4cf1df30aca224ae3cf7b9478f4a811726976908ef00102").unwrap();
    cbor_deserialize::<EcdhEsHkdf256PublicKey>(&serialized).unwrap();
}

#[test]
fn de_ed25519() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = Ed25519PublicKey { x };
    test_de(
        "a4010103272006215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        key,
    );
}

quickcheck::quickcheck! {
    #[test]
    fn serde_p256(x: Input, y: Input) -> bool {
        test_serde(P256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    #[test]
    fn serde_ecdh(x: Input, y: Input) -> bool {
        test_serde(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    #[test]
    fn serde_ed25519(x: Input) -> bool {
        test_serde(Ed25519PublicKey {
            x: x.0,
        })
    }
}


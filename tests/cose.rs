use core::fmt::Debug;

use cbor_smol::{cbor_deserialize, cbor_serialize_bytes};
use ciborium::Value;
use cosey::{EcdhEsHkdf256PublicKey, Ed25519PublicKey, P256PublicKey, PublicKey};
use heapless_bytes::Bytes;
use itertools::Itertools as _;
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

fn deserialize_map<T: DeserializeOwned>(
    map: Vec<(Value, Value)>,
) -> (Result<T, cbor_smol::Error>, Vec<u8>) {
    let map = Value::Map(map);
    let mut serialized: Vec<u8> = Default::default();
    ciborium::into_writer(&map, &mut serialized).unwrap();
    (cbor_deserialize(&serialized), serialized)
}

fn print_input_output<T: Debug + PartialEq>(
    input: &T,
    serialized: &[u8],
    deserialized: &Result<T, cbor_smol::Error>,
) {
    println!("serialized:\n  {}", hex::encode(serialized));
    println!("input:\n     {:?}", input);
    print!("deserialized:\n  ");
    if deserialized.as_ref() == Ok(input) {
        println!("Ok(input)");
    } else {
        println!("{:?}", deserialized);
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

fn test_de_alg<T: Serialize + DeserializeOwned + Debug + PartialEq>(
    data: T,
    alg: Option<i8>,
) -> bool {
    let serialized_value = Value::serialized(&data).unwrap();
    let mut fields = serialized_value.into_map().unwrap();
    // this must be alg
    assert_eq!(fields[1].0, Value::Integer(3.into()));

    let expect_success = if let Some(alg) = alg {
        // alg values may only work if they are correct
        let alg = Value::Integer(alg.into());
        if fields[1].1 == alg {
            true
        } else {
            fields[1].1 = alg;
            false
        }
    } else {
        // deserialization without alg must work
        fields.remove(1);
        true
    };

    let (deserialized, serialized) = deserialize_map::<T>(fields);
    let is_success = deserialized.is_ok() == expect_success;

    if !is_success {
        if alg.is_some() {
            if expect_success {
                println!("Expected correct deserialization for original algorithm");
            } else {
                println!("Expected error for invalid algorithm");
            }
        } else {
            println!("Expected correct deserialization for missing algorithm");
        }
        println!("alg: {:?}", alg);
        print_input_output(&data, &serialized, &deserialized);
    }

    is_success
}

fn test_de_order<T: Serialize + DeserializeOwned + Debug + PartialEq>(data: T) -> bool {
    let serialized_value = Value::serialized(&data).unwrap();
    let canonical_fields = serialized_value.into_map().unwrap();

    for fields in canonical_fields
        .iter()
        .cloned()
        .permutations(canonical_fields.len())
    {
        let is_canonical = fields == canonical_fields;
        let (deserialized, serialized) = deserialize_map::<T>(fields);

        // only the canonical order should be accepted
        let is_success = if is_canonical {
            Ok(&data) == deserialized.as_ref()
        } else {
            deserialized.is_err()
        };

        if !is_success {
            if is_canonical {
                println!("Expected correct deserialization for canonical order");
            } else {
                println!("Expected error for non-canonical order");
            }
            print_input_output(&data, &serialized, &deserialized);
            return false;
        }
    }

    let mut fields = canonical_fields;
    fields.push((Value::Integer(42.into()), Value::Text("foobar".to_owned())));
    fields.push((Value::Integer(24.into()), Value::Text("foobar".to_owned())));
    let (deserialized, serialized) = deserialize_map::<T>(fields);

    // injecting an unsupported field should not change the result
    let is_success = Ok(&data) == deserialized.as_ref();

    if !is_success {
        println!("Expected correct deserialization with unsupported fields");
        print_input_output(&data, &serialized, &deserialized);
    }

    is_success
}

#[test]
fn de_p256() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let y = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = P256PublicKey { x, y };
    let data = "a5010203262001215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff225820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    test_de(data, key.clone());
    test_de(data, PublicKey::P256Key(key));
}

#[test]
fn de_ecdh() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let y = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = EcdhEsHkdf256PublicKey { x, y };
    let data = "a501020338182001215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff225820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    test_de(data, key.clone());
    test_de(data, PublicKey::EcdhEsHkdf256Key(key));
}

#[test]
fn de_ed25519() {
    let x = Bytes::from_slice(&[0xff; 32]).unwrap();
    let key = Ed25519PublicKey { x };
    let data =
        "a4010103272006215820ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    test_de(data, key.clone());
    test_de(data, PublicKey::Ed25519Key(key));
}

quickcheck::quickcheck! {
    fn serde_p256(x: Input, y: Input) -> bool {
        test_serde(P256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn serde_ecdh(x: Input, y: Input) -> bool {
        test_serde(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn serde_ed25519(x: Input) -> bool {
        test_serde(Ed25519PublicKey {
            x: x.0,
        })
    }

    fn de_order_p256(x: Input, y: Input) -> bool {
        test_de_order(P256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn de_order_ecdh(x: Input, y: Input) -> bool {
        test_de_order(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        })
    }

    fn de_order_ed25519(x: Input) -> bool {
        test_de_order(Ed25519PublicKey {
            x: x.0,
        })
    }

    fn de_alg_p256(x: Input, y: Input, alg: Option<i8>) -> bool {
        test_de_alg(P256PublicKey {
            x: x.0,
            y: y.0,
        }, alg)
    }

    fn de_alg_ecdh(x: Input, y: Input, alg: Option<i8>) -> bool {
        test_de_alg(EcdhEsHkdf256PublicKey {
            x: x.0,
            y: y.0,
        }, alg)
    }

    fn de_alg_ed25519(x: Input, alg: Option<i8>) -> bool {
        test_de_alg(Ed25519PublicKey {
            x: x.0,
        }, alg)
    }
}

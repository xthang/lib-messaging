//
// Copyright 2023 Ready.io
//

#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]

use jni::objects::{JClass, JObject};
// use jni::sys::{jbyteArray, jlongArray};
use jni::JNIEnv;
// use std::convert::TryFrom;

// use lib_messaging_bridge::jni::*;
// use lib_messaging_protocol::*;

pub mod logging;

// #[no_mangle]
// pub unsafe extern "C" fn Java_com_cystack_ready_libmessaging_internal_Native_IdentityKeyPair_1Deserialize(
//     env: JNIEnv,
//     _class: JClass,
//     data: jbyteArray,
// ) -> jlongArray {
//     run_ffi_safe(&env, || {
//         let data = env.convert_byte_array(data)?;
//         let key = IdentityKeyPair::try_from(data.as_ref())?;

//         let public_key_handle = key.identity_key().public_key().convert_into(&env)?;
//         let private_key_handle = key.private_key().convert_into(&env)?;
//         let tuple = [public_key_handle, private_key_handle];

//         let result = env.new_long_array(2)?;
//         env.set_long_array_region(result, 0, &tuple)?;
//         Ok(result)
//     })
// }

/// An optimization barrier / guard against garbage collection.
///
/// cbindgen:ignore
#[no_mangle]
pub unsafe extern "C" fn Java_com_cystack_ready_libmessaging_internal_Native_keepAlive(
    _env: JNIEnv,
    _class: JClass,
    _obj: JObject,
) {
}

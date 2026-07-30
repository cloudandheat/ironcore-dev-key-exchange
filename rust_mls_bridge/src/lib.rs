use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::storage::StorageProvider;

use libc::{c_char, size_t};
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;

const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

static CLIENT_IDENTITIES: OnceLock<
    Mutex<HashMap<String, Arc<(OpenMlsRustCrypto, CredentialWithKey, SignatureKeyPair)>>>,
> = OnceLock::new();
static CLIENT_GROUPS: OnceLock<Mutex<HashMap<String, MlsGroup>>> = OnceLock::new();

pub fn get_provider(
    client_id: &String,
) -> Arc<(OpenMlsRustCrypto, CredentialWithKey, SignatureKeyPair)> {
    let map_lock = CLIENT_IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()));
    let hashmap = map_lock.lock().unwrap();
    hashmap
        .get(client_id)
        .expect("{client_id} not found.")
        .clone()
}

pub fn insert_provider(
    client_id: &String,
    crypto: (OpenMlsRustCrypto, CredentialWithKey, SignatureKeyPair),
) {
    let map_lock = CLIENT_IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut hashmap = map_lock.lock().unwrap();
    hashmap.insert(client_id.clone(), Arc::new(crypto));
}

pub fn insert_group(group_id: &String, group: MlsGroup) {
    let map_lock = CLIENT_GROUPS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut hashmap = map_lock.lock().unwrap();
    hashmap.insert(group_id.clone(), group);
}

fn create_group(client_id: &String, group_id: &String) {
    let provider = get_provider(client_id);
    let group = MlsGroup::new(
        &provider.0,
        &provider.2,
        &MlsGroupCreateConfig::default(),
        provider.1.clone(),
    )
    .expect("Failed to create MLS group");
    insert_group(group_id, group);
}

fn invite_members(
    client_id: &String,
    group_id: &String,
    target_kp_hex: String,
) -> (Vec<u8>, Vec<u8>) {
    let provider = get_provider(client_id);
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let group = groups.get_mut(group_id).expect("Group not found");

    let kp_bytes = hex::decode(target_kp_hex).expect("Invalid hex");
    let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
        .expect("Failed to deserialize KeyPackageIn");
    let key_package = key_package_in
        .validate(provider.0.crypto(), ProtocolVersion::Mls10)
        .expect("Failed to validate KeyPackage");

    // add_members produces both the Welcome message (for the new user)
    // and the Commit message (for existing users to update their epoch)
    let (mls_message_out, welcome_out, _group_info) = group
        .add_members(
            &provider.0,
            &provider.2,
            core::slice::from_ref(&key_package),
        )
        .expect("Could not add members.");

    group
        .merge_pending_commit(&provider.0)
        .expect("Error merging pending commit");

    let welcome_bytes = welcome_out
        .tls_serialize_detached()
        .expect("Error serializing welcome");
    let commit_bytes = mls_message_out
        .tls_serialize_detached()
        .expect("Error serializing commit");

    (welcome_bytes, commit_bytes)
}

fn join_group(
    client_id: &String,
    group_id: &String,
    serialized_welcome: &[u8],
    serialized_tree: &[u8],
) {
    let provider = get_provider(client_id);
    let mut welcome_slice = serialized_welcome;
    let mls_message_in =
        MlsMessageIn::tls_deserialize(&mut welcome_slice).expect("Error des welcome");
    let ratchet_tree = deserialize_tree(serialized_tree);
    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => unreachable!("Unexpected message type."),
    };

    let staged_join = StagedWelcome::new_from_welcome(
        &provider.0,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(ratchet_tree),
    )
    .expect("Error creating a staged join");

    let group = staged_join
        .into_group(&provider.0)
        .expect("Error creating group from join");
    insert_group(group_id, group);
}

fn process_commit(client_id: &String, group_id: &String, commit_bytes: &[u8]) {
    let provider = get_provider(client_id);
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let group = groups.get_mut(group_id).expect("Group not found");

    let mut commit_slice = commit_bytes;
    let mls_message_in =
        MlsMessageIn::tls_deserialize(&mut commit_slice).expect("Error des commit");

    let protocol_message: ProtocolMessage = match mls_message_in.extract() {
        MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
        MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
        _ => panic!("Expected a PublicMessage or PrivateMessage for a commit"),
    };

    let processed_message = group
        .process_message(&provider.0, protocol_message)
        .expect("Failed to process message");

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(&provider.0, *staged_commit)
                .expect("Failed to merge staged commit");
        }
        _ => panic!("Expected a StagedCommitMessage"),
    }
}

fn export_shared_secret(client_id: &String, group_id: &String, label: &str) -> Vec<u8> {
    let provider = get_provider(client_id);
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let group = groups.get(group_id).expect("Group not found");
    group
        .export_secret(provider.0.crypto(), label, b"context", 32)
        .expect("Failed to export secret")
}

// KeyPackage and Credential generators remain exactly the same...
fn generate_credential_with_key(client_id: &String) {
    let provider = OpenMlsRustCrypto::default();
    let identity = client_id.clone().into_bytes();
    let credential = BasicCredential::new(identity);
    let signature_keys =
        SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).expect("Error gen");

    let cred = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };
    signature_keys
        .store(provider.storage())
        .expect("Error storing");
    insert_provider(client_id, (provider, cred, signature_keys));
}

fn generate_key_package(client_id: &String) -> String {
    let provider = get_provider(client_id);
    let key_package_bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &provider.0, &provider.2, provider.1.clone())
        .expect("Failed to build KeyPackage");

    let key_package = key_package_bundle.key_package();
    let kp_hash = key_package
        .hash_ref(provider.0.crypto())
        .expect("Failed to hash KeyPackage");
    provider
        .0
        .storage()
        .write_key_package(&kp_hash, &key_package_bundle)
        .expect("Failed to store");
    let kp_bytes = key_package
        .tls_serialize_detached()
        .expect("Failed to serialize KeyPackage");
    hex::encode(kp_bytes)
}

fn deserialize_tree(serialized_tree: &[u8]) -> RatchetTreeIn {
    RatchetTreeIn::tls_deserialize(&mut &*serialized_tree).expect("Error deserializing tree")
}

fn serialize_tree(group_id: &String) -> Vec<u8> {
    let groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let group = groups.get(group_id).expect("Group not found");
    group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .expect("Error serializing tree")
}

// ==========================================
// C/FFI WRAPPERS FOR CGO
// ==========================================

#[repr(C)]
pub struct FfiBuffer {
    pub data: *mut u8,
    pub len: size_t,
}

fn vec_to_ffi(mut vec: Vec<u8>) -> FfiBuffer {
    vec.shrink_to_fit();
    let len = vec.len();
    let data = vec.as_mut_ptr();
    std::mem::forget(vec);
    FfiBuffer { data, len }
}

fn cstr_to_string(c_str: *const c_char) -> String {
    if c_str.is_null() {
        return String::new();
    }
    unsafe { CStr::from_ptr(c_str).to_string_lossy().into_owned() }
}

#[no_mangle]
pub extern "C" fn openmls_free_buffer(buf: FfiBuffer) {
    if !buf.data.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(buf.data, buf.len, buf.len);
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[no_mangle]
pub extern "C" fn ffi_generate_credential(client_id: *const c_char) {
    generate_credential_with_key(&cstr_to_string(client_id));
}

#[no_mangle]
pub extern "C" fn ffi_generate_key_package(client_id: *const c_char) -> *mut c_char {
    CString::new(generate_key_package(&cstr_to_string(client_id)))
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn ffi_create_group(client_id: *const c_char, group_id: *const c_char) {
    create_group(&cstr_to_string(client_id), &cstr_to_string(group_id));
}

#[no_mangle]
pub extern "C" fn ffi_invite_members(
    client_id: *const c_char,
    group_id: *const c_char,
    target_kp_hex: *const c_char,
    out_commit: *mut FfiBuffer,
) -> FfiBuffer {
    let (welcome, commit) = invite_members(
        &cstr_to_string(client_id),
        &cstr_to_string(group_id),
        cstr_to_string(target_kp_hex),
    );
    if !out_commit.is_null() {
        unsafe {
            *out_commit = vec_to_ffi(commit);
        }
    }
    vec_to_ffi(welcome)
}

#[no_mangle]
pub extern "C" fn ffi_process_commit(
    client_id: *const c_char,
    group_id: *const c_char,
    commit_ptr: *const u8,
    commit_len: size_t,
) {
    let commit = unsafe { std::slice::from_raw_parts(commit_ptr, commit_len) };
    process_commit(
        &cstr_to_string(client_id),
        &cstr_to_string(group_id),
        commit,
    );
}

#[no_mangle]
pub extern "C" fn ffi_serialize_tree(group_id: *const c_char) -> FfiBuffer {
    vec_to_ffi(serialize_tree(&cstr_to_string(group_id)))
}

#[no_mangle]
pub extern "C" fn ffi_join_group(
    client_id: *const c_char,
    group_id: *const c_char,
    welcome_ptr: *const u8,
    welcome_len: size_t,
    tree_ptr: *const u8,
    tree_len: size_t,
) {
    let welcome = unsafe { std::slice::from_raw_parts(welcome_ptr, welcome_len) };
    let tree = unsafe { std::slice::from_raw_parts(tree_ptr, tree_len) };
    join_group(
        &cstr_to_string(client_id),
        &cstr_to_string(group_id),
        welcome,
        tree,
    );
}

#[no_mangle]
pub extern "C" fn ffi_export_shared_secret(
    client_id: *const c_char,
    group_id: *const c_char,
    label: *const c_char,
) -> FfiBuffer {
    vec_to_ffi(export_shared_secret(
        &cstr_to_string(client_id),
        &cstr_to_string(group_id),
        &cstr_to_string(label),
    ))
}

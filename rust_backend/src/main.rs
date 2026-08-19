use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;
use openmls_traits::storage::StorageProvider;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use tonic::{transport::Server, Request, Response, Status};

pub mod mls_proto {
    tonic::include_proto!("mls");
}
use mls_proto::mls_service_server::{MlsService, MlsServiceServer};
use mls_proto::*;

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
    let mut groups = CLIENT_GROUPS
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
// gRPC WRAPPERS
// ==========================================

#[derive(Debug, Default)]
pub struct BackendMlsService {}

#[tonic::async_trait]
impl MlsService for BackendMlsService {
    async fn generate_credential(&self, request: Request<GenerateReq>) -> Result<Response<Empty>, Status> {
        println!("generate_credential");
        generate_credential_with_key(&request.into_inner().client_id);
        Ok(Response::new(Empty {}))
    }

    async fn generate_key_package(&self, request: Request<GenerateReq>) -> Result<Response<GenerateKeyPackageRes>, Status> {
        println!("generate_key_package");
        let hex = generate_key_package(&request.into_inner().client_id);
        Ok(Response::new(GenerateKeyPackageRes { key_package_hex: hex }))
    }

    async fn create_group(&self, request: Request<CreateGroupReq>) -> Result<Response<Empty>, Status> {
        println!("create_group");
        let req = request.into_inner();
        create_group(&req.client_id, &req.group_id);
        Ok(Response::new(Empty {}))
    }

    async fn invite_members(&self, request: Request<InviteReq>) -> Result<Response<InviteRes>, Status> {
        println!("invite_members");
        let req = request.into_inner();
        let (welcome, commit) = invite_members(&req.client_id, &req.group_id, req.target_kp_hex);
        Ok(Response::new(InviteRes { welcome_bytes: welcome, commit_bytes: commit }))
    }

    async fn process_commit(&self, request: Request<ProcessCommitReq>) -> Result<Response<Empty>, Status> {
        println!("process_commit");
        let req = request.into_inner();
        process_commit(&req.client_id, &req.group_id, &req.commit_bytes);
        Ok(Response::new(Empty {}))
    }

    async fn serialize_tree(&self, request: Request<SerializeTreeReq>) -> Result<Response<SerializeTreeRes>, Status> {
        println!("serialize_tree");
        let req = request.into_inner();
        let tree = serialize_tree(&req.group_id);
        Ok(Response::new(SerializeTreeRes { tree_bytes: tree }))
    }

    async fn join_group(&self, request: Request<JoinGroupReq>) -> Result<Response<Empty>, Status> {
        println!("join_group");
        let req = request.into_inner();
        join_group(&req.client_id, &req.group_id, &req.welcome_bytes, &req.tree_bytes);
        Ok(Response::new(Empty {}))
    }

    async fn export_shared_secret(&self, request: Request<ExportSecretReq>) -> Result<Response<ExportSecretRes>, Status> {
        println!("export_shared_secret");
        let req = request.into_inner();
        let secret = export_shared_secret(&req.client_id, &req.group_id, &req.label);
        Ok(Response::new(ExportSecretRes { secret_bytes: secret }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::]:50051".parse()?;
    let service = BackendMlsService::default();
    
    println!("Rust MLS gRPC Backend listening on {}", addr);
    Server::builder()
        .add_service(MlsServiceServer::new(service))
        .serve(addr)
        .await?;
    Ok(())
}

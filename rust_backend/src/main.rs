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
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let provider = get_provider(client_id);

    // 1. Do dangerous deserialization OUTSIDE the lock
    let kp_bytes = hex::decode(target_kp_hex).map_err(|e| format!("Invalid hex: {}", e))?;
    let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
        .map_err(|e| format!("Failed to deserialize KeyPackageIn: {:?}", e))?;
    let key_package = key_package_in
        .validate(provider.0.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| format!("Failed to validate KeyPackage: {:?}", e))?;

    // 2. Lock groups safely (recovering from poison if necessary)
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let group = groups.get_mut(group_id).ok_or("Group not found")?;

    let (mls_message_out, welcome_out, _group_info) = group
        .add_members(
            &provider.0,
            &provider.2,
            core::slice::from_ref(&key_package),
        )
        .map_err(|e| format!("Could not add members: {:?}", e))?;

    group
        .merge_pending_commit(&provider.0)
        .map_err(|e| format!("Error merging pending commit: {:?}", e))?;

    let welcome_bytes = welcome_out.tls_serialize_detached().unwrap();
    let commit_bytes = mls_message_out.tls_serialize_detached().unwrap();

    Ok((welcome_bytes, commit_bytes))
}

fn process_commit(client_id: &String, group_id: &String, commit_bytes: &[u8]) -> Result<(), String> {
    let provider = get_provider(client_id);
    let mut commit_slice = commit_bytes;
    
    let mls_message_in = MlsMessageIn::tls_deserialize(&mut commit_slice)
        .map_err(|e| format!("Error des commit: {:?}", e))?;

    let protocol_message: ProtocolMessage = match mls_message_in.extract() {
        MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
        MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
        _ => return Err("Expected a PublicMessage or PrivateMessage for a commit".to_string()),
    };

    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
        
    let group = groups.get_mut(group_id).ok_or("Group not found")?;

    let processed_message = group
        .process_message(&provider.0, protocol_message)
        .map_err(|e| format!("Failed to process message: {:?}", e))?;

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(&provider.0, *staged_commit)
                .map_err(|e| format!("Failed to merge staged commit: {:?}", e))?;
            Ok(())
        }
        _ => Err("Expected a StagedCommitMessage".to_string()),
    }
}

fn join_group(
    client_id: &String,
    group_id: &String,
    serialized_welcome: &[u8],
    serialized_tree: &[u8],
) -> Result<(), String> {
    let provider = get_provider(client_id);
    let mut welcome_slice = serialized_welcome;
    
    let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_slice)
        .map_err(|e| format!("Error des welcome: {:?}", e))?;
    let ratchet_tree = deserialize_tree(serialized_tree);
    
    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err("Unexpected message type.".to_string()),
    };

    let staged_join = StagedWelcome::new_from_welcome(
        &provider.0,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(ratchet_tree),
    ).map_err(|e| format!("Error creating a staged join: {:?}", e))?;

    let group = staged_join
        .into_group(&provider.0)
        .map_err(|e| format!("Error creating group from join: {:?}", e))?;
        
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    groups.insert(group_id.clone(), group);
    
    Ok(())
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
        let req = request.into_inner();
        match invite_members(&req.client_id, &req.group_id, req.target_kp_hex) {
            Ok((welcome, commit)) => Ok(Response::new(InviteRes { welcome_bytes: welcome, commit_bytes: commit })),
            Err(e) => Err(Status::internal(e))
        }
    }

    async fn process_commit(&self, request: Request<ProcessCommitReq>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        match process_commit(&req.client_id, &req.group_id, &req.commit_bytes) {
            Ok(_) => Ok(Response::new(Empty {})),
            Err(e) => Err(Status::internal(e))
        }
    }

    async fn join_group(&self, request: Request<JoinGroupReq>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        match join_group(&req.client_id, &req.group_id, &req.welcome_bytes, &req.tree_bytes) {
            Ok(_) => Ok(Response::new(Empty {})),
            Err(e) => Err(Status::internal(e))
        }
    }
    async fn serialize_tree(&self, request: Request<SerializeTreeReq>) -> Result<Response<SerializeTreeRes>, Status> {
        println!("serialize_tree");
        let req = request.into_inner();
        let tree = serialize_tree(&req.group_id);
        Ok(Response::new(SerializeTreeRes { tree_bytes: tree }))
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

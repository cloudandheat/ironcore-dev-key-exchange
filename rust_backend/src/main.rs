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
) -> Result<Arc<(OpenMlsRustCrypto, CredentialWithKey, SignatureKeyPair)>, Status> {
    let map_lock = CLIENT_IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()));
    let hashmap = map_lock
        .lock()
        .map_err(|_| Status::internal("Failed to acquire identity lock"))?;
    let provider = hashmap
        .get(client_id)
        .ok_or_else(|| Status::not_found(format!("Client {} not found.", client_id)))?;
    Ok(provider.clone())
}

pub fn insert_provider(
    client_id: &String,
    crypto: (OpenMlsRustCrypto, CredentialWithKey, SignatureKeyPair),
) -> Result<(), Status> {
    let map_lock = CLIENT_IDENTITIES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut hashmap = map_lock
        .lock()
        .map_err(|_| Status::internal("Failed to acquire identity lock"))?;
    hashmap.insert(client_id.clone(), Arc::new(crypto));
    Ok(())
}

pub fn insert_group(group_id: &String, group: MlsGroup) -> Result<(), Status> {
    let map_lock = CLIENT_GROUPS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut hashmap = map_lock
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    hashmap.insert(group_id.clone(), group);
    Ok(())
}

fn create_group(client_id: &String, group_id: &String) -> Result<(), Status> {
    let provider = get_provider(client_id)?;
    let group = MlsGroup::new(
        &provider.0,
        &provider.2,
        &MlsGroupCreateConfig::default(),
        provider.1.clone(),
    )
    .map_err(|e| Status::internal(format!("Failed to create MLS group: {:?}", e)))?;
    
    insert_group(group_id, group)
}

fn invite_members(
    client_id: &String,
    group_id: &String,
    target_kp_hex: String,
) -> Result<(Vec<u8>, Vec<u8>), Status> {
    let provider = get_provider(client_id)?;
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    let group = groups
        .get_mut(group_id)
        .ok_or_else(|| Status::not_found("Group not found"))?;

    let kp_bytes = hex::decode(target_kp_hex)
        .map_err(|e| Status::invalid_argument(format!("Invalid hex: {:?}", e)))?;
    
    let key_package_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
        .map_err(|e| Status::invalid_argument(format!("Failed to deserialize KeyPackageIn: {:?}", e)))?;
    
    let key_package = key_package_in
        .validate(provider.0.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| Status::invalid_argument(format!("Failed to validate KeyPackage: {:?}", e)))?;

    let (mls_message_out, welcome_out, _group_info) = group
        .add_members(
            &provider.0,
            &provider.2,
            core::slice::from_ref(&key_package),
        )
        .map_err(|e| Status::internal(format!("Could not add members: {:?}", e)))?;

    group
        .merge_pending_commit(&provider.0)
        .map_err(|e| Status::internal(format!("Error merging pending commit: {:?}", e)))?;

    let welcome_bytes = welcome_out
        .tls_serialize_detached()
        .map_err(|e| Status::internal(format!("Error serializing welcome: {:?}", e)))?;
    let commit_bytes = mls_message_out
        .tls_serialize_detached()
        .map_err(|e| Status::internal(format!("Error serializing commit: {:?}", e)))?;

    Ok((welcome_bytes, commit_bytes))
}

fn remove_member(client_id: &String, group_id: &String, target_client_id: &String) -> Result<Vec<u8>, Status> {
    let provider = get_provider(client_id)?;
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    let group = groups
        .get_mut(group_id)
        .ok_or_else(|| Status::not_found("Group not found"))?;

    let target_identity = target_client_id.clone().into_bytes();
    let expected_credential: Credential = BasicCredential::new(target_identity).into();

    let target_index = group.members()
        .find(|member| member.credential == expected_credential)
        .map(|member| member.index)
        .ok_or_else(|| Status::not_found("Target member not found in group"))?;

    let (mls_message_out, _welcome_out, _group_info) = group
        .remove_members(&provider.0, &provider.2, &[target_index])
        .map_err(|e| Status::internal(format!("Could not remove member: {:?}", e)))?;

    group
        .merge_pending_commit(&provider.0)
        .map_err(|e| Status::internal(format!("Error merging pending commit: {:?}", e)))?;

    mls_message_out
        .tls_serialize_detached()
        .map_err(|e| Status::internal(format!("Error serializing commit: {:?}", e)))
}

fn join_group(
    client_id: &String,
    group_id: &String,
    serialized_welcome: &[u8],
    serialized_tree: &[u8],
) -> Result<(), Status> {
    let provider = get_provider(client_id)?;
    let mut welcome_slice = serialized_welcome;
    
    let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_slice)
        .map_err(|e| Status::invalid_argument(format!("Error des welcome: {:?}", e)))?;
        
    let ratchet_tree = deserialize_tree(serialized_tree)?;
    let welcome = match mls_message_in.extract() {
        MlsMessageBodyIn::Welcome(welcome) => welcome,
        _ => return Err(Status::invalid_argument("Unexpected message type.")),
    };

    let staged_join = StagedWelcome::new_from_welcome(
        &provider.0,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(ratchet_tree),
    )
    .map_err(|e| Status::internal(format!("Error creating a staged join: {:?}", e)))?;

    let group = staged_join
        .into_group(&provider.0)
        .map_err(|e| Status::internal(format!("Error creating group from join: {:?}", e)))?;
        
    insert_group(group_id, group)
}

fn process_commit(client_id: &String, group_id: &String, commit_bytes: &[u8]) -> Result<(), Status> {
    let provider = get_provider(client_id)?;
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    let group = groups
        .get_mut(group_id)
        .ok_or_else(|| Status::not_found("Group not found"))?;

    let mut commit_slice = commit_bytes;
    let mls_message_in = MlsMessageIn::tls_deserialize(&mut commit_slice)
        .map_err(|e| Status::invalid_argument(format!("Error des commit: {:?}", e)))?;

    let protocol_message: ProtocolMessage = match mls_message_in.extract() {
        MlsMessageBodyIn::PublicMessage(pm) => pm.into(),
        MlsMessageBodyIn::PrivateMessage(pm) => pm.into(),
        _ => return Err(Status::invalid_argument("Expected a PublicMessage or PrivateMessage for a commit")),
    };

    let processed_message = group
        .process_message(&provider.0, protocol_message)
        .map_err(|e| Status::internal(format!("Failed to process message: {:?}", e)))?;

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
            group
                .merge_staged_commit(&provider.0, *staged_commit)
                .map_err(|e| Status::internal(format!("Failed to merge staged commit: {:?}", e)))?;
        }
        _ => return Err(Status::invalid_argument("Expected a StagedCommitMessage")),
    }
    
    Ok(())
}

fn export_shared_secret(client_id: &String, group_id: &String, label: &str) -> Result<Vec<u8>, Status> {
    let provider = get_provider(client_id)?;
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    let group = groups
        .get(group_id)
        .ok_or_else(|| Status::not_found("Group not found"))?;
        
    group
        .export_secret(provider.0.crypto(), label, b"context", 32)
        .map_err(|e| Status::internal(format!("Failed to export secret: {:?}", e)))
}

fn generate_credential_with_key(client_id: &String) -> Result<(), Status> {
    let provider = OpenMlsRustCrypto::default();
    let identity = client_id.clone().into_bytes();
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|e| Status::internal(format!("Error gen: {:?}", e)))?;

    let cred = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.public().into(),
    };
    signature_keys
        .store(provider.storage())
        .map_err(|e| Status::internal(format!("Error storing: {:?}", e)))?;
        
    insert_provider(client_id, (provider, cred, signature_keys))
}

fn generate_key_package(client_id: &String) -> Result<String, Status> {
    let provider = get_provider(client_id)?;
    let key_package_bundle = KeyPackage::builder()
        .build(CIPHERSUITE, &provider.0, &provider.2, provider.1.clone())
        .map_err(|e| Status::internal(format!("Failed to build KeyPackage: {:?}", e)))?;

    let key_package = key_package_bundle.key_package();
    let kp_hash = key_package
        .hash_ref(provider.0.crypto())
        .map_err(|e| Status::internal(format!("Failed to hash KeyPackage: {:?}", e)))?;
        
    provider
        .0
        .storage()
        .write_key_package(&kp_hash, &key_package_bundle)
        .map_err(|e| Status::internal(format!("Failed to store: {:?}", e)))?;
        
    let kp_bytes = key_package
        .tls_serialize_detached()
        .map_err(|e| Status::internal(format!("Failed to serialize KeyPackage: {:?}", e)))?;
        
    Ok(hex::encode(kp_bytes))
}

fn deserialize_tree(serialized_tree: &[u8]) -> Result<RatchetTreeIn, Status> {
    RatchetTreeIn::tls_deserialize(&mut &*serialized_tree)
        .map_err(|e| Status::invalid_argument(format!("Error deserializing tree: {:?}", e)))
}

fn serialize_tree(group_id: &String) -> Result<Vec<u8>, Status> {
    let groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    let group = groups
        .get(group_id)
        .ok_or_else(|| Status::not_found("Group not found"))?;
        
    group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map_err(|e| Status::internal(format!("Error serializing tree: {:?}", e)))
}

fn self_update(client_id: &String, group_id: &String) -> Result<Vec<u8>, Status> {
    let provider = get_provider(client_id)?;
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    let group = groups
        .get_mut(group_id)
        .ok_or_else(|| Status::not_found("Group not found"))?;

    // 1. Pass LeafNodeParameters::default()
    // 2. Call .into_contents() on the result to unpack the CommitMessageBundle
    let (mls_message_out, _welcome_out, _group_info) = group
        .self_update(&provider.0, &provider.2, LeafNodeParameters::default())
        .map_err(|e| Status::internal(format!("Could not self update: {:?}", e)))?
        .into_contents();

    group
        .merge_pending_commit(&provider.0)
        .map_err(|e| Status::internal(format!("Error merging pending commit: {:?}", e)))?;

    mls_message_out
        .tls_serialize_detached()
        .map_err(|e| Status::internal(format!("Error serializing commit: {:?}", e)))
}

// drop group from client
fn drop_group(group_id: &String) -> Result<(), Status> {
    let mut groups = CLIENT_GROUPS
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .map_err(|_| Status::internal("Failed to acquire group lock"))?;
    
    // Remove the group from local memory entirely
    groups.remove(group_id);
    Ok(())
}

#[derive(Debug, Default)]
pub struct BackendMlsService {}

#[tonic::async_trait]
impl MlsService for BackendMlsService {
    async fn generate_credential(&self, request: Request<GenerateReq>) -> Result<Response<Empty>, Status> {
        generate_credential_with_key(&request.into_inner().client_id)?;
        Ok(Response::new(Empty {}))
    }

    async fn generate_key_package(&self, request: Request<GenerateReq>) -> Result<Response<GenerateKeyPackageRes>, Status> {
        let hex = generate_key_package(&request.into_inner().client_id)?;
        Ok(Response::new(GenerateKeyPackageRes { key_package_hex: hex }))
    }

    async fn create_group(&self, request: Request<CreateGroupReq>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        create_group(&req.client_id, &req.group_id)?;
        Ok(Response::new(Empty {}))
    }

    async fn invite_members(&self, request: Request<InviteReq>) -> Result<Response<InviteRes>, Status> {
        let req = request.into_inner();
        let (welcome, commit) = invite_members(&req.client_id, &req.group_id, req.target_kp_hex)?;
        Ok(Response::new(InviteRes { welcome_bytes: welcome, commit_bytes: commit }))
    }

    async fn process_commit(&self, request: Request<ProcessCommitReq>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        process_commit(&req.client_id, &req.group_id, &req.commit_bytes)?;
        Ok(Response::new(Empty {}))
    }

    async fn serialize_tree(&self, request: Request<SerializeTreeReq>) -> Result<Response<SerializeTreeRes>, Status> {
        let req = request.into_inner();
        let tree = serialize_tree(&req.group_id)?;
        Ok(Response::new(SerializeTreeRes { tree_bytes: tree }))
    }

    async fn join_group(&self, request: Request<JoinGroupReq>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        join_group(&req.client_id, &req.group_id, &req.welcome_bytes, &req.tree_bytes)?;
        Ok(Response::new(Empty {}))
    }

    async fn export_shared_secret(&self, request: Request<ExportSecretReq>) -> Result<Response<ExportSecretRes>, Status> {
        let req = request.into_inner();
        let secret = export_shared_secret(&req.client_id, &req.group_id, &req.label)?;
        Ok(Response::new(ExportSecretRes { secret_bytes: secret }))
    }

    async fn remove_member(&self, request: Request<RemoveReq>) -> Result<Response<RemoveRes>, Status> {
        let req = request.into_inner();
        let commit_bytes = remove_member(&req.client_id, &req.group_id, &req.target_client_id)?;
        Ok(Response::new(RemoveRes { commit_bytes }))
    }

    async fn self_update(&self, request: Request<SelfUpdateReq>) -> Result<Response<SelfUpdateRes>, Status> {
        let req = request.into_inner();
        let commit_bytes = self_update(&req.client_id, &req.group_id)?;
        Ok(Response::new(SelfUpdateRes { commit_bytes }))
    }

    async fn drop_group(&self, request: Request<DropGroupReq>) -> Result<Response<Empty>, Status> {
        let req = request.into_inner();
        drop_group(&req.group_id)?;
        Ok(Response::new(Empty {}))
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
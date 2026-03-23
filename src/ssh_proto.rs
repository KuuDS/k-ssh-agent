use crate::error::{SshProtoError, SshProtoResult};
use ssh_key::PublicKey;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 0x0B;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 0x0C;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 0x0D;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 0x0E;
pub const SSH_AGENT_FAILURE: u8 = 0x05;

pub struct SshAgentMessage {
    pub msg_type: u8,
    pub payload: Vec<u8>,
}

impl SshAgentMessage {
    pub async fn read<R: AsyncReadExt + Unpin>(reader: &mut R) -> SshProtoResult<Self> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await.map_err(|e| SshProtoError::DecodingError(e.to_string()))?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 1024 * 1024 {
            return Err(SshProtoError::DecodingError("Message too large".to_string()));
        }

        let mut buffer = vec![0u8; len];
        reader.read_exact(&mut buffer).await.map_err(|e| SshProtoError::DecodingError(e.to_string()))?;

        if buffer.is_empty() {
            return Err(SshProtoError::DecodingError("Empty message".to_string()));
        }

        let msg_type = buffer[0];
        let payload = buffer[1..].to_vec();

        Ok(Self { msg_type, payload })
    }

    pub async fn write<W: AsyncWriteExt + Unpin>(&self, writer: &mut W) -> SshProtoResult<()> {
        let mut message = Vec::new();
        message.push(self.msg_type);
        message.extend_from_slice(&self.payload);

        let len = message.len() as u32;
        writer.write_all(&len.to_be_bytes()).await.map_err(|e| SshProtoError::EncodingError(e.to_string()))?;
        writer.write_all(&message).await.map_err(|e| SshProtoError::EncodingError(e.to_string()))?;
        writer.flush().await.map_err(|e| SshProtoError::EncodingError(e.to_string()))?;

        Ok(())
    }
}

pub fn encode_identities(keys: &[PublicKey]) -> SshProtoResult<Vec<u8>> {
    let mut payload = Vec::new();

    payload.extend_from_slice(&(keys.len() as u32).to_be_bytes());

    for key in keys {
        let key_blob = key.to_bytes()
            .map_err(|e| SshProtoError::EncodingError(format!("Failed to encode key: {}", e)))?;
        payload.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
        payload.extend_from_slice(&key_blob);
        payload.extend_from_slice(&0u32.to_be_bytes());
    }

    let mut message = Vec::new();
    message.push(SSH_AGENT_IDENTITIES_ANSWER);
    message.extend_from_slice(&payload);

    let len = message.len() as u32;
    let mut result = Vec::new();
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(&message);

    Ok(result)
}

pub fn decode_request_identities(data: &[u8]) -> SshProtoResult<()> {
    if !data.is_empty() {
        return Err(SshProtoError::DecodingError(
            "REQUEST_IDENTITIES should have empty payload".to_string(),
        ));
    }
    Ok(())
}

pub fn encode_sign_response(signature: &[u8]) -> SshProtoResult<Vec<u8>> {
    let mut payload = Vec::new();

    payload.extend_from_slice(&(signature.len() as u32).to_be_bytes());
    payload.extend_from_slice(signature);

    let mut message = Vec::new();
    message.push(SSH_AGENT_SIGN_RESPONSE);
    message.extend_from_slice(&payload);

    let len = message.len() as u32;
    let mut result = Vec::new();
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(&message);

    Ok(result)
}

pub fn encode_failure() -> SshProtoResult<Vec<u8>> {
    let message = vec![SSH_AGENT_FAILURE];

    let len = message.len() as u32;
    let mut result = Vec::new();
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(&message);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_encode_identities_empty() {
        let keys: Vec<PublicKey> = vec![];
        let encoded = encode_identities(&keys).unwrap();
        
        assert_eq!(encoded.len(), 9);
        assert_eq!(&encoded[0..4], &[0, 0, 0, 5]);
        assert_eq!(encoded[4], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&encoded[5..9], &[0, 0, 0, 0]);
    }

    #[test]
    fn test_encode_identities_single() {
        let key_str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMfm74AN3cywYuJZ9ba0VlT3fmGLCX1l8iRjr6vKJCqI";
        let key = PublicKey::from_str(key_str).unwrap();
        let keys = vec![key];
        
        let encoded = encode_identities(&keys).unwrap();
        
        assert!(encoded.len() > 9);
        assert_eq!(&encoded[0..4], &((encoded.len() - 4) as u32).to_be_bytes());
        assert_eq!(encoded[4], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&encoded[5..9], &[0, 0, 0, 1]);
    }

    #[test]
    fn test_encode_identities_multiple() {
        let key_str1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMfm74AN3cywYuJZ9ba0VlT3fmGLCX1l8iRjr6vKJCqI";
        let key_str2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEJX3pIQzTWnrzVnEem+l8yGu3vCl/M7fUeugTTlMals";
        let key1 = PublicKey::from_str(key_str1).unwrap();
        let key2 = PublicKey::from_str(key_str2).unwrap();
        let keys = vec![key1, key2];
        
        let encoded = encode_identities(&keys).unwrap();
        
        assert_eq!(encoded[4], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&encoded[5..9], &[0, 0, 0, 2]);
    }

    #[test]
    fn test_decode_request_identities() {
        let result = decode_request_identities(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_decode_request_identities_with_payload_should_fail() {
        let result = decode_request_identities(&[0x00]);
        assert!(result.is_err());
    }

    #[test]
    fn test_length_prefix() {
        let keys: Vec<PublicKey> = vec![];
        let encoded = encode_identities(&keys).unwrap();
        
        let length = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        
        assert_eq!(length, encoded.len() - 4);
        assert_eq!(length, 5);
    }

    #[test]
    fn test_encode_sign_response() {
        let signature = vec![0x01, 0x02, 0x03, 0x04];
        let encoded = encode_sign_response(&signature).unwrap();
        
        assert_eq!(encoded.len(), 13);
        assert_eq!(&encoded[0..4], &[0, 0, 0, 9]);
        assert_eq!(encoded[4], SSH_AGENT_SIGN_RESPONSE);
        assert_eq!(&encoded[5..9], &[0, 0, 0, 4]);
        assert_eq!(&encoded[9..13], &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_encode_failure() {
        let encoded = encode_failure().unwrap();
        
        assert_eq!(encoded.len(), 5);
        assert_eq!(&encoded[0..4], &[0, 0, 0, 1]);
        assert_eq!(encoded[4], SSH_AGENT_FAILURE);
    }
}

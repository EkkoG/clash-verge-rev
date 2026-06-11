use crate::config::{Config, IVergeAgeKey};
use crate::utils::help;
use age::{
    Decryptor, Encryptor,
    armor::{ArmoredReader, ArmoredWriter, Format},
    secrecy::ExposeSecret as _,
    x25519,
};
use anyhow::{Context as _, Result, anyhow, bail};
use std::{
    io::{Read as _, Write as _},
    str::FromStr,
};

const AGE_ARMOR_HEADER: &str = "-----BEGIN AGE ENCRYPTED FILE-----";

pub fn is_age_ciphertext(content: &str) -> bool {
    content.trim_start().starts_with(AGE_ARMOR_HEADER)
}

pub fn generate_age_keypair(name: Option<&str>) -> IVergeAgeKey {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    let default_name = format!("Age Key {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));

    IVergeAgeKey {
        id: Some(help::get_uid("age").into()),
        name: Some(name.unwrap_or(default_name.as_str()).trim().to_owned().into()),
        public_key: Some(recipient.to_string().into()),
        secret_key: Some(identity.to_string().expose_secret().to_owned().into()),
        created_at: Some(chrono::Local::now().timestamp() as usize),
    }
}

pub fn derive_public_key_from_secret_key(secret_key: &str) -> Result<String> {
    let identity = x25519::Identity::from_str(secret_key).map_err(|err| anyhow!("invalid age secret key: {err}"))?;
    Ok(identity.to_public().to_string().into())
}

pub async fn resolve_age_key_by_id(key_id: &str) -> Result<Option<IVergeAgeKey>> {
    let verge = Config::verge().await;
    let verge = verge.data_arc();
    Ok(verge
        .age_keys
        .as_ref()
        .and_then(|keys| keys.iter().find(|key| key.id.as_deref() == Some(key_id)).cloned()))
}

pub fn encrypt_age_string(public_key: &str, plaintext: &str) -> Result<String> {
    let recipient = x25519::Recipient::from_str(public_key).map_err(|err| anyhow!("invalid age public key: {err}"))?;
    let encryptor = Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| anyhow!("no age recipient configured"))?;

    let mut output = vec![];
    let armored = ArmoredWriter::wrap_output(&mut output, Format::AsciiArmor)
        .context("failed to initialize age armored writer")?;
    let mut writer = encryptor
        .wrap_output(armored)
        .context("failed to initialize age encryptor")?;
    writer
        .write_all(plaintext.as_bytes())
        .context("failed to write plaintext into age encryptor")?;
    let armored = writer.finish().context("failed to finalize age encryption")?;
    armored.finish().context("failed to finalize age armor")?;

    std::string::String::from_utf8(output)
        .map(Into::into)
        .context("age encryption produced invalid utf-8 output")
}

pub fn decrypt_age_string(secret_key: &str, ciphertext: &str) -> Result<String> {
    let identity = x25519::Identity::from_str(secret_key).map_err(|err| anyhow!("invalid age secret key: {err}"))?;
    let armored = ArmoredReader::new(ciphertext.as_bytes());
    let decryptor = Decryptor::new_buffered(armored).context("failed to initialize age decryptor")?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .context("failed to decrypt age ciphertext")?;
    let mut output = vec![];
    reader
        .read_to_end(&mut output)
        .context("failed to read decrypted age plaintext")?;

    std::string::String::from_utf8(output).context("age decrypted content is not valid utf-8")
}

pub async fn maybe_decrypt_profile_content(content: &str, age_key_id: Option<&str>) -> Result<String> {
    let normalized = content.trim_start_matches('\u{feff}');
    if !is_age_ciphertext(normalized) {
        return Ok(normalized.to_owned());
    }

    let key_id = age_key_id
        .filter(|id| !id.is_empty())
        .ok_or_else(|| anyhow!("profile content is age-encrypted but no age key is configured"))?;
    let key = resolve_age_key_by_id(key_id)
        .await?
        .ok_or_else(|| anyhow!("configured age key was not found: {key_id}"))?;

    decrypt_age_string(
        key.secret_key
            .as_deref()
            .ok_or_else(|| anyhow!("configured age key is missing its secret key"))?,
        normalized,
    )
    .with_context(|| format!("failed to decrypt content with age key {key_id}"))
}

pub async fn maybe_encrypt_profile_content(plaintext: &str, age_key_id: Option<&str>) -> Result<String> {
    let Some(key_id) = age_key_id.filter(|id| !id.is_empty()) else {
        return Ok(plaintext.to_owned());
    };
    let key = resolve_age_key_by_id(key_id)
        .await?
        .ok_or_else(|| anyhow!("configured age key was not found: {key_id}"))?;
    let public_key = key
        .public_key
        .as_deref()
        .ok_or_else(|| anyhow!("configured age key is missing its public key"))?;

    if is_age_ciphertext(plaintext) {
        bail!("expected plaintext when saving an age-enabled profile");
    }

    encrypt_age_string(public_key, plaintext)
        .with_context(|| format!("failed to encrypt content with age key {key_id}"))
}

use super::CmdResult;
use crate::{
    cmd::StringifyErr as _,
    config::{Config, IVerge, IVergeAgeKey, PrfOption, derive_public_key_from_secret_key},
    feat,
};
use anyhow::{Context as _, bail};
use clash_verge_draft::SharedDraft;
use smartstring::alias::String;

/// 获取Verge配置
#[tauri::command]
pub async fn get_verge_config() -> CmdResult<SharedDraft<IVerge>> {
    feat::fetch_verge_config().await.stringify_err()
}

/// 修改Verge配置
#[tauri::command]
pub async fn patch_verge_config(payload: IVerge) -> CmdResult {
    feat::patch_verge(&payload, false).await.stringify_err()
}

#[tauri::command]
pub async fn generate_age_keypair(name: Option<String>) -> CmdResult<IVergeAgeKey> {
    Ok(crate::config::generate_age_keypair(name.as_deref()))
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct IAgeKeyBindingProfile {
    pub uid: String,
    pub name: String,
}

#[tauri::command]
pub async fn import_age_secret_key(name: Option<String>, secret_key: String) -> CmdResult<IVergeAgeKey> {
    let public_key = derive_public_key_from_secret_key(secret_key.as_str()).stringify_err()?;
    let verge = Config::verge().await;
    let current = verge.data_arc();
    let existing = current.age_keys.clone().unwrap_or_default();

    if existing
        .iter()
        .any(|key| key.public_key.as_deref() == Some(public_key.as_str()))
    {
        return Err("age key already exists".into());
    }

    let new_key = IVergeAgeKey {
        id: Some(crate::utils::help::get_uid("age").into()),
        name: Some(
            name.unwrap_or_else(|| format!("Imported {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S")).into())
                .into(),
        ),
        public_key: Some(public_key.into()),
        secret_key: Some(secret_key.into()),
        created_at: Some(chrono::Local::now().timestamp() as usize),
    };
    Ok(new_key)
}

#[tauri::command]
pub async fn export_age_secret_key(key_id: String) -> CmdResult<String> {
    let verge = Config::verge().await;
    let verge = verge.data_arc();
    let key = verge
        .age_keys
        .as_ref()
        .and_then(|keys| keys.iter().find(|key| key.id.as_deref() == Some(key_id.as_str())))
        .cloned()
        .ok_or_else(|| String::from("age key not found"))?;

    key.secret_key.ok_or_else(|| String::from("age key has no secret key"))
}

#[tauri::command]
pub async fn delete_age_key(key_id: String) -> CmdResult {
    let bound = list_age_key_bindings(key_id.clone()).await?;
    if !bound.is_empty() {
        return Err(format!("age key is still bound to {} profile(s)", bound.len()).into());
    }

    let draft = Config::verge().await;
    let before = draft.data_arc().age_keys.as_ref().map_or(0, Vec::len);
    let retained = draft
        .data_arc()
        .age_keys
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|key| key.id.as_deref() != Some(key_id.as_str()))
        .collect::<Vec<_>>();
    if retained.len() == before {
        return Err("age key not found".into());
    }

    draft.edit_draft(|data| {
        data.age_keys = Some(retained.clone());
    });
    draft.apply();
    draft.data_arc().save_file().await.stringify_err()
}

#[tauri::command]
pub async fn list_age_key_bindings(key_id: String) -> CmdResult<Vec<IAgeKeyBindingProfile>> {
    let profiles = Config::profiles().await;
    let profiles = profiles.latest_arc();
    let items = profiles.items.as_ref().cloned().unwrap_or_default();

    let bindings = items
        .into_iter()
        .filter(|item| {
            matches!(item.itype.as_deref(), Some("remote" | "local"))
                && item.option.as_ref().and_then(|option| option.age_key_id.as_deref()) == Some(key_id.as_str())
        })
        .filter_map(|item| {
            let uid = item.uid?;
            let name = item.name?;
            Some(IAgeKeyBindingProfile { uid, name })
        })
        .collect::<Vec<_>>();

    Ok(bindings)
}

#[tauri::command]
pub async fn bind_age_key_to_profiles(key_id: String, profile_ids: Vec<String>) -> CmdResult {
    validate_age_key_exists(key_id.as_str()).await.stringify_err()?;
    patch_age_key_bindings(key_id.as_str(), &profile_ids, true)
        .await
        .stringify_err()
}

#[tauri::command]
pub async fn unbind_age_key_from_profiles(key_id: String, profile_ids: Vec<String>) -> CmdResult {
    validate_age_key_exists(key_id.as_str()).await.stringify_err()?;
    patch_age_key_bindings(key_id.as_str(), &profile_ids, false)
        .await
        .stringify_err()
}

async fn validate_age_key_exists(key_id: &str) -> anyhow::Result<()> {
    let verge = Config::verge().await;
    let verge = verge.data_arc();
    let exists = verge
        .age_keys
        .as_ref()
        .is_some_and(|keys| keys.iter().any(|key| key.id.as_deref() == Some(key_id)));
    if exists { Ok(()) } else { bail!("age key not found") }
}

async fn patch_age_key_bindings(key_id: &str, profile_ids: &[String], bind: bool) -> anyhow::Result<()> {
    let profiles = Config::profiles().await;
    profiles
        .with_data_modify(|mut data| async move {
            let items = data.items.as_mut().context("profiles list is empty")?;

            for profile_id in profile_ids {
                let item = items
                    .iter_mut()
                    .find(|item| item.uid.as_deref() == Some(profile_id.as_str()))
                    .with_context(|| format!("profile not found: {profile_id}"))?;

                if !matches!(item.itype.as_deref(), Some("remote" | "local")) {
                    bail!("only remote/local profiles can bind age keys");
                }

                let option = item.option.get_or_insert_with(PrfOption::default);
                if bind {
                    option.age_key_id = Some(key_id.into());
                } else if option.age_key_id.as_deref() == Some(key_id) {
                    option.age_key_id = None;
                }
            }

            data.save_file().await?;
            Ok((data, ()))
        })
        .await
}

// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Persistent installation state and DPAPI-protected account credentials.

use super::super::win32::{
    AtomicFile, OsStatus, OwnedLocal, OwnedSecurityDescriptor, ProcessToken, ToWideNul,
};
use super::account;
use crate::error::{Error as LandstripError, Mechanism, PolicyViolation};
use crate::policy::AccessPolicy;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::cell::OnceCell;
use std::env;
use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY,
};
use zeroize::Zeroize;

pub(super) const INSTALLATION_VERSION: u32 = 2;
const STATE_DIRECTORY: &str = "Landstrip/windows-restricted-user-v1";
const STATE_FILE: &str = "state.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum NetworkMode {
    Restricted,
    Unrestricted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Account {
    pub(super) name: String,
    pub(super) sid: String,
    pub(super) encrypted_password: String,
    pub(super) network_mode: NetworkMode,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(in crate::platform::windows) struct Installation {
    pub(super) version: u32,
    pub(super) id: String,
    pub(super) proxy_port_low: u16,
    pub(super) proxy_port_high: u16,
    pub(super) wfp_provider: String,
    pub(super) wfp_sublayer: String,
    pub(super) wfp_filters: Vec<String>,
    pub(super) complete: bool,
    pub(super) runner_path: PathBuf,
    pub(super) accounts: Vec<Account>,
}

pub(super) struct SecretWide(Vec<u16>);

impl SecretWide {
    pub(super) fn encrypt(password: &str) -> Result<String> {
        let mut clear = password.as_bytes().to_vec();
        let clear_len = u32::try_from(clear.len()).context("password is too long")?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: clear_len,
            pbData: clear.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let result = unsafe {
            CryptProtectData(
                &raw const input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        };
        clear.zeroize();
        if result == 0 {
            return Err(io::Error::last_os_error()).context("protect sandbox account credential");
        }

        let size = output.cbData as usize;
        let output = unsafe { OwnedLocal::from_raw(output.pbData) };
        let protected = unsafe { hex::encode(std::slice::from_raw_parts(output.as_ptr(), size)) };
        Ok(protected)
    }

    pub(super) fn decrypt(protected: &str) -> Result<Self> {
        let mut protected =
            hex::decode(protected).context("protected password is not valid hexadecimal")?;
        let protected_len =
            u32::try_from(protected.len()).context("protected password is too long")?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: protected_len,
            pbData: protected.as_mut_ptr(),
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let result = unsafe {
            CryptUnprotectData(
                &raw const input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &raw mut output,
            )
        };
        protected.zeroize();
        if result == 0 {
            return Err(io::Error::last_os_error()).context("unprotect sandbox account credential");
        }

        let size = output.cbData as usize;
        let output = unsafe { OwnedLocal::from_raw(output.pbData) };
        let mut clear = unsafe { std::slice::from_raw_parts(output.as_ptr(), size).to_vec() };
        let wide = std::str::from_utf8(&clear)
            .context("sandbox password is not UTF-8")
            .map(|password| {
                let mut wide = OsStr::new(password).encode_wide().collect::<Vec<_>>();
                wide.push(0);
                Self(wide)
            });
        clear.zeroize();
        wide
    }

    pub(super) fn as_ptr(&self) -> *const u16 {
        self.0.as_ptr()
    }
}

impl Drop for SecretWide {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub(super) struct StateStore {
    root: PathBuf,
    owner_dacl: OnceCell<OwnedSecurityDescriptor>,
}

impl StateStore {
    pub(super) fn locate() -> Result<Self> {
        let base = env::var_os("ProgramData").context("Windows ProgramData is unavailable")?;
        Ok(Self {
            root: PathBuf::from(base).join(STATE_DIRECTORY),
            owner_dacl: OnceCell::new(),
        })
    }

    pub(super) fn state_path(&self) -> PathBuf {
        self.root.join(STATE_FILE)
    }

    pub(super) fn leases_dir(&self) -> PathBuf {
        self.root.join("leases")
    }

    pub(super) fn runs_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    pub(super) fn init_runtime_dirs(&self) -> Result<()> {
        for runtime_directory in [self.leases_dir(), self.runs_dir()] {
            fs::create_dir_all(&runtime_directory).with_context(|| {
                format!(
                    "create restricted-user runtime directory {}",
                    runtime_directory.display()
                )
            })?;
            self.protect_path(&runtime_directory)?;
        }
        Ok(())
    }

    pub(super) fn write_json(
        &self,
        path: &Path,
        value: &impl Serialize,
        label: &str,
    ) -> Result<()> {
        let directory = path
            .parent()
            .with_context(|| format!("{label} path has no parent"))?;
        if !directory.is_dir() {
            fs::create_dir_all(directory)
                .with_context(|| format!("create {label} directory {}", directory.display()))?;
            self.protect_path(directory)?;
        }

        let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
        let bytes = serde_json::to_vec_pretty(value)?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)
                .with_context(|| format!("create {label} {}", temporary.display()))?;
            file.write_all(&bytes)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            drop(file);
            self.protect_path(&temporary)?;

            // MoveFileExW within the same directory preserves the file's DACL.
            AtomicFile::replace(&temporary, path)
                .with_context(|| format!("replace restricted-user file {}", path.display()))
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(super) fn protect_path(&self, path: &Path) -> Result<()> {
        let dacl = self
            .owner_security_descriptor()?
            .dacl()
            .context("get restricted-user state DACL")?;
        let path = path.to_wide_nul();
        let status = unsafe {
            SetNamedSecurityInfoW(
                path.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(OsStatus::from_code(status)).context("protect restricted-user state DACL");
        }
        Ok(())
    }

    fn owner_security_descriptor(&self) -> Result<&OwnedSecurityDescriptor> {
        if let Some(descriptor) = self.owner_dacl.get() {
            return Ok(descriptor);
        }
        let owner_sid = ProcessToken::current(TOKEN_QUERY)
            .context("open current process token")?
            .user_sid_string()
            .context("query current user SID")?;
        let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;{owner_sid})");
        let descriptor = OwnedSecurityDescriptor::from_sddl(&sddl)
            .context("build restricted-user state DACL")?;
        let _ = self.owner_dacl.set(descriptor);
        self.owner_dacl
            .get()
            .context("owner DACL was not initialized")
    }

    pub(super) fn remove(&self) -> Result<()> {
        for runtime_directory in [self.leases_dir(), self.runs_dir()] {
            match fs::remove_dir_all(&runtime_directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "remove restricted-user runtime directory {}",
                            runtime_directory.display()
                        )
                    });
                }
            }
        }

        let path = self.state_path();
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("remove restricted-user installation state"),
        }

        let _ = fs::remove_dir(&self.root);
        Ok(())
    }
}

impl Installation {
    pub(super) fn load_from(store: &StateStore) -> Result<Self> {
        let path = store.state_path();
        let bytes = fs::read(&path)
            .with_context(|| format!("restricted-user installation state {}", path.display()))?;
        let installation: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("restricted-user installation state {}", path.display()))?;
        if installation.version != INSTALLATION_VERSION {
            bail!(
                "restricted-user installation version {} is unsupported; expected {}; \
                 rerun `landstrip windows install`",
                installation.version,
                INSTALLATION_VERSION
            );
        }
        Ok(installation)
    }

    pub(super) fn load_optional() -> Result<Option<Self>> {
        let store = StateStore::locate()?;
        Self::load_optional_from(&store)
    }

    pub(super) fn load_optional_from(store: &StateStore) -> Result<Option<Self>> {
        match Self::load_from(store) {
            Ok(installation) => Ok(Some(installation)),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|source| source.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(in crate::platform::windows) fn load_installed() -> crate::error::Result<Option<Self>> {
        Self::load_optional().map_err(|error| {
            LandstripError::sandbox_setup(Mechanism::Windowsuser, error.into_boxed_dyn_error())
        })
    }

    pub(super) fn ensure_ready(&self) -> crate::error::Result<()> {
        if !self.complete {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                "restricted-user installation is incomplete",
            ));
        }
        Ok(())
    }

    pub(super) fn validate_policy(&self, policy: &AccessPolicy) -> crate::error::Result<()> {
        self.ensure_ready()?;
        let (accounts_healthy, runner_healthy) = self.health();
        if !accounts_healthy || !runner_healthy {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                "restricted-user installation is unhealthy",
            ));
        }
        let _ = self.resolve_network_mode(policy)?;
        Ok(())
    }

    pub(super) fn resolve_network_mode(
        &self,
        policy: &AccessPolicy,
    ) -> crate::error::Result<NetworkMode> {
        if !policy.allow_windows_additive_grants {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                "restricted-user isolation cannot enforce allowRead/allowWrite allowlists; \
                 set windows.allowAdditiveGrants to accept additive grants or uninstall it \
                 to use the AppContainer backend",
            ));
        }
        if policy.network_access.is_unrestricted() {
            return Ok(NetworkMode::Unrestricted);
        }
        self.validate_restricted_network(policy)?;
        Ok(NetworkMode::Restricted)
    }

    pub(super) fn save(&self, store: &StateStore) -> Result<()> {
        let path = store.state_path();
        store.write_json(&path, self, "restricted-user state")
    }

    pub(super) fn health(&self) -> (bool, bool) {
        let accounts_healthy = self.accounts.iter().all(|provisioned| {
            account::lookup_sid(&provisioned.name)
                .is_ok_and(|sid| sid.eq_ignore_ascii_case(&provisioned.sid))
        });
        (accounts_healthy, self.runner_path.is_file())
    }

    fn validate_restricted_network(&self, policy: &AccessPolicy) -> crate::error::Result<()> {
        if policy.allow_windows_loopback {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                "windows.allowLoopback is not supported by restricted-user isolation",
            ));
        }
        if policy.network_access.allows_local_binding() {
            return Err(PolicyViolation::LocalBindingUnsupported.into());
        }
        if policy
            .network_access
            .connect_tcp_ports()
            .iter()
            .any(|port| *port < self.proxy_port_low || *port > self.proxy_port_high)
        {
            return Err(LandstripError::sandbox_setup(
                Mechanism::Windowsuser,
                "restricted-user proxy port is outside the installed proxy port range",
            ));
        }
        Ok(())
    }
}

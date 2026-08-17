// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright (c) 2026 Jarkko Sakkinen

//! Persistent Windows Filtering Platform rules for restricted sandbox accounts.

use super::account;
use super::state::{Account, Installation, NetworkMode};
use super::{OwnedSecurityDescriptor, ToWideNul};
use anyhow::{Context, Result, bail};
use std::ptr;
use windows_sys::Win32::Foundation::{
    FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_NOT_FOUND, HANDLE,
};
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_EMPTY, FWP_MATCH_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE,
    FWP_RANGE0, FWP_SECURITY_DESCRIPTOR_TYPE, FWP_UINT8, FWP_UINT16, FWP_V4_ADDR_AND_MASK,
    FWP_V4_ADDR_MASK, FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0,
    FWPM_ACTION0, FWPM_ACTION0_0, FWPM_CONDITION_ALE_USER_ID, FWPM_CONDITION_IP_PROTOCOL,
    FWPM_CONDITION_IP_REMOTE_ADDRESS, FWPM_CONDITION_IP_REMOTE_PORT, FWPM_DISPLAY_DATA0,
    FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_FILTER0, FWPM_FILTER0_0,
    FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_LISTEN_V4,
    FWPM_LAYER_ALE_AUTH_LISTEN_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_PROVIDER_FLAG_PERSISTENT, FWPM_PROVIDER0,
    FWPM_SESSION0, FWPM_SUBLAYER_FLAG_PERSISTENT, FWPM_SUBLAYER0, FwpmEngineClose0,
    FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterDeleteByKey0, FwpmProviderAdd0,
    FwpmProviderDeleteByKey0, FwpmSubLayerAdd0, FwpmSubLayerDeleteByKey0, FwpmTransactionAbort0,
    FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::core::GUID;

const IPPROTO_TCP: u8 = 6;
const FILTER_WEIGHT_BLOCK: u8 = 0;
const FILTER_WEIGHT_PERMIT: u8 = 15;

pub(super) fn generate_key() -> Result<String> {
    account::random_identifier(16)
}

pub(super) fn install(installation: &Installation) -> Result<()> {
    let engine = Engine::open()?;
    let transaction = Transaction::begin(&engine)?;
    let provider = parse_key(&installation.wfp_provider)?;
    let sublayer = parse_key(&installation.wfp_sublayer)?;

    add_provider(engine.handle, provider)?;
    add_sublayer(engine.handle, provider, sublayer)?;

    let mut keys = installation.wfp_filters.iter().map(String::as_str);
    for account in installation
        .accounts
        .iter()
        .filter(|account| account.network_mode == NetworkMode::Restricted)
    {
        add_account_filters(
            engine.handle,
            installation,
            account,
            provider,
            sublayer,
            &mut keys,
        )?;
    }
    if keys.next().is_some() {
        bail!("restricted-user state has surplus WFP filter keys");
    }

    transaction.commit()?;
    Ok(())
}

pub(super) fn uninstall(installation: &Installation) -> Result<()> {
    let engine = Engine::open()?;
    let transaction = Transaction::begin(&engine)?;

    for key in installation.wfp_filters.iter().rev() {
        let key = parse_key(key)?;
        allow_not_found(
            unsafe { FwpmFilterDeleteByKey0(engine.handle, &raw const key) },
            "FwpmFilterDeleteByKey0",
        )?;
    }

    let sublayer = parse_key(&installation.wfp_sublayer)?;
    allow_not_found(
        unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &raw const sublayer) },
        "FwpmSubLayerDeleteByKey0",
    )?;
    let provider = parse_key(&installation.wfp_provider)?;
    allow_not_found(
        unsafe { FwpmProviderDeleteByKey0(engine.handle, &raw const provider) },
        "FwpmProviderDeleteByKey0",
    )?;

    transaction.commit()?;
    Ok(())
}

fn add_account_filters<'a>(
    engine: HANDLE,
    installation: &Installation,
    account: &Account,
    provider: GUID,
    sublayer: GUID,
    keys: &mut impl Iterator<Item = &'a str>,
) -> Result<()> {
    let user = UserCondition::new(&account.sid)?;
    for (layer, family) in [
        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, AddressFamily::V4),
        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, AddressFamily::V6),
    ] {
        let permit_key = next_filter_key(keys)?;
        add_proxy_permit(
            engine,
            permit_key,
            provider,
            sublayer,
            layer,
            family,
            installation.proxy_port_low,
            installation.proxy_port_high,
            &user,
        )?;

        let block_key = next_filter_key(keys)?;
        add_block(engine, block_key, provider, sublayer, layer, &user)?;
    }

    for layer in [
        FWPM_LAYER_ALE_AUTH_LISTEN_V4,
        FWPM_LAYER_ALE_AUTH_LISTEN_V6,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ] {
        let key = next_filter_key(keys)?;
        add_block(engine, key, provider, sublayer, layer, &user)?;
    }
    Ok(())
}

fn next_filter_key<'a>(keys: &mut impl Iterator<Item = &'a str>) -> Result<GUID> {
    let key = keys
        .next()
        .context("restricted-user state is missing a WFP filter key")?;
    parse_key(key)
}

fn add_provider(engine: HANDLE, key: GUID) -> Result<()> {
    let name = "Landstrip restricted-user sandbox".to_wide_nul();
    let provider = FWPM_PROVIDER0 {
        providerKey: key,
        displayData: display(&name),
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: ptr::null_mut(),
    };
    ensure_success_or(
        unsafe { FwpmProviderAdd0(engine, &raw const provider, ptr::null_mut()) },
        "FwpmProviderAdd0",
        &[FWP_E_ALREADY_EXISTS.cast_unsigned()],
    )
}

fn add_sublayer(engine: HANDLE, provider: GUID, key: GUID) -> Result<()> {
    let name = "Landstrip restricted-user sandbox".to_wide_nul();
    let mut provider = provider;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: key,
        displayData: display(&name),
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &raw mut provider,
        providerData: empty_blob(),
        weight: u16::MAX,
    };
    ensure_success_or(
        unsafe { FwpmSubLayerAdd0(engine, &raw const sublayer, ptr::null_mut()) },
        "FwpmSubLayerAdd0",
        &[FWP_E_ALREADY_EXISTS.cast_unsigned()],
    )
}

#[allow(clippy::too_many_arguments)]
fn add_proxy_permit(
    engine: HANDLE,
    key: GUID,
    provider: GUID,
    sublayer: GUID,
    layer: GUID,
    family: AddressFamily,
    low_port: u16,
    high_port: u16,
    user: &UserCondition,
) -> Result<()> {
    let mut port_range = FWP_RANGE0 {
        valueLow: uint16_value(low_port),
        valueHigh: uint16_value(high_port),
    };
    let mut v4_loopback = FWP_V4_ADDR_AND_MASK {
        addr: u32::from_be_bytes([127, 0, 0, 0]),
        mask: u32::from_be_bytes([255, 0, 0, 0]),
    };
    let mut v6_loopback = FWP_V6_ADDR_AND_MASK {
        addr: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        prefixLength: 128,
    };
    let address_value = match family {
        AddressFamily::V4 => FWP_CONDITION_VALUE0 {
            r#type: FWP_V4_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v4AddrMask: &raw mut v4_loopback,
            },
        },
        AddressFamily::V6 => FWP_CONDITION_VALUE0 {
            r#type: FWP_V6_ADDR_MASK,
            Anonymous: FWP_CONDITION_VALUE0_0 {
                v6AddrMask: &raw mut v6_loopback,
            },
        },
    };
    let mut conditions = vec![
        user.filter_condition(),
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_UINT8,
                Anonymous: FWP_CONDITION_VALUE0_0 { uint8: IPPROTO_TCP },
            },
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: address_value,
        },
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: FWP_MATCH_RANGE,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_RANGE_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    rangeValue: &raw mut port_range,
                },
            },
        },
    ];
    add_filter(
        engine,
        key,
        provider,
        sublayer,
        layer,
        FWP_ACTION_PERMIT,
        FILTER_WEIGHT_PERMIT,
        &mut conditions,
    )
}

fn add_block(
    engine: HANDLE,
    key: GUID,
    provider: GUID,
    sublayer: GUID,
    layer: GUID,
    user: &UserCondition,
) -> Result<()> {
    let mut conditions = [user.filter_condition()];
    add_filter(
        engine,
        key,
        provider,
        sublayer,
        layer,
        FWP_ACTION_BLOCK,
        FILTER_WEIGHT_BLOCK,
        &mut conditions,
    )
}

#[allow(clippy::too_many_arguments)]
fn add_filter(
    engine: HANDLE,
    key: GUID,
    mut provider: GUID,
    sublayer: GUID,
    layer: GUID,
    action: u32,
    weight: u8,
    conditions: &mut [FWPM_FILTER_CONDITION0],
) -> Result<()> {
    let name = "Landstrip restricted-user network boundary".to_wide_nul();
    let filter = FWPM_FILTER0 {
        filterKey: key,
        displayData: display(&name),
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &raw mut provider,
        providerData: empty_blob(),
        layerKey: layer,
        subLayerKey: sublayer,
        weight: FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        },
        numFilterConditions: u32::try_from(conditions.len())
            .context("too many WFP filter conditions")?,
        filterCondition: conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: action,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::from_u128(0),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: ptr::null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };
    let mut id = 0;
    ensure_success(
        unsafe { FwpmFilterAdd0(engine, &raw const filter, ptr::null_mut(), &raw mut id) },
        "FwpmFilterAdd0",
    )
}

#[derive(Clone, Copy)]
enum AddressFamily {
    V4,
    V6,
}

struct UserCondition {
    _descriptor: OwnedSecurityDescriptor,
    blob: FWP_BYTE_BLOB,
}

impl UserCondition {
    fn new(sid: &str) -> Result<Self> {
        let descriptor = OwnedSecurityDescriptor::from_sddl(format!("D:(A;;0x00000001;;;{sid})"))
            .context("build WFP account condition")?;
        let blob = FWP_BYTE_BLOB {
            size: descriptor.size(),
            data: descriptor.as_ptr().cast(),
        };
        Ok(Self {
            _descriptor: descriptor,
            blob,
        })
    }

    fn filter_condition(&self) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_USER_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 {
                    sd: (&raw const self.blob).cast_mut(),
                },
            },
        }
    }
}

struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open() -> Result<Self> {
        let name = "Landstrip restricted-user management".to_wide_nul();
        let session = FWPM_SESSION0 {
            sessionKey: GUID::from_u128(0),
            displayData: display(&name),
            flags: 0,
            txnWaitTimeoutInMSec: u32::MAX,
            processId: 0,
            sid: ptr::null_mut(),
            username: ptr::null_mut(),
            kernelMode: 0,
        };
        let mut handle = ptr::null_mut();
        ensure_success(
            unsafe {
                FwpmEngineOpen0(
                    ptr::null(),
                    RPC_C_AUTHN_DEFAULT.cast_unsigned(),
                    ptr::null(),
                    &raw const session,
                    &raw mut handle,
                )
            },
            "FwpmEngineOpen0",
        )?;
        Ok(Self { handle })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                FwpmEngineClose0(self.handle);
            }
        }
    }
}

struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl<'a> Transaction<'a> {
    fn begin(engine: &'a Engine) -> Result<Self> {
        ensure_success(
            unsafe { FwpmTransactionBegin0(engine.handle, 0) },
            "FwpmTransactionBegin0",
        )?;
        Ok(Self {
            engine,
            committed: false,
        })
    }

    fn commit(mut self) -> Result<()> {
        ensure_success(
            unsafe { FwpmTransactionCommit0(self.engine.handle) },
            "FwpmTransactionCommit0",
        )?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.handle);
            }
        }
    }
}

fn ensure_success(result: u32, operation: &str) -> Result<()> {
    ensure_success_or(result, operation, &[])
}

fn allow_not_found(result: u32, operation: &str) -> Result<()> {
    ensure_success_or(
        result,
        operation,
        &[
            FWP_E_FILTER_NOT_FOUND.cast_unsigned(),
            FWP_E_NOT_FOUND.cast_unsigned(),
        ],
    )
}

fn ensure_success_or(result: u32, operation: &str, allowed: &[u32]) -> Result<()> {
    if result == 0 || allowed.contains(&result) {
        Ok(())
    } else {
        bail!("{operation} failed with WFP status 0x{result:08x}")
    }
}

fn parse_key(value: &str) -> Result<GUID> {
    let value = u128::from_str_radix(value, 16)
        .with_context(|| format!("invalid WFP object key {value}"))?;
    Ok(GUID::from_u128(value))
}

fn display(name: &[u16]) -> FWPM_DISPLAY_DATA0 {
    FWPM_DISPLAY_DATA0 {
        name: name.as_ptr().cast_mut(),
        description: ptr::null_mut(),
    }
}

fn uint16_value(value: u16) -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_UINT16,
        Anonymous: FWP_VALUE0_0 { uint16: value },
    }
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: ptr::null_mut(),
    }
}

fn empty_value() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: FWP_VALUE0_0 {
            uint64: ptr::null_mut(),
        },
    }
}

//! Durable, secret-free route receipts for Fabric-managed Claude requests.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64},
    Arc, Mutex, OnceLock,
};

static ROUTE_EVENT_PROCESS_INSTANCE_ID: OnceLock<String> = OnceLock::new();

/// Identifies live stores in this process separately from leases left by an earlier process.
fn route_event_process_instance_id() -> &'static str {
    ROUTE_EVENT_PROCESS_INSTANCE_ID.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

pub const CORRELATION_HEADER: &str = "x-fabric-managed-attempt-id";
const MAX_PAGE_SIZE: usize = 500;
const MAX_SCAN_SEQUENCES: u64 = 1_000;
const MAX_EVENT_BYTES: u64 = 16 * 1024;
// Quota reserves final records, possible atomic-write temps, per-correlation state, and metadata.
const LOGICAL_FILE_OVERHEAD_BYTES: u64 = 512;
const LOGICAL_EVENT_SLOT_BYTES: u64 = MAX_EVENT_BYTES + LOGICAL_FILE_OVERHEAD_BYTES;
const PER_HOP_RESERVATION_BYTES: u64 = 6 * LOGICAL_EVENT_SLOT_BYTES;
const PER_CORRELATION_RESERVATION_BYTES: u64 = 2 * LOGICAL_EVENT_SLOT_BYTES;
const SYSTEM_METADATA_RESERVE_BYTES: u64 = 256 * 1024;
const MAX_ROUTE_STORAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ROUTE_ACTIVITY_ENTRIES: usize = 2_048;

/// Correlation carried only inside the local proxy request extensions.
#[derive(Clone)]
pub struct ManagedRouteCall {
    pub store: Arc<RouteEventStore>,
    pub correlation_id: String,
    pub call_id: String,
    pub requested_model: String,
    hop_sequence: std::sync::Arc<AtomicU64>,
}

impl ManagedRouteCall {
    pub fn new(
        store: Arc<RouteEventStore>,
        correlation_id: String,
        call_id: String,
        requested_model: String,
    ) -> Self {
        Self {
            store,
            correlation_id,
            call_id,
            requested_model,
            hop_sequence: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }
}

struct CallActivity {
    state: Mutex<CallActivityState>,
    active_watch: tokio::sync::watch::Sender<u64>,
}

#[derive(Default)]
struct CallActivityState {
    seal_checked: bool,
    ingress_closed: bool,
    active_calls: u64,
}

/// Keeps an admitted Claude call active until its final response body ends or is dropped.
pub struct ManagedCallLease {
    activity: Arc<CallActivity>,
    settings_dir: PathBuf,
    correlation_id: String,
    call_id: String,
}

impl Drop for ManagedCallLease {
    fn drop(&mut self) {
        let Ok(mut state) = self.activity.state.lock() else {
            return;
        };
        if let Err(error) = release_durable_call_lease(
            &self.settings_dir,
            &self.correlation_id,
            &self.call_id,
            route_event_process_instance_id(),
        ) {
            log::error!("[RouteReceipt] failed to release admitted call lease: {error}");
        }
        state.active_calls = state.active_calls.saturating_sub(1);
        self.activity.active_watch.send_replace(state.active_calls);
    }
}

impl ManagedCallLease {
    /// Returns the call ID admitted by this lease.
    pub fn call_id(&self) -> &str {
        &self.call_id
    }
}

fn release_durable_call_lease(
    settings_dir: &Path,
    correlation_id: &str,
    call_id: &str,
    process_instance_id: &str,
) -> std::io::Result<()> {
    ensure_settings_dir(settings_dir)?;
    let events_dir = settings_dir.join("managed-route-events");
    ensure_private_events_dir(&events_dir)?;
    let lock_path = settings_dir.join("managed-route-events.lock");
    let _process_lock = acquire_file_lock(&lock_path)?;
    let seal_path = events_dir.join(format!("corr-{correlation_id}.seal.json"));
    let mut seal = read_seal_state(&seal_path, correlation_id)?.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed route admission lease lost its durable seal state",
        )
    })?;
    if seal.active_call_owner.as_deref() != Some(process_instance_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed route admission lease owner changed",
        ));
    }
    let position = seal
        .active_call_ids
        .iter()
        .position(|active_call_id| active_call_id == call_id)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "managed route admission lease was already released",
            )
        })?;
    seal.active_call_ids.remove(position);
    if seal.active_call_ids.is_empty() {
        seal.active_call_owner = None;
    }
    write_seal_state(&seal_path, &seal)
}

/// Per-outbound-call observer shared by the forwarding wrapper and send seam.
#[derive(Clone)]
pub struct ManagedHopObserver {
    call: ManagedRouteCall,
    hop_id: String,
    started: std::sync::Arc<Mutex<Option<RouteEvent>>>,
    terminal_state: std::sync::Arc<std::sync::atomic::AtomicU8>,
    status_code: std::sync::Arc<Mutex<Option<u16>>>,
}

impl ManagedHopObserver {
    pub fn new(call: ManagedRouteCall) -> Self {
        Self {
            call,
            hop_id: uuid::Uuid::new_v4().to_string(),
            started: std::sync::Arc::new(Mutex::new(None)),
            terminal_state: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
            status_code: std::sync::Arc::new(Mutex::new(None)),
        }
    }

    pub fn start(&self, provider_id: &str, upstream_model: Option<&str>) -> std::io::Result<()> {
        let hop_seq = self
            .call
            .hop_sequence
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            .saturating_add(1);
        let mut event = RouteEvent::started(
            &self.call.correlation_id,
            &self.call.call_id,
            hop_seq,
            &self.hop_id,
            provider_id,
            &self.call.requested_model,
        );
        event.upstream_model = upstream_model.map(str::to_string);
        if let Err(error) = self.call.store.append(event.clone()) {
            // Capacity or fsync failure refuses the send, so this candidate hop was not
            // outbound. Restore the scoped sequence when no later hop has claimed it.
            let _ = self.call.hop_sequence.compare_exchange(
                hop_seq,
                hop_seq.saturating_sub(1),
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            );
            return Err(error);
        }
        *self
            .started
            .lock()
            .map_err(|_| std::io::Error::other("route hop lock poisoned"))? = Some(event);
        Ok(())
    }

    pub fn started_event(&self) -> Option<RouteEvent> {
        self.started.lock().ok().and_then(|event| event.clone())
    }

    pub fn record_headers(&self, status_code: u16) -> std::io::Result<()> {
        let Some(started) = self.started_event() else {
            self.terminal_state
                .store(3, std::sync::atomic::Ordering::Release);
            return Err(std::io::Error::other("route hop started event is missing"));
        };
        let mut observed_status = match self.status_code.lock() {
            Ok(observed_status) => observed_status,
            Err(_) => {
                self.terminal_state
                    .store(3, std::sync::atomic::Ordering::Release);
                return Err(std::io::Error::other("route status lock poisoned"));
            }
        };
        let mut event = RouteEvent::finished_from(
            &started,
            started.upstream_model.clone(),
            Some(status_code),
            "response_headers_received",
        );
        event.event_type = RouteEventType::HopHeaders;
        if let Err(error) = self.call.store.append(event) {
            self.terminal_state
                .store(3, std::sync::atomic::Ordering::Release);
            return Err(error);
        }
        *observed_status = Some(status_code);
        Ok(())
    }

    pub fn observed_status_code(&self) -> Option<u16> {
        self.status_code.lock().ok().and_then(|value| *value)
    }

    pub fn terminal_persistence_failed(&self) -> bool {
        self.terminal_state
            .load(std::sync::atomic::Ordering::Acquire)
            == 3
    }

    pub fn finish(
        &self,
        started: &RouteEvent,
        upstream_model: Option<String>,
        status_code: Option<u16>,
        outcome: &str,
    ) -> std::io::Result<()> {
        match self.terminal_state.compare_exchange(
            0,
            1,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(2) => return Ok(()),
            Err(3) => {
                return Err(std::io::Error::other(
                    "route terminal receipt persistence previously failed",
                ))
            }
            Err(_) => {
                return Err(std::io::Error::other(
                    "route terminal receipt persistence is already in progress",
                ))
            }
        }
        let event = RouteEvent::finished_from(started, upstream_model, status_code, outcome);
        match self.call.store.append(event) {
            Ok(()) => {
                self.terminal_state
                    .store(2, std::sync::atomic::Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.terminal_state
                    .store(3, std::sync::atomic::Ordering::Release);
                Err(error)
            }
        }
    }
}

/// Append-only route-event store. Each event is atomically published as its own file.
pub struct RouteEventStore {
    settings_dir: PathBuf,
    writer: Mutex<()>,
    activities: Mutex<HashMap<String, Arc<CallActivity>>>,
    reconciled: AtomicBool,
    observed_sequence: AtomicU64,
    observed_allocated_bytes: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteEvent {
    pub schema_version: u8,
    /// Global cursor shared across all correlation IDs in this settings directory.
    pub sequence: u64,
    /// 1-based event cursor scoped to one Fabric correlation ID.
    pub correlation_sequence: u64,
    pub correlation_id: String,
    pub call_id: String,
    pub hop_seq: u64,
    pub hop_id: String,
    pub event_type: RouteEventType,
    pub occurred_at: String,
    pub app: String,
    pub provider_id: String,
    pub provider_revision: Option<String>,
    pub provider_revision_status: String,
    pub requested_model: String,
    pub upstream_model: Option<String>,
    pub status_code: Option<u16>,
    pub outcome: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
// The `hop_` prefix is part of the persisted and control-socket event vocabulary.
#[allow(clippy::enum_variant_names)]
pub enum RouteEventType {
    HopStarted,
    HopHeaders,
    HopFinished,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteEventsQuery {
    pub correlation_id: String,
    #[serde(default)]
    pub after: u64,
    #[serde(default)]
    pub through: Option<u64>,
    #[serde(default = "default_page_size")]
    pub limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteSealQuery {
    pub correlation_id: String,
    #[serde(default = "default_seal_timeout_ms")]
    pub timeout_ms: u64,
}

fn default_seal_timeout_ms() -> u64 {
    30_000
}

/// Marker used by the proxy handler to return HTTP 507 without retrying another provider.
#[derive(Debug)]
pub struct RouteStorageFull;

impl std::fmt::Display for RouteStorageFull {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("managed route receipt storage quota is full")
    }
}

impl std::error::Error for RouteStorageFull {}

pub fn is_storage_full_error(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<RouteStorageFull>())
}

fn default_page_size() -> usize {
    MAX_PAGE_SIZE
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteEventsPage {
    pub schema_version: u8,
    pub correlation_id: String,
    pub events: Vec<RouteEvent>,
    pub event_count: u64,
    /// Global sequence cursor through which the bounded scan completed.
    pub next_after: u64,
    pub latest_sequence: u64,
    pub high_watermark: u64,
    pub cursor_ahead: bool,
    pub has_more: bool,
    /// True when a sequence file in the scanned range is absent or invalid.
    pub cursor_gap: bool,
    /// True when the bounded scan stopped before reaching the snapshot's latest sequence.
    pub scan_truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DurableSealState {
    schema_version: u8,
    correlation_id: String,
    ingress_closed: bool,
    /// Request call IDs admitted before ingress closed and not yet released.
    #[serde(default)]
    active_call_ids: Vec<String>,
    /// Process instance allowed to extend the current active call set.
    #[serde(default)]
    active_call_owner: Option<String>,
    pending_hops: u64,
    #[serde(default)]
    event_count: u64,
    #[serde(default)]
    reserved_hops: u64,
    #[serde(default)]
    metadata_reserved: bool,
    high_watermark: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DurableAllocatorState {
    schema_version: u8,
    allocated_bytes: u64,
}

#[derive(Default)]
struct RebuiltCorrelationState {
    event_count: u64,
    pending_hops: u64,
    completed_hops: u64,
    last_sequence: Option<u64>,
    hops: HashMap<String, RebuiltHopState>,
}

struct RebuiltHopState {
    started: RouteEvent,
    headers_seen: bool,
    finished: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteSealResponse {
    pub schema_version: u8,
    pub producer_schema_generation: u8,
    pub correlation_id: String,
    /// True only after ingress is closed and active/pending hops are drained.
    /// Receipt completeness still requires paging through `highWatermark` with no cursor gap,
    /// scan truncation, or `hop_started` lacking a matching `hop_finished`.
    pub sealed: bool,
    pub ingress_closed: bool,
    /// Number of admitted request call IDs whose leases have not been released.
    pub active_calls: u64,
    pub pending_hops: u64,
    pub event_count: u64,
    pub high_watermark: Option<u64>,
    pub timed_out: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RouteControlInfo {
    pub schema_version: u8,
    pub producer_schema_generation: u8,
    pub proxy_port: Option<u16>,
    pub loopback_reachable: bool,
}

pub fn route_control_info(bound_address: Option<std::net::SocketAddr>) -> RouteControlInfo {
    RouteControlInfo {
        schema_version: 1,
        producer_schema_generation: 1,
        proxy_port: bound_address.map(|address| address.port()),
        loopback_reachable: bound_address
            .is_some_and(|address| address.ip().is_loopback() || address.ip().is_unspecified()),
    }
}

impl RouteEventStore {
    pub fn new(settings_dir: impl Into<PathBuf>) -> Self {
        Self {
            settings_dir: settings_dir.into(),
            writer: Mutex::new(()),
            activities: Mutex::new(HashMap::new()),
            reconciled: AtomicBool::new(false),
            observed_sequence: AtomicU64::new(0),
            observed_allocated_bytes: AtomicU64::new(0),
        }
    }

    fn events_dir(&self) -> PathBuf {
        self.settings_dir.join("managed-route-events")
    }

    fn event_path(&self, sequence: u64) -> PathBuf {
        self.events_dir().join(format!("{sequence:020}.json"))
    }

    fn sequence_path(&self) -> PathBuf {
        self.settings_dir.join("managed-route-events.sequence")
    }

    fn lock_path(&self) -> PathBuf {
        self.settings_dir.join("managed-route-events.lock")
    }

    fn allocator_path(&self) -> PathBuf {
        self.events_dir().join("allocator.json")
    }

    fn reserve_storage_locked(&self, bytes: u64) -> std::io::Result<()> {
        let path = self.allocator_path();
        let mut state = read_allocator_state(&path, &self.events_dir())?;
        let allocated_bytes = state
            .allocated_bytes
            .checked_add(bytes)
            .ok_or_else(route_storage_full_error)?;
        if allocated_bytes.saturating_add(SYSTEM_METADATA_RESERVE_BYTES) > MAX_ROUTE_STORAGE_BYTES {
            return Err(route_storage_full_error());
        }
        state.allocated_bytes = allocated_bytes;
        write_allocator_state(&path, &state, &self.events_dir())
    }

    fn release_storage_locked(&self, bytes: u64) -> std::io::Result<()> {
        let path = self.allocator_path();
        let mut state = read_allocator_state(&path, &self.events_dir())?;
        state.allocated_bytes = state.allocated_bytes.checked_sub(bytes).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "route allocator reservation underflow",
            )
        })?;
        write_allocator_state(&path, &state, &self.events_dir())
    }

    fn ensure_reconciled_locked(&self) -> std::io::Result<()> {
        let latest_sequence = self.latest_sequence_locked()?;
        let allocated_bytes = self.allocator_bytes_locked()?;
        if self.reconciled.load(std::sync::atomic::Ordering::Acquire)
            && latest_sequence
                == self
                    .observed_sequence
                    .load(std::sync::atomic::Ordering::Acquire)
            && allocated_bytes
                == self
                    .observed_allocated_bytes
                    .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(());
        }
        self.reconcile_durable_state_locked()?;
        self.remember_current_locked()?;
        self.reconciled
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn force_reconcile_locked(&self) -> std::io::Result<()> {
        if let Err(error) = self.reconcile_durable_state_locked() {
            self.reconciled
                .store(false, std::sync::atomic::Ordering::Release);
            return Err(error);
        }
        self.remember_current_locked()?;
        self.reconciled
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn allocator_bytes_locked(&self) -> std::io::Result<u64> {
        let path = self.allocator_path();
        match fs::symlink_metadata(&path) {
            Ok(_) => Ok(read_allocator_state(&path, &self.events_dir())?.allocated_bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error),
        }
    }

    fn remember_current_locked(&self) -> std::io::Result<()> {
        let latest_sequence = self.latest_sequence_locked()?;
        let allocated_bytes = self.allocator_bytes_locked()?;
        self.observed_sequence
            .store(latest_sequence, std::sync::atomic::Ordering::Release);
        self.observed_allocated_bytes
            .store(allocated_bytes, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn reconcile_durable_state_locked(&self) -> std::io::Result<()> {
        let latest_sequence = self.latest_sequence_locked()?;
        let mut temporary_reservations = 0_u64;
        for entry in fs::read_dir(self.events_dir())? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if name.ends_with(".tmp") {
                let metadata = fs::symlink_metadata(entry.path())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if !metadata.file_type().is_file()
                        || metadata.uid() != unsafe { libc::geteuid() }
                        || metadata.mode() & 0o077 != 0
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "managed route temporary file is not private and owner-controlled",
                        ));
                    }
                }
                #[cfg(not(unix))]
                if !metadata.file_type().is_file() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "managed route temporary path is not a regular file",
                    ));
                }
                temporary_reservations = temporary_reservations.saturating_add(1);
                continue;
            }
            let Some(sequence) = name
                .strip_suffix(".json")
                .filter(|value| {
                    value.len() == 20 && value.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            if sequence > latest_sequence {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed route event exists beyond the contiguous sequence watermark",
                ));
            }
        }
        let mut correlations = HashMap::<String, RebuiltCorrelationState>::new();
        for sequence in 1..=latest_sequence {
            let event =
                read_event_file(&self.event_path(sequence), sequence)?.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "managed route event sequence contains a gap",
                    )
                })?;
            validate_event(&event)?;
            let state = correlations
                .entry(event.correlation_id.clone())
                .or_default();
            let expected_correlation_sequence = state.event_count.saturating_add(1);
            if event.correlation_sequence != expected_correlation_sequence {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed route correlation sequence is inconsistent",
                ));
            }
            match event.event_type {
                RouteEventType::HopStarted => {
                    if state.hops.contains_key(&event.hop_id) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "managed route hop has duplicate start events",
                        ));
                    }
                    state.pending_hops = state.pending_hops.saturating_add(1);
                    state.hops.insert(
                        event.hop_id.clone(),
                        RebuiltHopState {
                            started: event.clone(),
                            headers_seen: false,
                            finished: false,
                        },
                    );
                }
                RouteEventType::HopHeaders => {
                    let Some(hop) = state.hops.get_mut(&event.hop_id) else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "managed route headers event has no start event",
                        ));
                    };
                    if hop.headers_seen || hop.finished || !same_hop_identity(&hop.started, &event)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "managed route headers event conflicts with its start event",
                        ));
                    }
                    hop.headers_seen = true;
                }
                RouteEventType::HopFinished => {
                    let Some(hop) = state.hops.get_mut(&event.hop_id) else {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "managed route finish event has no start event",
                        ));
                    };
                    if hop.finished
                        || event.outcome.is_none()
                        || !same_hop_identity(&hop.started, &event)
                    {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "managed route finish event conflicts with its start event",
                        ));
                    }
                    hop.finished = true;
                    state.pending_hops = state.pending_hops.saturating_sub(1);
                    state.completed_hops = state.completed_hops.saturating_add(1);
                }
            }
            state.event_count = expected_correlation_sequence;
            state.last_sequence = Some(sequence);
        }

        let mut seal_states = HashMap::<String, DurableSealState>::new();
        for entry in fs::read_dir(self.events_dir())? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Some(correlation_id) = name
                .strip_prefix("corr-")
                .and_then(|value| value.strip_suffix(".seal.json"))
            else {
                continue;
            };
            validate_correlation_id(correlation_id).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed route seal filename has an invalid correlation id",
                )
            })?;
            let path = self.seal_path(correlation_id);
            let state = read_seal_state(&path, correlation_id)?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed route seal state disappeared during reconciliation",
                )
            })?;
            if seal_states
                .insert(correlation_id.to_string(), state)
                .is_some()
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed route has duplicate correlation seal states",
                ));
            }
        }

        if correlations
            .keys()
            .any(|correlation_id| !seal_states.contains_key(correlation_id))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "managed route evidence has no correlation seal state",
            ));
        }

        let mut allocated_bytes = 0_u64;
        for (correlation_id, seal_state) in &mut seal_states {
            let rebuilt = correlations.remove(correlation_id).unwrap_or_default();
            if seal_state.high_watermark.is_some_and(|watermark| {
                watermark > latest_sequence
                    || rebuilt.last_sequence.is_some_and(|last| last > watermark)
            }) || (seal_state.high_watermark.is_some() && rebuilt.pending_hops != 0)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "managed route evidence changed after its seal watermark",
                ));
            }
            let counters_changed = seal_state.pending_hops != rebuilt.pending_hops
                || seal_state.reserved_hops != rebuilt.pending_hops
                || seal_state.event_count != rebuilt.event_count
                || !seal_state.metadata_reserved;
            seal_state.pending_hops = rebuilt.pending_hops;
            seal_state.reserved_hops = rebuilt.pending_hops;
            seal_state.event_count = rebuilt.event_count;
            seal_state.metadata_reserved = true;
            let correlation_bytes = PER_CORRELATION_RESERVATION_BYTES
                .checked_add(
                    rebuilt
                        .completed_hops
                        .checked_mul(3 * LOGICAL_EVENT_SLOT_BYTES)
                        .ok_or_else(route_storage_full_error)?,
                )
                .and_then(|bytes| {
                    rebuilt
                        .pending_hops
                        .checked_mul(PER_HOP_RESERVATION_BYTES)
                        .and_then(|pending_bytes| bytes.checked_add(pending_bytes))
                })
                .ok_or_else(route_storage_full_error)?;
            allocated_bytes = allocated_bytes
                .checked_add(correlation_bytes)
                .ok_or_else(route_storage_full_error)?;
            if counters_changed {
                write_seal_state(&self.seal_path(correlation_id), seal_state)?;
            }
        }
        if allocated_bytes.saturating_add(SYSTEM_METADATA_RESERVE_BYTES) > MAX_ROUTE_STORAGE_BYTES {
            return Err(route_storage_full_error());
        }
        let allocated_bytes = allocated_bytes
            .checked_add(
                temporary_reservations
                    .checked_mul(LOGICAL_EVENT_SLOT_BYTES)
                    .ok_or_else(route_storage_full_error)?,
            )
            .ok_or_else(route_storage_full_error)?;
        if allocated_bytes.saturating_add(SYSTEM_METADATA_RESERVE_BYTES) > MAX_ROUTE_STORAGE_BYTES {
            return Err(route_storage_full_error());
        }
        let allocator_path = self.allocator_path();
        let mut allocator = match fs::symlink_metadata(&allocator_path) {
            Ok(_) => read_allocator_state(&allocator_path, &self.events_dir())?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => DurableAllocatorState {
                schema_version: 1,
                allocated_bytes: 0,
            },
            Err(error) => return Err(error),
        };
        if allocator.allocated_bytes != allocated_bytes {
            allocator.allocated_bytes = allocated_bytes;
            write_allocator_state(&allocator_path, &allocator, &self.events_dir())?;
        }
        Ok(())
    }

    fn seal_path(&self, correlation_id: &str) -> PathBuf {
        self.events_dir()
            .join(format!("corr-{correlation_id}.seal.json"))
    }

    fn activity_for(&self, correlation_id: &str) -> std::io::Result<Arc<CallActivity>> {
        let mut activities = self
            .activities
            .lock()
            .map_err(|_| std::io::Error::other("route activity registry lock poisoned"))?;
        activities.retain(|_, activity| {
            if Arc::strong_count(activity) > 1 {
                return true;
            }
            activity
                .state
                .lock()
                .map(|state| state.active_calls != 0)
                .unwrap_or(true)
        });
        if !activities.contains_key(correlation_id)
            && activities.len() >= MAX_ROUTE_ACTIVITY_ENTRIES
        {
            return Err(route_storage_full_error());
        }
        Ok(activities
            .entry(correlation_id.to_string())
            .or_insert_with(|| {
                let (active_watch, _) = tokio::sync::watch::channel(0);
                Arc::new(CallActivity {
                    state: Mutex::new(CallActivityState::default()),
                    active_watch,
                })
            })
            .clone())
    }

    /// Registers a correlation before body processing so sealing cannot miss ingress.
    pub fn register_call(&self, correlation_id: &str) -> std::io::Result<ManagedCallLease> {
        let result = self.register_call_inner(correlation_id);
        if result.as_ref().is_err_and(should_reconcile_after_error) {
            self.reconciled
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn register_call_inner(&self, correlation_id: &str) -> std::io::Result<ManagedCallLease> {
        validate_correlation_id(correlation_id).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid correlation id")
        })?;
        let call_id = uuid::Uuid::new_v4().to_string();
        let activity = self.activity_for(correlation_id)?;
        let mut state = activity
            .state
            .lock()
            .map_err(|_| std::io::Error::other("route activity lock poisoned"))?;
        ensure_settings_dir(&self.settings_dir)?;
        let _local = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        ensure_private_events_dir(&self.events_dir())?;
        self.ensure_reconciled_locked()?;
        let path = self.seal_path(correlation_id);
        let mut durable = match read_seal_state(&path, correlation_id)? {
            Some(durable) => durable,
            None => {
                self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
                DurableSealState {
                    schema_version: 1,
                    correlation_id: correlation_id.to_string(),
                    ingress_closed: false,
                    active_call_ids: Vec::new(),
                    active_call_owner: None,
                    pending_hops: 0,
                    event_count: 0,
                    reserved_hops: 0,
                    metadata_reserved: true,
                    high_watermark: None,
                }
            }
        };
        if durable.ingress_closed {
            state.ingress_closed = true;
            state.seal_checked = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Fabric correlation has been sealed; new calls are rejected",
            ));
        }
        let same_live_process_owner = !durable.active_call_ids.is_empty()
            && durable.active_call_owner.as_deref() == Some(route_event_process_instance_id());
        if (!durable.active_call_ids.is_empty() || durable.pending_hops > 0)
            && !same_live_process_owner
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Fabric correlation has unresolved admitted calls or route evidence; new calls are rejected",
            ));
        }
        if !durable.metadata_reserved {
            self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
            durable.metadata_reserved = true;
        }
        self.remember_current_locked()?;
        durable.active_call_owner = Some(route_event_process_instance_id().to_string());
        durable.active_call_ids.push(call_id.clone());
        write_seal_state(&path, &durable)?;
        state.seal_checked = true;
        state.active_calls = state.active_calls.saturating_add(1);
        activity.active_watch.send_replace(state.active_calls);
        Ok(ManagedCallLease {
            activity: activity.clone(),
            settings_dir: self.settings_dir.clone(),
            correlation_id: correlation_id.to_string(),
            call_id,
        })
    }

    /// Closes ingress durably, waits for admitted calls, then returns a stable cursor.
    pub async fn seal(
        &self,
        correlation_id: &str,
        timeout: std::time::Duration,
    ) -> std::io::Result<RouteSealResponse> {
        validate_correlation_id(correlation_id).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid correlation id")
        })?;
        let activity = self.activity_for(correlation_id)?;
        {
            let mut activity_state = activity
                .state
                .lock()
                .map_err(|_| std::io::Error::other("route activity lock poisoned"))?;
            ensure_settings_dir(&self.settings_dir)?;
            let _local = self
                .writer
                .lock()
                .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
            let _process_lock = acquire_file_lock(&self.lock_path())?;
            ensure_private_events_dir(&self.events_dir())?;
            self.force_reconcile_locked()?;
            let path = self.seal_path(correlation_id);
            let mut durable = read_seal_state(&path, correlation_id)?.ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Fabric correlation was never admitted",
                )
            })?;
            if !durable.ingress_closed {
                durable.ingress_closed = true;
                write_seal_state(&path, &durable)?;
            }
            activity_state.ingress_closed = true;
            activity_state.seal_checked = true;
        }

        let deadline = tokio::time::Instant::now() + timeout;
        let mut active_rx = activity.active_watch.subscribe();
        loop {
            let active_calls = self.durable_active_lease_count(correlation_id)?;
            if active_calls == 0 {
                break;
            }
            if tokio::time::timeout_at(deadline, async {
                tokio::select! {
                    _ = active_rx.changed() => {},
                    _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {},
                }
            })
            .await
            .is_err()
            {
                return self.seal_response(correlation_id, false, true, None);
            }
        }

        let _local = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        self.force_reconcile_locked()?;
        let path = self.seal_path(correlation_id);
        let mut durable = read_seal_state(&path, correlation_id)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable seal state disappeared",
            )
        })?;
        if !durable.active_call_ids.is_empty()
            || durable.pending_hops != 0
            || durable.reserved_hops != 0
        {
            drop(_process_lock);
            drop(_local);
            return self.seal_response(correlation_id, false, false, None);
        }
        let high_watermark = self.latest_sequence_locked()?;
        durable.high_watermark = Some(durable.high_watermark.unwrap_or(high_watermark));
        write_seal_state(&path, &durable)?;
        self.remember_current_locked()?;
        Ok(RouteSealResponse {
            schema_version: 1,
            producer_schema_generation: 1,
            correlation_id: correlation_id.to_string(),
            sealed: true,
            ingress_closed: true,
            active_calls: 0,
            pending_hops: 0,
            event_count: durable.event_count,
            high_watermark: durable.high_watermark,
            timed_out: false,
        })
    }

    fn seal_response(
        &self,
        correlation_id: &str,
        sealed: bool,
        timed_out: bool,
        high_watermark: Option<u64>,
    ) -> std::io::Result<RouteSealResponse> {
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        ensure_private_events_dir(&self.events_dir())?;
        self.force_reconcile_locked()?;
        let durable = read_seal_state(&self.seal_path(correlation_id), correlation_id)?;
        let active_calls = durable
            .as_ref()
            .map_or(0, |state| state.active_call_ids.len() as u64);
        let pending_hops = durable.as_ref().map_or(0, |state| state.pending_hops);
        let event_count = durable.as_ref().map_or(0, |state| state.event_count);
        Ok(RouteSealResponse {
            schema_version: 1,
            producer_schema_generation: 1,
            correlation_id: correlation_id.to_string(),
            sealed,
            ingress_closed: true,
            active_calls,
            pending_hops,
            event_count,
            high_watermark,
            timed_out,
        })
    }

    fn durable_active_lease_count(&self, correlation_id: &str) -> std::io::Result<u64> {
        let _local = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        ensure_private_events_dir(&self.events_dir())?;
        let durable = read_seal_state(&self.seal_path(correlation_id), correlation_id)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "Fabric correlation was never admitted",
                )
            })?;
        Ok(durable.active_call_ids.len() as u64)
    }

    fn latest_sequence_locked(&self) -> std::io::Result<u64> {
        let persisted = read_last_sequence(&self.sequence_path())?;
        let mut latest = persisted;
        loop {
            let next = latest.saturating_add(1);
            match read_event_file(&self.event_path(next), next) {
                Ok(Some(_)) => latest = next,
                Ok(None) => break,
                Err(error) => return Err(error),
            }
        }
        if latest > persisted {
            write_sequence_atomically(&self.sequence_path(), latest)?;
        }
        Ok(latest)
    }

    /// Atomically allocates a global sequence and publishes an immutable event file.
    pub fn append(&self, event: RouteEvent) -> std::io::Result<()> {
        let result = self.append_inner(event);
        if result.as_ref().is_err_and(should_reconcile_after_error) {
            self.reconciled
                .store(false, std::sync::atomic::Ordering::Release);
        }
        result
    }

    fn append_inner(&self, mut event: RouteEvent) -> std::io::Result<()> {
        validate_event(&event)?;
        let _local = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
        ensure_settings_dir(&self.settings_dir)?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        ensure_private_events_dir(&self.events_dir())?;
        self.ensure_reconciled_locked()?;

        let seal_path = self.seal_path(&event.correlation_id);
        let mut seal_state = match read_seal_state(&seal_path, &event.correlation_id)? {
            Some(state) => state,
            None => {
                self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
                let initial = DurableSealState {
                    schema_version: 1,
                    correlation_id: event.correlation_id.clone(),
                    ingress_closed: false,
                    active_call_ids: Vec::new(),
                    active_call_owner: None,
                    pending_hops: 0,
                    event_count: 0,
                    reserved_hops: 0,
                    metadata_reserved: true,
                    high_watermark: None,
                };
                write_seal_state(&seal_path, &initial)?;
                initial
            }
        };
        if seal_state.high_watermark.is_some() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed route correlation is sealed; late events are rejected",
            ));
        }
        if seal_state.ingress_closed
            && !seal_state
                .active_call_ids
                .iter()
                .any(|call_id| call_id == &event.call_id)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed route call was not admitted before ingress closed",
            ));
        }
        let is_hop_started = event.event_type == RouteEventType::HopStarted;
        let is_hop_headers = event.event_type == RouteEventType::HopHeaders;
        let is_hop_finished = event.event_type == RouteEventType::HopFinished;
        if !seal_state.metadata_reserved {
            self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
            seal_state.metadata_reserved = true;
            write_seal_state(&seal_path, &seal_state)?;
        }
        if is_hop_started {
            self.reserve_storage_locked(PER_HOP_RESERVATION_BYTES)?;
        } else if (is_hop_headers || is_hop_finished) && seal_state.reserved_hops == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "managed route hop event has no durable capacity reservation",
            ));
        }

        let last = self.latest_sequence_locked()?;
        let sequence = last.saturating_add(1);
        event.sequence = sequence;
        let correlation_sequence = seal_state
            .event_count
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("correlation event count overflow"))?;
        event.correlation_sequence = correlation_sequence;
        let line = serde_json::to_vec(&event)
            .map_err(|error| std::io::Error::other(format!("serialize route event: {error}")))?;
        if line.len() as u64 > MAX_EVENT_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "route event exceeds the maximum record size",
            ));
        }

        let final_path = self.event_path(sequence);
        match fs::symlink_metadata(&final_path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "route event sequence already exists",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        // A crash can leave an unpublished temp while the next append reuses this sequence.
        let temporary_path = self
            .events_dir()
            .join(format!(".{sequence:020}.{}.tmp", uuid::Uuid::new_v4()));
        write_private_file(&temporary_path, &line)?;
        fs::rename(&temporary_path, &final_path)?;
        sync_directory(&self.events_dir())?;
        write_sequence_atomically(&self.sequence_path(), sequence)?;
        seal_state.event_count = correlation_sequence;
        if is_hop_started {
            seal_state.pending_hops = seal_state.pending_hops.saturating_add(1);
            seal_state.reserved_hops = seal_state.reserved_hops.saturating_add(1);
        }
        if is_hop_finished {
            // Release only the three temporary-write slots. Three final event slots remain
            // charged permanently; missing optional headers therefore over-reserve safely.
            self.release_storage_locked(3 * LOGICAL_EVENT_SLOT_BYTES)?;
            seal_state.pending_hops = seal_state.pending_hops.saturating_sub(1);
            seal_state.reserved_hops = seal_state.reserved_hops.saturating_sub(1);
        }
        write_seal_state(&seal_path, &seal_state)?;
        self.remember_current_locked()?;
        Ok(())
    }

    /// Reads a bounded cursor page for one exact attempt correlation ID.
    pub fn read_page(
        &self,
        correlation_id: &str,
        after: u64,
        through: Option<u64>,
        limit: usize,
    ) -> std::io::Result<RouteEventsPage> {
        validate_correlation_id(correlation_id).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid correlation id")
        })?;
        ensure_settings_dir(&self.settings_dir)?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        ensure_private_events_dir(&self.events_dir())?;
        let latest_sequence = self.latest_sequence_locked()?;
        let event_count = read_seal_state(&self.seal_path(correlation_id), correlation_id)?
            .map_or(0, |state| state.event_count);
        let high_watermark = through.map_or(latest_sequence, |value| value.min(latest_sequence));
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let scan_end = high_watermark.min(after.saturating_add(MAX_SCAN_SEQUENCES));
        let mut events = Vec::with_capacity(limit);
        let mut sequence = after.saturating_add(1);
        let mut next_after = after;
        let mut cursor_gap = false;
        while after < scan_end && sequence <= scan_end {
            match read_event_file(&self.event_path(sequence), sequence) {
                Ok(Some(event)) => {
                    if event.correlation_id == correlation_id {
                        events.push(event);
                    }
                }
                Ok(None) => cursor_gap = true,
                Err(_) => cursor_gap = true,
            }
            next_after = sequence;
            if events.len() >= limit {
                break;
            }
            if sequence == scan_end {
                break;
            }
            sequence += 1;
        }
        let scan_truncated = next_after < high_watermark
            && high_watermark.saturating_sub(after) > MAX_SCAN_SEQUENCES;
        Ok(RouteEventsPage {
            schema_version: 1,
            correlation_id: correlation_id.to_string(),
            events,
            event_count,
            next_after,
            latest_sequence,
            high_watermark,
            cursor_ahead: after > high_watermark,
            has_more: next_after < high_watermark,
            cursor_gap,
            scan_truncated,
        })
    }
}

/// Returns the owner settings-dir-derived Unix control socket path.
pub fn control_socket_path(settings_dir: &Path) -> PathBuf {
    settings_dir
        .join("managed-route-control")
        .join("control.sock")
}

/// Accepts a conservative opaque Fabric attempt identifier.
pub fn validate_correlation_id(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.len() > 160 || value == "." || value == ".." {
        return Err(());
    }
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        Ok(())
    } else {
        Err(())
    }
}

/// Identifies the reserved correlation header so no upstream adapter can forward it.
pub fn is_reserved_correlation_header(name: &http::HeaderName) -> bool {
    name.as_str().eq_ignore_ascii_case(CORRELATION_HEADER)
}

fn validate_event(event: &RouteEvent) -> std::io::Result<()> {
    validate_correlation_id(&event.correlation_id).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid correlation id")
    })?;
    for value in [
        event.call_id.as_str(),
        event.hop_id.as_str(),
        event.provider_id.as_str(),
        event.requested_model.as_str(),
    ] {
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "route event field is invalid",
            ));
        }
    }
    for value in [
        event.upstream_model.as_deref(),
        event.provider_revision.as_deref(),
        event.outcome.as_deref(),
        Some(event.provider_revision_status.as_str()),
    ]
    .into_iter()
    .flatten()
    {
        if value.len() > 256 || value.chars().any(char::is_control) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "route event field is invalid",
            ));
        }
    }
    Ok(())
}

fn same_hop_identity(started: &RouteEvent, later: &RouteEvent) -> bool {
    started.correlation_id == later.correlation_id
        && started.call_id == later.call_id
        && started.hop_seq == later.hop_seq
        && started.hop_id == later.hop_id
        && started.provider_id == later.provider_id
        && started.provider_revision == later.provider_revision
        && started.provider_revision_status == later.provider_revision_status
        && started.requested_model == later.requested_model
        && match (&started.upstream_model, &later.upstream_model) {
            (Some(started), Some(later)) => started == later,
            _ => true,
        }
}

fn read_event_file(path: &Path, expected_sequence: u64) -> std::io::Result<Option<RouteEvent>> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    if !metadata.file_type().is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed route event is not an owned regular file",
        ));
    }
    #[cfg(not(unix))]
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed route event is not a regular file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if file.metadata()?.len() > MAX_EVENT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "oversized route event",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_EVENT_BYTES + 1).read_to_end(&mut bytes)?;
    let event: RouteEvent = serde_json::from_slice(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid route event: {error}"),
        )
    })?;
    if event.sequence != expected_sequence {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "route event cursor mismatch",
        ));
    }
    Ok(Some(event))
}

#[cfg(unix)]
fn read_last_sequence(path: &Path) -> std::io::Result<u64> {
    use std::os::unix::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file() && metadata.uid() == unsafe { libc::geteuid() } =>
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)?;
            let mut value = String::new();
            file.read_to_string(&mut value)?;
            value.trim().parse::<u64>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid sequence state: {error}"),
                )
            })
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed route sequence path is not an owned regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}

fn read_seal_state(path: &Path, correlation_id: &str) -> std::io::Result<Option<DurableSealState>> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    if !metadata.file_type().is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed route seal path is not an owned regular file",
        ));
    }
    if metadata.len() > MAX_EVENT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed route seal state is oversized",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_EVENT_BYTES + 1).read_to_end(&mut bytes)?;
    let state: DurableSealState = serde_json::from_slice(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid managed route seal state: {error}"),
        )
    })?;
    if state.schema_version != 1 || state.correlation_id != correlation_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed route seal identity or schema mismatch",
        ));
    }
    Ok(Some(state))
}

fn route_storage_full_error() -> std::io::Error {
    std::io::Error::other(RouteStorageFull)
}

fn should_reconcile_after_error(error: &std::io::Error) -> bool {
    !is_storage_full_error(error)
        && !matches!(
            error.kind(),
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::InvalidInput
        )
}

fn read_allocator_state(path: &Path, events_dir: &Path) -> std::io::Result<DurableAllocatorState> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut entries = fs::read_dir(events_dir)?;
            if entries.next().is_some() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "route allocator is missing beside existing evidence; refusing undercount",
                ));
            }
            return Ok(DurableAllocatorState {
                schema_version: 1,
                allocated_bytes: 0,
            });
        }
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    if !metadata.file_type().is_file() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "route allocator path is not an owned regular file",
        ));
    }
    if metadata.len() > 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "route allocator state is oversized",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes)?;
    let state: DurableAllocatorState = serde_json::from_slice(&bytes).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid route allocator state: {error}"),
        )
    })?;
    if state.schema_version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported route allocator schema",
        ));
    }
    Ok(state)
}

fn write_allocator_state(
    path: &Path,
    state: &DurableAllocatorState,
    events_dir: &Path,
) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.uid() == unsafe { libc::geteuid() } => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "route allocator path is not an owned regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let bytes = serde_json::to_vec(state)
        .map_err(|error| std::io::Error::other(format!("serialize allocator state: {error}")))?;
    let temporary = events_dir.join(format!("allocator.{}.tmp", uuid::Uuid::new_v4()));
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    sync_directory(events_dir)
}

fn write_seal_state(path: &Path, state: &DurableSealState) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.uid() == unsafe { libc::geteuid() } => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed route seal path is not an owned regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "managed route seal path has no parent",
        )
    })?;
    let bytes = serde_json::to_vec(state).map_err(|error| {
        std::io::Error::other(format!("serialize managed route seal state: {error}"))
    })?;
    if bytes.len() as u64 > MAX_EVENT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "managed route seal state is oversized",
        ));
    }
    let temporary = parent.join(format!(
        "corr-{}.{}.tmp",
        state.correlation_id,
        uuid::Uuid::new_v4()
    ));
    write_private_file(&temporary, &bytes)?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

#[cfg(not(unix))]
fn read_last_sequence(_path: &Path) -> std::io::Result<u64> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "managed route receipts require Unix domain sockets",
    ))
}

fn write_sequence_atomically(path: &Path, sequence: u64) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.uid() == unsafe { libc::geteuid() } => {}
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed route sequence path is not an owned regular file",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "sequence path has no parent",
        )
    })?;
    let temporary = parent.join(format!(
        "managed-route-events.sequence.{}.tmp",
        uuid::Uuid::new_v4()
    ));
    write_private_file(&temporary, sequence.to_string().as_bytes())?;
    fs::rename(&temporary, path)?;
    sync_directory(parent)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn ensure_settings_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && metadata.uid() == unsafe { libc::geteuid() } =>
            {
                Ok(())
            }
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "managed route settings path is not an owned directory",
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path)?;
                let metadata = fs::symlink_metadata(path)?;
                if metadata.file_type().is_dir() && metadata.uid() == unsafe { libc::geteuid() } {
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "managed route settings path is not an owned directory",
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)
    }
}

fn ensure_private_events_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if metadata.file_type().is_dir()
                    && metadata.uid() == unsafe { libc::geteuid() } =>
            {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed route event directory is not an owned directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(path)?;
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) => return Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(unix)]
struct FileLock(File);

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(unix)]
fn acquire_file_lock(path: &Path) -> std::io::Result<FileLock> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed route lock is not a private owned regular file",
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileLock(file))
}

#[cfg(not(unix))]
fn acquire_file_lock(_path: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "managed route receipts require Unix domain sockets",
    ))
}

impl RouteEvent {
    pub fn started(
        correlation_id: &str,
        call_id: &str,
        hop_seq: u64,
        hop_id: &str,
        provider_id: &str,
        requested_model: &str,
    ) -> Self {
        Self {
            schema_version: 1,
            sequence: 0,
            correlation_sequence: 0,
            correlation_id: correlation_id.to_string(),
            call_id: call_id.to_string(),
            hop_seq,
            hop_id: hop_id.to_string(),
            event_type: RouteEventType::HopStarted,
            occurred_at: chrono::Utc::now().to_rfc3339(),
            app: "claude".to_string(),
            provider_id: provider_id.to_string(),
            provider_revision: None,
            provider_revision_status: "unavailable_from_producer".to_string(),
            requested_model: requested_model.to_string(),
            upstream_model: None,
            status_code: None,
            outcome: None,
        }
    }

    pub fn finished_from(
        started: &Self,
        upstream_model: Option<String>,
        status_code: Option<u16>,
        outcome: &str,
    ) -> Self {
        let mut event = started.clone();
        event.sequence = 0;
        event.event_type = RouteEventType::HopFinished;
        event.occurred_at = chrono::Utc::now().to_rfc3339();
        event.upstream_model = upstream_model;
        event.status_code = status_code;
        event.outcome = Some(outcome.to_string());
        event
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn correlation_id_is_bounded_and_header_safe() {
        assert!(validate_correlation_id("attempt-123:child_1").is_ok());
        assert!(validate_correlation_id("").is_err());
        assert!(validate_correlation_id("attempt id").is_err());
        assert!(validate_correlation_id("..").is_err());
        assert!(validate_correlation_id(&"a".repeat(161)).is_err());
    }

    #[test]
    fn route_control_info_exposes_only_live_port_and_loopback_reachability() {
        let loopback = route_control_info(Some("127.0.0.1:43210".parse().unwrap()));
        assert_eq!(loopback.schema_version, 1);
        assert_eq!(loopback.producer_schema_generation, 1);
        assert_eq!(loopback.proxy_port, Some(43210));
        assert!(loopback.loopback_reachable);
        let wire = serde_json::to_value(&loopback).unwrap();
        assert_eq!(wire["schemaVersion"], 1);
        assert_eq!(wire["producerSchemaGeneration"], 1);
        assert_eq!(wire["proxyPort"], 43210);
        assert_eq!(wire["loopbackReachable"], true);
        assert_eq!(wire.as_object().unwrap().len(), 4);

        let wildcard = route_control_info(Some("0.0.0.0:43211".parse().unwrap()));
        assert_eq!(wildcard.proxy_port, Some(43211));
        assert!(wildcard.loopback_reachable);

        let external = route_control_info(Some("192.0.2.10:43212".parse().unwrap()));
        assert_eq!(external.proxy_port, Some(43212));
        assert!(!external.loopback_reachable);
        assert_eq!(route_control_info(None).proxy_port, None);
    }

    #[test]
    fn reserved_header_is_filtered_for_non_claude_ingress_too() {
        let mut inbound = http::HeaderMap::new();
        inbound.insert(CORRELATION_HEADER, "attempt-1".parse().unwrap());
        inbound.insert("x-client", "value".parse().unwrap());
        let forwarded = inbound
            .iter()
            .filter(|(name, _)| !is_reserved_correlation_header(name))
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect::<http::HeaderMap>();
        assert!(!forwarded.contains_key(CORRELATION_HEADER));
        assert_eq!(forwarded.get("x-client").unwrap(), "value");
    }

    #[test]
    fn appends_and_pages_exact_correlation_with_global_cursor() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        let first = RouteEvent::started("attempt-a", "call-a", 1, "hop-a", "p1", "claude-x");
        store.append(first.clone()).unwrap();
        store
            .append(RouteEvent::finished_from(
                &first,
                Some("model-x".into()),
                Some(200),
                "upstream_body_complete",
            ))
            .unwrap();
        store
            .append(RouteEvent::started(
                "attempt-b",
                "call-b",
                1,
                "hop-b",
                "p2",
                "claude-y",
            ))
            .unwrap();

        let page = store.read_page("attempt-a", 0, None, 1).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.event_count, 2);
        assert_eq!(page.events[0].sequence, 1);
        assert!(page.has_more);
        let next = store
            .read_page("attempt-a", page.next_after, None, 10)
            .unwrap();
        assert_eq!(next.events.len(), 1);
        assert_eq!(next.events[0].event_type, RouteEventType::HopFinished);
        assert!(!next.has_more);
        assert_eq!(
            store.read_page("attempt-b", 0, None, 10).unwrap().events[0].sequence,
            3
        );
        assert_eq!(
            store
                .read_page("attempt-missing", 0, None, 10)
                .unwrap()
                .events
                .len(),
            0
        );
        let cursor_ahead = store.read_page("attempt-a", 99, None, 10).unwrap();
        assert!(cursor_ahead.cursor_ahead);
        assert_eq!(cursor_ahead.latest_sequence, 3);
        assert!(cursor_ahead.events.is_empty());
    }

    #[test]
    fn global_sequence_survives_store_recreation_and_concurrent_instances() {
        let dir = tempdir().unwrap();
        let mut threads = Vec::new();
        for thread_index in 0..8 {
            let settings_dir = dir.path().to_path_buf();
            threads.push(std::thread::spawn(move || {
                let store = RouteEventStore::new(settings_dir);
                for index in 0..10 {
                    let id = format!("attempt-{thread_index}-{index}");
                    store
                        .append(RouteEvent::started(&id, "call", 1, "hop", "p", "m"))
                        .unwrap();
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let store = RouteEventStore::new(dir.path());
        let page = store.read_page("attempt-0-0", 0, None, 500).unwrap();
        assert_eq!(page.latest_sequence, 80);
        assert!(!page.cursor_gap);
        assert!(!page.scan_truncated);
        let sequences = fs::read_dir(store.events_dir())
            .unwrap()
            .filter_map(|entry| {
                let name = entry.ok()?.file_name();
                let name = name.to_string_lossy();
                name.strip_suffix(".json")?.parse::<u64>().ok()
            })
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(sequences.len(), 80);
    }

    #[test]
    fn missing_sequence_is_reported_as_cursor_gap_and_scan_is_bounded() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        for seq in 1..=MAX_SCAN_SEQUENCES + 2 {
            let correlation_id = if seq > MAX_SCAN_SEQUENCES {
                "attempt"
            } else {
                "unrelated"
            };
            let mut event = RouteEvent::started(correlation_id, "call", seq, "hop", "p", "m");
            event.sequence = seq;
            event.correlation_sequence = if correlation_id == "attempt" {
                seq - MAX_SCAN_SEQUENCES
            } else {
                seq
            };
            fs::create_dir_all(store.events_dir()).unwrap();
            fs::write(store.event_path(seq), serde_json::to_vec(&event).unwrap()).unwrap();
        }
        fs::write(store.sequence_path(), (MAX_SCAN_SEQUENCES + 2).to_string()).unwrap();
        fs::remove_file(store.event_path(2)).unwrap();
        let first = store.read_page("attempt", 0, None, usize::MAX).unwrap();
        assert!(first.events.is_empty());
        assert!(first.has_more);
        assert!(first.cursor_gap);
        assert!(first.scan_truncated);
        assert_eq!(first.next_after, MAX_SCAN_SEQUENCES);
        let later = store
            .read_page("attempt", first.next_after, None, MAX_PAGE_SIZE)
            .unwrap();
        assert_eq!(later.events.len(), 2);
        assert_eq!(later.next_after, MAX_SCAN_SEQUENCES + 2);
    }

    #[test]
    fn failed_start_persistence_prevents_observer_from_becoming_started() {
        let dir = tempdir().unwrap();
        let not_a_directory = dir.path().join("not-a-directory");
        fs::write(&not_a_directory, "x").unwrap();
        let store = std::sync::Arc::new(RouteEventStore::new(&not_a_directory));
        let call = ManagedRouteCall::new(store, "attempt".into(), "call".into(), "model".into());
        let observer = ManagedHopObserver::new(call);
        assert!(observer.start("provider", Some("upstream-model")).is_err());
        assert!(observer.started_event().is_none());
    }

    #[test]
    fn terminal_persistence_failure_is_reported_and_never_retried() {
        let dir = tempdir().unwrap();
        let store = std::sync::Arc::new(RouteEventStore::new(dir.path()));
        let call = ManagedRouteCall::new(
            store.clone(),
            "attempt".into(),
            "call".into(),
            "model".into(),
        );
        let observer = ManagedHopObserver::new(call);
        observer.start("provider", Some("model")).unwrap();
        let allocated_before_failure =
            read_allocator_state(&store.allocator_path(), &store.events_dir())
                .unwrap()
                .allocated_bytes;
        fs::remove_file(store.lock_path()).unwrap();
        fs::create_dir(store.lock_path()).unwrap();
        let started = observer.started_event().unwrap();
        assert!(observer
            .finish(
                &started,
                Some("model".into()),
                Some(200),
                "upstream_body_complete"
            )
            .is_err());
        assert_eq!(
            read_allocator_state(&store.allocator_path(), &store.events_dir())
                .unwrap()
                .allocated_bytes,
            allocated_before_failure
        );
        assert!(observer
            .finish(
                &started,
                Some("model".into()),
                Some(200),
                "upstream_body_complete"
            )
            .is_err());
        fs::remove_dir(store.lock_path()).unwrap();
        File::create(store.lock_path()).unwrap();
        let page = RouteEventStore::new(dir.path())
            .read_page("attempt", 0, None, 10)
            .unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event_type, RouteEventType::HopStarted);
    }

    #[tokio::test]
    async fn seal_waits_for_active_call_then_is_idempotent_and_rejects_new_calls() {
        let dir = tempdir().unwrap();
        let store = Arc::new(RouteEventStore::new(dir.path()));
        let lease = store.register_call("attempt-seal").unwrap();
        let call = ManagedRouteCall::new(
            store.clone(),
            "attempt-seal".into(),
            lease.call_id().to_string(),
            "model".into(),
        );
        let observer = ManagedHopObserver::new(call);
        observer.start("provider", Some("upstream-model")).unwrap();
        observer.record_headers(200).unwrap();

        let timed_out = store
            .seal("attempt-seal", std::time::Duration::from_millis(1))
            .await
            .unwrap();
        assert!(!timed_out.sealed);
        assert!(timed_out.ingress_closed);
        assert!(timed_out.timed_out);
        assert_eq!(timed_out.active_calls, 1);
        assert_eq!(timed_out.high_watermark, None);
        assert!(store.register_call("attempt-seal").is_err());

        observer
            .finish(
                &observer.started_event().unwrap(),
                Some("upstream-model".into()),
                Some(200),
                "upstream_body_complete",
            )
            .unwrap();
        drop(lease);

        let sealed = store
            .seal("attempt-seal", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(sealed.sealed);
        assert_eq!(sealed.active_calls, 0);
        assert_eq!(sealed.pending_hops, 0);
        assert_eq!(sealed.event_count, 3);
        assert_eq!(sealed.high_watermark, Some(3));
        let repeated = RouteEventStore::new(dir.path())
            .seal("attempt-seal", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(repeated.sealed);
        assert_eq!(repeated.high_watermark, sealed.high_watermark);
    }

    #[tokio::test]
    async fn seal_after_restart_stays_incomplete_for_durable_started_only_hop() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        store
            .append(RouteEvent::started(
                "attempt-crash",
                "call-1",
                1,
                "hop-1",
                "provider",
                "model",
            ))
            .unwrap();

        let restarted = RouteEventStore::new(dir.path());
        let seal = restarted
            .seal("attempt-crash", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!seal.sealed);
        assert!(seal.ingress_closed);
        assert_eq!(seal.active_calls, 0);
        assert_eq!(seal.pending_hops, 1);
        assert_eq!(seal.high_watermark, None);
        assert!(restarted.register_call("attempt-crash").is_err());
        let allocator =
            read_allocator_state(&restarted.allocator_path(), &restarted.events_dir()).unwrap();
        assert!(
            allocator.allocated_bytes
                >= PER_CORRELATION_RESERVATION_BYTES + PER_HOP_RESERVATION_BYTES
        );
    }

    #[tokio::test]
    async fn restart_rebuilds_started_only_counters_from_immutable_events() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        store
            .append(RouteEvent::started(
                "attempt-reconcile-start",
                "call-1",
                1,
                "hop-1",
                "provider",
                "model",
            ))
            .unwrap();
        let mut state = read_seal_state(
            &store.seal_path("attempt-reconcile-start"),
            "attempt-reconcile-start",
        )
        .unwrap()
        .unwrap();
        state.event_count = 0;
        state.pending_hops = 0;
        state.reserved_hops = 0;
        write_seal_state(&store.seal_path("attempt-reconcile-start"), &state).unwrap();
        let mut allocator =
            read_allocator_state(&store.allocator_path(), &store.events_dir()).unwrap();
        allocator.allocated_bytes = PER_CORRELATION_RESERVATION_BYTES;
        write_allocator_state(&store.allocator_path(), &allocator, &store.events_dir()).unwrap();

        let restarted = RouteEventStore::new(dir.path());
        let seal = restarted
            .seal("attempt-reconcile-start", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!seal.sealed);
        assert_eq!(seal.event_count, 1);
        assert_eq!(seal.pending_hops, 1);
        assert_eq!(seal.high_watermark, None);
        let allocator =
            read_allocator_state(&restarted.allocator_path(), &restarted.events_dir()).unwrap();
        assert_eq!(
            allocator.allocated_bytes,
            PER_CORRELATION_RESERVATION_BYTES + PER_HOP_RESERVATION_BYTES
        );
    }

    #[tokio::test]
    async fn seal_refreshes_counters_changed_by_another_store() {
        let dir = tempdir().unwrap();
        let sealing_store = RouteEventStore::new(dir.path());
        let lease = sealing_store.register_call("attempt-cross-store").unwrap();
        drop(lease);

        RouteEventStore::new(dir.path())
            .append(RouteEvent::started(
                "attempt-cross-store",
                "call-1",
                1,
                "hop-1",
                "provider",
                "model",
            ))
            .unwrap();
        let mut state = read_seal_state(
            &sealing_store.seal_path("attempt-cross-store"),
            "attempt-cross-store",
        )
        .unwrap()
        .unwrap();
        state.event_count = 0;
        state.pending_hops = 0;
        state.reserved_hops = 0;
        write_seal_state(&sealing_store.seal_path("attempt-cross-store"), &state).unwrap();

        let seal = sealing_store
            .seal("attempt-cross-store", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(!seal.sealed);
        assert_eq!(seal.event_count, 1);
        assert_eq!(seal.pending_hops, 1);
        assert_eq!(seal.high_watermark, None);
    }

    #[tokio::test]
    async fn restart_reconciles_published_finish_and_releases_unused_reservation() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        let started = RouteEvent::started(
            "attempt-reconcile-finish",
            "call-1",
            1,
            "hop-1",
            "provider",
            "model",
        );
        store.append(started.clone()).unwrap();
        let mut headers = RouteEvent::finished_from(
            &started,
            started.upstream_model.clone(),
            Some(200),
            "response_headers_received",
        );
        headers.event_type = RouteEventType::HopHeaders;
        store.append(headers).unwrap();
        store
            .append(RouteEvent::finished_from(
                &started,
                started.upstream_model.clone(),
                Some(200),
                "response_complete",
            ))
            .unwrap();

        let mut state = read_seal_state(
            &store.seal_path("attempt-reconcile-finish"),
            "attempt-reconcile-finish",
        )
        .unwrap()
        .unwrap();
        state.event_count = 2;
        state.pending_hops = 1;
        state.reserved_hops = 1;
        write_seal_state(&store.seal_path("attempt-reconcile-finish"), &state).unwrap();

        let restarted = RouteEventStore::new(dir.path());
        let seal = restarted
            .seal(
                "attempt-reconcile-finish",
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
        assert!(seal.sealed);
        assert_eq!(seal.event_count, 3);
        assert_eq!(seal.pending_hops, 0);
        assert_eq!(seal.high_watermark, Some(3));
        let allocator =
            read_allocator_state(&restarted.allocator_path(), &restarted.events_dir()).unwrap();
        assert_eq!(
            allocator.allocated_bytes,
            PER_CORRELATION_RESERVATION_BYTES + 3 * LOGICAL_EVENT_SLOT_BYTES
        );
    }

    #[tokio::test]
    async fn second_store_waits_for_an_admitted_call_before_sealing() {
        let dir = tempdir().unwrap();
        let original = Arc::new(RouteEventStore::new(dir.path()));
        let lease = original.register_call("attempt-handover").unwrap();
        let replacement = RouteEventStore::new(dir.path());
        let seal_path = original.seal_path("attempt-handover");
        let seal_task = tokio::spawn(async move {
            replacement
                .seal("attempt-handover", std::time::Duration::from_secs(1))
                .await
                .unwrap()
        });
        let durable = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let durable = read_seal_state(&seal_path, "attempt-handover")
                    .unwrap()
                    .unwrap();
                if durable.ingress_closed {
                    break durable;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement store closes ingress");
        assert_eq!(durable.active_call_ids, vec![lease.call_id().to_string()]);
        assert!(RouteEventStore::new(dir.path())
            .register_call("attempt-handover")
            .is_err());
        let unadmitted = ManagedHopObserver::new(ManagedRouteCall::new(
            original.clone(),
            "attempt-handover".into(),
            "unadmitted-call".into(),
            "model".into(),
        ));
        assert!(unadmitted.start("provider", Some("model")).is_err());

        let call = ManagedRouteCall::new(
            original.clone(),
            "attempt-handover".into(),
            lease.call_id().to_string(),
            "model".into(),
        );
        let observer = ManagedHopObserver::new(call);
        observer.start("provider", Some("model")).unwrap();
        observer.record_headers(200).unwrap();
        observer
            .finish(
                &observer.started_event().unwrap(),
                Some("model".into()),
                Some(200),
                "upstream_body_complete",
            )
            .unwrap();
        drop(lease);

        let seal = seal_task.await.unwrap();
        assert!(seal.sealed);
        assert_eq!(seal.active_calls, 0);
        assert_eq!(seal.pending_hops, 0);
        assert_eq!(seal.event_count, 3);
        assert_eq!(seal.high_watermark, Some(3));
    }

    #[test]
    fn stores_in_the_same_process_can_admit_concurrent_calls() {
        let dir = tempdir().unwrap();
        let first_store = RouteEventStore::new(dir.path());
        let first_lease = first_store.register_call("attempt-shared-owner").unwrap();
        let second_store = RouteEventStore::new(dir.path());
        let second_lease = second_store
            .register_call("attempt-shared-owner")
            .expect("same-process stores share the active admission owner");

        assert_ne!(first_lease.call_id(), second_lease.call_id());
        let seal_path = first_store.seal_path("attempt-shared-owner");
        let durable = read_seal_state(&seal_path, "attempt-shared-owner")
            .unwrap()
            .unwrap();
        assert_eq!(durable.active_call_ids.len(), 2);
        assert_eq!(
            durable.active_call_owner.as_deref(),
            Some(route_event_process_instance_id())
        );

        drop(first_lease);
        let durable = read_seal_state(&seal_path, "attempt-shared-owner")
            .unwrap()
            .unwrap();
        assert_eq!(durable.active_call_ids, vec![second_lease.call_id()]);
        assert_eq!(
            durable.active_call_owner.as_deref(),
            Some(route_event_process_instance_id())
        );

        drop(second_lease);
        let durable = read_seal_state(&seal_path, "attempt-shared-owner")
            .unwrap()
            .unwrap();
        assert!(durable.active_call_ids.is_empty());
        assert_eq!(durable.active_call_owner, None);
    }

    #[tokio::test]
    async fn replacement_store_never_seals_an_unreleased_call_lease() {
        let dir = tempdir().unwrap();
        let original = RouteEventStore::new(dir.path());
        let lease = original.register_call("attempt-crashed-call").unwrap();
        std::mem::forget(lease);

        let mut durable = read_seal_state(
            &original.seal_path("attempt-crashed-call"),
            "attempt-crashed-call",
        )
        .unwrap()
        .unwrap();
        durable.active_call_owner = Some("previous-process-instance".to_string());
        write_seal_state(&original.seal_path("attempt-crashed-call"), &durable).unwrap();

        let replacement = RouteEventStore::new(dir.path());
        assert!(replacement.register_call("attempt-crashed-call").is_err());
        let seal = replacement
            .seal("attempt-crashed-call", std::time::Duration::from_millis(5))
            .await
            .unwrap();
        assert!(!seal.sealed);
        assert!(seal.timed_out);
        assert_eq!(seal.active_calls, 1);
        assert_eq!(seal.high_watermark, None);
    }

    #[tokio::test]
    async fn route_events_page_stops_at_sealed_high_watermark() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        let first = RouteEvent::started("attempt-through", "call", 1, "hop-1", "p", "m");
        store.append(first.clone()).unwrap();
        store
            .append(RouteEvent::finished_from(
                &first,
                Some("m".into()),
                Some(200),
                "upstream_body_complete",
            ))
            .unwrap();
        let high_watermark = 2;
        store
            .append(RouteEvent::started("other", "call", 1, "hop", "p", "m"))
            .unwrap();

        let page = store
            .read_page("attempt-through", 0, Some(high_watermark), 10)
            .unwrap();
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.high_watermark, high_watermark);
        assert!(!page.has_more);
        assert_eq!(page.latest_sequence, 3);
    }

    #[tokio::test]
    async fn sealed_true_does_not_hide_a_later_receipt_gap() {
        let dir = tempdir().unwrap();
        let store = Arc::new(RouteEventStore::new(dir.path()));
        let lease = store.register_call("attempt-gap-after-seal").unwrap();
        let call = ManagedRouteCall::new(
            store.clone(),
            "attempt-gap-after-seal".into(),
            lease.call_id().to_string(),
            "model".into(),
        );
        let observer = ManagedHopObserver::new(call);
        observer.start("provider", Some("model")).unwrap();
        observer.record_headers(200).unwrap();
        observer
            .finish(
                &observer.started_event().unwrap(),
                Some("model".into()),
                Some(200),
                "upstream_body_complete",
            )
            .unwrap();
        drop(lease);

        let seal = store
            .seal("attempt-gap-after-seal", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(seal.sealed);
        fs::remove_file(store.event_path(2)).unwrap();
        let page = store
            .read_page("attempt-gap-after-seal", 0, seal.high_watermark, 10)
            .unwrap();
        assert!(page.cursor_gap);
        assert_eq!(page.events.len(), 2);
        assert!(!page.scan_truncated);
    }

    #[test]
    fn correlation_event_count_detects_omission_without_global_cursor_gap() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        fs::create_dir_all(store.events_dir()).unwrap();
        let mut first = RouteEvent::started("attempt-omission", "call", 1, "hop-1", "p", "m");
        first.sequence = 1;
        first.correlation_sequence = 1;
        let mut unrelated = RouteEvent::started("other", "call", 1, "hop-2", "p", "m");
        unrelated.sequence = 2;
        unrelated.correlation_sequence = 1;
        let mut third = RouteEvent::started("attempt-omission", "call", 2, "hop-3", "p", "m");
        third.sequence = 3;
        // Simulate a producer omission while its durable correlation count advances.
        third.correlation_sequence = 3;
        for event in [first, unrelated, third] {
            fs::write(
                store.event_path(event.sequence),
                serde_json::to_vec(&event).unwrap(),
            )
            .unwrap();
        }
        fs::write(store.sequence_path(), "3").unwrap();
        write_seal_state(
            &store.seal_path("attempt-omission"),
            &DurableSealState {
                schema_version: 1,
                correlation_id: "attempt-omission".to_string(),
                ingress_closed: true,
                active_call_ids: Vec::new(),
                active_call_owner: None,
                pending_hops: 0,
                event_count: 3,
                reserved_hops: 0,
                metadata_reserved: true,
                high_watermark: Some(3),
            },
        )
        .unwrap();

        let page = store.read_page("attempt-omission", 0, Some(3), 10).unwrap();
        assert_eq!(page.event_count, 3);
        assert!(!page.cursor_gap);
        assert_eq!(
            page.events
                .iter()
                .map(|event| event.correlation_sequence)
                .collect::<Vec<_>>(),
            [1, 3]
        );
        assert_ne!(
            page.events
                .iter()
                .map(|event| event.correlation_sequence)
                .collect::<Vec<_>>(),
            (1..=page.event_count).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn storage_quota_rejects_started_hop_but_reads_and_seal_still_work() {
        let dir = tempdir().unwrap();
        let store = Arc::new(RouteEventStore::new(dir.path()));
        let lease = store.register_call("attempt-at-cap").unwrap();
        {
            let _local = store.writer.lock().unwrap();
            let _process_lock = acquire_file_lock(&store.lock_path()).unwrap();
            let mut allocator =
                read_allocator_state(&store.allocator_path(), &store.events_dir()).unwrap();
            allocator.allocated_bytes =
                MAX_ROUTE_STORAGE_BYTES - SYSTEM_METADATA_RESERVE_BYTES - PER_HOP_RESERVATION_BYTES
                    + 1;
            write_allocator_state(&store.allocator_path(), &allocator, &store.events_dir())
                .unwrap();
            store.observed_allocated_bytes.store(
                allocator.allocated_bytes,
                std::sync::atomic::Ordering::Release,
            );
        }
        let call = ManagedRouteCall::new(
            store.clone(),
            "attempt-at-cap".into(),
            "call-1".into(),
            "model".into(),
        );
        let observer = ManagedHopObserver::new(call);
        let error = observer.start("provider", Some("model")).unwrap_err();
        assert!(is_storage_full_error(&error));
        assert!(observer.started_event().is_none());
        assert!(store
            .read_page("attempt-at-cap", 0, None, 10)
            .unwrap()
            .events
            .is_empty());
        drop(lease);
        let seal = store
            .seal("attempt-at-cap", std::time::Duration::from_secs(1))
            .await
            .unwrap();
        assert!(seal.sealed);
        assert_eq!(seal.high_watermark, Some(0));
    }

    #[test]
    fn unique_quota_failures_do_not_accumulate_activity_entries() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        ensure_settings_dir(&store.settings_dir).unwrap();
        ensure_private_events_dir(&store.events_dir()).unwrap();
        write_allocator_state(
            &store.allocator_path(),
            &DurableAllocatorState {
                schema_version: 1,
                allocated_bytes: MAX_ROUTE_STORAGE_BYTES - SYSTEM_METADATA_RESERVE_BYTES,
            },
            &store.events_dir(),
        )
        .unwrap();
        store
            .reconciled
            .store(true, std::sync::atomic::Ordering::Release);
        store.observed_allocated_bytes.store(
            MAX_ROUTE_STORAGE_BYTES - SYSTEM_METADATA_RESERVE_BYTES,
            std::sync::atomic::Ordering::Release,
        );

        for index in 0..(MAX_ROUTE_ACTIVITY_ENTRIES * 2) {
            let correlation_id = format!("attempt-{index}");
            let error = match store.register_call(&correlation_id) {
                Ok(_) => panic!("a full route store admitted a new correlation"),
                Err(error) => error,
            };
            assert!(is_storage_full_error(&error));
            assert!(store.activities.lock().unwrap().len() <= 1);
        }

        let unknown_seal = futures::executor::block_on(
            store.seal("never-admitted", std::time::Duration::from_millis(1)),
        );
        assert_eq!(
            unknown_seal.unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(!store.seal_path("never-admitted").exists());
        assert!(store.activities.lock().unwrap().len() <= 1);
    }

    #[test]
    fn terminal_releases_only_unused_slots_and_allows_next_reserved_hop() {
        let dir = tempdir().unwrap();
        let store = Arc::new(RouteEventStore::new(dir.path()));
        let _lease = store.register_call("attempt-release").unwrap();
        {
            let _local = store.writer.lock().unwrap();
            let _process_lock = acquire_file_lock(&store.lock_path()).unwrap();
            let mut allocator =
                read_allocator_state(&store.allocator_path(), &store.events_dir()).unwrap();
            allocator.allocated_bytes = MAX_ROUTE_STORAGE_BYTES
                - SYSTEM_METADATA_RESERVE_BYTES
                - (2 * PER_HOP_RESERVATION_BYTES)
                + (3 * LOGICAL_EVENT_SLOT_BYTES);
            write_allocator_state(&store.allocator_path(), &allocator, &store.events_dir())
                .unwrap();
            store.observed_allocated_bytes.store(
                allocator.allocated_bytes,
                std::sync::atomic::Ordering::Release,
            );
        }
        let call = ManagedRouteCall::new(
            store.clone(),
            "attempt-release".into(),
            "call-1".into(),
            "model".into(),
        );
        let first = ManagedHopObserver::new(call.clone());
        let second = ManagedHopObserver::new(call);
        first.start("provider-1", Some("model")).unwrap();
        let full = second.start("provider-2", Some("model")).unwrap_err();
        assert!(is_storage_full_error(&full));
        assert!(second.started_event().is_none());

        first.record_headers(200).unwrap();
        first
            .finish(
                &first.started_event().unwrap(),
                Some("model".into()),
                Some(200),
                "upstream_body_complete",
            )
            .unwrap();
        let mut allocator =
            read_allocator_state(&store.allocator_path(), &store.events_dir()).unwrap();
        assert_eq!(
            allocator.allocated_bytes,
            MAX_ROUTE_STORAGE_BYTES - SYSTEM_METADATA_RESERVE_BYTES - PER_HOP_RESERVATION_BYTES
        );

        second.start("provider-2", Some("model")).unwrap();
        assert_eq!(second.started_event().unwrap().hop_seq, 2);
        allocator = read_allocator_state(&store.allocator_path(), &store.events_dir()).unwrap();
        assert_eq!(
            allocator.allocated_bytes,
            MAX_ROUTE_STORAGE_BYTES - SYSTEM_METADATA_RESERVE_BYTES
        );
    }

    #[test]
    fn legacy_event_temp_remains_reserved_without_blocking_global_sequence_reuse() {
        let dir = tempdir().unwrap();
        let store = RouteEventStore::new(dir.path());
        let call = ManagedRouteCall::new(
            Arc::new(RouteEventStore::new(dir.path())),
            "attempt-temp".into(),
            "call-1".into(),
            "model".into(),
        );
        let observer = ManagedHopObserver::new(call);
        observer.start("provider", Some("model")).unwrap();

        // A process can die after private temp creation but before publishing the
        // global sequence file. Preserve the legacy fixed name, but do not reuse it
        // for another correlation's next global event.
        let temp_path = store.events_dir().join(".00000000000000000002.tmp");
        write_private_file(&temp_path, b"partial temp data").unwrap();

        let unrelated_call = ManagedRouteCall::new(
            Arc::new(RouteEventStore::new(dir.path())),
            "attempt-unrelated".into(),
            "call-1".into(),
            "model".into(),
        );
        let unrelated_observer = ManagedHopObserver::new(unrelated_call);
        unrelated_observer
            .start("provider-unrelated", Some("model"))
            .unwrap();
        unrelated_observer.record_headers(201).unwrap();
        unrelated_observer
            .finish(
                &unrelated_observer.started_event().unwrap(),
                Some("model".into()),
                Some(201),
                "upstream_body_complete",
            )
            .unwrap();

        observer.record_headers(200).unwrap();
        observer
            .finish(
                &observer.started_event().unwrap(),
                Some("model".into()),
                Some(200),
                "upstream_body_complete",
            )
            .unwrap();
        assert!(temp_path.exists());
        let page = store.read_page("attempt-temp", 0, None, 10).unwrap();
        assert_eq!(page.events.len(), 3);
        assert_eq!(page.events[0].event_type, RouteEventType::HopStarted);
        assert_eq!(page.events[1].event_type, RouteEventType::HopHeaders);
        assert_eq!(page.events[2].event_type, RouteEventType::HopFinished);
        let seal = futures::executor::block_on(
            store.seal("attempt-temp", std::time::Duration::from_millis(1)),
        )
        .unwrap();
        assert!(seal.sealed);
        assert_eq!(seal.pending_hops, 0);
    }
}

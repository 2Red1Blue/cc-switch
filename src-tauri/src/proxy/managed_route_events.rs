//! Durable, secret-free route receipts for Fabric-managed Claude requests.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{atomic::AtomicU64, Arc, Mutex};

pub const CORRELATION_HEADER: &str = "x-fabric-managed-attempt-id";
const MAX_PAGE_SIZE: usize = 500;
const MAX_SCAN_SEQUENCES: u64 = 1_000;
const MAX_EVENT_BYTES: u64 = 16 * 1024;
// Quota uses fixed logical slots, including final records, possible atomic-write temps,
// per-correlation seal state, and filesystem metadata. Allocations are never recycled.
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
}

impl Drop for ManagedCallLease {
    fn drop(&mut self) {
        let Ok(mut state) = self.activity.state.lock() else {
            return;
        };
        state.active_calls = state.active_calls.saturating_sub(1);
        self.activity.active_watch.send_replace(state.active_calls);
    }
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
        *self
            .status_code
            .lock()
            .map_err(|_| std::io::Error::other("route status lock poisoned"))? = Some(status_code);
        let Some(started) = self.started_event() else {
            return Err(std::io::Error::other("route hop started event is missing"));
        };
        let mut event = RouteEvent::finished_from(
            &started,
            started.upstream_model.clone(),
            Some(status_code),
            "response_headers_received",
        );
        event.event_type = RouteEventType::HopHeaders;
        self.call.store.append(event)
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
        validate_correlation_id(correlation_id).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid correlation id")
        })?;
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
        let path = self.seal_path(correlation_id);
        let mut durable = read_seal_state(&path, correlation_id)?;
        if durable.as_ref().is_some_and(|seal| seal.ingress_closed) {
            state.ingress_closed = true;
            state.seal_checked = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Fabric correlation has been sealed; new calls are rejected",
            ));
        }
        if durable.as_ref().is_some_and(|seal| seal.pending_hops > 0) && state.active_calls == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Fabric correlation has unresolved route evidence; new calls are rejected",
            ));
        }
        if durable.is_none() {
            self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
            let initial = DurableSealState {
                schema_version: 1,
                correlation_id: correlation_id.to_string(),
                ingress_closed: false,
                pending_hops: 0,
                event_count: 0,
                reserved_hops: 0,
                metadata_reserved: true,
                high_watermark: None,
            };
            write_seal_state(&path, &initial)?;
        } else if durable.as_ref().is_some_and(|seal| !seal.metadata_reserved) {
            self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
            if let Some(seal) = durable.as_mut() {
                seal.metadata_reserved = true;
                write_seal_state(&path, seal)?;
            }
        }
        state.seal_checked = true;
        state.active_calls = state.active_calls.saturating_add(1);
        activity.active_watch.send_replace(state.active_calls);
        Ok(ManagedCallLease {
            activity: activity.clone(),
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
            let active_calls = *active_rx.borrow_and_update();
            if active_calls == 0 {
                break;
            }
            if tokio::time::timeout_at(deadline, active_rx.changed())
                .await
                .is_err()
            {
                return self.seal_response(correlation_id, false, active_calls, true, None);
            }
        }

        let _local = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        let path = self.seal_path(correlation_id);
        let mut durable = read_seal_state(&path, correlation_id)?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "durable seal state disappeared",
            )
        })?;
        if durable.pending_hops != 0 || durable.reserved_hops != 0 {
            drop(_process_lock);
            drop(_local);
            return self.seal_response(correlation_id, false, 0, false, None);
        }
        let high_watermark = self.latest_sequence_locked()?;
        durable.high_watermark = Some(durable.high_watermark.unwrap_or(high_watermark));
        write_seal_state(&path, &durable)?;
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
        active_calls: u64,
        timed_out: bool,
        high_watermark: Option<u64>,
    ) -> std::io::Result<RouteSealResponse> {
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        let durable = read_seal_state(&self.seal_path(correlation_id), correlation_id)?;
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
    pub fn append(&self, mut event: RouteEvent) -> std::io::Result<()> {
        validate_event(&event)?;
        let _local = self
            .writer
            .lock()
            .map_err(|_| std::io::Error::other("route event writer lock poisoned"))?;
        ensure_settings_dir(&self.settings_dir)?;
        let _process_lock = acquire_file_lock(&self.lock_path())?;
        ensure_private_events_dir(&self.events_dir())?;

        let seal_path = self.seal_path(&event.correlation_id);
        let mut seal_state = match read_seal_state(&seal_path, &event.correlation_id)? {
            Some(state) => state,
            None => {
                self.reserve_storage_locked(PER_CORRELATION_RESERVATION_BYTES)?;
                let initial = DurableSealState {
                    schema_version: 1,
                    correlation_id: event.correlation_id.clone(),
                    ingress_closed: false,
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
            seal_state.pending_hops = seal_state.pending_hops.saturating_add(1);
            seal_state.reserved_hops = seal_state.reserved_hops.saturating_add(1);
            write_seal_state(&seal_path, &seal_state)?;
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
        let temporary_path = self.events_dir().join(format!(".{sequence:020}.tmp"));
        write_private_file(&temporary_path, &line)?;
        fs::rename(&temporary_path, &final_path)?;
        sync_directory(&self.events_dir())?;
        write_sequence_atomically(&self.sequence_path(), sequence)?;
        seal_state.event_count = correlation_sequence;
        if is_hop_finished {
            // Release only the three temporary-write slots. Three final event slots remain
            // charged permanently; missing optional headers therefore over-reserve safely.
            self.release_storage_locked(3 * LOGICAL_EVENT_SLOT_BYTES)?;
            seal_state.pending_hops = seal_state.pending_hops.saturating_sub(1);
            seal_state.reserved_hops = seal_state.reserved_hops.saturating_sub(1);
        }
        write_seal_state(&seal_path, &seal_state)?;
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
    let temporary = events_dir.join("allocator.json.tmp");
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
    let temporary = parent.join(format!("corr-{}.seal.json.tmp", state.correlation_id));
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
    let temporary = parent.join("managed-route-events.sequence.tmp");
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
                return Ok(());
            }
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed route settings path is not an owned directory",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path)?;
                let metadata = fs::symlink_metadata(path)?;
                if metadata.file_type().is_dir() && metadata.uid() == unsafe { libc::geteuid() } {
                    return Ok(());
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "managed route settings path is not an owned directory",
                ));
            }
            Err(error) => return Err(error),
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
            "call-1".into(),
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
            "call-1".into(),
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
    fn ambiguous_event_temp_remains_reserved_and_is_never_deleted() {
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
        let temp_path = store.events_dir().join(".00000000000000000002.tmp");
        fs::write(&temp_path, b"partial temp data").unwrap();

        assert!(observer.record_headers(200).is_err());
        assert!(temp_path.exists());
        let page = store.read_page("attempt-temp", 0, None, 10).unwrap();
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.events[0].event_type, RouteEventType::HopStarted);
        let seal = futures::executor::block_on(
            store.seal("attempt-temp", std::time::Duration::from_millis(1)),
        )
        .unwrap();
        assert!(!seal.sealed);
        assert_eq!(seal.pending_hops, 1);
    }
}

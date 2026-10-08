//! Stable C ABI used by Qt/C++ and other thin frontends.

#![deny(unsafe_op_in_unsafe_fn)]

use compatforge_capability::{ContextCapabilityQuery, HostProbe};
use compatforge_domain::{CoreConfig, LaunchPlan, LaunchRequest};
use compatforge_inspect::inspect_path;
use compatforge_orchestrator::{PolicyEngine, PreparedLaunch};
use compatforge_process::{EventPoll, LaunchHandle, ProcessSupervisor};
use compatforge_provider_macos::{create_local_context, MacOsLocalContextRequest};
use compatforge_service::{AutomationService, ServiceConfig, ServiceError, ServiceRequest};
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::ptr;
use std::time::Duration;

const API_VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum CfStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    InvalidJson = 3,
    InvalidArgument = 4,
    PlanningFailed = 5,
    AuthorizationFailed = 6,
    ProcessFailed = 7,
    Timeout = 8,
    EndOfStream = 9,
    ProbeFailed = 10,
    InspectionFailed = 11,
    PreparationFailed = 12,
    BootstrapFailed = 13,
    ServiceFailed = 14,
    NotFound = 15,
    Conflict = 16,
    Panic = 255,
}

#[repr(C)]
pub struct CfContext {
    config: CoreConfig,
}

#[repr(C)]
pub struct CfLaunch {
    handle: LaunchHandle,
}

#[repr(C)]
pub struct CfPreparedLaunch {
    prepared: PreparedLaunch,
}

#[repr(C)]
pub struct CfService {
    service: AutomationService,
}

struct FfiFailure {
    status: CfStatus,
    message: String,
}

impl FfiFailure {
    fn new(status: CfStatus, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

/// Return the semantic API version as a process-lifetime C string.
#[must_use]
#[no_mangle]
pub extern "C" fn cf_api_version() -> *const c_char {
    API_VERSION.as_ptr().cast()
}

/// Return the stable C ABI major version.
#[must_use]
#[no_mangle]
pub const extern "C" fn cf_abi_version() -> u32 {
    1
}

/// Return a read-only host capability snapshot as an owned JSON string.
///
/// # Safety
///
/// `out_capabilities_json` must be valid for one pointer write. A non-null
/// result must be released with [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_probe_capabilities(out_capabilities_json: *mut *mut c_char) -> CfStatus {
    ffi_boundary(|| {
        if out_capabilities_json.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_capabilities_json is null"));
        }
        unsafe { ptr::write(out_capabilities_json, ptr::null_mut()) };
        let report = HostProbe::probe()
            .map_err(|error| FfiFailure::new(CfStatus::ProbeFailed, format!("host probe failed: {error}")))?;
        let json = serde_json::to_string_pretty(&report).map_err(|error| {
            FfiFailure::new(
                CfStatus::ProbeFailed,
                format!("capability serialization failed: {error}"),
            )
        })?;
        unsafe { write_owned_string(json, out_capabilities_json) }
    })
}

/// Inspect a Windows executable without mapping or executing it.
///
/// # Safety
///
/// `absolute_path` must point to a valid NUL-terminated UTF-8 string.
/// `out_report_json` must be valid for one pointer write. The output is set to
/// null before path validation and a non-null result must be released with
/// [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_inspect_executable(
    absolute_path: *const c_char,
    out_report_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if out_report_json.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_report_json is null"));
        }
        unsafe { ptr::write(out_report_json, ptr::null_mut()) };
        let absolute_path = unsafe { read_utf8(absolute_path, "absolute_path") }?;
        let report = inspect_path(Path::new(&absolute_path)).map_err(|error| {
            FfiFailure::new(
                CfStatus::InspectionFailed,
                format!("executable inspection failed: {error}"),
            )
        })?;
        let json = serde_json::to_string(&report).map_err(|error| {
            FfiFailure::new(
                CfStatus::InspectionFailed,
                format!("inspection serialization failed: {error}"),
            )
        })?;
        unsafe { write_owned_string(json, out_report_json) }
    })
}

/// Return the context's public capability projection as an owned JSON string.
///
/// This query is pure: it builds a typed, allowlisted projection from the
/// capability report already held by `context`. It never probes providers,
/// copies private context fields, or touches host state.
///
/// # Safety
///
/// `context` must be a live pointer created by [`cf_context_create`].
/// `out_report_json` must be valid for one pointer write. The output is set to
/// null before context validation and a non-null result must be released with
/// [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_capabilities_get(context: *const CfContext, out_report_json: *mut *mut c_char) -> CfStatus {
    ffi_boundary(|| {
        if out_report_json.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_report_json is null"));
        }
        unsafe { ptr::write(out_report_json, ptr::null_mut()) };
        if context.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "context is null"));
        }

        let context = unsafe { &*context };
        let report = ContextCapabilityQuery::report(&context.config).map_err(|error| {
            FfiFailure::new(
                CfStatus::ProbeFailed,
                format!("context capability query failed: {error}"),
            )
        })?;
        let json = serde_json::to_string(&report).map_err(|error| {
            FfiFailure::new(
                CfStatus::ProbeFailed,
                format!("capability serialization failed: {error}"),
            )
        })?;
        unsafe { write_owned_string(json, out_report_json) }
    })
}

/// Create a planning context from a UTF-8 JSON configuration.
///
/// # Safety
///
/// `config_json` must point to a valid NUL-terminated string. `out_context`
/// must be valid for one pointer write and must later be released exactly once
/// with [`cf_context_release`].
#[no_mangle]
pub unsafe extern "C" fn cf_context_create(config_json: *const c_char, out_context: *mut *mut CfContext) -> CfStatus {
    ffi_boundary(|| {
        if out_context.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_context is null"));
        }
        unsafe { ptr::write(out_context, ptr::null_mut()) };
        let config_text = unsafe { read_utf8(config_json, "config_json") }?;
        let config: CoreConfig = serde_json::from_str(&config_text)
            .map_err(|error| FfiFailure::new(CfStatus::InvalidJson, format!("invalid config JSON: {error}")))?;
        config
            .validate()
            .map_err(|error| FfiFailure::new(CfStatus::InvalidArgument, format!("invalid config: {error}")))?;

        let context = Box::into_raw(Box::new(CfContext { config }));
        unsafe { ptr::write(out_context, context) };
        Ok(())
    })
}

/// Discover and verify a local macOS Wine Runtime, register a preview Pack,
/// and create the opaque Core context in one Rust-owned operation. The public
/// receipt deliberately contains no user paths.
///
/// # Safety
///
/// `request_json` must be a UTF-8 NUL-terminated JSON request. Both output
/// pointers must be valid for one write and are cleared before validation.
/// The returned context is released with [`cf_context_release`] and the
/// receipt with [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_macos_local_context_create(
    request_json: *const c_char,
    out_context: *mut *mut CfContext,
    out_receipt_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if out_context.is_null() || out_receipt_json.is_null() {
            return Err(FfiFailure::new(
                CfStatus::NullPointer,
                "out_context or out_receipt_json is null",
            ));
        }
        unsafe {
            ptr::write(out_context, ptr::null_mut());
            ptr::write(out_receipt_json, ptr::null_mut());
        }
        let request_text = unsafe { read_utf8(request_json, "request_json") }?;
        let request: MacOsLocalContextRequest = serde_json::from_str(&request_text).map_err(|error| {
            FfiFailure::new(
                CfStatus::InvalidJson,
                format!("invalid bootstrap request JSON: {error}"),
            )
        })?;
        let host = HostProbe::probe().map_err(|error| {
            FfiFailure::new(
                CfStatus::BootstrapFailed,
                format!("host probe failed during bootstrap: {error}"),
            )
        })?;
        let local = create_local_context(&host, &request)
            .map_err(|error| FfiFailure::new(CfStatus::BootstrapFailed, error.to_string()))?;
        let receipt = serde_json::to_string_pretty(&local.receipt).map_err(|error| {
            FfiFailure::new(
                CfStatus::BootstrapFailed,
                format!("bootstrap receipt serialization failed: {error}"),
            )
        })?;
        let context = Box::new(CfContext { config: local.config });
        unsafe { write_owned_string(receipt, out_receipt_json) }?;
        unsafe { ptr::write(out_context, Box::into_raw(context)) };
        Ok(())
    })
}

/// Create the persistent application/Bottle/settings/job service for a Core
/// context. The service never discovers a Runtime independently; every launch
/// is prepared and authorized against the supplied context.
///
/// # Safety
///
/// `context` must be live, `service_config_json` must be valid UTF-8 JSON and
/// `out_service` must be valid for one pointer write. Release the result with
/// [`cf_service_release`].
#[no_mangle]
pub unsafe extern "C" fn cf_service_create(
    context: *const CfContext,
    service_config_json: *const c_char,
    out_service: *mut *mut CfService,
) -> CfStatus {
    ffi_boundary(|| {
        if out_service.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_service is null"));
        }
        unsafe { ptr::write(out_service, ptr::null_mut()) };
        if context.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "context is null"));
        }
        let config_text = unsafe { read_utf8(service_config_json, "service_config_json") }?;
        let service_config: ServiceConfig = serde_json::from_str(&config_text)
            .map_err(|error| FfiFailure::new(CfStatus::InvalidJson, format!("invalid service config JSON: {error}")))?;
        let context = unsafe { &*context };
        let service = AutomationService::new(context.config.clone(), service_config).map_err(service_failure)?;
        unsafe { ptr::write(out_service, Box::into_raw(Box::new(CfService { service }))) };
        Ok(())
    })
}

/// Execute one versioned service operation and return its owned JSON response.
/// This is the complete headless application-management API used by desktop,
/// CLI, tests and external automation agents.
///
/// # Safety
///
/// `service` must be live, `request_json` must be valid UTF-8 JSON and
/// `out_response_json` must be valid for one pointer write. Free the returned
/// string with [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_service_call(
    service: *const CfService,
    request_json: *const c_char,
    out_response_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if out_response_json.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_response_json is null"));
        }
        unsafe { ptr::write(out_response_json, ptr::null_mut()) };
        if service.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "service is null"));
        }
        let request_text = unsafe { read_utf8(request_json, "request_json") }?;
        let request: ServiceRequest = serde_json::from_str(&request_text).map_err(|error| {
            FfiFailure::new(CfStatus::InvalidJson, format!("invalid service request JSON: {error}"))
        })?;
        let service = unsafe { &*service };
        let response = service.service.call(request).map_err(service_failure)?;
        let json = serde_json::to_string(&response).map_err(|error| {
            FfiFailure::new(
                CfStatus::ServiceFailed,
                format!("service response serialization failed: {error}"),
            )
        })?;
        unsafe { write_owned_string(json, out_response_json) }
    })
}

/// Compile a UTF-8 launch request into an owned UTF-8 launch-plan string.
///
/// # Safety
///
/// `context` must be a live pointer created by [`cf_context_create`].
/// `request_json` must point to a valid NUL-terminated string. `out_plan_json`
/// must be valid for one pointer write; a non-null result must be released with
/// [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_compile_launch(
    context: *const CfContext,
    request_json: *const c_char,
    out_plan_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if context.is_null() || out_plan_json.is_null() {
            return Err(FfiFailure::new(
                CfStatus::NullPointer,
                "context or out_plan_json is null",
            ));
        }
        unsafe { ptr::write(out_plan_json, ptr::null_mut()) };
        let request_text = unsafe { read_utf8(request_json, "request_json") }?;
        let request: LaunchRequest = serde_json::from_str(&request_text)
            .map_err(|error| FfiFailure::new(CfStatus::InvalidJson, format!("invalid launch request JSON: {error}")))?;
        let context = unsafe { &*context };
        let plan = PolicyEngine::compile(&context.config, &request)
            .map_err(|error| FfiFailure::new(CfStatus::PlanningFailed, format!("planning failed: {error}")))?;
        let json = serde_json::to_string_pretty(&plan).map_err(|error| {
            FfiFailure::new(CfStatus::PlanningFailed, format!("plan serialization failed: {error}"))
        })?;
        unsafe { write_owned_string(json, out_plan_json) }
    })
}

/// Inspect and materialize a selected PE into an opaque trusted launch.
///
/// # Safety
///
/// `context` must be a live context. Both string pointers must be valid UTF-8
/// NUL-terminated strings. `out_prepared` is cleared before validation and a
/// non-null result must be released with [`cf_prepared_launch_release`].
#[no_mangle]
pub unsafe extern "C" fn cf_launch_prepare(
    context: *const CfContext,
    absolute_executable_path: *const c_char,
    request_json: *const c_char,
    out_prepared: *mut *mut CfPreparedLaunch,
) -> CfStatus {
    ffi_boundary(|| {
        if out_prepared.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_prepared is null"));
        }
        unsafe { ptr::write(out_prepared, ptr::null_mut()) };
        if context.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "context is null"));
        }
        let path = unsafe { read_utf8(absolute_executable_path, "absolute_executable_path") }?;
        let request_text = unsafe { read_utf8(request_json, "request_json") }?;
        let request: LaunchRequest = serde_json::from_str(&request_text)
            .map_err(|error| FfiFailure::new(CfStatus::InvalidJson, format!("invalid launch request JSON: {error}")))?;
        let context = unsafe { &*context };
        let prepared = PreparedLaunch::prepare(&context.config, Path::new(&path), &request)
            .map_err(|error| FfiFailure::new(CfStatus::PreparationFailed, error.to_string()))?;
        unsafe { ptr::write(out_prepared, Box::into_raw(Box::new(CfPreparedLaunch { prepared }))) };
        Ok(())
    })
}

/// Serialize the inspection evidence owned by a prepared launch.
///
/// # Safety
///
/// `prepared` must be live and `out_report_json` valid for one pointer write.
#[no_mangle]
pub unsafe extern "C" fn cf_prepared_launch_inspection_get(
    prepared: *const CfPreparedLaunch,
    out_report_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if out_report_json.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_report_json is null"));
        }
        unsafe { ptr::write(out_report_json, ptr::null_mut()) };
        if prepared.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "prepared is null"));
        }
        let prepared = unsafe { &*prepared };
        let json = serde_json::to_string_pretty(prepared.prepared.inspection()).map_err(|error| {
            FfiFailure::new(
                CfStatus::PreparationFailed,
                format!("inspection serialization failed: {error}"),
            )
        })?;
        unsafe { write_owned_string(json, out_report_json) }
    })
}

/// Serialize the immutable plan owned by a prepared launch.
///
/// # Safety
///
/// `prepared` must be live and `out_plan_json` valid for one pointer write.
#[no_mangle]
pub unsafe extern "C" fn cf_prepared_launch_plan_get(
    prepared: *const CfPreparedLaunch,
    out_plan_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if out_plan_json.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_plan_json is null"));
        }
        unsafe { ptr::write(out_plan_json, ptr::null_mut()) };
        if prepared.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "prepared is null"));
        }
        let prepared = unsafe { &*prepared };
        let json = serde_json::to_string_pretty(prepared.prepared.plan()).map_err(|error| {
            FfiFailure::new(
                CfStatus::PreparationFailed,
                format!("plan serialization failed: {error}"),
            )
        })?;
        unsafe { write_owned_string(json, out_plan_json) }
    })
}

/// Re-authorize and start an opaque prepared launch against a context.
///
/// # Safety
///
/// All input handles must be live. `out_launch` is cleared before validation
/// and a non-null result must be released with [`cf_launch_release`].
#[no_mangle]
pub unsafe extern "C" fn cf_prepared_launch_start(
    context: *const CfContext,
    prepared: *const CfPreparedLaunch,
    out_launch: *mut *mut CfLaunch,
) -> CfStatus {
    ffi_boundary(|| {
        if out_launch.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "out_launch is null"));
        }
        unsafe { ptr::write(out_launch, ptr::null_mut()) };
        if context.is_null() || prepared.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "context or prepared is null"));
        }
        let context = unsafe { &*context };
        let prepared = unsafe { &*prepared };
        let plan = prepared
            .prepared
            .authorize(&context.config)
            .map_err(|error| FfiFailure::new(CfStatus::AuthorizationFailed, error.to_string()))?;
        let handle = ProcessSupervisor::start(plan)
            .map_err(|error| FfiFailure::new(CfStatus::ProcessFailed, error.to_string()))?;
        unsafe { ptr::write(out_launch, Box::into_raw(Box::new(CfLaunch { handle }))) };
        Ok(())
    })
}

/// Start an authorized launch plan and return an opaque process handle.
///
/// # Safety
///
/// `context` must be a live pointer created by [`cf_context_create`].
/// `plan_json` must point to a valid NUL-terminated string. `out_launch` must
/// be valid for one pointer write and later released with [`cf_launch_release`].
#[no_mangle]
pub unsafe extern "C" fn cf_launch_start(
    context: *const CfContext,
    plan_json: *const c_char,
    out_launch: *mut *mut CfLaunch,
) -> CfStatus {
    ffi_boundary(|| {
        if context.is_null() || out_launch.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "context or out_launch is null"));
        }
        unsafe { ptr::write(out_launch, ptr::null_mut()) };
        let plan_text = unsafe { read_utf8(plan_json, "plan_json") }?;
        let plan: LaunchPlan = serde_json::from_str(&plan_text)
            .map_err(|error| FfiFailure::new(CfStatus::InvalidJson, format!("invalid launch plan JSON: {error}")))?;
        let context = unsafe { &*context };
        PolicyEngine::authorize(&context.config, &plan).map_err(|error| {
            FfiFailure::new(
                CfStatus::AuthorizationFailed,
                format!("launch authorization failed: {error}"),
            )
        })?;
        let handle = ProcessSupervisor::start(&plan)
            .map_err(|error| FfiFailure::new(CfStatus::ProcessFailed, error.to_string()))?;
        unsafe { ptr::write(out_launch, Box::into_raw(Box::new(CfLaunch { handle }))) };
        Ok(())
    })
}

/// Poll the next versioned runtime event as an owned JSON string.
///
/// # Safety
///
/// `launch` must be a live pointer returned by [`cf_launch_start`].
/// `out_event_json` must be valid for one pointer write. A non-null string must
/// be released with [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_launch_next_event(
    launch: *const CfLaunch,
    timeout_ms: u32,
    out_event_json: *mut *mut c_char,
) -> CfStatus {
    ffi_boundary(|| {
        if launch.is_null() || out_event_json.is_null() {
            return Err(FfiFailure::new(
                CfStatus::NullPointer,
                "launch or out_event_json is null",
            ));
        }
        unsafe { ptr::write(out_event_json, ptr::null_mut()) };
        let launch = unsafe { &*launch };
        match launch.handle.next_event(Duration::from_millis(u64::from(timeout_ms))) {
            EventPoll::Event(event) => {
                let json = serde_json::to_string(&event).map_err(|error| {
                    FfiFailure::new(CfStatus::ProcessFailed, format!("event serialization failed: {error}"))
                })?;
                unsafe { write_owned_string(json, out_event_json) }
            }
            EventPoll::Timeout => Err(FfiFailure::new(CfStatus::Timeout, "runtime event poll timed out")),
            EventPoll::Closed => Err(FfiFailure::new(CfStatus::EndOfStream, "runtime event stream closed")),
        }
    })
}

/// Request idempotent termination of a supervised process.
///
/// # Safety
///
/// `launch` must be a live pointer returned by [`cf_launch_start`].
#[no_mangle]
pub unsafe extern "C" fn cf_launch_terminate(launch: *const CfLaunch) -> CfStatus {
    ffi_boundary(|| {
        if launch.is_null() {
            return Err(FfiFailure::new(CfStatus::NullPointer, "launch is null"));
        }
        let launch = unsafe { &*launch };
        launch
            .handle
            .terminate()
            .map_err(|error| FfiFailure::new(CfStatus::ProcessFailed, error.to_string()))
    })
}

/// Copy the current thread's last structured FFI error into an owned string.
///
/// # Safety
///
/// `out_error_json` must be valid for one pointer write. A non-null result must
/// be released with [`cf_string_free`].
#[no_mangle]
pub unsafe extern "C" fn cf_last_error_json(out_error_json: *mut *mut c_char) -> CfStatus {
    if out_error_json.is_null() {
        return CfStatus::NullPointer;
    }
    unsafe { ptr::write(out_error_json, ptr::null_mut()) };
    let value = LAST_ERROR.with(|slot| {
        slot.borrow()
            .as_ref()
            .map(|error| error.to_string_lossy().into_owned())
            .unwrap_or_else(|| r#"{"status":0,"message":""}"#.into())
    });
    match unsafe { write_owned_string(value, out_error_json) } {
        Ok(()) => CfStatus::Ok,
        Err(error) => error.status,
    }
}

/// Release a string returned by CompatForge.
///
/// # Safety
///
/// `value` must be null or a pointer returned by this library that has not
/// already been released.
#[no_mangle]
pub unsafe extern "C" fn cf_string_free(value: *mut c_char) {
    if !value.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(CString::from_raw(value));
        }));
    }
}

/// Release a context returned by CompatForge.
///
/// # Safety
///
/// `context` must be null or a pointer returned by [`cf_context_create`] that
/// has not already been released.
#[no_mangle]
pub unsafe extern "C" fn cf_context_release(context: *mut CfContext) {
    if !context.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(context));
        }));
    }
}

/// Release a service, requesting termination of every job still owned by it.
///
/// # Safety
///
/// `service` must be null or a pointer returned by [`cf_service_create`] that
/// has not already been released.
#[no_mangle]
pub unsafe extern "C" fn cf_service_release(service: *mut CfService) {
    if !service.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(service));
        }));
    }
}

/// Release an opaque prepared launch.
///
/// # Safety
///
/// `prepared` must be null or a live pointer returned by [`cf_launch_prepare`].
#[no_mangle]
pub unsafe extern "C" fn cf_prepared_launch_release(prepared: *mut CfPreparedLaunch) {
    if !prepared.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(prepared));
        }));
    }
}

/// Release a launch handle, terminating a still-running child first.
///
/// # Safety
///
/// `launch` must be null or a pointer returned by [`cf_launch_start`] that has
/// not already been released.
#[no_mangle]
pub unsafe extern "C" fn cf_launch_release(launch: *mut CfLaunch) {
    if !launch.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(launch));
        }));
    }
}

fn ffi_boundary(operation: impl FnOnce() -> Result<(), FfiFailure>) -> CfStatus {
    let _ = LAST_ERROR.with(|slot| slot.borrow_mut().take());
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => CfStatus::Ok,
        Ok(Err(error)) => {
            set_last_error(error.status, &error.message);
            error.status
        }
        Err(_) => {
            set_last_error(CfStatus::Panic, "panic contained at the C ABI boundary");
            CfStatus::Panic
        }
    }
}

fn service_failure(error: ServiceError) -> FfiFailure {
    let status = match error.code() {
        "not-found" => CfStatus::NotFound,
        "conflict" => CfStatus::Conflict,
        "invalid-request" => CfStatus::InvalidArgument,
        _ => CfStatus::ServiceFailed,
    };
    FfiFailure::new(status, error.to_string())
}

unsafe fn read_utf8(value: *const c_char, name: &'static str) -> Result<String, FfiFailure> {
    if value.is_null() {
        return Err(FfiFailure::new(CfStatus::NullPointer, format!("{name} is null")));
    }
    unsafe { CStr::from_ptr(value) }
        .to_str()
        .map(str::to_owned)
        .map_err(|error| FfiFailure::new(CfStatus::InvalidUtf8, format!("{name} is not UTF-8: {error}")))
}

unsafe fn write_owned_string(value: String, output: *mut *mut c_char) -> Result<(), FfiFailure> {
    if output.is_null() {
        return Err(FfiFailure::new(CfStatus::NullPointer, "output pointer is null"));
    }
    let value = CString::new(value)
        .map_err(|_| FfiFailure::new(CfStatus::InvalidArgument, "output contains an interior NUL"))?;
    unsafe { ptr::write(output, value.into_raw()) };
    Ok(())
}

fn set_last_error(status: CfStatus, message: &str) {
    let json = serde_json::json!({
        "status": status as u32,
        "message": message,
    })
    .to_string();
    if let Ok(error) = CString::new(json) {
        LAST_ERROR.with(|slot| {
            let _ = slot.borrow_mut().replace(error);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use compatforge_domain::{
        CapabilityObservation, CapabilityReport, CapabilityValue, GraphicsBackendKind, ProbeSource, ProbeStatus,
        ProviderDescriptor, RuntimeEventKind, RuntimeKind, TranslatorKind,
    };
    use compatforge_inspect::{PeArchitecture, PeInspectionReport, PeSubsystem};

    fn create_context(config: &CoreConfig) -> *mut CfContext {
        let config = CString::new(serde_json::to_string(config).unwrap()).unwrap();
        let mut context = ptr::null_mut();
        unsafe {
            assert_eq!(cf_context_create(config.as_ptr(), &mut context), CfStatus::Ok);
        }
        context
    }

    fn make_object_writable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = std::fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o600);
            std::fs::set_permissions(path, permissions).unwrap();
        }
        #[cfg(windows)]
        {
            let status = std::process::Command::new("attrib")
                .arg("-R")
                .arg(path)
                .status()
                .unwrap();
            assert!(status.success());
        }
    }

    fn example_config() -> CoreConfig {
        serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap()
    }

    fn assert_report_satisfies_schema_v1(json: &str) {
        let schema: serde_json::Value =
            serde_json::from_str(include_str!("../../../schemas/capability-report.schema.json")).unwrap();
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        for required in schema["required"].as_array().unwrap() {
            assert!(value.get(required.as_str().unwrap()).is_some());
        }
        assert_eq!(value["schemaVersion"], schema["properties"]["schemaVersion"]["const"]);
        for collection in ["runtimeProviders", "translators", "graphicsBackends"] {
            assert!(value[collection].is_array());
        }
        assert!(value
            .get("features")
            .and_then(serde_json::Value::as_object)
            .into_iter()
            .flatten()
            .all(|(_, value)| value.is_boolean() || value.is_string() || value.is_number()));
        assert!(value
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|observation| observation.get("value"))
            .all(|value| value.is_boolean() || value.is_string() || value.is_number()));

        // CapabilityReport uses deny_unknown_fields recursively and typed
        // scalar values, while validate() enforces the conditional and
        // uniqueness constraints in the checked-in Schema v1 contract.
        let report: CapabilityReport = serde_json::from_value(value).unwrap();
        report.validate().unwrap();
    }

    #[test]
    fn reports_stable_versions() {
        assert_eq!(cf_abi_version(), 1);
        let api_version = unsafe { CStr::from_ptr(cf_api_version()) }.to_str().unwrap();
        assert_eq!(api_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn probes_capabilities_across_the_c_abi() {
        let mut output = ptr::null_mut();
        unsafe {
            assert_eq!(cf_probe_capabilities(&mut output), CfStatus::Ok);
            let report: CapabilityReport = serde_json::from_str(CStr::from_ptr(output).to_str().unwrap()).unwrap();
            report.validate().unwrap();
            assert!(!report.observations.is_empty());
            cf_string_free(output);
        }
    }

    #[test]
    fn inspects_a_pe_fixture_across_the_c_abi() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hello-x86_64.exe")
            .canonicalize()
            .unwrap();
        let fixture = CString::new(fixture.to_string_lossy().as_bytes()).unwrap();
        let mut output = ptr::null_mut();
        unsafe {
            assert_eq!(cf_inspect_executable(fixture.as_ptr(), &mut output), CfStatus::Ok);
            let report: PeInspectionReport = serde_json::from_str(CStr::from_ptr(output).to_str().unwrap()).unwrap();
            assert_eq!(report.architecture, PeArchitecture::X86_64);
            assert_eq!(report.subsystem, PeSubsystem::WindowsConsole);
            assert_eq!(report.import_libraries, ["kernel32.dll"]);
            cf_string_free(output);
        }
    }

    #[test]
    fn inspection_fails_closed_and_clears_output() {
        let relative = CString::new("hello.exe").unwrap();
        let mut output = std::ptr::NonNull::<c_char>::dangling().as_ptr();
        let mut error_output = ptr::null_mut();
        unsafe {
            assert_eq!(
                cf_inspect_executable(relative.as_ptr(), &mut output),
                CfStatus::InspectionFailed
            );
            assert!(output.is_null());
            assert_eq!(cf_last_error_json(&mut error_output), CfStatus::Ok);
            assert!(CStr::from_ptr(error_output)
                .to_str()
                .unwrap()
                .contains("path must be absolute"));
            cf_string_free(error_output);
        }
    }

    #[test]
    fn queries_context_capabilities_with_independent_owned_buffers() {
        let context = create_context(&example_config());
        let mut first = ptr::null_mut();
        let mut second = ptr::null_mut();

        unsafe {
            assert_eq!(cf_capabilities_get(context, &mut first), CfStatus::Ok);
            assert_eq!(cf_capabilities_get(context, &mut second), CfStatus::Ok);
            assert!(!first.is_null());
            assert!(!second.is_null());
            assert_ne!(first, second);

            let first_json = CStr::from_ptr(first).to_str().unwrap().to_owned();
            let second_json = CStr::from_ptr(second).to_str().unwrap().to_owned();
            assert_eq!(first_json, second_json);
            assert_report_satisfies_schema_v1(&first_json);

            cf_string_free(first);
            cf_string_free(second);
            cf_context_release(context);
        }
    }

    #[test]
    fn capability_query_clears_output_on_null_context() {
        let mut output = std::ptr::NonNull::<c_char>::dangling().as_ptr();
        unsafe {
            assert_eq!(cf_capabilities_get(ptr::null(), &mut output), CfStatus::NullPointer);
        }
        assert!(output.is_null());

        let context = create_context(&example_config());
        unsafe {
            assert_eq!(cf_capabilities_get(context, ptr::null_mut()), CfStatus::NullPointer);
            cf_context_release(context);
        }
    }

    #[test]
    fn manages_applications_through_the_generic_service_abi() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("compatforge-service-ffi-{}-{unique}", std::process::id()));
        let mut config = example_config();
        config.storage_root = root.join("storage").to_string_lossy().into_owned();
        let context = create_context(&config);
        let service_config = CString::new(
            serde_json::json!({
                "schemaVersion": "1",
                "serviceRoot": root.join("service").to_string_lossy(),
            })
            .to_string(),
        )
        .unwrap();
        let mut service = ptr::null_mut();
        let mut output = ptr::null_mut();
        unsafe {
            assert_eq!(
                cf_service_create(context, service_config.as_ptr(), &mut service),
                CfStatus::Ok
            );
            let seed = CString::new(
                r#"{"schemaVersion":"1","requestId":"ffi-request-01","operation":"applications.seed-defaults","payload":{}}"#,
            )
            .unwrap();
            assert_eq!(cf_service_call(service, seed.as_ptr(), &mut output), CfStatus::Ok);
            cf_string_free(output);
            output = ptr::null_mut();
            let list = CString::new(
                r#"{"schemaVersion":"1","requestId":"ffi-request-02","operation":"applications.list","payload":{}}"#,
            )
            .unwrap();
            assert_eq!(cf_service_call(service, list.as_ptr(), &mut output), CfStatus::Ok);
            let response: serde_json::Value = serde_json::from_str(CStr::from_ptr(output).to_str().unwrap()).unwrap();
            assert_eq!(response["result"].as_array().unwrap().len(), 3);
            cf_string_free(output);
            cf_service_release(service);
            cf_context_release(context);
        }
    }

    #[test]
    fn unavailable_provider_is_a_successful_capability_result() {
        let mut config = example_config();
        config.capabilities.runtime_providers = vec![ProviderDescriptor {
            id: "wine-not-installed".into(),
            kind: "wine".into(),
            version: "pack-pinned".into(),
            available: false,
            reason: Some("verified runtime pack is not installed".into()),
            capabilities: vec!["win64".into(), "win32".into()],
        }];
        config.capabilities.translators.clear();
        config.capabilities.graphics_backends.clear();
        let context = create_context(&config);
        let mut output = ptr::null_mut();

        unsafe {
            assert_eq!(cf_capabilities_get(context, &mut output), CfStatus::Ok);
            let report: CapabilityReport = serde_json::from_str(CStr::from_ptr(output).to_str().unwrap()).unwrap();
            assert!(!report.runtime_providers[0].available);
            assert_eq!(
                report.runtime_providers[0].reason.as_deref(),
                Some("configured provider is unavailable")
            );
            assert_eq!(report.runtime_providers[0].capabilities, ["win32", "win64"]);
            assert!(report.translators.is_empty());
            assert!(report.graphics_backends.is_empty());
            cf_string_free(output);
            cf_context_release(context);
        }
    }

    #[test]
    fn capability_query_does_not_materialize_or_expose_context_paths() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("compatforge-capability-query-{}-{unique}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let storage = root.join("must-not-be-created");
        let executable = root.join("must-not-be-executed");
        let mut config = example_config();
        config.storage_root = storage.to_string_lossy().into_owned();
        config.runtime_bindings[0].executable = executable.to_string_lossy().into_owned();
        config.runtime_bindings[0].wineserver_executable = Some(executable.to_string_lossy().into_owned());
        let context = create_context(&config);
        let mut output = ptr::null_mut();

        unsafe {
            assert_eq!(cf_capabilities_get(context, &mut output), CfStatus::Ok);
            let json = CStr::from_ptr(output).to_str().unwrap();
            let root_text = root.to_string_lossy();
            assert!(!json.contains(root_text.as_ref()));
            assert!(std::fs::read_dir(&root).unwrap().next().is_none());
            cf_string_free(output);
            cf_context_release(context);
        }
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn capability_query_does_not_copy_secrets_paths_or_process_observations() {
        let mut config = example_config();
        config
            .capabilities
            .features
            .insert("authToken".into(), CapabilityValue::String("secret".into()));
        config
            .capabilities
            .features
            .insert("userPath".into(), CapabilityValue::String("/home/alice/private".into()));
        config.capabilities.observations.push(CapabilityObservation {
            id: "process.command-line".into(),
            category: "process".into(),
            status: ProbeStatus::Detected,
            source: ProbeSource::Configuration,
            value: Some(CapabilityValue::String("--token secret /home/alice/private".into())),
            reason: None,
        });
        let context = create_context(&config);
        let mut output = ptr::null_mut();

        unsafe {
            assert_eq!(cf_capabilities_get(context, &mut output), CfStatus::Ok);
            let json = CStr::from_ptr(output).to_str().unwrap();
            assert_report_satisfies_schema_v1(json);
            assert!(!json.contains("authToken"));
            assert!(!json.contains("userPath"));
            assert!(!json.contains("secret"));
            assert!(!json.contains("/home/alice/private"));
            assert!(!json.contains("process.command-line"));
            cf_string_free(output);
            cf_context_release(context);
        }
    }

    #[test]
    fn compiles_a_launch_plan_across_the_c_abi() {
        let config = CString::new(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let request = CString::new(include_str!("../../../examples/launch-request.json")).unwrap();
        let mut context = ptr::null_mut();
        let mut output = ptr::null_mut();

        unsafe {
            assert_eq!(cf_context_create(config.as_ptr(), &mut context), CfStatus::Ok);
            assert_eq!(cf_compile_launch(context, request.as_ptr(), &mut output), CfStatus::Ok);
            let plan_text = CStr::from_ptr(output).to_str().unwrap();
            let plan: LaunchPlan = serde_json::from_str(plan_text).unwrap();
            assert_eq!(plan.request_id, "018fe3cb-9d12-7b52-b334-1cce0e857fc9");
            cf_string_free(output);
            cf_context_release(context);
        }
    }

    #[test]
    fn prepares_and_reads_an_inspection_bound_launch_across_the_c_abi() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("compatforge-ffi-prepare-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hello-x86_64.exe")
            .canonicalize()
            .unwrap();
        let mut config = example_config();
        config.storage_root = root.join("store").to_string_lossy().into_owned();
        let mut request: LaunchRequest =
            serde_json::from_str(include_str!("../../../examples/launch-request.json")).unwrap();
        request.executable.path = fixture.to_string_lossy().into_owned();
        request.executable.architecture = compatforge_domain::CpuArchitecture::X86_64;
        request.executable.sha256 = None;

        let context = create_context(&config);
        let fixture = CString::new(fixture.to_string_lossy().as_bytes()).unwrap();
        let request = CString::new(serde_json::to_string(&request).unwrap()).unwrap();
        let mut prepared = ptr::null_mut();
        let mut inspection_json = ptr::null_mut();
        let mut plan_json = ptr::null_mut();
        unsafe {
            assert_eq!(
                cf_launch_prepare(context, fixture.as_ptr(), request.as_ptr(), &mut prepared),
                CfStatus::Ok
            );
            assert_eq!(
                cf_prepared_launch_inspection_get(prepared, &mut inspection_json),
                CfStatus::Ok
            );
            assert_eq!(cf_prepared_launch_plan_get(prepared, &mut plan_json), CfStatus::Ok);
            let inspection: PeInspectionReport =
                serde_json::from_str(CStr::from_ptr(inspection_json).to_str().unwrap()).unwrap();
            let plan: LaunchPlan = serde_json::from_str(CStr::from_ptr(plan_json).to_str().unwrap()).unwrap();
            assert_eq!(plan.guest_artifact.as_ref().unwrap().digest, inspection.file_digest);

            let object = Path::new(&plan.guest_artifact.as_ref().unwrap().stored_path);
            make_object_writable(object);

            cf_string_free(inspection_json);
            cf_string_free(plan_json);
            cf_prepared_launch_release(prepared);
            cf_context_release(context);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepared_launch_rejects_a_different_context_before_process_creation() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("compatforge-ffi-context-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/hello-x86_64.exe")
            .canonicalize()
            .unwrap();
        let mut config = example_config();
        config.storage_root = root.join("store").to_string_lossy().into_owned();
        let original_context = create_context(&config);
        config.sandbox_profile = compatforge_domain::SandboxProfile::Strict;
        let changed_context = create_context(&config);
        let mut request: LaunchRequest =
            serde_json::from_str(include_str!("../../../examples/launch-request.json")).unwrap();
        request.executable.path = fixture.to_string_lossy().into_owned();
        request.executable.architecture = compatforge_domain::CpuArchitecture::X86_64;
        request.executable.sha256 = None;
        let fixture = CString::new(fixture.to_string_lossy().as_bytes()).unwrap();
        let request = CString::new(serde_json::to_string(&request).unwrap()).unwrap();
        let mut prepared = ptr::null_mut();
        let mut launch = ptr::null_mut();
        let mut plan_json = ptr::null_mut();

        unsafe {
            assert_eq!(
                cf_launch_prepare(original_context, fixture.as_ptr(), request.as_ptr(), &mut prepared),
                CfStatus::Ok
            );
            assert_eq!(
                cf_prepared_launch_start(changed_context, prepared, &mut launch),
                CfStatus::AuthorizationFailed
            );
            assert!(launch.is_null());
            assert_eq!(cf_prepared_launch_plan_get(prepared, &mut plan_json), CfStatus::Ok);
            let plan: LaunchPlan = serde_json::from_str(CStr::from_ptr(plan_json).to_str().unwrap()).unwrap();
            let object = Path::new(&plan.guest_artifact.as_ref().unwrap().stored_path);
            make_object_writable(object);
            cf_string_free(plan_json);
            cf_prepared_launch_release(prepared);
            cf_context_release(original_context);
            cf_context_release(changed_context);
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn prepared_launch_functions_clear_outputs_before_handle_validation() {
        let mut prepared = std::ptr::NonNull::<CfPreparedLaunch>::dangling().as_ptr();
        let mut text = std::ptr::NonNull::<c_char>::dangling().as_ptr();
        let mut launch = std::ptr::NonNull::<CfLaunch>::dangling().as_ptr();
        unsafe {
            assert_eq!(
                cf_launch_prepare(ptr::null(), ptr::null(), ptr::null(), &mut prepared),
                CfStatus::NullPointer
            );
            assert!(prepared.is_null());
            assert_eq!(
                cf_prepared_launch_inspection_get(ptr::null(), &mut text),
                CfStatus::NullPointer
            );
            assert!(text.is_null());
            text = std::ptr::NonNull::<c_char>::dangling().as_ptr();
            assert_eq!(
                cf_prepared_launch_plan_get(ptr::null(), &mut text),
                CfStatus::NullPointer
            );
            assert!(text.is_null());
            assert_eq!(
                cf_prepared_launch_start(ptr::null(), ptr::null(), &mut launch),
                CfStatus::NullPointer
            );
            assert!(launch.is_null());
        }
    }

    #[test]
    fn contains_json_errors_without_unwinding() {
        let config = CString::new(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let invalid_request = CString::new("{").unwrap();
        let mut context = ptr::null_mut();
        let mut output = ptr::null_mut();
        let mut error_output = ptr::null_mut();

        unsafe {
            assert_eq!(cf_context_create(config.as_ptr(), &mut context), CfStatus::Ok);
            assert_eq!(
                cf_compile_launch(context, invalid_request.as_ptr(), &mut output),
                CfStatus::InvalidJson
            );
            assert!(output.is_null());
            assert_eq!(cf_last_error_json(&mut error_output), CfStatus::Ok);
            let error_text = CStr::from_ptr(error_output).to_str().unwrap();
            assert!(error_text.contains("invalid launch request JSON"));
            cf_string_free(error_output);
            cf_context_release(context);
        }
    }

    #[test]
    fn starts_and_observes_a_process_across_the_c_abi() {
        let mut config: CoreConfig =
            serde_json::from_str(include_str!("../../../examples/context-config.linux-arm64.json")).unwrap();
        let root = std::env::current_dir().unwrap().to_string_lossy().into_owned();
        let executable = std::env::current_exe().unwrap().to_string_lossy().into_owned();
        config.storage_root.clone_from(&root);
        config.runtime_bindings[0].executable.clone_from(&executable);
        config.runtime_bindings[0].wineserver_executable = None;

        let plan = LaunchPlan {
            schema_version: "1".into(),
            request_id: "ffi-process-test".into(),
            runtime: compatforge_domain::RuntimeSelection {
                provider: RuntimeKind::Wine,
                pack_id: config.runtime_bindings[0].pack_id.clone(),
                pack_digest: config.runtime_bindings[0].pack_digest.clone(),
            },
            translator: compatforge_domain::TranslatorSelection {
                provider: TranslatorKind::Fex,
                version: Some("test".into()),
            },
            graphics: compatforge_domain::GraphicsSelection {
                backend: GraphicsBackendKind::WineD3d,
                version: Some("test".into()),
                options: std::collections::BTreeMap::new(),
            },
            process: compatforge_domain::NativeCommand {
                executable,
                arguments: vec!["--list".into()],
                environment: std::collections::BTreeMap::from([
                    ("COMPATFORGE_RUNTIME_PACK".into(), "wine-linux-arm64-fex".into()),
                    ("WINEPREFIX".into(), format!("{root}/bottles/ffi-process-test/prefix")),
                ]),
                working_directory: root,
            },
            guest_artifact: None,
            bottle_executable: None,
            mounts: Vec::new(),
            sandbox: compatforge_domain::SandboxPolicy {
                profile: config.sandbox_profile,
                network: compatforge_domain::NetworkPolicy::Deny,
                allow_devices: Vec::new(),
            },
            lifecycle: compatforge_domain::ProcessLifecycle {
                termination_grace_milliseconds: config.supervisor.termination_grace_milliseconds,
                maximum_runtime_milliseconds: config.supervisor.maximum_runtime_milliseconds,
                wineserver: None,
            },
            decision_trace: Vec::new(),
        };
        let config = CString::new(serde_json::to_string(&config).unwrap()).unwrap();
        let plan = CString::new(serde_json::to_string(&plan).unwrap()).unwrap();
        let mut context = ptr::null_mut();
        let mut launch = ptr::null_mut();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut exited = false;

        unsafe {
            assert_eq!(cf_context_create(config.as_ptr(), &mut context), CfStatus::Ok);
            assert_eq!(cf_launch_start(context, plan.as_ptr(), &mut launch), CfStatus::Ok);
            while std::time::Instant::now() < deadline && !exited {
                let mut output = ptr::null_mut();
                match cf_launch_next_event(launch, 250, &mut output) {
                    CfStatus::Ok => {
                        let event: compatforge_domain::RuntimeEvent =
                            serde_json::from_str(CStr::from_ptr(output).to_str().unwrap()).unwrap();
                        exited = event.kind == RuntimeEventKind::Exited;
                        cf_string_free(output);
                    }
                    CfStatus::Timeout => {}
                    status => panic!("unexpected event status: {status:?}"),
                }
            }
            assert!(exited);
            cf_launch_release(launch);
            cf_context_release(context);
        }
    }
}

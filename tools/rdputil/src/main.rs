//! One-shot RDP utility for computer-use glue: screenshot, mouse and keyboard.
//!
//! Extends the `screenshot` example machinery with an input path. Each
//! invocation opens a full Standard RDP Security session (the only transport
//! some legacy-configured servers accept), optionally injects fast-path input
//! events right after activation, keeps decoding updates for `--idle-secs` so
//! the server's reaction lands in the framebuffer, then optionally saves a
//! verification PNG — the act+observe primitive for the Python glue.
//!
//! # Usage example
//!
//! ```shell
//! cargo run --example=rdputil -- screenshot --host <HOSTNAME> -u <USERNAME> -p <PASSWORD> -o out.png
//! cargo run --example=rdputil -- mouse --host <HOSTNAME> -u <USERNAME> -p <PASSWORD> --x 640 --y 512 -o after.png
//! cargo run --example=rdputil -- mouse --host <HOSTNAME> -u <USERNAME> -p <PASSWORD> --x 640 --y 512 --action dblclick
//! cargo run --example=rdputil -- key --host <HOSTNAME> -u <USERNAME> -p <PASSWORD> --scancode 0x1c -o after.png
//! cargo run --example=rdputil -- key --host <HOSTNAME> -u <USERNAME> -p <PASSWORD> --text "hello"
//! ```

#![allow(unused_crate_dependencies)] // false positives because there is both a library and a binary
#![allow(clippy::print_stdout)]

mod rail;
mod serve;

use core::time::Duration;
use std::io::{BufRead, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Context as _;
use connector::Credentials;
use ironrdp::cliprdr::backend::CliprdrBackend;
use ironrdp::cliprdr::pdu::{
    ClipboardFormat, ClipboardFormatId, ClipboardGeneralCapabilityFlags, FileContentsRequest,
    FileContentsResponse, FormatDataRequest, FormatDataResponse, LockDataId,
};
use ironrdp::cliprdr::{Cliprdr, CliprdrClient};
use ironrdp::connector;
use ironrdp::connector::ConnectionResult;
use ironrdp::connector::Sequence as _;
use ironrdp::connector::connection_activation::{ConnectionActivationFactory, ConnectionActivationState};
use ironrdp::svc::{SvcMessage, SvcProcessor};
use ironrdp::pdu::gcc::{ConnectionType, KeyboardType};
use ironrdp::pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp::pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder, ActiveStageOutput, GracefulDisconnectReason};
use ironrdp_rail::pdu::{ActivatePdu, ExecutePdu, ExecuteResult, GetApplicationIdRequestPdu};
use ironrdp_rdpdr::pdu::efs::{
    AnyIoCtlCode, DecodedDeviceControlRequest, DeviceControlRequest, DeviceIoRequest, NtStatus, PrinterIoRequest,
    ServerDeviceAnnounceResponse, ServerDriveIoRequest,
};
use ironrdp_rdpdr::pdu::esc::{ScardCall, ScardIoCtlCode};
use ironrdp_rdpdr::{RdpdrBackend, RdpdrBackendFactory, RdpdrDrive};
use ironrdp_rdpdr_native as rdpdr_native;

use rail::{RailClient, RailControlEvent, RailEvent, RailInputEvent};

/// Verdict of the RAIL EXEC order in the current session, shared with the
/// serve daemon's loss triage: after a successful launch, the server tearing
/// the connection down when the app's last window closes is the expected
/// RemoteApp episode boundary, not a fault.
pub(crate) static RAIL_EXEC_OK: AtomicBool = AtomicBool::new(false);
pub(crate) static RAIL_EXEC_FAILED: AtomicBool = AtomicBool::new(false);

/// Grace deadline for releasing the queued RAIL EXEC after the server
/// handshake. Session-scoped state rather than a pump_until local: the serve
/// daemon pumps in short slices and the window routinely outlives the slice
/// that received the handshake, so a per-call local would drop it unissued.
static RAIL_RELEASE: Mutex<Option<Instant>> = Mutex::new(None);

/// Window id of the launched RemoteApp awaiting its Activate report. The first
/// top-level window the server describes after a successful launch is the app
/// itself; reporting it activated stands in for the focus click an interactive
/// client sends, without which the session's window-manager shortcuts (Alt+F4)
/// have no target and the app can never be torn down by the user side.
static RAIL_ACTIVATE: Mutex<Option<u32>> = Mutex::new(None);

/// Server-side window id of the launched RemoteApp, once known. The app_close
/// op targets it. 0 means no app window has been identified this session.
pub(crate) static RAIL_WINDOW: AtomicU32 = AtomicU32::new(0);

/// Post-launch window ids awaiting identity confirmation via GET_APPLICATIONID.
static RAIL_PROBE: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Window ids whose identity was already requested this session.
static RAIL_PROBED: Mutex<Vec<u32>> = Mutex::new(Vec::new());

/// Display name of the redirected drive as the guest sees it:
/// \\tsclient\<RDPDR_DRIVE_NAME>.
pub(crate) const RDPDR_DRIVE_NAME: &str = "tools";

/// Capability verdict for the redirected-drive share. Starts `Pending`; the
/// server's device-announce response settles it for the session.
#[derive(Clone, Debug, Default)]
pub(crate) enum RdpdrCap {
    #[default]
    Pending,
    Accepted,
    /// Carries the server's NTSTATUS render.
    Rejected(String),
}

impl RdpdrCap {
    pub(crate) fn as_label(&self) -> String {
        match self {
            RdpdrCap::Pending => "pending".to_owned(),
            RdpdrCap::Accepted => "accepted".to_owned(),
            RdpdrCap::Rejected(status) => format!("rejected:{status}"),
        }
    }
}

/// Session-level rdpdr capability signal shared between the backend wrapper
/// (wire side) and the file ops (JSON side).
#[derive(Clone, Debug, Default)]
pub(crate) struct RdpdrGate(Arc<Mutex<RdpdrCap>>);

impl RdpdrGate {
    fn set(&self, cap: RdpdrCap) {
        *self.0.lock().unwrap() = cap;
    }

    pub(crate) fn cap(&self) -> RdpdrCap {
        self.0.lock().unwrap().clone()
    }
}

/// Delegating backend that records the server's verdict on our device
/// announcement. A rejected share must turn into a fast, explicit file-op
/// failure — otherwise file_push "succeeds" while the guest never sees the
/// file.
#[derive(Debug)]
struct GateBackend {
    inner: Box<dyn RdpdrBackend>,
    gate: RdpdrGate,
}

impl_as_any!(GateBackend);

impl RdpdrBackend for GateBackend {
    fn supports_drive_security(&self) -> bool {
        self.inner.supports_drive_security()
    }

    fn reset(&mut self) -> PduResult<()> {
        self.inner.reset()
    }

    fn restore_drive(&mut self, device_id: u32) -> PduResult<()> {
        self.inner.restore_drive(device_id)
    }

    fn add_drive(&mut self, device_id: u32) -> PduResult<()> {
        self.inner.add_drive(device_id)
    }

    fn remove_drive(&mut self, device_id: u32) -> PduResult<Vec<SvcMessage>> {
        self.inner.remove_drive(device_id)
    }

    fn handle_server_device_announce_response(&mut self, pdu: ServerDeviceAnnounceResponse) -> PduResult<()> {
        if pdu.result_code == NtStatus::SUCCESS {
            self.gate.set(RdpdrCap::Accepted);
        } else {
            self.gate.set(RdpdrCap::Rejected(format!("{:?}", pdu.result_code)));
        }
        self.inner.handle_server_device_announce_response(pdu)
    }

    fn handle_scard_call(
        &mut self,
        req: DeviceControlRequest<ScardIoCtlCode>,
        call: ScardCall,
    ) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_scard_call(req, call)
    }

    fn handle_drive_io_request(&mut self, req: ServerDriveIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_drive_io_request(req)
    }

    fn handle_drive_device_control(
        &mut self,
        req: DecodedDeviceControlRequest<AnyIoCtlCode>,
    ) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_drive_device_control(req)
    }

    fn poll_deferred_messages(&mut self) -> PduResult<Vec<SvcMessage>> {
        self.inner.poll_deferred_messages()
    }

    fn handle_user_logged_on(&mut self, rdpdr: &mut ironrdp::rdpdr::Rdpdr) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_user_logged_on(rdpdr)
    }

    fn handle_printer_io_request(&mut self, req: PrinterIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.inner.handle_printer_io_request(req)
    }

    fn reject_printer_write(&mut self, req: DeviceIoRequest) -> PduResult<Vec<SvcMessage>> {
        self.inner.reject_printer_write(req)
    }
}
use ironrdp_pdu::input::{InputEvent, InputEventPdu, ScanCodePdu, UnicodePdu};
use ironrdp_pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason, McsMessage};
use ironrdp_pdu::x224::X224;
use ironrdp_pdu::rdp::client_info::{CompressionType, PerformanceFlags, TimezoneInfo};
use ironrdp_pdu::geometry::InclusiveRectangle;
use ironrdp_pdu::rdp::headers::ShareDataPdu;
use ironrdp_pdu::rdp::refresh_rectangle::RefreshRectanglePdu;
use ironrdp_pdu::WriteBuf;
use ironrdp_pdu::{impl_as_any, PduResult};
use sspi::network_client::reqwest_network_client::ReqwestNetworkClient;
use tokio_rustls::rustls;
use tracing::{debug, info, trace, warn};

const HELP: &str = "\
USAGE:
  cargo run --example=rdputil -- <COMMAND> --host <HOSTNAME> -u <USERNAME> -p <PASSWORD> [flags]

COMMANDS:
  screenshot                        render the current framebuffer to a PNG
      [-o/--output <FILE>]            (default: out.png)
      [--idle-secs <N>]               quiet period before saving (default: 15)
  mouse                             inject a mouse action, then observe
      --x <N> --y <N>                 target coordinates
      [--button left|right|middle|none]              (default: left)
      [--action click|dblclick|press|release|move]   (default: click)
      [-o/--output <FILE>]            optional verification PNG
      [--idle-secs <N>]               (default: 6)
  key                               inject keyboard input, then observe
      [--scancode <0xNN>]             scan code to press and release
      [--scancodes <0xNN,0xNN,...>]   sequence of scan codes, typed in order
      [--text <STRING>]               unicode text to type (experimental)
      [--seq <TOKENS>]                mixed event sequence, comma separated:
                                        k<0xNN>  key tap (press + release)
                                        ke<0xNN> extended key tap (E0-prefixed, e.g. ke0x5b = Win)
                                        d<0xNN> / u<0xNN>   key down / key up
                                        de<0xNN> / ue<0xNN> extended key down / up (for chords)
                                        c<x>-<y> left click at (x, y)
                                        r<x>-<y> right click at (x, y)
                                      e.g. --seq ke0x5b,c600-644,k0x02,k0x1c
      [-o/--output <FILE>]            optional verification PNG
      [--idle-secs <N>]               (default: 6)

COMMON FLAGS:
  [--port <PORT>]  [-d/--domain <DOMAIN>]
  [--compression-enabled <true|false>] [--compression-level <0..3>]
  [--pre-secs <N>]                settle time before injecting (default: 3)
  [--event-delay-ms <N>]          spacing between injected events (default: 30)
";

fn main() -> anyhow::Result<()> {
    // Value-aware: probing scripts export RDPUTIL_LEGACY_INPUT=0 to mean "off";
    // a presence check (is_some) would flip legacy mode on and feed nt5 mouse
    // values to modern servers, killing the session.
    ironrdp_pdu::input::set_legacy_nt5_input(matches!(
        std::env::var("RDPUTIL_LEGACY_INPUT").as_deref(),
        Ok("1") | Ok("true") | Ok("on")
    ));

    let command = match parse_args() {
        Ok(command) => command,
        Err(e) => {
            println!("{HELP}");
            return Err(e.context("invalid argument(s)"));
        }
    };

    setup_logging()?;

    run(command)
}

#[derive(Debug)]
pub(crate) struct CommonArgs {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) domain: Option<String>,
    pub(crate) compression_enabled: bool,
    pub(crate) compression_level: u32,
    pub(crate) output: Option<PathBuf>,
    pub(crate) idle_secs: u64,
    pub(crate) burst: u64,
    pub(crate) pre_secs: u64,
    pub(crate) event_delay_ms: u64,
    pub(crate) events: Vec<(FastPathInputEvent, u64)>,
}

#[derive(Debug)]
enum Command {
    Screenshot(CommonArgs),
    Mouse(CommonArgs),
    Key(CommonArgs),
    Serve(serve::ServeArgs),
}

fn parse_args() -> anyhow::Result<Command> {
    let mut args = pico_args::Arguments::from_env();

    if args.contains(["-h", "--help"]) {
        anyhow::bail!("help requested");
    }

    let subcommand = args.subcommand()?;

    if subcommand.as_deref() == Some("serve") {
        return Ok(Command::Serve(serve::ServeArgs::parse(&mut args)?));
    }

    let subcommand = match subcommand.as_deref() {
        Some("screenshot") | Some("mouse") | Some("key") => subcommand.unwrap(),
        _ => anyhow::bail!("a subcommand is required: screenshot, mouse, key or serve"),
    };

    let events = match subcommand.as_str() {
        "mouse" => match args.opt_value_from_str::<_, String>("--seq")? {
            Some(seq) => parse_seq_events(&seq)?,
            None => parse_mouse_events(&mut args)?.into_iter().map(|e| (e, 0)).collect::<Vec<_>>(),
        },
        "key" => parse_key_events(&mut args)?,
        _ => Vec::new(),
    };

    let common = CommonArgs {
        host: args.value_from_str("--host")?,
        port: args.opt_value_from_str("--port")?.unwrap_or(3389),
        username: args.value_from_str(["-u", "--username"])?,
        password: args.value_from_str(["-p", "--password"])?,
        domain: args.opt_value_from_str(["-d", "--domain"])?,
        compression_enabled: args.opt_value_from_str("--compression-enabled")?.unwrap_or(true),
        compression_level: args.opt_value_from_str("--compression-level")?.unwrap_or(3),
        output: args.opt_value_from_str(["-o", "--output"])?,
        idle_secs: args
            .opt_value_from_str("--idle-secs")?
            .unwrap_or(if subcommand == "screenshot" { 15 } else { 6 }),
        pre_secs: args.opt_value_from_str("--pre-secs")?.unwrap_or(if subcommand == "screenshot" {
            0
        } else {
            3
        }),
        event_delay_ms: args.opt_value_from_str("--event-delay-ms")?.unwrap_or(30),
        burst: args.opt_value_from_str("--burst")?.unwrap_or(0),
        events,
    };

    if common.compression_level > 3 {
        anyhow::bail!("Invalid compression level. Valid values are 0, 1, 2, 3.");
    }

    Ok(match subcommand.as_str() {
        "mouse" => Command::Mouse(common),
        "key" => Command::Key(common),
        _ => Command::Screenshot(common),
    })
}

fn parse_mouse_events(args: &mut pico_args::Arguments) -> anyhow::Result<Vec<FastPathInputEvent>> {
    let x: u16 = args.value_from_str("--x")?;
    let y: u16 = args.value_from_str("--y")?;
    let button: String = args.opt_value_from_str("--button")?.unwrap_or_else(|| "left".to_owned());
    let action: String = args.opt_value_from_str("--action")?.unwrap_or_else(|| "click".to_owned());

    let (down_flags, up_flags) = match button.as_str() {
        "left" => (PointerFlags::LEFT_BUTTON, PointerFlags::LEFT_BUTTON),
        "right" => (PointerFlags::RIGHT_BUTTON, PointerFlags::RIGHT_BUTTON),
        "middle" => (PointerFlags::MIDDLE_BUTTON_OR_WHEEL, PointerFlags::MIDDLE_BUTTON_OR_WHEEL),
        "none" => (PointerFlags::empty(), PointerFlags::empty()),
        other => anyhow::bail!("unknown button '{other}': left, right, middle or none"),
    };

    let pdu = |flags: PointerFlags| {
        FastPathInputEvent::MouseEvent(MousePdu {
            flags,
            number_of_wheel_rotation_units: 0,
            x_position: x,
            y_position: y,
        })
    };
    let move_event = || pdu(PointerFlags::MOVE);
    let press = |flags: PointerFlags| pdu(flags | PointerFlags::DOWN);
    let release = |flags: PointerFlags| pdu(flags);

    let events = match action.as_str() {
        "move" => vec![move_event()],
        "click" => vec![move_event(), press(down_flags), release(up_flags)],
        "dblclick" => vec![move_event(), press(down_flags), release(up_flags), press(down_flags), release(up_flags)],
        "press" => vec![move_event(), press(down_flags)],
        "release" => vec![move_event(), release(up_flags)],
        other => anyhow::bail!("unknown action '{other}': click, dblclick, press, release or move"),
    };

    Ok(events)
}

fn parse_key_events(args: &mut pico_args::Arguments) -> anyhow::Result<Vec<(FastPathInputEvent, u64)>> {
    let mut events: Vec<(FastPathInputEvent, u64)> = Vec::new();

    if let Some(scancode) = args.opt_value_from_str::<_, String>("--scancode")? {
        let scancode = scancode.trim_start_matches("0x");
        let scancode = u8::from_str_radix(scancode, 16).context("--scancode must be a hex byte (e.g. 0x1c)")?;
        events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), scancode), 0));
        events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, scancode), 0));
    }

    if let Some(scancodes) = args.opt_value_from_str::<_, String>("--scancodes")? {
        for entry in scancodes.split(',') {
            let entry = entry.trim().trim_start_matches("0x");
            let scancode = u8::from_str_radix(entry, 16).context("--scancodes entries must be hex bytes (e.g. 0x1c)")?;
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), scancode), 0));
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, scancode), 0));
        }
    }

    if let Some(text) = args.opt_value_from_str::<_, String>("--text")? {
        for ch in text.encode_utf16() {
            events.push((FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), ch), 0));
            events.push((FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, ch), 0));
        }
    }

    if let Some(seq) = args.opt_value_from_str::<_, String>("--seq")? {
        events.extend(parse_seq_events(&seq)?);
    }

    if events.is_empty() {
        anyhow::bail!("key needs --scancode <0xNN>, --scancodes, --text <STRING> or --seq <TOKENS>");
    }

    Ok(events)
}

fn parse_seq_events(seq: &str) -> anyhow::Result<Vec<(FastPathInputEvent, u64)>> {
    let mut events = Vec::new();
    let mut pending_wait_ms = 0u64;

    for token in seq.split(',') {
        let token = token.trim();
        if token.is_empty() {
            continue;
        }

        if let Some(rest) = token.strip_prefix('w') {
            let ms = rest
                .parse::<u64>()
                .context("--seq wait token must be a millisecond count (e.g. w2000)")?;
            pending_wait_ms = pending_wait_ms.saturating_add(ms);
            continue;
        }

        if let Some(rest) = token.strip_prefix("ke") {
            let scancode = u8::from_str_radix(rest.trim_start_matches("0x"), 16)
                .context("--seq extended key token must be a hex byte (e.g. ke0x5b)")?;
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED, scancode), pending_wait_ms));
            events.push((
                FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED | KeyboardFlags::RELEASE, scancode),
                0,
            ));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix('k') {
            let scancode = u8::from_str_radix(rest.trim_start_matches("0x"), 16)
                .context("--seq key token must be a hex byte (e.g. k0x1c)")?;
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), scancode), pending_wait_ms));
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, scancode), 0));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix("de") {
            let scancode = u8::from_str_radix(rest.trim_start_matches("0x"), 16)
                .context("--seq extended key-down token must be a hex byte (e.g. de0x5b)")?;
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED, scancode), pending_wait_ms));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix("ue") {
            let scancode = u8::from_str_radix(rest.trim_start_matches("0x"), 16)
                .context("--seq extended key-up token must be a hex byte (e.g. ue0x5b)")?;
            events.push((
                FastPathInputEvent::KeyboardEvent(KeyboardFlags::EXTENDED | KeyboardFlags::RELEASE, scancode),
                pending_wait_ms,
            ));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix('d') {
            let scancode = u8::from_str_radix(rest.trim_start_matches("0x"), 16)
                .context("--seq key-down token must be a hex byte (e.g. d0x1d)")?;
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), scancode), pending_wait_ms));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix('u') {
            let scancode = u8::from_str_radix(rest.trim_start_matches("0x"), 16)
                .context("--seq key-up token must be a hex byte (e.g. u0x1d)")?;
            events.push((FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, scancode), pending_wait_ms));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix('c') {
            let (x, y) = rest.split_once('-').context("--seq click token must be c<x>-<y> (e.g. c600-644)")?;
            let (x, y) = (x.parse::<u16>().context("--seq click x coordinate")?, y.parse::<u16>().context("--seq click y coordinate")?);
            let pdu = |flags: PointerFlags| {
                FastPathInputEvent::MouseEvent(MousePdu {
                    flags,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                })
            };
            events.push((pdu(PointerFlags::MOVE), pending_wait_ms));
            events.push((pdu(PointerFlags::LEFT_BUTTON | PointerFlags::DOWN), 0));
            events.push((pdu(PointerFlags::LEFT_BUTTON), 0));
            pending_wait_ms = 0;
        } else if let Some(rest) = token.strip_prefix('r') {
            let (x, y) = rest
                .split_once('-')
                .context("--seq right-click token must be r<x>-<y> (e.g. r600-644)")?;
            let (x, y) = (
                x.parse::<u16>().context("--seq right-click x coordinate")?,
                y.parse::<u16>().context("--seq right-click y coordinate")?,
            );
            let pdu = |flags: PointerFlags| {
                FastPathInputEvent::MouseEvent(MousePdu {
                    flags,
                    number_of_wheel_rotation_units: 0,
                    x_position: x,
                    y_position: y,
                })
            };
            events.push((pdu(PointerFlags::MOVE), pending_wait_ms));
            events.push((pdu(PointerFlags::RIGHT_BUTTON | PointerFlags::DOWN), 0));
            events.push((pdu(PointerFlags::RIGHT_BUTTON), 0));
            pending_wait_ms = 0;
        } else {
            anyhow::bail!("unknown --seq token '{token}': expected k<0xNN>, ke<0xNN>, d/u<0xNN>, de/ue<0xNN>, c<x>-<y>, r<x>-<y> or w<ms>");
        }
    }

    Ok(events)
}

fn setup_logging() -> anyhow::Result<()> {
    use tracing::metadata::LevelFilter;
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::prelude::*;

    // stdout is protocol space in serve mode; every diagnostic goes to stderr.
    let fmt_layer = tracing_subscriber::fmt::layer()
        .compact()
        .with_writer(std::io::stderr);

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .with_env_var("IRONRDP_LOG")
        .from_env_lossy();

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(env_filter)
        .try_init()
        .context("failed to set tracing global subscriber")?;

    Ok(())
}

fn run(command: Command) -> anyhow::Result<()> {
    let (common, label) = match command {
        Command::Screenshot(common) => (common, "screenshot"),
        Command::Mouse(common) => (common, "mouse"),
        Command::Key(common) => (common, "key"),
        Command::Serve(serve_args) => return serve::run_serve(serve_args),
    };

    info!(
        host = %common.host,
        port = common.port,
        username = %common.username,
        label,
        output = ?common.output,
        events = common.events.len(),
        "run"
    );

    let (connection_result, framed, _, _) = connect(&common, false, None).context("connect")?;
    info!(compression_type = ?connection_result.compression_type, "Negotiated compression");

    let mut image = DecodedImage::new(
        ironrdp_graphics::image_processing::PixelFormat::RgbA32,
        connection_result.desktop_size.width,
        connection_result.desktop_size.height,
    );

    active_stage(connection_result, framed, &mut image, &common.events, &common).context("active stage")?;

    if let Some(output) = &common.output {
        let nonzero = image.data().iter().filter(|&&b| b != 0).count();
        eprintln!("FBSTAT width={} height={} data_len={} nonzero_bytes={}", image.width(), image.height(), image.data().len(), nonzero);

        let img: image::ImageBuffer<image::Rgba<u8>, _> =
            image::ImageBuffer::from_raw(u32::from(image.width()), u32::from(image.height()), image.data())
                .context("invalid image")?;

        img.save(output).context("save image to disk")?;
        info!(output = %output.display(), "Image saved");
    }

    Ok(())
}

/// Drives the connection sequence, retrying on failure. Kept at 3 attempts:
/// some servers rate-limit repeated SYNs from one source port.
pub(crate) fn connect(
    common: &CommonArgs,
    cliprdr: bool,
    rdpdr: Option<&std::path::Path>,
) -> anyhow::Result<(ConnectionResult, AnyFramed, Option<ClipState>, Option<RdpdrGate>)> {
    const MAX_ATTEMPTS: usize = 3;

    let mut last_error = None;

    for attempt in 1..=MAX_ATTEMPTS {
        let connector_config = build_config(
            common.username.clone(),
            common.password.clone(),
            common.domain.clone(),
            common.compression_enabled,
            common.compression_level,
        )?;

        match connect_once(connector_config, &common.host, common.port, cliprdr, rdpdr) {
            Ok(result) => return Ok(result),
            Err(error) => {
                warn!(attempt, MAX_ATTEMPTS, error = %error.root_cause(), "Connection attempt failed");
                last_error = Some(error);
                if attempt < MAX_ATTEMPTS {
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    }

    Err(last_error.expect("at least one attempt").context("all connection attempts failed"))
}

fn connect_once(
    config: connector::Config,
    server_name: &str,
    port: u16,
    cliprdr: bool,
    rdpdr: Option<&std::path::Path>,
) -> anyhow::Result<(ConnectionResult, AnyFramed, Option<ClipState>, Option<RdpdrGate>)> {
    // Windows couples rdpdr initialization to audio support: with
    // INFO_NOAUDIOPLAYBACK set in the Client Info PDU the server never starts
    // the rdpdr handshake, no matter that the RDPSND static channel is
    // advertised. Claim audio playback whenever drive redirection is on; the
    // Noop RDPSND backend keeps that path silent.
    let mut config = config;
    if rdpdr.is_some() {
        config.enable_audio_playback = true;
    }
    // Snapshot before the config moves into the connector: the RAIL processor
    // seeds its work-area system parameters with the same client identity the
    // Info PDU carries.
    let rail_client = remote_app_requested().then(|| {
        RailClient::new(
            config.client_build,
            config.desktop_size.width,
            config.desktop_size.height,
        )
    });
    let server_addr = lookup_addr(server_name, port).context("lookup addr")?;

    info!(%server_addr, "Looked up server address");

    let tcp_stream = TcpStream::connect(server_addr).context("TCP connect")?;

    // Sets the read timeout for the TCP stream so a stalling server during the
    // handshake cannot hang the process forever (connect() retries instead).
    // Generous: a guest buried in reconnect storms or first-logon profile
    // loading can take many seconds to answer negotiation, and treating that
    // as a hard failure turns one slow start into a dead session.
    let read_timeout_secs: u64 = std::env::var("RDPUTIL_READ_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    tcp_stream
        .set_read_timeout(Some(Duration::from_secs(read_timeout_secs)))
        .expect("set_read_timeout call failed");

    let client_addr = tcp_stream.local_addr().context("get socket local address")?;

    let mut framed = ironrdp_blocking::Framed::new(tcp_stream);

    // Only the explicit standard-RDP-security opt-in skips the TLS upgrade;
    // the connector refuses a server-selected protocol it did not offer.
    let skip_tls = config.enable_standard_rdp_security && !config.enable_tls && !config.enable_credssp;

    let mut connector = connector::ClientConnector::new(config, client_addr);

    let mut connector = if let Ok(path) = std::env::var("RDPUTIL_COOKIE_IN") {
        match std::fs::read(&path) {
            Ok(mut bytes) => {
                let decoded: Result<ironrdp_pdu::rdp::session_info::ServerAutoReconnect, _> =
                    ironrdp_pdu::Decode::decode(&mut ironrdp_pdu::cursor::ReadCursor::new(&bytes));
                match decoded {
                    Ok(cookie) => {
                        println!("COOKIE INJECTED logon_id={}", cookie.logon_id);
                        connector.with_auto_reconnect_cookie(cookie)
                    }
                    Err(e) => {
                        eprintln!("cookie decode failed: {e}");
                        connector
                    }
                }
            }
            Err(e) => {
                eprintln!("cookie read failed: {e}");
                connector
            }
        }
    } else {
        connector
    };

    // Drive-mode clipboard channel (RDPUTIL_CLIPRDR=1): a headless backend
    // that lets `cb` read the guest clipboard text via initiate_paste.
    let clip = if cliprdr {
        let state = ClipState::default();
        connector = connector.with_static_channel(Cliprdr::new(Box::new(DriveClipBackend { state: state.clone() })));
        Some(state)
    } else {
        None
    };

    // Drive redirection (rdpdr): expose a host directory to the guest as a
    // \\tsclient\<name> share for the file_push/file_pull ops. The backend
    // owns per-session device state, so a fresh one is built per connection
    // attempt, which keeps reconnects consistent.
    let mut rdpdr_gate: Option<RdpdrGate> = None;
    if let Some(dir) = rdpdr {
        // Windows servers only issue RDPDR traffic when RDPSND is also
        // advertised; a silent RDPSND channel keeps the redirect alive.
        connector = connector.with_static_channel(ironrdp_rdpsnd::client::Rdpsnd::new(
            Box::new(ironrdp_rdpsnd::client::NoopRdpsndBackend),
        ));
        let drive =
            rdpdr_native::RedirectedDrive::new(42, RDPDR_DRIVE_NAME, dir, false).context("redirected drive definition")?;
        let factory = rdpdr_native::WindowsRdpdrBackendFactory::from_drives(vec![drive]).context("rdpdr backend factory")?;
        let product = factory
            .build_rdpdr_backend()
            .map_err(|e| anyhow::anyhow!("rdpdr backend build: {e}"))?;
        let (backend, drives) = product.into_parts();
        let drives = drives.into_iter().map(RdpdrDrive::into_parts).collect::<Vec<_>>();
        // Watch the server's announce verdict so file ops can fail fast when
        // the share never becomes visible to the guest.
        let gate = RdpdrGate::default();
        let backend = GateBackend { inner: backend, gate: gate.clone() };
        connector = connector
            .with_static_channel(ironrdp::rdpdr::Rdpdr::new(Box::new(backend), "rdputil".to_owned()).with_drives(Some(drives)));
        rdpdr_gate = Some(gate);
    }

    // Dynamic display control (RDPUTIL_DISP=1): host the Display Control DVC
    // behind DRDYNVC so the drive-mode `resize W H` command can change the
    // guest resolution on the fly (MS-RDPEDISP). Attach before connect_begin
    // so the channel is negotiated in the GCC like cliprdr above.
    if std::env::var("RDPUTIL_DISP").as_deref() == Ok("1") {
        connector = connector.with_static_channel(
            ironrdp::dvc::DrdynvcClient::new()
                .with_dynamic_channel(ironrdp::displaycontrol::client::DisplayControlClient::new(|_| Ok(Vec::new()))),
        );
    }

    // RemoteApp (RAIL, RDPUTIL_REMOTE_APP): the connector advertises INFO_RAIL
    // and negotiates the RAIL capability; the launch itself travels as an EXEC
    // order on the "rail" static channel once the server handshake completes
    // (rail_kickoff). MS-RDPERP requires the launch data here, not in the
    // Client Info PDU.
    if let Some(rail_client) = rail_client {
        connector = connector.with_static_channel(rail_client);
    }

    let should_upgrade = ironrdp_blocking::connect_begin(&mut framed, &mut connector).context("begin connection")?;

    let initial_stream = framed.into_inner_no_leftover();

    let (stream, server_public_key) = if skip_tls {
        debug!("Standard RDP security: skipping TLS upgrade");
        (RdpStream::Plain(initial_stream), Vec::new())
    } else {
        debug!("TLS upgrade");
        let (tls_stream, server_public_key) = tls_upgrade(initial_stream, server_name.to_owned()).context("TLS upgrade")?;
        (RdpStream::Tls(tls_stream), server_public_key)
    };

    let upgraded = ironrdp_blocking::mark_as_upgraded(should_upgrade, &mut connector);

    let mut framed = ironrdp_blocking::Framed::new(stream);

    let mut network_client = ReqwestNetworkClient;
    let connection_result = ironrdp_blocking::connect_finalize(
        upgraded,
        connector,
        &mut framed,
        &mut network_client,
        server_name.to_owned().into(),
        server_public_key,
        None,
    )
    .context("finalize connection")?;

    eprintln!(
        "SERVE channels rdpdr={:?} rdpsnd={:?}",
        connection_result.static_channels.get_channel_id_by_type::<ironrdp::rdpdr::Rdpdr>(),
        connection_result.static_channels.get_channel_id_by_type::<ironrdp_rdpsnd::client::Rdpsnd>(),
    );

    Ok((connection_result, framed, clip, rdpdr_gate))
}

/// Replays the mstsc MS_T120 static-channel announce on the I/O channel.
///
/// Five verbatim T.124 payloads captured from a reference mstsc session,
/// hex-embedded below. The inner sender field ([4..6] LE) is patched to our
/// MCS user id — the server routes T.120 by sender, so a verbatim replay
/// carrying another client's id is dead air. Frames go out as plain-MAC MCS
/// SendDataRequests on the I/O channel (the security envelope, incl. the
/// checksum-disabled variant the announce needs, is applied by
/// `ActiveStage::secure_raw_frame`), 80 ms apart, right after activation.
/// Without this announce a legacy server kills any connection that injects
/// input (10054).
pub(crate) fn send_t120_announce(
    active_stage: &ActiveStage,
    framed: &mut AnyFramed,
    user_channel_id: u16,
    io_channel_id: u16,
) -> anyhow::Result<()> {
    const T120_ANNOUNCE_FRAMES: [&str; 5] = [
        "54021300f103ea030100ea0306003e024d53545343001700000001001800010003000002000000001d04000000000000000002001c0020000100010001000005d002000001000100001a0100000003005800000000000000000000000000000000000000000001001400000001000000aa000101010101000001010100010000000101010101010101000001010000000000a1060600000000000084030000000000a8030000130028000200000378000000780000005101000000000000000000000000000000000000000000000a0008000600000007000c00000000000000000005000c00000000000200020008000a0001001400150009000800000000000d005800b100000004080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c000800010000000e0008000100000010003400fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe0000014000000800010001030000000f0008000100000011000c00010000000028640014000c00010000000000000015000c0002000000000a00011a0008002b4809001c000c0012000000000000001b00060003001e0008000200000018000b0002000000030c001d005f0002b91b8dca0f004f15589fae2d1a87e2d6010300010103d4cc44278a9d744e803c0ecbeea19c54053100310000000100000025000000c0cb080000000100c1cb1d00000001c0cf0200080000014000020101010001400002010104",
        "16001700f103ea030100000108001f0000000100ea03",
        "1a001700f103ea03010000010c00140000000400000000000000",
        "1a001700f103ea03010000010c00140000000100000000000000",
        "1a001700f103ea03010000010000270000000000000003003200",
    ];

    for hex_frame in T120_ANNOUNCE_FRAMES {
        let mut body = decode_hex(hex_frame);
        // T.124 sender = legacy self.user_id = raw MCS userId wire value + 1003
        // (= user_channel_id + 2; mstsc's capture shows 0x3f1 under the same
        // rule). The T.120 bridge routes by this field — an unregistered
        // sender is ignored at best, disruptive at worst.
        let t124_sender = user_channel_id + 2;
        body[4..6].copy_from_slice(&t124_sender.to_le_bytes());

        let mut frame = Vec::with_capacity(4 + 3 + 3 + body.len());
        frame.extend_from_slice(&[0x03, 0x00, 0x00, 0x00]); // TPKT, length patched below
        frame.extend_from_slice(&[0x02, 0xf0, 0x80]); // X224 data
        frame.push(0x64); // MCS SendDataRequest
        // initiator selector: raw wire value from MCS Attach User Confirm =
        // user_channel_id - BASE_CHANNEL_ID(1001) — the same value ironrdp's
        // own SendDataRequests carry (legacy: per_int16(user_id, 1003)).
        frame.extend_from_slice(&user_channel_id.saturating_sub(1001).to_be_bytes());
        frame.extend_from_slice(&io_channel_id.to_be_bytes());
        frame.push(0x70); // segment
        let mcs_len = body.len();
        if mcs_len < 0x80 {
            frame.push(mcs_len as u8);
        } else {
            frame.push(0x80 | ((mcs_len >> 8) & 0x7f) as u8);
            frame.push((mcs_len & 0xff) as u8);
        }
        frame.extend_from_slice(&body);
        let total = frame.len() as u16;
        frame[2..4].copy_from_slice(&total.to_be_bytes());

        let secured = active_stage.secure_raw_frame(frame).context("secure T.120 frame")?;
        framed.write_all(secured.as_slice()).context("write T.120 announce")?;
        std::thread::sleep(Duration::from_millis(80));
    }
    Ok(())
}

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn active_stage(
    connection_result: ConnectionResult,
    mut framed: AnyFramed,
    image: &mut DecodedImage,
    events: &[(FastPathInputEvent, u64)],
    common: &CommonArgs,
) -> anyhow::Result<()> {
    framed
        .get_inner_mut()
        .0
        .set_read_timeout(Some(Duration::from_secs(1)))
        .context("set read timeout")?;

    let mut active_stage = ActiveStageBuilder {
        static_channels: connection_result.static_channels,
        user_channel_id: connection_result.user_channel_id,
        io_channel_id: connection_result.io_channel_id,
        message_channel_id: connection_result.message_channel_id,
        share_id: connection_result.share_id,
        compression_type: connection_result.compression_type,
        enable_server_pointer: connection_result.enable_server_pointer,
        pointer_software_rendering: connection_result.pointer_software_rendering,
        security: connection_result.security,
    }
    .build();

    // RemoteApp: queue the launch right away; the RAIL processor releases it
    // after the server handshake (rail_service). No-op in desktop mode.
    rail_kickoff(&mut active_stage, &mut framed)?;

    // Ask the server to repaint the whole desktop. Reconnecting to a static
    // session (e.g. XP) resends no deltas on its own, which leaves the
    // framebuffer all-black. Opt-in via env because XP advertises suppress
    // output support yet resets the connection when the toggle pair arrives.
    if std::env::var("RDPUTIL_FORCE_REFRESH").as_deref() == Ok("1") {
        let mut frame = WriteBuf::new();
        active_stage
            .encode_static(
                &mut frame,
                ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                    areas_to_refresh: vec![InclusiveRectangle {
                        left: 0,
                        top: 0,
                        right: connection_result.desktop_size.width.saturating_sub(1),
                        bottom: connection_result.desktop_size.height.saturating_sub(1),
                    }],
                }),
            )
            .context("encode refresh rect")?;
        let frame = frame.into_inner();
        framed.write_all(frame.as_slice()).context("write refresh rect")?;
    }

    // MS_T120 announce: every real client (mstsc/iOS/legacy) announces its
    // T.120 entity on the I/O channel right after activation. A legacy
    // server's input path RSTs connections that inject input without it:
    // pure screenshots survive, any input injection dies with 10054, and a
    // fresh boot changes nothing. The five frames in send_t120_announce are
    // verbatim mstsc captures; the inner sender field is patched to our MCS
    // user id because the server routes T.120 by sender (a verbatim replay
    // is dead air).
    if std::env::var("RDPUTIL_T120").as_deref() != Ok("0") {
        send_t120_announce(
            &active_stage,
            &mut framed,
            connection_result.user_channel_id,
            connection_result.io_channel_id,
        )
        .context("send MS_T120 announce")?;
    }

    // Interactive drive mode (RDPUTIL_DRIVE=1): an XP-era server's session
    // dies on RDP
    // disconnect, so an entire desktop operation (launch winmine, configure,
    // play) must happen inside ONE connection, with per-step visual feedback.
    // run_drive owns the rest of the session (incl. optional reconnects) and
    // returns on `q` — never falls through to --seq/idle handling.
    if std::env::var("RDPUTIL_DRIVE").as_deref() == Ok("1") {
        return run_drive(common, image);
    }

    if !events.is_empty() {
        // Let the initial update flood drain before injecting, mirroring the
        // legacy client's settle-then-send pattern (input sent during the
        // flood produced no visible effect on that server).
        let terminated = pump_until(
            &mut framed,
            &mut active_stage,
            image,
            Instant::now() + Duration::from_secs(common.pre_secs),
            None,
        )?;
        if terminated {
            return Ok(());
        }

        // One event per secured frame, spaced apart — the pattern the legacy
        // client field-validated. The security
        // envelope is applied by `process_fastpath_input`.
        let slow_input = std::env::var("RDPUTIL_SLOW_INPUT").as_deref() == Ok("1");
        for (i, (event, pre_wait_ms)) in events.iter().enumerate() {
            if i > 0 {
                std::thread::sleep(Duration::from_millis(common.event_delay_ms + pre_wait_ms));
            } else if *pre_wait_ms > 0 {
                std::thread::sleep(Duration::from_millis(*pre_wait_ms));
            }
            // Field truth for XP-era servers: ALL input must be slow-path
            // there. The earlier "fast-path mouse only" routing was a misread —
            // the clicks tested were landing on a disabled button, and the
            // real blocker was the wrong keyboard flag bits (fixed in
            // slow_input_event). Slow mouse flags match legacy's proven
            // mouse(): MOVE=0x0400, down=0x9000, up=0x1000 (see
            // slow_input_event).
            if slow_input {
                // XP-era servers only accept slow-path input PDUs: fast-path
                // input is silently dropped there (while modern servers reset
                // the connection on the slow path), so route through the share
                // channel instead.
                let pdu = ShareDataPdu::Input(InputEventPdu(vec![slow_input_event(event)?]));
                let mut buf = WriteBuf::new();
                active_stage.encode_static(&mut buf, pdu)?;
                let frame = buf.into_inner();
                eprintln!(
                    "SLOWFRAME len={} head={:02x?}",
                    frame.len(),
                    &frame[..frame.len().min(48)]
                );
                framed.write_all(frame.as_slice()).context("write slow-path input")?;
            } else {
                let outputs = active_stage.process_fastpath_input(image, std::slice::from_ref(event))?;
                for out in outputs {
                    if let ActiveStageOutput::ResponseFrame(frame) = out {
                        framed.write_all(&frame).context("write input response")?;
                    }
                }
            }
        }
        info!(count = events.len(), delay_ms = common.event_delay_ms, "Input events injected");
    }

    // Observe for the idle window so the server's reaction to the injected
    // input lands in the framebuffer before the PNG is saved.
    pump_until(
        &mut framed,
        &mut active_stage,
        image,
        Instant::now() + Duration::from_secs(common.idle_secs),
        None,
    )?;

    // Burst mode: keep the connection up and snapshot the framebuffer every
    // 5 s (<output>_bNNN.png) to watch slow state transitions (XP logon).
    if common.burst > 0 {
        if let Some(output) = &common.output {
            let stem = output
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| "burst".into());
            for i in 0..common.burst {
                let path = output.with_file_name(format!("{stem}_b{i:03}.png"));
                let data = image.data().to_vec();
                let img: image::ImageBuffer<image::Rgba<u8>, _> =
                    image::ImageBuffer::from_raw(u32::from(image.width()), u32::from(image.height()), data)
                        .context("invalid image")?;
                img.save(&path).context("save burst frame")?;
                eprintln!("BURST {i} -> {}", path.display());
                pump_until(&mut framed, &mut active_stage, image, Instant::now() + Duration::from_secs(5), None)?;
            }
        }
    }

    Ok(())
}

/// Maps a fast-path input event to its slow-path PDU equivalent. The flag
/// encodings differ (fast-path: u8 RELEASE=0x01/EXTENDED=0x02/EXTENDED1=0x04;
/// slow-path: u16 DOWN=0x4000/RELEASE=0x8000/EXTENDED=0x0100/EXTENDED_1=0x0200),
/// and slow-path keyboard events carry an explicit DOWN bit.
pub(crate) fn slow_input_event(event: &FastPathInputEvent) -> anyhow::Result<InputEvent> {
    use ironrdp_pdu::input::scan_code::KeyboardFlags as SlowKbFlags;
    use ironrdp_pdu::input::unicode;
    Ok(match event {
        FastPathInputEvent::MouseEvent(mp) => {
            // Slow-path TS_MOUSE_EVENT: MOVE=0x0800, DOWN|BUTTON1=0x9000,
            // BUTTON1=0x1000 — the SAME encoding on nt5 (at128.h:
            // TS_FLAG_MOUSE_MOVE=0x0800, TS_INPUT_EVENT_MOUSE=0x8001) and
            // modern servers. The historical "nt5 moves on 0x0400" belief
            // sent TS_FLAG_MOUSE_DOUBLE instead; the server's button switch
            // (aimapi.cpp) disconnects on unrecognized flag combos, which is
            // what actually killed sessions after the first mouse event.
            InputEvent::Mouse(mp.clone())
        }
        FastPathInputEvent::KeyboardEvent(flags, sc) => {
            // Wire truth (at128.h 1183-1191 vs MS-RDPBCGR): EXTENDED=0x0100
            // and EXTENDED_1=0x0200 agree on both; the RELEASE bit does NOT —
            // modern TS_KBDFLAGS_RELEASE=0x0001, nt5 TS_KBDFLAGS_RELEASE=
            // 0x8000 (aimapi.cpp tests only that bit; 0x0001 is KBDFLAGS_RIGHT
            // there, so a 0x0001 "release" reads as a second key-down on XP).
            // Down is all bits clear on both. The earlier field conclusion
            // "0x8000 never landed, 0x0001 does" was a misread: a RIGHT-flag
            // down lands as a visible press, masking the missing release.
            let release_bit: u16 = if ironrdp_pdu::input::legacy_nt5_input() {
                0x8000
            } else {
                0x0001
            };
            let mut slow: u16 = 0;
            if flags.contains(KeyboardFlags::RELEASE) {
                slow |= release_bit;
            }
            if flags.contains(KeyboardFlags::EXTENDED) {
                slow |= 0x0100;
            }
            if flags.contains(KeyboardFlags::EXTENDED1) {
                slow |= 0x0200;
            }
            InputEvent::ScanCode(ScanCodePdu {
                flags: ironrdp_pdu::input::scan_code::KeyboardFlags::from_bits_retain(slow),
                key_code: u16::from(*sc),
            })
        }
        FastPathInputEvent::UnicodeKeyboardEvent(flags, ch) => {
            // UnicodePdu carries its own u16 KeyboardFlags whose only member is RELEASE.
            let slow = if flags.contains(KeyboardFlags::RELEASE) {
                unicode::KeyboardFlags::RELEASE
            } else {
                unicode::KeyboardFlags::empty()
            };
            InputEvent::Unicode(UnicodePdu {
                flags: slow,
                unicode_code: *ch,
            })
        }
        other => anyhow::bail!("slow-path encoding of {other:?} is not supported"),
    })
}

/// Decodes server frames until `deadline`, keeping the framebuffer current and
/// answering the server. Returns true if the server terminated the session.
/// Drive-mode session runner: owns the stdin reader thread (spawned once, so
/// commands appended while a reconnect is in flight queue in the OS pipe and
/// the channel instead of being lost) and the optional reconnect loop.
/// RDPUTIL_RECONNECT=1 turns any transport error into a fresh full connection
/// (new handshake, ActiveStage, T120 announce); RDPUTIL_RECONNECT_CMD runs
/// before each retry — the field-proven place to purge wedged legacy sessions
/// (e.g. a server-side session-reset helper). RDPUTIL_RECONNECT_DELAY_MS spaces
/// attempts (default 5000).
fn run_drive(common: &CommonArgs, image: &mut DecodedImage) -> anyhow::Result<()> {
    use std::sync::mpsc;
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        for line in stdin.lock().lines() {
            match line {
                Ok(l) => {
                    if tx.send(l).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let reconnect = std::env::var("RDPUTIL_RECONNECT").as_deref() == Ok("1");
    let delay_ms: u64 = std::env::var("RDPUTIL_RECONNECT_DELAY_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let cliprdr_enabled = std::env::var("RDPUTIL_CLIPRDR").as_deref() == Ok("1");

    let mut round = 0u32;
    loop {
        round += 1;
        let (connection_result, mut framed, clip, _) = match connect(common, cliprdr_enabled, None) {
            Ok(ok) => ok,
            Err(e) => {
                if !reconnect {
                    return Err(e);
                }
                eprintln!("RECONNECT round={round} connect failed: {e:#}");
                run_reconnect_hook();
                std::thread::sleep(Duration::from_millis(delay_ms));
                continue;
            }
        };

        let mut stage = ActiveStageBuilder {
            static_channels: connection_result.static_channels,
            user_channel_id: connection_result.user_channel_id,
            io_channel_id: connection_result.io_channel_id,
            message_channel_id: connection_result.message_channel_id,
            share_id: connection_result.share_id,
            compression_type: connection_result.compression_type,
            enable_server_pointer: connection_result.enable_server_pointer,
            pointer_software_rendering: connection_result.pointer_software_rendering,
            security: connection_result.security,
        }
        .build();

        // RemoteApp launches once — on the first connection of the drive
        // episode. A reconnect lands back in a plain desktop session; the
        // app is gone by then.
        if round == 1 {
            rail_kickoff(&mut stage, &mut framed)?;
        }

        // A reconnected framebuffers stays all-black until the server is asked
        // to repaint (XP field truth), and the input-ready T.120 announce must
        // be replayed on every fresh connection, not just the first.
        if std::env::var("RDPUTIL_FORCE_REFRESH").as_deref() == Ok("1") {
            let mut frame = WriteBuf::new();
            stage.encode_static(
                &mut frame,
                ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                    areas_to_refresh: vec![InclusiveRectangle {
                        left: 0,
                        top: 0,
                        right: connection_result.desktop_size.width.saturating_sub(1),
                        bottom: connection_result.desktop_size.height.saturating_sub(1),
                    }],
                }),
            )
            .context("encode refresh rect")?;
            let frame = frame.into_inner();
            framed.write_all(frame.as_slice()).context("write refresh rect")?;
        }
        if std::env::var("RDPUTIL_T120").as_deref() != Ok("0") {
            send_t120_announce(
                &stage,
                &mut framed,
                connection_result.user_channel_id,
                connection_result.io_channel_id,
            )?;
        }

        // Fresh per connection: the channel ids it holds change on reconnect.
        let activation = connection_result.activation_factory;
        match drive_loop(&mut framed, &mut stage, image, &rx, clip.as_ref(), &activation) {
            Ok(()) => {
                eprintln!("DRIVE graceful end round={round}");
                return Ok(());
            }
            Err(e) => {
                if !reconnect {
                    return Err(e);
                }
                eprintln!("RECONNECT round={round} connection lost: {e:#}");
                run_reconnect_hook();
                std::thread::sleep(Duration::from_millis(delay_ms));
            }
        }
    }
}

fn run_reconnect_hook() {
    let Ok(cmd) = std::env::var("RDPUTIL_RECONNECT_CMD") else {
        return;
    };
    if cmd.trim().is_empty() {
        return;
    }
    eprintln!("RECONNECT hook: {cmd}");
    let status = if cfg!(windows) {
        std::process::Command::new("cmd").args(["/C", &cmd]).status()
    } else {
        std::process::Command::new("sh").arg("-c").arg(&cmd).status()
    };
    match status {
        Ok(s) => eprintln!("RECONNECT hook exit {s}"),
        Err(e) => eprintln!("RECONNECT hook spawn failed: {e}"),
    }
}

pub(crate) fn frame_hash(image: &DecodedImage) -> u64 {
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    hasher.write(image.data());
    hasher.finish()
}

/// Shared view of the drive clipboard backend's state. The backend itself is
/// owned by the `Cliprdr` static channel (inside ActiveStage); these `Arc`s
/// let `drive_loop` observe handshake progress and paste results without
/// touching the channel.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClipState {
    /// Server sent Monitor Ready and wants our Format List advertisement.
    pub(crate) advertise: Arc<std::sync::Mutex<bool>>,
    /// clip_tick already sent the (empty) Format List advertisement.
    pub(crate) advertised: Arc<std::sync::atomic::AtomicBool>,
    /// Server accepted our Format List — channel fully initialized.
    pub(crate) ready: Arc<std::sync::Mutex<bool>>,
    /// Formats the guest clipboard currently offers (from on_remote_copy).
    pub(crate) formats: Arc<std::sync::Mutex<Vec<u32>>>,
    /// Paste result: None = pending, Some(Err) = error response, Some(Ok) = text.
    pub(crate) response: Arc<std::sync::Mutex<Option<Result<String, ()>>>>,
    /// Client→guest write: pending UTF-16 payload awaiting the guest's Format
    /// Data Request, kept so repeated pastes can be served without re-set.
    pub(crate) write_pending: Arc<std::sync::Mutex<Option<Vec<u8>>>>,
    /// Client→guest write: a Format Data Request arrived and must be answered
    /// by the session loop (the backend itself cannot emit PDUs).
    pub(crate) write_requested: Arc<std::sync::atomic::AtomicBool>,
}

/// Headless clipboard backend: advertises CF_UNICODETEXT, records what the
/// guest offers, surfaces paste results to the session loop via `ClipState`,
/// and flags incoming Format Data Requests so the loop can answer them from
/// `write_pending` (client→guest write direction).
#[derive(Debug)]
pub(crate) struct DriveClipBackend {
    pub(crate) state: ClipState,
}

ironrdp::core::impl_as_any!(DriveClipBackend);

impl CliprdrBackend for DriveClipBackend {
    fn temporary_directory(&self) -> &str {
        // Probe hook: let callers try an absolute Windows-style path
        // (rdpclip may reject a relative temp dir).
        if let Ok(t) = std::env::var("RDPUTIL_CLIP_TMPDIR") {
            return Box::leak(t.into_boxed_str());
        }
        ".cliprdr"
    }

    fn client_capabilities(&self) -> ClipboardGeneralCapabilityFlags {
        ClipboardGeneralCapabilityFlags::empty()
    }

    fn on_ready(&mut self) {
        eprintln!("CLIP ready");
        *self.state.ready.lock().unwrap() = true;
    }

    fn on_request_format_list(&mut self) {
        *self.state.advertise.lock().unwrap() = true;
    }

    fn on_process_negotiated_capabilities(&mut self, capabilities: ClipboardGeneralCapabilityFlags) {
        eprintln!("CLIP server-caps {capabilities:?}");
    }

    fn on_format_list_response(&mut self, ok: bool) {
        eprintln!("CLIP format-list-response ok={ok}");
    }

    fn on_remote_copy(&mut self, available_formats: &[ClipboardFormat]) {
        let ids: Vec<u32> = available_formats.iter().map(|f| f.id.0).collect();
        eprintln!("CLIP remote-formats {ids:?}");
        *self.state.formats.lock().unwrap() = ids;
    }

    fn on_format_data_request(&mut self, _request: FormatDataRequest) {
        // The session loop owns the wire: it polls `write_requested` between
        // pump slices and answers via submit_format_data (serve mode), or
        // leaves the flag set (drive mode has no write direction yet).
        use std::sync::atomic::Ordering;
        eprintln!("CLIP format-data-request (client->guest write path)");
        self.state.write_requested.store(true, Ordering::Relaxed);
    }

    fn on_format_data_response(&mut self, response: FormatDataResponse<'_>) {
        if response.is_error() {
            eprintln!("CLIP paste-error");
            *self.state.response.lock().unwrap() = Some(Err(()));
            return;
        }
        let data = response.data();
        let mut units: Vec<u16> = data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        let text = String::from_utf16_lossy(&units);
        eprintln!("CLIP paste len={}", text.chars().count());
        *self.state.response.lock().unwrap() = Some(Ok(text));
    }

    fn on_file_contents_request(&mut self, _request: FileContentsRequest) {}

    fn on_file_contents_response(&mut self, _response: FileContentsResponse<'_>) {}

    fn on_lock(&mut self, _data_id: LockDataId) {}

    fn on_unlock(&mut self, _data_id: LockDataId) {}
}

/// Sends one slow-path input event as its own secured frame.
pub(crate) fn send_slow_event(
    framed: &mut AnyFramed,
    active_stage: &mut ActiveStage,
    event: &FastPathInputEvent,
) -> anyhow::Result<()> {
    let pdu = ShareDataPdu::Input(InputEventPdu(vec![slow_input_event(event)?]));
    let mut buf = WriteBuf::new();
    active_stage.encode_static(&mut buf, pdu)?;
    framed.write_all(buf.into_inner().as_slice()).context("write slow-path input")?;
    Ok(())
}

/// The four standard text formats, announced nameless. This mirrors the exact
/// Format List shape Windows rdpclip itself broadcasts (flags=0, entry = id +
/// empty UTF-16 name): named entries — however canonical — are acknowledged
/// but registered as empty guest clipboard data with no delayed rendering, so
/// pastes find nothing and no Format Data Request is ever sent. The guest's
/// own text copy produces exactly the group [CF_UNICODETEXT, CF_LOCALE,
/// CF_TEXT, CF_OEMTEXT].
pub(crate) fn golden_text_formats() -> [ClipboardFormat; 4] {
    [
        ClipboardFormat::new(ClipboardFormatId::CF_UNICODETEXT),
        ClipboardFormat::new(ClipboardFormatId::CF_TEXT),
        ClipboardFormat::new(ClipboardFormatId::CF_OEMTEXT),
        ClipboardFormat::new(ClipboardFormatId::CF_LOCALE),
    ]
}

/// Progresses the CLIPRDR initialization: once the server's Monitor Ready has
/// flagged the backend, sends the (empty) Format List advertisement that
/// completes the handshake. Called from the drive loop's pump section.
pub(crate) fn clip_tick(framed: &mut AnyFramed, active_stage: &mut ActiveStage, clip: &ClipState) {
    use std::sync::atomic::Ordering;
    // Probe mode 4: stay silent on init so `cb` can send a bare Format Data
    // Request — tests whether the server responds to ANY client PDU.
    if std::env::var("RDPUTIL_CLIP_MODE").as_deref() == Ok("4") {
        clip.advertised.store(true, Ordering::Relaxed);
        return;
    }
    if clip.advertised.load(Ordering::Relaxed) || !*clip.advertise.lock().unwrap() {
        return;
    }
    // Probe hook: hold the advertisement for N seconds after Monitor Ready
    // (rdpclip may drop client PDUs that arrive during its own init).
    static ARMED: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    if let Ok(secs) = std::env::var("RDPUTIL_CLIP_DELAY") {
        let armed = *ARMED.get_or_init(std::time::Instant::now);
        if armed.elapsed().as_secs() < secs.parse::<u64>().unwrap_or(0) {
            return;
        }
    }
    let (name, msgs) = {
        let Some(actor) = active_stage.get_svc_processor_mut::<CliprdrClient>() else {
            return;
        };
        let name = actor.channel_name();
        // Advertise the standard text formats even though we hold no local
        // clipboard content yet: an empty list is ignored by Windows servers
        // (no Format List Response ever arrives, so the channel never turns
        // Ready), and named entries get registered as empty guest clipboard
        // data instead of delayed-rendered formats (see golden_text_formats).
        // A guest paste before any clipboard_set is answered with a failed
        // Format Data Response, mirroring an empty clipboard.
        let synthetic = golden_text_formats();
        match actor.initiate_copy(&synthetic) {
            Ok(msgs) => (name, msgs),
            Err(e) => {
                eprintln!("CLIP initiate_copy failed: {e}");
                return;
            }
        }
    };
    // Windows rdpclip (field-observed) goes silent when several
    // virtual-channel PDUs of the init bundle arrive coalesced in one TCP
    // segment; each PDU must be its own segment, so default to a 500ms gap.
    let stagger = std::env::var("RDPUTIL_CLIP_STAGGER")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(500);
    let msgs: Vec<_> = msgs.into();
    for m in msgs {
        let frame = match active_stage.process_svc_messages_by_name(&name, vec![m]) {
            Ok(frame) => frame,
            Err(e) => {
                eprintln!("CLIP encode failed: {e}");
                return;
            }
        };
        if let Err(e) = framed.write_all(frame.as_slice()) {
            eprintln!("CLIP send failed: {e}");
            return;
        }
        if stagger > 0 {
            std::thread::sleep(Duration::from_millis(stagger));
        }
    }
    clip.advertised.store(true, Ordering::Relaxed);
    eprintln!("CLIP advertised");
}

/// Interactive one-connection drive loop (RDPUTIL_DRIVE=1). Command grammar
/// (whitespace-separated, one per line, `#` comments allowed):
///   c X Y     left click       r X Y     right click      m X Y   move
///   k 0xNN    tap key          kd 0xNN / ku 0xNN  key down / up
///   ke 0xNN   tap extended key (0xE0-prefixed scancode, e.g. Win=0x5b)
///   w MS      wait (keeps pumping server deltas)
///   s NAME    save current framebuffer to NAME.png (forces a full repaint
///             first when RDPUTIL_FORCE_REFRESH=1)
///   S NAME    stable save: wait until the framebuffer is effectively static
///             (RDPUTIL_STABLE_N consecutive 250ms pump slices whose pixel
///             diff vs the reference frame is within RDPUTIL_STABLE_TOL_PX,
///             default 64) so late deltas land in the PNG; saves anyway after
///             RDPUTIL_STABLE_TIMEOUT_MS (default 10000) so animated screens
///             (game timers) cannot hang the pipeline
///   cb        read guest clipboard text (CF_UNICODETEXT) over CLIPRDR;
///             prints CLIP begin / lines / CLIP end (needs RDPUTIL_CLIPRDR=1
///             so the channel is attached at connect time)
///   resize W H  dynamic resolution change (MS-RDPEDISP): sends a single-
///             monitor Monitor Layout over the Display Control DVC and pumps
///             through the server's Deactivation-Reactivation Sequence, which
///             carries the new desktop size (needs RDPUTIL_DISP=1 at connect
///             time; spec bounds 200..=8192, width even)
///   q         graceful exit
fn drive_loop(
    framed: &mut AnyFramed,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    rx: &std::sync::mpsc::Receiver<String>,
    clip: Option<&ClipState>,
    activation: &ConnectionActivationFactory,
) -> anyhow::Result<()> {
    eprintln!("DRIVE ready");

    let force_refresh = std::env::var("RDPUTIL_FORCE_REFRESH").as_deref() == Ok("1");
    loop {
        // Keep the wire moving in 250 ms slices so deltas land between commands.
        pump_until(framed, active_stage, image, Instant::now() + Duration::from_millis(250), Some(activation))?;
        if let Some(clip) = clip {
            clip_tick(framed, active_stage, clip);
        }

        while let Ok(raw) = rx.try_recv() {
            let line = raw.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tok: Vec<&str> = line.split_whitespace().collect();
            let res: anyhow::Result<()> = (|| {
                match tok.as_slice() {
                    ["c", x, y] | ["r", x, y] | ["m", x, y] => {
                        let (x, y) = (x.parse::<u16>()?, y.parse::<u16>()?);
                        let pdu = |flags: PointerFlags| {
                            FastPathInputEvent::MouseEvent(MousePdu {
                                flags,
                                number_of_wheel_rotation_units: 0,
                                x_position: x,
                                y_position: y,
                            })
                        };
                        let fast = std::env::var("RDPUTIL_FAST_MOUSE").as_deref() == Ok("1");
                        send_input_event(framed, active_stage, image, &pdu(PointerFlags::MOVE), 150, fast)?;
                        if tok[0] != "m" {
                            let (down, up) = match tok[0] {
                                "c" => (PointerFlags::LEFT_BUTTON | PointerFlags::DOWN, PointerFlags::LEFT_BUTTON),
                                _ => (PointerFlags::RIGHT_BUTTON | PointerFlags::DOWN, PointerFlags::RIGHT_BUTTON),
                            };
                            send_input_event(framed, active_stage, image, &pdu(down), 150, fast)?;
                            send_input_event(framed, active_stage, image, &pdu(up), 150, fast)?;
                        }
                        Ok(())
                    }
                    ["k", sc] | ["kd", sc] | ["ku", sc] | ["ke", sc] => {
                        let sc = sc.parse::<u8>()?;
                        let fast = std::env::var("RDPUTIL_FAST_KB").as_deref() == Ok("1");
                        let flags = |rel: bool, ext: bool| {
                            let mut f = KeyboardFlags::empty();
                            if rel {
                                f |= KeyboardFlags::RELEASE;
                            }
                            if ext {
                                f |= KeyboardFlags::EXTENDED;
                            }
                            f
                        };
                        match tok[0] {
                            "k" | "ke" => {
                                let ext = tok[0] == "ke";
                                send_input_event(framed, active_stage, image, &FastPathInputEvent::KeyboardEvent(flags(false, ext), sc), 80, fast)?;
                                send_input_event(framed, active_stage, image, &FastPathInputEvent::KeyboardEvent(flags(true, ext), sc), 80, fast)?;
                            }
                            "kd" => send_input_event(framed, active_stage, image, &FastPathInputEvent::KeyboardEvent(flags(false, false), sc), 80, fast)?,
                            _ => send_input_event(framed, active_stage, image, &FastPathInputEvent::KeyboardEvent(flags(true, false), sc), 80, fast)?,
                        }
                        Ok(())
                    }
                    ["w", ms] => {
                        let ms = ms.parse::<u64>()?;
                        pump_until(framed, active_stage, image, Instant::now() + Duration::from_millis(ms), Some(activation))?;
                        Ok(())
                    }
                    ["resize", w, h] => {
                        // Dynamic resolution (MS-RDPEDISP): single-monitor
                        // Monitor Layout over the Display Control DVC. The
                        // server applies it and answers with a Deactivation-
                        // Reactivation Sequence carrying the new desktop size;
                        // pump_until runs that inline and rebuilds the
                        // framebuffer. Bounds per 2.2.2.2.1: 200..=8192 px,
                        // width must be even.
                        let w = w.parse::<u32>()?.clamp(200, 8192) & !1;
                        let h = h.parse::<u32>()?.clamp(200, 8192);
                        match active_stage.encode_resize(w, h, None, None) {
                            Some(Ok(frame)) => {
                                framed.write_all(frame.as_slice()).context("write resize")?;
                                eprintln!("RESIZE sent {w}x{h}; pumping for reactivation");
                                let deadline = Instant::now() + Duration::from_secs(10);
                                pump_until(framed, active_stage, image, deadline, Some(activation))?;
                                eprintln!("RESIZE now {}x{}", image.width(), image.height());
                            }
                            Some(Err(e)) => eprintln!("RESIZE encode failed: {e:#}"),
                            None => eprintln!("RESIZE unavailable (restart with RDPUTIL_DISP=1?)"),
                        }
                        Ok(())
                    }
                    ["s", name] => {
                        if force_refresh {
                            let mut frame = WriteBuf::new();
                            active_stage
                                .encode_static(
                                    &mut frame,
                                    ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                                        areas_to_refresh: vec![InclusiveRectangle {
                                            left: 0,
                                            top: 0,
                                            right: u16::try_from(image.width().saturating_sub(1))?,
                                            bottom: u16::try_from(image.height().saturating_sub(1))?,
                                        }],
                                    }),
                                )
                                .context("encode refresh rect")?;
                            framed.write_all(frame.into_inner().as_slice()).context("write refresh rect")?;
                            pump_until(framed, active_stage, image, Instant::now() + Duration::from_millis(600), Some(activation))?;
                        }
                        let path = PathBuf::from(format!("{name}.png"));
                        let data = image.data().to_vec();
                        let img: image::ImageBuffer<image::Rgba<u8>, _> = image::ImageBuffer::from_raw(
                            u32::from(image.width()),
                            u32::from(image.height()),
                            data,
                        )
                        .context("invalid image")?;
                        img.save(&path).context("save drive frame")?;
                        eprintln!("SAVED {}", path.display());
                        Ok(())
                    }
                    ["S", name] => {
                        // Stable save: wait until the framebuffer is
                        // *effectively* static — N consecutive 250ms pump
                        // slices whose pixel diff vs the reference frame is
                        // within tolerance — so late-arriving deltas from the
                        // last input land in the PNG. Exact-hash equality is
                        // unreachable on real desktops: the taskbar clock
                        // repaints a handful of pixels every second, and idle
                        // slices last as long as the socket read timeout.
                        // Tiny diffs (clock, caret blink) are absorbed by the
                        // tolerance; anything larger resets the run and
                        // becomes the new reference. Saves anyway after a
                        // timeout so animated screens (game timers) cannot
                        // hang the pipeline forever — the root cause of a
                        // stale-frame "unopened=0" misread, now
                        // handled protocol-side instead of guessed in python.
                        let n = std::env::var("RDPUTIL_STABLE_N")
                            .ok()
                            .and_then(|v| v.parse::<u32>().ok())
                            .unwrap_or(3)
                            .max(1);
                        let timeout_ms = std::env::var("RDPUTIL_STABLE_TIMEOUT_MS")
                            .ok()
                            .and_then(|v| v.parse::<u64>().ok())
                            .unwrap_or(10000);
                        let tol_px = std::env::var("RDPUTIL_STABLE_TOL_PX")
                            .ok()
                            .and_then(|v| v.parse::<usize>().ok())
                            .unwrap_or(64);
                        // Thin slices: with the default 1s socket read
                        // timeout an idle pump blocks for the full second,
                        // so the 250ms deadline alone cannot bound the slice
                        // duration (and always straddles a clock tick).
                        let _ = framed.get_inner_mut().0.set_read_timeout(Some(Duration::from_millis(100)));
                        let start = Instant::now();
                        let mut reference = image.data().to_vec();
                        let mut last = frame_hash(image);
                        let mut run = 0u32;
                        loop {
                            if start.elapsed().as_millis() as u64 >= timeout_ms {
                                eprintln!("STABLE timeout elapsed={}ms run={run}", start.elapsed().as_millis());
                                break;
                            }
                            pump_until(framed, active_stage, image, Instant::now() + Duration::from_millis(250), Some(activation))?;
                            let h = frame_hash(image);
                            let data = image.data();
                            let diff = if h == last {
                                0
                            } else {
                                last = h;
                                data.chunks_exact(4)
                                    .zip(reference.chunks_exact(4))
                                    .filter(|(p, r)| {
                                        p[0].abs_diff(r[0]) > 10
                                            || p[1].abs_diff(r[1]) > 10
                                            || p[2].abs_diff(r[2]) > 10
                                    })
                                    .count()
                            };
                            if diff <= tol_px {
                                run += 1;
                            } else {
                                eprintln!("STABLE reset diff={diff}");
                                reference = data.to_vec();
                                run = 1;
                            }
                            if run >= n {
                                eprintln!("STABLE stable run={run} elapsed={}ms", start.elapsed().as_millis());
                                break;
                            }
                        }
                        let path = PathBuf::from(format!("{name}.png"));
                        let data = image.data().to_vec();
                        let img: image::ImageBuffer<image::Rgba<u8>, _> = image::ImageBuffer::from_raw(
                            u32::from(image.width()),
                            u32::from(image.height()),
                            data,
                        )
                        .context("invalid image")?;
                        img.save(&path).context("save drive frame")?;
                        eprintln!("SAVED {}", path.display());
                        Ok(())
                    }
                    ["cb"] => {
                        // Read the guest clipboard as text. Blocks until the
                        // CLIPRDR handshake completes on first use, then sends
                        // a Format Data Request for CF_UNICODETEXT and prints
                        // the response between CLIP begin / CLIP end markers.
                        let Some(clip) = clip else {
                            anyhow::bail!("cliprdr disabled (restart with RDPUTIL_CLIPRDR=1)");
                        };
                        let force = std::env::var("RDPUTIL_CLIP_MODE").as_deref() == Ok("4");
                        let start = Instant::now();
                        while !*clip.ready.lock().unwrap() {
                            if force {
                                break;
                            }
                            if start.elapsed().as_millis() > 8000 {
                                anyhow::bail!("CLIP notready");
                            }
                            clip_tick(framed, active_stage, clip);
                            pump_until(framed, active_stage, image, Instant::now() + Duration::from_millis(250), Some(activation))?;
                        }
                        if !force {
                            let formats = clip.formats.lock().unwrap().clone();
                            if !formats.contains(&ClipboardFormatId::CF_UNICODETEXT.0) {
                                eprintln!("CLIP none formats={formats:?}");
                                return Ok(());
                            }
                        }
                        *clip.response.lock().unwrap() = None;
                        let (name, msgs) = {
                            let Some(actor) = active_stage.get_svc_processor_mut::<CliprdrClient>() else {
                                anyhow::bail!("CLIP channel missing");
                            };
                            let name = actor.channel_name();
                            let msgs =
                                actor.initiate_paste(ClipboardFormatId::CF_UNICODETEXT).context("initiate_paste")?;
                            (name, msgs)
                        };
                        let frame = active_stage
                            .process_svc_messages_by_name(&name, msgs.into())
                            .context("clip format data request")?;
                        framed.write_all(frame.as_slice()).context("clip write")?;
                        let start = Instant::now();
                        loop {
                            if let Some(res) = clip.response.lock().unwrap().take() {
                                match res {
                                    Ok(text) => {
                                        eprintln!("CLIP begin");
                                        for line in text.lines() {
                                            eprintln!("{line}");
                                        }
                                        eprintln!("CLIP end");
                                    }
                                    Err(()) => eprintln!("CLIP error"),
                                }
                                return Ok(());
                            }
                            if start.elapsed().as_millis() > 5000 {
                                anyhow::bail!("CLIP timeout");
                            }
                            pump_until(framed, active_stage, image, Instant::now() + Duration::from_millis(250), Some(activation))?;
                        }
                    }
                    ["q"] => {
                        // Graceful hang-up: without the ultimatum the server waits
                        // out a transport timeout before releasing the session.
                        let _ = send_goodbye(framed);
                        anyhow::bail!("__quit__")
                    }
                    _ => anyhow::bail!("unknown command"),
                }
            })();
            match res {
                Ok(()) => eprintln!("DONE {line}"),
                Err(e) => {
                    if format!("{:#}", e).contains("__quit__") {
                        eprintln!("DRIVE bye");
                        return Ok(());
                    }
                    eprintln!("FAIL {line}: {e:#}");
                }
            }
        }
    }
}

/// Sends one mouse event in drive mode with the inter-event gap the XP server
/// was field-proven to accept. Zero-gap slow-path bursts (MOVE+DOWN+UP written
/// back-to-back) drew an "invalid input messageType" alert + 10054 reset, while
/// the same events spaced ~150 ms apart (as --seq does with --event-delay-ms)
/// worked on both msgina and the live desktop. RDPUTIL_FAST_MOUSE=1 routes
/// through fast-path instead as a fallback experiment.
pub(crate) fn send_input_event(
    framed: &mut AnyFramed,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    event: &FastPathInputEvent,
    gap_ms: u64,
    fast: bool,
) -> anyhow::Result<()> {
    if fast {
        let outputs = active_stage.process_fastpath_input(image, std::slice::from_ref(event))?;
        for out in outputs {
            if let ActiveStageOutput::ResponseFrame(frame) = out {
                framed.write_all(&frame)?;
            }
        }
    } else {
        send_slow_event(framed, active_stage, event)?;
    }
    std::thread::sleep(Duration::from_millis(gap_ms));
    Ok(())
}

pub(crate) fn pump_until(
    framed: &mut AnyFramed,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    deadline: Instant,
    activation: Option<&ConnectionActivationFactory>,
) -> anyhow::Result<bool> {
    'pump: loop {
        if Instant::now() >= deadline {
            return Ok(false);
        }

        // RAIL housekeeping runs before the read, not after: on a quiet wire
        // the read below times out every iteration, and a release scheduled
        // at the loop bottom would only ever run when other traffic happened
        // to arrive — the queued launch would wait forever.
        rail_service(framed, active_stage)?;

        let (action, payload) = match framed.read_pdu() {
            Ok((action, payload)) => (action, payload),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
            Err(e) => return Err(anyhow::Error::new(e).context("read frame")),
        };

        trace!(?action, frame_length = payload.len(), "Frame received");

        let outputs = match active_stage.process(image, action, &payload) {
            Ok(outputs) => outputs,
            Err(e) => {
                // Legacy Windows servers emit PDUs we may not parse; keep the session alive.
                warn!(frame_length = payload.len(), ?action, error_chain = %format!("{:#}", e), "Skipping undecodable frame");
                let hex: String = payload.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
                warn!(frame_hex = %hex, "Undecodable frame payload");
                continue;
            }
        };

        for out in outputs {
            match out {
                ActiveStageOutput::ResponseFrame(frame) => framed.write_all(&frame).context("write response")?,
                ActiveStageOutput::Terminate(reason) => {
                    // XP sends Share Control PDUs whose type IronRDP cannot decode
                    // right after finalization; the session layer surfaces those as
                    // Terminate. Treating that as a real shutdown ended the session
                    // ~15 ms after activation (before a single bitmap arrived).
                    // Keep pumping; a genuine disconnect shows up as a socket error.
                    //
                    // A genuine disconnect is exactly what the ultimatum-based
                    // reasons are: the server hangs up right after, so acknowledge
                    // it with our own ultimatum (the [MS-RDPBCGR] graceful
                    // disconnect handshake). Skipping the reply leaves the server
                    // WinStation in its disconnect-transition state until a
                    // transport timeout expires, during which reconnect attempts
                    // are rejected with a "terminal is busy" error.
                    if matches!(
                        reason,
                        GracefulDisconnectReason::UserInitiated | GracefulDisconnectReason::ServerInitiated
                    ) {
                        match send_goodbye(framed) {
                            Ok(()) => info!("GOODBYE sent"),
                            Err(e) => warn!(error = %format!("{e:#}"), "GOODBYE failed"),
                        }
                        // RemoteApp lifecycle: after a successful EXEC the
                        // server tears the session down when the app's last
                        // window closes. That shutdown is the expected episode
                        // boundary — end the pump on it instead of riding
                        // through to the socket error.
                        if RAIL_EXEC_OK.load(Ordering::Relaxed) {
                            eprintln!("APP_SESSION_ENDED");
                            return Ok(true);
                        }
                    }
                    warn!(?reason, "Server requested terminate; ignoring and continuing");
                    continue 'pump;
                }
                ActiveStageOutput::DeactivateAll => {
                    // Deactivation-Reactivation Sequence (MS-RDPBCGR 1.3.1.3):
                    // after a display-control Monitor Layout request the server
                    // deactivates the share and re-runs activation, carrying the
                    // NEW desktop size in its Demand Active PDU. Some servers skip
                    // the Deactivate-All and just re-send the Demand Active PDU
                    // mid-session; the session layer intercepts that and surfaces
                    // it as DeactivateAll with the frame stashed for pickup.
                    let Some(factory) = activation else {
                        eprintln!("DEACTIVATE ignored (no activation factory; drive mode only)");
                        continue 'pump;
                    };
                    let preseed = active_stage.take_pending_demand_active();
                    run_reactivation(framed, active_stage, image, factory, preseed)?;
                }
                ActiveStageOutput::AutoReconnectCookie(cookie) => {
                    if let Ok(path) = std::env::var("RDPUTIL_COOKIE_OUT") {
                        let mut buf = vec![0u8; ironrdp_pdu::Encode::size(&cookie)];
                        let mut cur = ironrdp_pdu::cursor::WriteCursor::new(&mut buf);
                        match ironrdp_pdu::Encode::encode(&cookie, &mut cur) {
                            Ok(()) => {
                                let _ = std::fs::write(&path, &buf);
                                println!("COOKIE SAVED logon_id={} bytes={}", cookie.logon_id, buf.len());
                            }
                            Err(e) => eprintln!("cookie encode failed: {e}"),
                        }
                    }
                }
                _ => {}
            }
        }

        // rdpdr backends complete file IO on worker threads; their responses
        // leave the processor only when polled. Drain them every slice so
        // guest file operations never stall between pump iterations.
        poll_rdpdr(framed, active_stage)?;
    }
}

/// Reads an env knob, trimming and treating blank as unset.
fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

/// RemoteApp requested via RDPUTIL_REMOTE_APP (RAIL session mode).
pub(crate) fn remote_app_requested() -> bool {
    non_empty_env("RDPUTIL_REMOTE_APP").is_some()
}

/// Session mode reported to the gateway's state op.
pub(crate) fn session_mode() -> &'static str {
    if remote_app_requested() {
        "remoteapp"
    } else if non_empty_env("RDPUTIL_ALT_SHELL").is_some() {
        "altshell"
    } else {
        "desktop"
    }
}

/// Program name of the requested app-scoped session, for state reporting.
pub(crate) fn remote_app_label() -> String {
    non_empty_env("RDPUTIL_REMOTE_APP")
        .or_else(|| non_empty_env("RDPUTIL_ALT_SHELL"))
        .unwrap_or_default()
}

/// Verdict of the current session's RAIL EXEC order, for state reporting.
pub(crate) fn rail_exec_verdict() -> &'static str {
    if RAIL_EXEC_OK.load(Ordering::Relaxed) {
        "ok"
    } else if RAIL_EXEC_FAILED.load(Ordering::Relaxed) {
        "failed"
    } else {
        "none"
    }
}

/// Clears the EXEC verdicts of the previous session: every fresh session
/// starts with none, so an app exit can only ever refer to the current app.
pub(crate) fn rail_reset() {
    RAIL_EXEC_OK.store(false, Ordering::Relaxed);
    RAIL_EXEC_FAILED.store(false, Ordering::Relaxed);
    RAIL_WINDOW.store(0, Ordering::Relaxed);
    *RAIL_RELEASE.lock().unwrap() = None;
    *RAIL_ACTIVATE.lock().unwrap() = None;
    RAIL_PROBE.lock().unwrap().clear();
    RAIL_PROBED.lock().unwrap().clear();
}

/// Queues the RemoteApp EXEC order right after activation. The RAIL processor
/// holds the order until the server handshake completes, then rail_service
/// releases it. Call once per fresh session — a reconnect must not launch a
/// second app instance.
pub(crate) fn rail_kickoff(active_stage: &mut ActiveStage, framed: &mut AnyFramed) -> anyhow::Result<()> {
    let Some(program) = non_empty_env("RDPUTIL_REMOTE_APP") else {
        return Ok(());
    };
    rail_reset();
    let pdu = ExecutePdu {
        flags: 0,
        executable: program,
        working_directory: non_empty_env("RDPUTIL_REMOTE_APP_WORKDIR").unwrap_or_default(),
        arguments: non_empty_env("RDPUTIL_REMOTE_APP_ARGS").unwrap_or_default(),
    };
    eprintln!("RAIL EXEC queued exe={}", pdu.executable);
    let (name, messages) = {
        let processor = active_stage
            .get_svc_processor_mut::<RailClient>()
            .context("RAIL channel missing: the server refused the RAIL capability")?;
        let messages = processor
            .queue_execute(pdu)
            .map_err(|e| anyhow::anyhow!("queue RAIL EXEC: {e}"))?;
        (processor.channel_name(), messages)
    };
    // While queued the launch emits no bytes; a non-empty batch means the
    // channel was already established (not expected this early) — flush anyway.
    let messages: Vec<SvcMessage> = messages.into();
    if !messages.is_empty() {
        let frame = active_stage
            .process_svc_messages_by_name(&name, messages)
            .context("encode RAIL EXEC")?;
        framed.write_all(frame.as_slice()).context("write RAIL EXEC")?;
    }
    Ok(())
}

/// Per-iteration RAIL housekeeping inside the pump loop: drain processor
/// events, record EXEC results, and release the queued launch a beat after
/// the server handshake. The desktop client releases when its window is
/// ready; headless there is no window, so a fixed grace stands in (the same
/// 250 ms deadline upstream uses). No-op unless a RemoteApp session was
/// requested.
fn rail_service(framed: &mut AnyFramed, active_stage: &mut ActiveStage) -> anyhow::Result<()> {
    let events = match active_stage.get_svc_processor_mut::<RailClient>() {
        Some(processor) => processor.take_events(),
        None => return Ok(()),
    };
    for event in events {
        match event {
            RailEvent::Handshake { queued_execute_count, .. } => {
                eprintln!("RAIL handshake queued_executes={queued_execute_count}");
                *RAIL_RELEASE.lock().unwrap() = Some(Instant::now() + Duration::from_millis(250));
            }
            RailEvent::ExecuteResult(result) => {
                let ok = result.result == ExecuteResult::Ok;
                eprintln!(
                    "RAIL EXEC_RESULT result={:?} raw={} exe={}",
                    result.result, result.raw_result, result.executable
                );
                if ok {
                    RAIL_EXEC_OK.store(true, Ordering::Relaxed);
                } else {
                    RAIL_EXEC_FAILED.store(true, Ordering::Relaxed);
                }
            }
            RailEvent::Control(RailControlEvent::MinMaxInfo(info)) => {
                if RAIL_EXEC_OK.load(Ordering::Relaxed) && info.window_id != 0 {
                    // Activate once per session: the server re-reports MinMaxInfo
                    // periodically, and re-arming here would loop forever.
                    let mut pending = RAIL_ACTIVATE.lock().unwrap();
                    if pending.is_none() && RAIL_WINDOW.load(Ordering::Relaxed) == 0 {
                        *pending = Some(info.window_id);
                    }
                    drop(pending);
                    let mut probed = RAIL_PROBED.lock().unwrap();
                    if !probed.contains(&info.window_id) {
                        probed.push(info.window_id);
                        RAIL_PROBE.lock().unwrap().push(info.window_id);
                    }
                }
            }
            RailEvent::ApplicationId { window_id, application_id, process_id, process_image_name } => {
                eprintln!(
                    "RAIL appid window={window_id} app={application_id} pid={:?} image={:?}",
                    process_id, process_image_name
                );
            }
            _ => {}
        }
    }
    let (name, messages) = match active_stage.get_svc_processor_mut::<RailClient>() {
        Some(processor) => {
            let due = RAIL_RELEASE.lock().unwrap().is_some_and(|at| Instant::now() >= at);
            let mut messages: Vec<SvcMessage> = if due {
                *RAIL_RELEASE.lock().unwrap() = None;
                processor
                    .release_queued_after_handshake()
                    .map_err(|e| anyhow::anyhow!("release queued RAIL: {e}"))?
                    .into()
            } else {
                Vec::new()
            };
            if let Some(window_id) = RAIL_ACTIVATE.lock().unwrap().take() {
                RAIL_WINDOW.store(window_id, Ordering::Relaxed);
                eprintln!("RAIL activate window={window_id}");
                let activate: Vec<SvcMessage> = processor
                    .queue_input(RailInputEvent::Activate(ActivatePdu { window_id, enabled: true }))
                    .map_err(|e| anyhow::anyhow!("queue RAIL activate: {e}"))?
                    .into();
                messages.extend(activate);
            }
            for probe_id in RAIL_PROBE.lock().unwrap().drain(..) {
                let probe: Vec<SvcMessage> = processor
                    .queue_input(RailInputEvent::GetApplicationId(GetApplicationIdRequestPdu { window_id: probe_id }))
                    .map_err(|e| anyhow::anyhow!("queue RAIL appid probe: {e}"))?
                    .into();
                messages.extend(probe);
            }
            (processor.channel_name(), messages)
        }
        None => return Ok(()),
    };
    if !messages.is_empty() {
        eprintln!("RAIL release sent messages={}", messages.len());
        let frame = active_stage
            .process_svc_messages_by_name(&name, messages)
            .context("encode RAIL release")?;
        framed.write_all(frame.as_slice()).context("write RAIL release")?;
    }
    Ok(())
}

/// Drains deferred rdpdr responses (backend worker threads answering file IO)
/// and sends them on the wire. No-op unless the rdpdr channel is registered.
fn poll_rdpdr(framed: &mut AnyFramed, active_stage: &mut ActiveStage) -> anyhow::Result<()> {
    let (name, msgs) = {
        let Some(actor) = active_stage.get_svc_processor_mut::<ironrdp::rdpdr::Rdpdr>() else {
            return Ok(());
        };
        let name = actor.channel_name();
        let msgs = actor.poll_deferred_messages()?;
        (name, msgs)
    };
    if msgs.is_empty() {
        return Ok(());
    }
    eprintln!("RDPDRTX count={}", msgs.len());
    let frame = active_stage.process_svc_messages_by_name(&name, msgs.into())?;
    framed.write_all(frame.as_slice()).context("write rdpdr response")?;
    Ok(())
}

/// Sends the MCS Disconnect Provider Ultimatum that hangs up a session the
/// way the protocol's graceful disconnect is defined. The server releases the
/// WinStation as soon as it arrives; an abrupt socket close instead leaves the
/// terminal in its disconnect-transition state for a long while, during which
/// reconnect attempts are rejected as busy.
fn send_goodbye(framed: &mut AnyFramed) -> anyhow::Result<()> {
    let pdu = X224(McsMessage::DisconnectProviderUltimatum(
        DisconnectProviderUltimatum::from_reason(DisconnectReason::UserRequested),
    ));
    let mut buf = vec![0u8; ironrdp_pdu::Encode::size(&pdu)];
    let mut cur = ironrdp_pdu::cursor::WriteCursor::new(&mut buf);
    ironrdp_pdu::Encode::encode(&pdu, &mut cur).map_err(|e| anyhow::anyhow!("encode goodbye: {e}"))?;
    framed.write_all(&buf).context("write goodbye")
}

/// Drives the Deactivation-Reactivation Sequence inline (MS-RDPBCGR 1.3.1.3):
/// steps the activation sequence over the raw wire — Sync/Cooperate/Font List/
/// Font List PDU — until Finalized, then rebuilds the fast-path processor with
/// the new share_id and the framebuffer with the new desktop size. The Display
/// Control DVC lives on the DRDYNVC static channel and survives deactivation.
///
/// `preseed` is an already-received Demand Active PDU frame (decrypted, its
/// receive cipher stream already advanced) to feed to the fresh sequence before
/// reading further frames from the wire.
fn run_reactivation(
    framed: &mut AnyFramed,
    active_stage: &mut ActiveStage,
    image: &mut DecodedImage,
    factory: &ConnectionActivationFactory,
    mut preseed: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    eprintln!("DEACTIVATE reactivation begin preseed={}", preseed.is_some());
    framed.get_inner_mut().0.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut seq = factory.create();
    let mut buf = WriteBuf::new();
    loop {
        buf.clear();
        let written = if seq.next_pdu_hint().is_some() {
            // Read through the same demux as the main pump: between
            // Deactivate-All and Demand Active the server keeps streaming
            // (encrypted) fast-path updates, and every received frame must
            // advance the receive cipher stream or all later decryptions
            // desync. read_by_hint alone would hand the sequence raw
            // ciphertext, so decrypt through the stage first.
            let payload = if let Some(frame) = preseed.take() {
                frame
            } else {
                let (action, payload) = loop {
                    match framed.read_pdu() {
                        Ok(ok) => break ok,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => continue,
                        Err(e) => return Err(anyhow::Error::new(e).context("read reactivation frame")),
                    }
                };
                let payload = active_stage
                    .decrypt_inbound_frame(action, &payload)
                    .map_err(|e| anyhow::Error::new(e).context("decrypt reactivation frame"))?;
                if !matches!(action, ironrdp_pdu::Action::X224) {
                    // Graphics/pointer update mid-reactivation: the cipher stream
                    // stays in sync, the PDU itself is not part of the sequence.
                    continue;
                }
                payload.into_owned()
            };
            seq.step(&payload, framed.last_read_at(), &mut buf)?
        } else {
            seq.step_no_input(&mut buf)?
        };
        if let Some(len) = written.size() {
            // Sequence output bypasses ActiveStage::process, so the security
            // envelope must be applied here: post-activation, the server
            // drops the connection on unencrypted client PDUs.
            let secured = active_stage.secure_outgoing_frame(buf[..len].to_vec())?;
            framed.write_all(&secured).context("write reactivation pdu")?;
        }
        if let ConnectionActivationState::Finalized {
            desktop_size,
            share_id,
            enable_server_pointer,
            pointer_software_rendering,
            static_channel_chunk_size,
            ..
        } = seq.connection_activation_state()
        {
            let (w, h) = (desktop_size.width, desktop_size.height);
            if !active_stage.reactivate(
                factory.io_channel_id(),
                factory.user_channel_id(),
                share_id,
                enable_server_pointer,
                pointer_software_rendering,
                static_channel_chunk_size,
            ) {
                anyhow::bail!("invalid static channel chunk size on reactivation");
            }
            *image = DecodedImage::new(image.pixel_format(), w, h);
            framed.get_inner_mut().0.set_read_timeout(Some(Duration::from_secs(1)))?;
            eprintln!("REACTIVATE done share_id={share_id:#x} desktop={w}x{h}");
            return Ok(());
        }
    }
}

fn lookup_addr(hostname: &str, port: u16) -> anyhow::Result<core::net::SocketAddr> {
    use std::net::ToSocketAddrs as _;
    let addr = (hostname, port)
        .to_socket_addrs()?
        .next()
        .context("socket address not found")?;
    Ok(addr)
}

fn tls_upgrade(
    stream: TcpStream,
    server_name: String,
) -> anyhow::Result<(rustls::StreamOwned<rustls::ClientConnection, TcpStream>, Vec<u8>)> {
    let mut config = rustls::client::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(danger::NoCertificateVerification))
        .with_no_client_auth();

    // This adds support for the SSLKEYLOGFILE env variable (https://wiki.wireshark.org/TLS#using-the-pre-master-secret)
    config.key_log = std::sync::Arc::new(rustls::KeyLogFile::new());

    // Disable TLS resumption because it’s not supported by some services such as CredSSP.
    //
    // > The CredSSP Protocol does not extend the TLS wire protocol. TLS session resumption is not supported.
    //
    // source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c
    config.resumption = rustls::client::Resumption::disabled();

    let config = std::sync::Arc::new(config);

    let server_name = server_name.try_into()?;

    let client = rustls::ClientConnection::new(config, server_name)?;

    let mut tls_stream = rustls::StreamOwned::new(client, stream);

    // We need to flush in order to ensure the TLS handshake is moving forward. Without flushing,
    // it’s likely the peer certificate is not yet received a this point.
    tls_stream.flush()?;

    let cert = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .context("peer certificate is missing")?;

    let server_public_key = extract_tls_server_public_key(cert)?;

    Ok((tls_stream, server_public_key))
}

fn extract_tls_server_public_key(cert: &[u8]) -> anyhow::Result<Vec<u8>> {
    use x509_cert::der::Decode as _;

    let cert = x509_cert::Certificate::from_der(cert)?;

    debug!(subject = %cert.tbs_certificate().subject());

    let server_public_key = cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .as_bytes()
        .context("subject public key BIT STRING is not aligned")?
        .to_owned();

    Ok(server_public_key)
}

fn build_config(
    username: String,
    password: String,
    domain: Option<String>,
    compression_enabled: bool,
    compression_level: u32,
) -> anyhow::Result<connector::Config> {
    let compression_type = if compression_enabled {
        Some(compression_type_from_level(compression_level)?)
    } else {
        None
    };

    // RDPUTIL_SSL=1: TLS-only transport, no CredSSP/NLA. Credentials ride in
    // the Client Info PDU. Needed against servers whose CredSSP branch hangs.
    let ssl_only = std::env::var("RDPUTIL_SSL").as_deref() == Ok("1");
    // RDPUTIL_LEGACY_CLIENT=1: advertise a Client Info PDU indistinguishable
    // from a Windows 2000/XP-era client — the compact RDP 5.x flag set (no
    // LOGON_NOTIFY / LOGON_ERRORS / MOUSE_HAS_WHEEL / NO_AUDIO_PLAYBACK) and
    // a clientBuild of 2600. Legacy winlogon copies these fields into the
    // WINSTATIONCLIENT structure it consults when starting the user desktop.
    let legacy_client = std::env::var("RDPUTIL_LEGACY_CLIENT").as_deref() == Ok("1");
    // Session mode knobs (desktop mode when both unset):
    // RDPUTIL_REMOTE_APP=<program> (+ _ARGS, _WORKDIR): RemoteApp — the
    // connector sets INFO_RAIL and the "rail" channel carries the launch as an
    // EXEC order (rail_kickoff); the session ends when the app exits.
    // RDPUTIL_ALT_SHELL=<program> (+ _WORKDIR): the program replaces the
    // desktop shell via the Client Info PDU alternate-shell field — the
    // pre-RAIL mechanism that also reaches RDP 5.x servers.
    let remote_app = non_empty_env("RDPUTIL_REMOTE_APP").is_some();
    // mstsc fills the Client Info PDU alternate-shell field with rdpinit.exe
    // in RemoteApp mode, and legacy (pre-Win8) servers only enter the
    // RemoteApp flow when the session shell is rdpinit.exe; a blank field
    // makes their EXEC orders silently no-op. An explicit RDPUTIL_ALT_SHELL
    // overrides it.
    let alt_shell = non_empty_env("RDPUTIL_ALT_SHELL")
        .or_else(|| remote_app.then(|| "rdpinit.exe".to_string()));
    if remote_app && legacy_client {
        eprintln!("WARN RDPUTIL_REMOTE_APP with RDPUTIL_LEGACY_CLIENT: the legacy Info PDU flag set predates RAIL");
    }
    Ok(connector::Config {
        credentials: Credentials::UsernamePassword { username, password },
        domain,
        enable_tls: if ssl_only { true } else { std::env::var("RDPUTIL_CREDSSP").as_deref() == Ok("1") },
        enable_credssp: if ssl_only { false } else { std::env::var("RDPUTIL_CREDSSP").as_deref() == Ok("1") },
        enable_standard_rdp_security: !ssl_only,
        keyboard_type: KeyboardType::IBM_ENHANCED,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        connection_type: ConnectionType::Lan,
        ime_file_name: String::new(),
        dig_product_id: String::new(),
        desktop_size: connector::DesktopSize {
            width: std::env::var("RDPUTIL_W").ok().and_then(|v| v.parse().ok()).unwrap_or(1280),
            height: std::env::var("RDPUTIL_H").ok().and_then(|v| v.parse().ok()).unwrap_or(1024),
        },
        monitor_layout: None,
        // RDPUTIL_BPP=<15|16|24>: request a legacy session color depth. The
        // default is 32 bpp; servers predating RDP 6.0 may not paint at all
        // against that request. An empty codec list keeps basic bitmap
        // updates (no surface commands).
        bitmap: std::env::var("RDPUTIL_BPP")
            .ok()
            .and_then(|bpp| bpp.parse::<u32>().ok())
            .map(|color_depth| connector::BitmapConfig {
                lossy_compression: false,
                color_depth,
                codecs: ironrdp_pdu::rdp::capability_sets::BitmapCodecs(Vec::new()),
            }),
        client_build: if legacy_client { 2600 } else { 0 },
        client_name: "rdputil".to_owned(),
        client_dir: "C:\\Windows\\System32\\mstscax.dll".to_owned(),

        #[cfg(windows)]
        platform: MajorPlatformType::WINDOWS,
        #[cfg(target_os = "macos")]
        platform: MajorPlatformType::MACINTOSH,
        #[cfg(target_os = "ios")]
        platform: MajorPlatformType::IOS,
        #[cfg(target_os = "linux")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "android")]
        platform: MajorPlatformType::ANDROID,
        #[cfg(target_os = "freebsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "dragonfly")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "openbsd")]
        platform: MajorPlatformType::UNIX,
        #[cfg(target_os = "netbsd")]
        platform: MajorPlatformType::UNIX,

        enable_server_pointer: false, // Disable custom pointers (there is no user interaction anyway).
        request_data: None,
        autologon: std::env::var("RDPUTIL_AUTOLOGON")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .unwrap_or(true),
        enable_audio_playback: false,
        enable_audio_capture: false,
        compression_type,
        pointer_software_rendering: true,
        multitransport_flags: None,
        support_dyn_vc_gfx_protocol: false,
        legacy_info_flags: legacy_client,
        performance_flags: PerformanceFlags::default(),
        desktop_scale_factor: 0,
        hardware_id: None,
        license_cache: None,
        timezone_info: TimezoneInfo::default(),
        alternate_shell: alt_shell.unwrap_or_default(),
        work_dir: non_empty_env("RDPUTIL_ALT_WORKDIR").unwrap_or_default(),
        remote_application_mode: remote_app,
        rail_support_level: if remote_app {
            ironrdp_pdu::rdp::capability_sets::RailSupportLevel::SUPPORTED
        } else {
            ironrdp_pdu::rdp::capability_sets::RailSupportLevel::empty()
        },
    })
}

#[cfg(test)]
mod config_tests {
    use super::build_config;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// With no session-mode env set, the connector config must stay a plain
    /// desktop session: no INFO_RAIL, no alternate shell, no RAIL capability.
    #[test]
    fn defaults_to_desktop_session() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("RDPUTIL_REMOTE_APP");
        std::env::remove_var("RDPUTIL_ALT_SHELL");
        let config = build_config("u".to_owned(), "p".to_owned(), None, false, 0).unwrap();
        assert!(!config.remote_application_mode);
        assert!(config.alternate_shell.is_empty());
        assert!(config.work_dir.is_empty());
        assert!(config.rail_support_level.is_empty());
    }

    /// RemoteApp mode follows the mstsc convention: the Client Info PDU shell
    /// field carries rdpinit.exe unless the operator overrides it, so legacy
    /// (pre-Win8) servers enter the RemoteApp flow instead of dropping EXEC.
    #[test]
    fn remote_app_defaults_shell_to_rdpinit() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("RDPUTIL_REMOTE_APP", "notepad.exe");
        std::env::remove_var("RDPUTIL_ALT_SHELL");
        let config = build_config("u".to_owned(), "p".to_owned(), None, false, 0).unwrap();
        assert!(config.remote_application_mode);
        assert_eq!(config.alternate_shell, "rdpinit.exe");
        std::env::set_var("RDPUTIL_ALT_SHELL", "myshell.exe");
        let config = build_config("u".to_owned(), "p".to_owned(), None, false, 0).unwrap();
        assert_eq!(config.alternate_shell, "myshell.exe");
        std::env::remove_var("RDPUTIL_REMOTE_APP");
        std::env::remove_var("RDPUTIL_ALT_SHELL");
    }
}

fn compression_type_from_level(level: u32) -> anyhow::Result<CompressionType> {
    match level {
        0 => Ok(CompressionType::K8),
        1 => Ok(CompressionType::K64),
        2 => Ok(CompressionType::Rdp6),
        3 => Ok(CompressionType::Rdp61),
        _ => anyhow::bail!("Invalid compression level. Valid values are 0, 1, 2, 3."),
    }
}

/// The transport stream: either plain TCP (Standard RDP Security) or TLS-upgraded.
pub(crate) enum RdpStream {
    Plain(TcpStream),
    Tls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
}

impl RdpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            RdpStream::Plain(stream) => stream.set_read_timeout(timeout),
            RdpStream::Tls(stream) => stream.get_ref().set_read_timeout(timeout),
        }
    }
}

impl Read for RdpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = match self {
            RdpStream::Plain(stream) => stream.read(buf),
            RdpStream::Tls(stream) => stream.read(buf),
        }?;
        if std::env::var_os("DUMP_WIRE").is_some() && n > 0 {
            eprintln!("WIRE IN {} {:02x?}", n, &buf[..n]);
        }
        Ok(n)
    }
}

impl Write for RdpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if std::env::var_os("DUMP_WIRE").is_some() {
            eprintln!("WIRE OUT {} {:02x?}", buf.len(), buf);
        }
        match self {
            RdpStream::Plain(stream) => stream.write(buf),
            RdpStream::Tls(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            RdpStream::Plain(stream) => stream.flush(),
            RdpStream::Tls(stream) => stream.flush(),
        }
    }
}

pub(crate) type AnyFramed = ironrdp_blocking::Framed<RdpStream>;

mod danger {
    use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use tokio_rustls::rustls::{DigitallySignedStruct, Error, SignatureScheme, pki_types};

    #[derive(Debug)]
    pub(super) struct NoCertificateVerification;

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _: &pki_types::CertificateDer<'_>,
            _: &[pki_types::CertificateDer<'_>],
            _: &pki_types::ServerName<'_>,
            _: &[u8],
            _: pki_types::UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &pki_types::CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }
}

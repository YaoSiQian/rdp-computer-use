//! `rdputil serve` — long-lived single-session RDP daemon.
//!
//! One process owns exactly one RDP session; multi-target fan-out is the
//! gateway's job. The wire protocol is line-delimited JSON on stdin/stdout:
//! one response line per request, plus asynchronous `ev` events for session
//! state transitions. Diagnostics (tracing) stay on stderr.
//!
//! Requests:  `{"id":N,"op":"<op>","p":{...}}`
//! Responses: `{"id":N,"ok":true,"t_ms":N,"r":{...}}` / `{"id":N,"ok":false,"t_ms":N,"err":{...}}`
//! Events:    `{"ev":"hello",...}`, `{"ev":"session","state":...}`, `{"ev":"bye"}`
//!
//! Session invariants enforced here rather than left to the caller:
//! - golden rule: before the first input of any sequence (no screenshot since
//!   the previous input), a pre-shot is taken automatically and its artifact
//!   path is returned as `pre_shot` in the op response;
//! - death-signature triage: a connection reset landing right after input is
//!   reported as `input_violation` and does NOT auto-reconnect, preserving the
//!   evidence for inspection;
//! - clipboard write direction: a guest Format Data Request is answered from
//!   the pending payload between pump slices (the backend cannot emit PDUs).

use core::time::Duration;
use std::collections::HashSet;
use std::io::{BufRead, Write as _};
use std::path::PathBuf;
use std::sync::mpsc::{self, TryRecvError};
use std::time::Instant;

use anyhow::Context as _;
use serde_json::{json, Value};

use ironrdp::cliprdr::pdu::{ClipboardFormatId, FormatDataResponse, OwnedFormatDataResponse};
use ironrdp::cliprdr::CliprdrClient;
use ironrdp::connector::connection_activation::ConnectionActivationFactory;
use ironrdp::connector::ConnectionResult;
use ironrdp::pdu::geometry::InclusiveRectangle;
use ironrdp::pdu::input::fast_path::{FastPathInputEvent, KeyboardFlags};
use ironrdp::pdu::input::mouse::{MousePdu, PointerFlags};
use ironrdp::pdu::mcs::{DisconnectProviderUltimatum, DisconnectReason, McsMessage};
use ironrdp::pdu::rdp::headers::ShareDataPdu;
use ironrdp::pdu::rdp::refresh_rectangle::RefreshRectanglePdu;
use ironrdp::pdu::x224::X224;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageBuilder};
use ironrdp::svc::SvcProcessor as _;
use ironrdp_pdu::WriteBuf;

use crate::{
    clip_tick, connect, frame_hash, golden_text_formats, pump_until, send_input_event, send_t120_announce, AnyFramed,
    ClipState, CommonArgs,
};

const PUMP_SLICE_MS: u64 = 250;
const STABLE_RUN_SLICES: u32 = 3;

/// Error surfaced to the JSON layer. Codes follow the design's error model;
/// the connection-ladder family codes (E_CONN_TARGET etc.) are attached by
/// the gateway, which sees the connect phase from outside.
pub(crate) struct SrvErr {
    code: &'static str,
    detail: String,
}

impl SrvErr {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self { code, detail: detail.into() }
    }
}

fn serr(code: &'static str, detail: impl Into<String>) -> SrvErr {
    SrvErr::new(code, detail)
}

impl From<anyhow::Error> for SrvErr {
    fn from(e: anyhow::Error) -> Self {
        serr("E_PROTO", format!("{e:#}"))
    }
}

type SrvResult = Result<Value, SrvErr>;

#[derive(Debug)]
pub(crate) struct ServeArgs {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub domain: Option<String>,
    pub label: String,
    pub artifacts_dir: PathBuf,
    pub cliprdr: bool,
    pub golden_rule: bool,
    pub sacrifice_first: bool,
    pub slow_input: bool,
    pub reconnect: bool,
}

impl ServeArgs {
    pub(crate) fn parse(args: &mut pico_args::Arguments) -> anyhow::Result<Self> {
        let password = match args.opt_value_from_str::<_, String>(["-p", "--password"])? {
            // The gateway passes secrets via env so they never land in argv
            // (visible in process listings on some platforms).
            Some(p) => p,
            None => std::env::var("RDPUTIL_PASS").map_err(|_| anyhow::anyhow!("serve needs -p or RDPUTIL_PASS"))?,
        };
        // Optional canvas override before any connection: the connector config
        // reads these env vars on every connect, CLI wins over environment.
        if let Some(w) = args.opt_value_from_str::<_, u16>("--w")? {
            std::env::set_var("RDPUTIL_W", w.to_string());
        }
        if let Some(h) = args.opt_value_from_str::<_, u16>("--h")? {
            std::env::set_var("RDPUTIL_H", h.to_string());
        }
        Ok(Self {
            host: args.value_from_str::<_, String>("--host")?,
            port: args.opt_value_from_str::<_, u16>("--port")?.unwrap_or(3389),
            username: args.value_from_str::<_, String>(["-u", "--username"])?,
            password,
            domain: args.opt_value_from_str::<_, String>(["-d", "--domain"])?,
            label: args.opt_value_from_str::<_, String>("--label")?.unwrap_or_else(|| "generic".to_owned()),
            artifacts_dir: args
                .opt_value_from_str::<_, PathBuf>("--artifacts-dir")?
                .unwrap_or_else(|| PathBuf::from(".")),
            cliprdr: args.contains("--cliprdr"),
            golden_rule: flag(args, "--golden-rule", true)?,
            sacrifice_first: flag(args, "--sacrifice-first", false)?,
            slow_input: flag(args, "--slow-input", false)?,
            reconnect: flag(args, "--reconnect", true)?,
        })
    }
}

/// Env-style flag parsing: by value ("1"/"true"/"on"), never by presence.
fn flag(args: &mut pico_args::Arguments, name: &'static str, default: bool) -> anyhow::Result<bool> {
    match args.opt_value_from_str::<_, String>(name)? {
        Some(v) => Ok(matches!(v.as_str(), "1" | "true" | "on" | "yes")),
        None => Ok(default),
    }
}

struct Conn {
    framed: AnyFramed,
    stage: ActiveStage,
    image: DecodedImage,
    activation: ConnectionActivationFactory,
}

struct Daemon {
    args: ServeArgs,
    common: CommonArgs,
    clip: Option<ClipState>,
    conn: Option<Conn>,
    status: &'static str,
    connected_at: Option<Instant>,
    inputs_total: u64,
    inputs_since_shot: u64,
    last_input_at: Option<Instant>,
    shot_seq: u32,
    last_shot: Option<Value>,
    reconnects: u32,
    last_sig: Option<String>,
    boot: Instant,
}

pub(crate) fn run_serve(args: ServeArgs) -> anyhow::Result<()> {
    let common = CommonArgs {
        host: args.host.clone(),
        port: args.port,
        username: args.username.clone(),
        password: args.password.clone(),
        domain: args.domain.clone(),
        compression_enabled: true,
        compression_level: 3,
        output: None,
        idle_secs: 0,
        burst: 0,
        pre_secs: 0,
        event_delay_ms: 30,
        events: Vec::new(),
    };

    let mut daemon = Daemon {
        clip: None,
        conn: None,
        status: "connecting",
        connected_at: None,
        inputs_total: 0,
        inputs_since_shot: 0,
        last_input_at: None,
        shot_seq: 0,
        last_shot: None,
        reconnects: 0,
        last_sig: None,
        boot: Instant::now(),
        args,
        common,
    };

    daemon.emit(json!({
        "ev": "hello", "proto": 1, "pid": std::process::id(),
        "label": daemon.args.label,
        "golden_rule": daemon.args.golden_rule,
        "desktop": {"w": negotiated_width(), "h": negotiated_height()},
    }));

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

    if daemon.args.sacrifice_first {
        daemon.sacrifice();
    }
    daemon.establish();

    loop {
        if daemon.conn.is_some() {
            let mut lost = None;
            {
                let Conn { framed, stage, image, activation, .. } = daemon.conn.as_mut().unwrap();
                if let Err(e) = pump_until(
                    framed,
                    stage,
                    image,
                    Instant::now() + Duration::from_millis(PUMP_SLICE_MS),
                    Some(activation),
                ) {
                    lost = Some(e);
                }
                if lost.is_none() {
                    if let Some(clip) = daemon.clip.as_ref() {
                        clip_tick(framed, stage, clip);
                        if let Err(e) = answer_clip_write(framed, stage, clip) {
                            eprintln!("SERVE clip write failed: {e:#}");
                        }
                    }
                }
            }
            if let Some(e) = lost {
                daemon.handle_lost(e);
                continue;
            }
        } else if daemon.status == "dead" {
            // Parked: the session is gone and policy forbids reconnecting.
            // Keep answering requests (E_CONN for ops, `state` works, `q`
            // exits) until the gateway decides what to do next.
            match rx.recv_timeout(Duration::from_secs(1)) {
                Ok(raw) => {
                    if !daemon.dispatch(&raw) {
                        return Ok(());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
            continue;
        }

        // Drain everything queued during the pump slice.
        loop {
            match rx.try_recv() {
                Ok(raw) => {
                    if !daemon.dispatch(&raw) {
                        return Ok(());
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
    }
}

impl Daemon {
    fn emit(&self, v: Value) {
        println!("{v}");
        let _ = std::io::stdout().flush();
    }

    fn respond(&self, id: u64, result: SrvResult, t_ms: u128) {
        let line = match result {
            Ok(r) => json!({"id": id, "ok": true, "t_ms": t_ms, "r": r}),
            Err(e) => json!({"id": id, "ok": false, "t_ms": t_ms, "err": {"code": e.code, "detail": e.detail}}),
        };
        self.emit(line);
    }

    /// Handles one raw request line. Returns false when the daemon should exit.
    fn dispatch(&mut self, raw: &str) -> bool {
        let start = Instant::now();
        let (id, op, params) = match serde_json::from_str::<Value>(raw) {
            Ok(v) => (
                v.get("id").and_then(|x| x.as_u64()).unwrap_or(0),
                v.get("op").and_then(|x| x.as_str()).unwrap_or("").to_owned(),
                v.get("p").cloned().unwrap_or_else(|| json!({})),
            ),
            Err(e) => {
                self.emit(json!({"ev": "error", "detail": format!("unparseable request: {e}")}));
                return true;
            }
        };
        if op == "q" {
            if let Some(Conn { framed, .. }) = self.conn.as_mut() {
                // Graceful disconnect: the MCS Disconnect Provider Ultimatum
                // tells the guest to tear the session down now. An abrupt TCP
                // drop leaves the listener holding half-dead session state,
                // and repeated drops wedge it into accepting-but-never-
                // answering (observed in the field, only a guest service
                // restart clears it).
                let dpu = McsMessage::DisconnectProviderUltimatum(
                    DisconnectProviderUltimatum::from_reason(DisconnectReason::UserRequested),
                );
                match ironrdp_pdu::encode_vec(&X224(dpu)) {
                    Ok(frame) => {
                        if let Err(e) = framed.write_all(frame.as_slice()) {
                            eprintln!("SERVE disconnect ultimatum write failed: {e}");
                        }
                    }
                    Err(e) => eprintln!("SERVE disconnect ultimatum encode failed: {e}"),
                }
            }
            self.respond(id, Ok(json!({"bye": true})), start.elapsed().as_millis());
            self.emit(json!({"ev": "bye"}));
            return false;
        }
        let result = self.exec(&op, &params);
        self.respond(id, result, start.elapsed().as_millis());
        true
    }

    fn exec(&mut self, op: &str, p: &Value) -> SrvResult {
        if self.conn.is_none() {
            if op == "state" {
                return self.op_state();
            }
            return Err(serr(
                "E_CONN",
                format!("session not connected (status={}, last_sig={:?})", self.status, self.last_sig),
            ));
        }
        match op {
            "screenshot" => {
                let wait = pget(p, "wait_stable_ms").unwrap_or(1500);
                let tol = pget(p, "tol_px").unwrap_or(64);
                self.save_shot(wait, tol)
            }
            "click" | "move" => {
                let x: u16 = preq_u16(p, "x")?;
                let y: u16 = preq_u16(p, "y")?;
                let button = p.get("button").and_then(|v| v.as_str()).unwrap_or("left");
                let double = p.get("double").and_then(|v| v.as_bool()).unwrap_or(false);
                let (down, up) = match button {
                    "left" => (PointerFlags::LEFT_BUTTON | PointerFlags::DOWN, PointerFlags::LEFT_BUTTON),
                    "right" => (PointerFlags::RIGHT_BUTTON | PointerFlags::DOWN, PointerFlags::RIGHT_BUTTON),
                    "middle" => (
                        PointerFlags::MIDDLE_BUTTON_OR_WHEEL | PointerFlags::DOWN,
                        PointerFlags::MIDDLE_BUTTON_OR_WHEEL,
                    ),
                    other => return Err(serr("E_RANGE", format!("unknown button '{other}' (left|right|middle)"))),
                };
                self.golden_shot()?;
                let pdu = |flags: PointerFlags| {
                    FastPathInputEvent::MouseEvent(MousePdu {
                        flags,
                        number_of_wheel_rotation_units: 0,
                        x_position: x,
                        y_position: y,
                    })
                };
                let mut events = vec![pdu(PointerFlags::MOVE)];
                if op == "click" {
                    events.push(pdu(down));
                    events.push(pdu(up));
                    if double {
                        events.push(pdu(down));
                        events.push(pdu(up));
                    }
                }
                self.send_events(events, 150)?;
                self.mark_input();
                Ok(self.input_response())
            }
            "type" => {
                let text: String = preq_str(p, "text")?;
                let mode = p.get("mode").and_then(|v| v.as_str()).unwrap_or("keys");
                if mode == "clipboard" {
                    // Paste-typing is the gateway composing clipboard_set with
                    // a ctrl+v key op once the write direction is verified.
                    return Err(serr(
                        "E_UNSUPPORTED",
                        "mode=clipboard not available; compose clipboard_set + key ctrl+v",
                    ));
                }
                self.golden_shot()?;
                self.op_type(&text)?;
                self.mark_input();
                Ok(self.input_response())
            }
            "key" => {
                let combo: String = preq_str(p, "combo")?;
                self.golden_shot()?;
                self.op_key(&combo)?;
                self.mark_input();
                Ok(self.input_response())
            }
            "scroll" => Err(serr("E_UNSUPPORTED", "scroll awaits the wheel-encoding probe; use keyboard alternatives")),
            "wait" => {
                let ms = pget(p, "ms").unwrap_or(1000).min(60_000);
                let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
                pump_until(framed, stage, image, Instant::now() + Duration::from_millis(ms), Some(activation))
                    .map_err(SrvErr::from)?;
                Ok(json!({}))
            }
            "clipboard_get" => self.op_clipboard_get(),
            "clipboard_set" => self.op_clipboard_set(p),
            "resize" => self.op_resize(p),
            "refresh" => self.op_refresh(),
            "state" => self.op_state(),
            other => Err(serr("E_PROTO", format!("unknown op '{other}'"))),
        }
    }

    /// The op response for input ops: the golden-rule pre-shot path (if one
    /// was taken), so the caller can diff against its own post-input shot.
    fn input_response(&self) -> Value {
        json!({"pre_shot": self.last_shot.as_ref().and_then(|s| s.get("png").cloned()).unwrap_or(Value::Null)})
    }

    fn mark_input(&mut self) {
        self.inputs_total += 1;
        self.inputs_since_shot += 1;
        self.last_input_at = Some(Instant::now());
    }

    /// Golden rule: the daemon, not the agent, guarantees a screenshot exists
    /// before the first input of any sequence.
    fn golden_shot(&mut self) -> Result<(), SrvErr> {
        if self.args.golden_rule && self.inputs_since_shot == 0 {
            self.save_shot(0, 64)?;
        }
        Ok(())
    }

    fn send_events(&mut self, events: Vec<FastPathInputEvent>, gap_ms: u64) -> Result<(), SrvErr> {
        let fast = !self.slow_input_requested();
        let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
        let mut since_pump = 0usize;
        for event in &events {
            send_input_event(framed, stage, image, event, gap_ms, fast).map_err(SrvErr::from)?;
            since_pump += 1;
            // Keep the wire moving during long sequences so server probes keep
            // being answered (single blocking-thread model).
            if since_pump >= 32 {
                pump_until(framed, stage, image, Instant::now() + Duration::from_millis(100), Some(activation))
                    .map_err(SrvErr::from)?;
                since_pump = 0;
            }
        }
        Ok(())
    }

    fn slow_input_requested(&self) -> bool {
        self.args.slow_input || matches!(std::env::var("RDPUTIL_SLOW_INPUT").as_deref(), Ok("1") | Ok("true") | Ok("on"))
    }

    fn op_type(&mut self, text: &str) -> Result<(), SrvErr> {
        let mut events = Vec::new();
        for ch in text.chars() {
            match char_key(ch) {
                Some(CharKey::Scan(sc, shift)) => {
                    if shift {
                        events.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), 0x2a));
                    }
                    events.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::empty(), sc));
                    events.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, sc));
                    if shift {
                        events.push(FastPathInputEvent::KeyboardEvent(KeyboardFlags::RELEASE, 0x2a));
                    }
                }
                Some(CharKey::Unicode(unit)) => {
                    events.push(FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::empty(), unit));
                    events.push(FastPathInputEvent::UnicodeKeyboardEvent(KeyboardFlags::RELEASE, unit));
                }
                None => {}
            }
        }
        if events.is_empty() {
            return Ok(());
        }
        self.send_events(events, 30)
    }

    fn op_key(&mut self, combo: &str) -> Result<(), SrvErr> {
        let keys = parse_combo(combo).map_err(SrvErr::from)?;
        let (mods, taps): (Vec<_>, Vec<_>) = keys.into_iter().partition(|(_, _, modifier)| *modifier);
        let mut events = Vec::new();
        for (sc, ext, _) in &mods {
            events.push(kb_event(*sc, *ext, false));
        }
        match taps.len() {
            0 => {}
            1 => {
                let (sc, ext, _) = taps[0];
                events.push(kb_event(sc, ext, false));
                events.push(kb_event(sc, ext, true));
            }
            _ => {
                // Several non-modifier names type in order (e.g. "a+b").
                for (sc, ext, _) in &taps {
                    events.push(kb_event(*sc, *ext, false));
                    events.push(kb_event(*sc, *ext, true));
                }
            }
        }
        for (sc, ext, _) in mods.iter().rev() {
            events.push(kb_event(*sc, *ext, true));
        }
        if events.is_empty() {
            return Err(serr("E_RANGE", "empty key combo"));
        }
        self.send_events(events, 80)
    }

    fn wait_clip_ready(&mut self) -> Result<(), SrvErr> {
        let clip = match self.clip.as_ref() {
            Some(c) => c,
            None => return Err(serr("E_CLIP", "cliprdr disabled (restart with --cliprdr)")),
        };
        let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
        let start = Instant::now();
        while !*clip.ready.lock().unwrap() {
            if start.elapsed().as_millis() > 8000 {
                return Err(serr("E_CLIP", "cliprdr handshake not ready"));
            }
            clip_tick(framed, stage, clip);
            pump_until(framed, stage, image, Instant::now() + Duration::from_millis(PUMP_SLICE_MS), Some(activation))
                .map_err(SrvErr::from)?;
        }
        Ok(())
    }

    fn op_clipboard_get(&mut self) -> SrvResult {
        self.wait_clip_ready()?;
        let clip = self.clip.as_ref().unwrap();
        let formats = clip.formats.lock().unwrap().clone();
        // Probe mode 5: request anyway. If a just-advertised format was
        // registered on the guest clipboard (delayed rendering), rdpclip must
        // ask us to render it before answering — visible as a Format Data
        // Request on stderr — then return the data. A FAIL response means the
        // advertisement was never registered.
        if formats.is_empty() && std::env::var("RDPUTIL_CLIP_MODE").as_deref() != Ok("5") {
            return Err(serr("E_CLIP", format!("guest offers no CF_UNICODETEXT (formats={formats:?})")));
        }
        *clip.response.lock().unwrap() = None;
        let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
        let (name, msgs) = {
            let Some(actor) = stage.get_svc_processor_mut::<CliprdrClient>() else {
                return Err(serr("E_CLIP", "cliprdr channel missing"));
            };
            let name = actor.channel_name();
            let msgs = actor
                .initiate_paste(ClipboardFormatId::CF_UNICODETEXT)
                .map_err(|e| serr("E_CLIP", format!("initiate_paste: {e}")))?;
            (name, msgs)
        };
        let frame = stage
            .process_svc_messages_by_name(&name, msgs.into())
            .map_err(|e| serr("E_CLIP", format!("encode paste request: {e}")))?;
        framed.write_all(frame.as_slice()).map_err(|e| serr("E_CLIP", format!("write paste request: {e}")))?;
        let start = Instant::now();
        loop {
            if let Some(res) = clip.response.lock().unwrap().take() {
                return match res {
                    Ok(text) => Ok(json!({"text": text})),
                    Err(()) => Err(serr("E_CLIP", "guest refused the format data request")),
                };
            }
            if start.elapsed().as_millis() > 5000 {
                return Err(serr("E_TIMEOUT", "clipboard paste timed out"));
            }
            pump_until(framed, stage, image, Instant::now() + Duration::from_millis(PUMP_SLICE_MS), Some(activation))
                .map_err(SrvErr::from)?;
            // A delayed-rendered guest format makes rdpclip ask US for the
            // data before it can answer; serve that request from
            // write_pending right here (the main loop's answer_clip_write
            // only runs between ops).
            answer_clip_write(framed, stage, clip)?;
        }
    }

    /// Client→guest clipboard write, part 1: stash the UTF-16 payload and
    /// advertise CF_UNICODETEXT so the guest sees fresh content. Part 2 (the
    /// guest's Format Data Request) is answered by the pump loop via
    /// `answer_clip_write`. Pasting on the guest is the caller's Ctrl+V.
    fn op_clipboard_set(&mut self, p: &Value) -> SrvResult {
        let text: String = preq_str(p, "text")?;
        self.wait_clip_ready()?;
        let clip = self.clip.as_ref().unwrap();
        let mut units: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        units.extend_from_slice(&[0, 0]); // CF_UNICODETEXT NUL terminator
        *clip.write_pending.lock().unwrap() = Some(units);
        {
            let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
            advertise_formats(framed, stage).map_err(SrvErr::from)?;
            pump_until(framed, stage, image, Instant::now() + Duration::from_millis(PUMP_SLICE_MS), Some(activation))
                .map_err(SrvErr::from)?;
        }
        // Our advertisement replaced the guest clipboard; whatever the guest
        // offered before is gone until its own next copy broadcast. Reading
        // back our own push yields an empty/failed response.
        clip.formats.lock().unwrap().clear();
        Ok(json!({"chars": text.chars().count()}))
    }

    fn op_resize(&mut self, p: &Value) -> SrvResult {
        let w_req = pget(p, "w").unwrap_or(0);
        let h_req = pget(p, "h").unwrap_or(0);
        if !(200..=8192).contains(&w_req) || !(200..=8192).contains(&h_req) {
            return Err(serr("E_RANGE", "resize bounds: 200..=8192 px (width even)"));
        }
        let w = w_req as u32 & !1;
        let h = h_req as u32;
        let new_size = {
            let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
            match stage.encode_resize(w, h, None, None) {
                Some(Ok(frame)) => {
                    framed.write_all(frame.as_slice()).map_err(|e| serr("E_PROTO", format!("write resize: {e}")))?;
                    // Pump through the Deactivation-Reactivation Sequence; it
                    // carries the new desktop size and pump_until rebuilds the
                    // framebuffer inline.
                    pump_until(framed, stage, image, Instant::now() + Duration::from_secs(10), Some(activation))
                        .map_err(SrvErr::from)?;
                    Ok((image.width(), image.height()))
                }
                Some(Err(e)) => Err(serr("E_PROTO", format!("resize encode failed: {e:#}"))),
                None => Err(serr("E_UNSUPPORTED", "display control not attached at connect time")),
            }
        };
        // The framebuffer changed wholesale: re-arm the golden rule even on
        // the error path, since the wire state is uncertain after a failed
        // resize attempt.
        self.inputs_since_shot = 0;
        self.last_shot = None;
        match new_size {
            Ok((gw, gh)) => Ok(json!({"w": gw, "h": gh})),
            Err(e) => Err(e),
        }
    }

    fn op_refresh(&mut self) -> SrvResult {
        let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
        let mut frame = WriteBuf::new();
        stage
            .encode_static(
                &mut frame,
                ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                    areas_to_refresh: vec![InclusiveRectangle {
                        left: 0,
                        top: 0,
                        right: image.width().saturating_sub(1),
                        bottom: image.height().saturating_sub(1),
                    }],
                }),
            )
            .map_err(anyhow::Error::from)
            .map_err(SrvErr::from)?;
        framed.write_all(frame.into_inner().as_slice()).map_err(|e| serr("E_PROTO", format!("write refresh: {e}")))?;
        pump_until(framed, stage, image, Instant::now() + Duration::from_millis(600), Some(activation))
            .map_err(SrvErr::from)?;
        Ok(json!({}))
    }

    fn op_state(&mut self) -> SrvResult {
        Ok(json!({
            "status": self.status,
            "label": self.args.label,
            "uptime_ms": self.boot.elapsed().as_millis() as u64,
            "connected_ms": self.connected_at.map(|t| t.elapsed().as_millis() as u64),
            "desktop": self.conn.as_ref().map(|c| json!({"w": c.image.width(), "h": c.image.height()})),
            "inputs_total": self.inputs_total,
            "inputs_since_shot": self.inputs_since_shot,
            "last_input_age_ms": self.last_input_at.map(|t| t.elapsed().as_millis() as u64),
            "shots": self.shot_seq,
            "last_shot": self.last_shot,
            "reconnects": self.reconnects,
            "last_sig": self.last_sig,
            "golden_rule": self.args.golden_rule,
        }))
    }

    /// Saves the current framebuffer: with `wait_stable_ms > 0` waits until N
    /// consecutive 250ms pump slices differ from the reference frame by at
    /// most `tol_px` pixels (late deltas land in the PNG; tiny repaints like
    /// clock ticks are absorbed by the tolerance), otherwise takes an
    /// immediate dump after one slice. Returns in-process statistics so
    /// callers can judge black-screen/alive/changed without touching pixels.
    fn save_shot(&mut self, wait_stable_ms: u64, tol_px: u64) -> SrvResult {
        std::fs::create_dir_all(&self.args.artifacts_dir)
            .map_err(|e| serr("E_PROTO", format!("artifacts dir: {e}")))?;
        let seq = self.shot_seq + 1;
        let path = self.args.artifacts_dir.join(format!("shot_{seq:04}.png"));
        let outcome = {
            let Conn { framed, stage, image, activation, .. } = self.conn.as_mut().unwrap();
            // Thin slices: an idle pump must not block on the socket read
            // timeout or every slice straddles a full second.
            let _ = framed.get_inner_mut().0.set_read_timeout(Some(Duration::from_millis(100)));
            let mut stable = false;
            if wait_stable_ms > 0 {
                let start = Instant::now();
                let mut reference = image.data().to_vec();
                let mut last = frame_hash(image);
                let mut run = 0u32;
                loop {
                    if start.elapsed().as_millis() as u64 >= wait_stable_ms {
                        break;
                    }
                    pump_until(
                        framed,
                        stage,
                        image,
                        Instant::now() + Duration::from_millis(PUMP_SLICE_MS),
                        Some(activation),
                    )
                    .map_err(SrvErr::from)?;
                    let hash = frame_hash(image);
                    let diff = if hash == last { 0 } else { last = hash; pixel_diff(&reference, image.data()) };
                    if diff as u64 <= tol_px {
                        run += 1;
                    } else {
                        reference = image.data().to_vec();
                        run = 1;
                    }
                    if run >= STABLE_RUN_SLICES {
                        break;
                    }
                }
                stable = run >= STABLE_RUN_SLICES;
            } else {
                pump_until(framed, stage, image, Instant::now() + Duration::from_millis(PUMP_SLICE_MS), Some(activation))
                    .map_err(SrvErr::from)?;
            }
            let (mean_lum, distinct) = pixel_stats(image);
            dump_png(image, &path).map_err(|e| serr("E_PROTO", format!("save shot: {e:#}")))?;
            json!({
                "png": path.display().to_string(),
                "mean_lum": (mean_lum * 10000.0).round() / 10000.0,
                "distinct": distinct,
                "w": image.width(),
                "h": image.height(),
                "stable": stable,
            })
        };
        self.shot_seq = seq;
        self.inputs_since_shot = 0;
        self.last_shot = Some(outcome.clone());
        Ok(outcome)
    }

    /// Burns the first-connect arbitration fuse with a throwaway connection:
    /// some servers terminate the first session after a server-side reboot
    /// ~30s in, so the daemon opens, holds, and drops a sacrificial session
    /// before the real one. Any transport error during the hold is expected.
    fn sacrifice(&mut self) {
        self.emit(json!({"ev": "session", "state": "sacrificing"}));
        let outcome = (|| -> anyhow::Result<()> {
            let (cr, mut framed, _) = connect(&self.common, false)?;
            let user_channel_id = cr.user_channel_id;
            let io_channel_id = cr.io_channel_id;
            let (mut stage, _, w, h) = build_stage(cr);
            let mut image = DecodedImage::new(ironrdp_graphics::image_processing::PixelFormat::RgbA32, w, h);
            if std::env::var("RDPUTIL_T120").as_deref() != Ok("0") {
                send_t120_announce(&stage, &mut framed, user_channel_id, io_channel_id)?;
            }
            pump_until(&mut framed, &mut stage, &mut image, Instant::now() + Duration::from_secs(40), None)?;
            Ok(())
        })();
        if let Err(e) = outcome {
            eprintln!("SERVE sacrifice hold ended: {e:#}");
        }
        std::thread::sleep(Duration::from_secs(8));
    }

    fn establish(&mut self) {
        self.status = "connecting";
        self.emit(json!({"ev": "session", "state": "connecting", "attempt": self.reconnects}));
        match connect(&self.common, self.args.cliprdr) {
            Ok((cr, framed, clip)) => {
                let user_channel_id = cr.user_channel_id;
                let io_channel_id = cr.io_channel_id;
                let repaint = self.reconnects > 0;
                let (mut stage, activation, w, h) = build_stage(cr);
                // Outgoing SVC traffic is fragmented at the negotiated VirtualChannel
                // chunk size. CHANNEL_CHUNK_LENGTH is the floor every peer reassembles
                // reliably; clamp to it rather than trusting an advertised larger size.
                let negotiated = stage.static_channel_chunk_size();
                let chunk_size = negotiated.min(ironrdp::svc::CHANNEL_CHUNK_LENGTH);
                if chunk_size != negotiated {
                    stage.set_static_channel_chunk_size(chunk_size);
                }
                eprintln!("SERVE svc chunk negotiated={negotiated} used={chunk_size}");
                let mut framed = framed;
                if std::env::var("RDPUTIL_T120").as_deref() != Ok("0") {
                    if let Err(e) = send_t120_announce(&mut stage, &mut framed, user_channel_id, io_channel_id) {
                        eprintln!("SERVE t120 announce failed: {e:#}");
                    }
                }
                if repaint {
                    // A reconnected framebuffer stays all-black until the
                    // server is asked to repaint.
                    let mut buf = WriteBuf::new();
                    match stage.encode_static(
                        &mut buf,
                        ShareDataPdu::RefreshRectangle(RefreshRectanglePdu {
                            areas_to_refresh: vec![InclusiveRectangle {
                                left: 0,
                                top: 0,
                                right: w.saturating_sub(1),
                                bottom: h.saturating_sub(1),
                            }],
                        }),
                    ) {
                        Ok(_) => {
                            let _ = framed.write_all(buf.into_inner().as_slice());
                        }
                        Err(e) => eprintln!("SERVE refresh encode failed: {e:#}"),
                    }
                }
                self.clip = clip;
                self.conn = Some(Conn {
                    framed,
                    stage,
                    image: DecodedImage::new(ironrdp_graphics::image_processing::PixelFormat::RgbA32, w, h),
                    activation,
                });
                self.status = "active";
                self.connected_at = Some(Instant::now());
                self.inputs_since_shot = 0;
                self.last_shot = None;
                self.emit(json!({"ev": "session", "state": "connected", "desktop": {"w": w, "h": h}}));
            }
            Err(e) => {
                self.last_sig = Some("connect_failed".to_owned());
                self.status = "dead";
                self.emit(
                    json!({"ev": "session", "state": "dead", "detail": {"sig": "connect_failed", "error": format!("{e:#}")}}),
                );
            }
        }
    }

    fn handle_lost(&mut self, err: anyhow::Error) {
        let detail = format!("{err:#}");
        eprintln!("SERVE connection lost: {detail}");
        // A connection that lived a minute was real work; the next loss starts
        // a fresh reconnect budget.
        if self.connected_at.is_some_and(|t| t.elapsed() > Duration::from_secs(60)) {
            self.reconnects = 0;
        }
        let mut sig = "wedge_or_network";
        if let Some(io) = err.root_cause().downcast_ref::<std::io::Error>() {
            match io.kind() {
                std::io::ErrorKind::ConnectionReset => sig = "reset",
                std::io::ErrorKind::ConnectionAborted => sig = "server_disconnected",
                _ => {}
            }
        }
        // Triage heuristic: a reset right after input without a fresh
        // screenshot is an input-protocol violation — keep the evidence, do
        // not auto-reconnect.
        let input_violation = sig == "reset"
            && self.inputs_since_shot > 0
            && self.last_input_at.is_some_and(|t| t.elapsed() < Duration::from_secs(3));
        if input_violation {
            sig = "input_violation";
        }
        self.last_sig = Some(sig.to_owned());
        self.conn = None;
        self.connected_at = None;
        self.emit(json!({"ev": "session", "state": "dead", "detail": {"sig": sig, "error": detail}}));

        if input_violation || !self.args.reconnect || self.reconnects >= 20 {
            self.status = "dead";
            return;
        }
        self.status = "reconnecting";
        self.reconnects += 1;
        let delay = std::env::var("RDPUTIL_RECONNECT_DELAY_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(2000);
        std::thread::sleep(Duration::from_millis(delay));
        self.establish();
    }
}

fn build_stage(cr: ConnectionResult) -> (ActiveStage, ConnectionActivationFactory, u16, u16) {
    let activation = cr.activation_factory;
    let (w, h) = (cr.desktop_size.width, cr.desktop_size.height);
    let stage = ActiveStageBuilder {
        static_channels: cr.static_channels,
        user_channel_id: cr.user_channel_id,
        io_channel_id: cr.io_channel_id,
        message_channel_id: cr.message_channel_id,
        share_id: cr.share_id,
        compression_type: cr.compression_type,
        enable_server_pointer: cr.enable_server_pointer,
        pointer_software_rendering: cr.pointer_software_rendering,
        security: cr.security,
    }
    .build();
    (stage, activation, w, h)
}

/// Answers a pending guest Format Data Request from `write_pending`
/// (client→guest clipboard write). The backend flags the request; the session
/// loop owns the wire and carries the response between pump slices.
fn answer_clip_write(framed: &mut AnyFramed, stage: &mut ActiveStage, clip: &ClipState) -> anyhow::Result<()> {
    use std::sync::atomic::Ordering;
    if !clip.write_requested.swap(false, Ordering::Relaxed) {
        return Ok(());
    }
    let pending = clip.write_pending.lock().unwrap().clone();
    let response: OwnedFormatDataResponse = match pending {
        Some(ref bytes) => {
            eprintln!("CLIP format-data-response len={} (client->guest write path)", bytes.len());
            FormatDataResponse::new_data(bytes.clone())
        }
        None => {
            eprintln!("CLIP format-data-response error (no pending write payload)");
            FormatDataResponse::new_error()
        }
    };
    let (name, msgs) = {
        let Some(actor) = stage.get_svc_processor_mut::<CliprdrClient>() else {
            anyhow::bail!("cliprdr channel missing");
        };
        let name = actor.channel_name();
        let msgs = actor.submit_format_data(response).context("submit_format_data")?;
        (name, msgs)
    };
    let frame = stage.process_svc_messages_by_name(&name, msgs.into()).context("encode format data response")?;
    framed.write_all(frame.as_slice()).context("write format data response")?;
    Ok(())
}

/// Sends a fresh Format List advertisement (standard text group) so the guest
/// picks up new clipboard content after `clipboard_set`. Per-[MS-RDPECLIP]
/// each Format List replaces the previous one. Uses the same per-PDU segment
/// separation the init path was field-proven to require.
fn advertise_formats(framed: &mut AnyFramed, stage: &mut ActiveStage) -> anyhow::Result<()> {
    let formats = golden_text_formats();
    let (name, msgs) = {
        let Some(actor) = stage.get_svc_processor_mut::<CliprdrClient>() else {
            anyhow::bail!("cliprdr channel missing");
        };
        let name = actor.channel_name();
        let msgs = actor.initiate_copy(&formats).context("initiate_copy")?;
        (name, msgs)
    };
    let msgs: Vec<_> = msgs.into();
    for m in msgs {
        let frame = stage.process_svc_messages_by_name(&name, vec![m]).context("encode format list")?;
        framed.write_all(frame.as_slice()).context("write format list")?;
        std::thread::sleep(Duration::from_millis(500));
    }
    Ok(())
}

fn dump_png(image: &DecodedImage, path: &PathBuf) -> anyhow::Result<()> {
    let img: image::ImageBuffer<image::Rgba<u8>, _> =
        image::ImageBuffer::from_raw(u32::from(image.width()), u32::from(image.height()), image.data().to_vec())
            .context("invalid image")?;
    img.save(path).context("save png")
}

/// (mean_lum, distinct_colors) over the RGBA framebuffer, computed here so
/// agents judge screen state from numbers instead of reading pixels.
fn pixel_stats(image: &DecodedImage) -> (f64, usize) {
    let data = image.data();
    let mut sum = 0f64;
    let mut seen: HashSet<u32> = HashSet::with_capacity(1 << 16);
    let px_count = (image.width() as usize * image.height() as usize).max(1);
    for px in data.chunks_exact(4) {
        let (r, g, b) = (px[0] as u32, px[1] as u32, px[2] as u32);
        sum += 0.2126 * r as f64 + 0.7152 * g as f64 + 0.0722 * b as f64;
        seen.insert((r << 16) | (g << 8) | b);
    }
    (sum / px_count as f64 / 255.0, seen.len())
}

fn pixel_diff(a: &[u8], b: &[u8]) -> usize {
    a.chunks_exact(4)
        .zip(b.chunks_exact(4))
        .filter(|(p, r)| p[0].abs_diff(r[0]) > 10 || p[1].abs_diff(r[1]) > 10 || p[2].abs_diff(r[2]) > 10)
        .count()
}

fn pget(p: &Value, key: &str) -> Option<u64> {
    p.get(key).and_then(|v| v.as_u64())
}

fn preq_str(p: &Value, key: &str) -> Result<String, SrvErr> {
    p.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned())
        .ok_or_else(|| serr("E_RANGE", format!("missing or non-string param '{key}'")))
}

fn preq_u16(p: &Value, key: &str) -> Result<u16, SrvErr> {
    let v = p
        .get(key)
        .and_then(|v| v.as_i64())
        .ok_or_else(|| serr("E_RANGE", format!("missing or non-integer param '{key}'")))?;
    u16::try_from(v).map_err(|_| serr("E_RANGE", format!("param '{key}' out of range: {v}")))
}

fn negotiated_width() -> u16 {
    std::env::var("RDPUTIL_W").ok().and_then(|v| v.parse().ok()).unwrap_or(1280)
}

fn negotiated_height() -> u16 {
    std::env::var("RDPUTIL_H").ok().and_then(|v| v.parse().ok()).unwrap_or(1024)
}

enum CharKey {
    Scan(u8, bool),
    Unicode(u16),
}

/// US-layout mapping for printable characters. `Some(Scan(sc, shift))` for
/// keys the scancode layout covers, `Some(Unicode)` as the fallback for
/// anything else, `None` to skip. `\r` is skipped so CRLF text does not
/// double-enter.
fn char_key(ch: char) -> Option<CharKey> {
    let scan = |sc: u8, shift: bool| Some(CharKey::Scan(sc, shift));
    match ch {
        '\r' => None,
        '\n' => scan(0x1c, false),
        '\t' => scan(0x0f, false),
        ' ' => scan(0x39, false),
        'a'..='z' => scan(US_LOWER[(ch as u8 - b'a') as usize], false),
        'A'..='Z' => scan(US_LOWER[(ch as u8 - b'A') as usize], true),
        '0'..='9' => {
            let d = ch as u8 - b'0';
            scan(if d == 0 { 0x0b } else { 0x01 + d }, false)
        }
        '!' => scan(0x02, true),
        '@' => scan(0x03, true),
        '#' => scan(0x04, true),
        '$' => scan(0x05, true),
        '%' => scan(0x06, true),
        '^' => scan(0x07, true),
        '&' => scan(0x08, true),
        '*' => scan(0x09, true),
        '(' => scan(0x0a, true),
        ')' => scan(0x0b, true),
        '`' => scan(0x29, false),
        '~' => scan(0x29, true),
        '-' => scan(0x0c, false),
        '_' => scan(0x0c, true),
        '=' => scan(0x0d, false),
        '+' => scan(0x0d, true),
        '[' => scan(0x1a, false),
        '{' => scan(0x1a, true),
        ']' => scan(0x1b, false),
        '}' => scan(0x1b, true),
        '\\' => scan(0x2b, false),
        '|' => scan(0x2b, true),
        ';' => scan(0x27, false),
        ':' => scan(0x27, true),
        '\'' => scan(0x28, false),
        '"' => scan(0x28, true),
        ',' => scan(0x33, false),
        '<' => scan(0x33, true),
        '.' => scan(0x34, false),
        '>' => scan(0x34, true),
        '/' => scan(0x35, false),
        '?' => scan(0x35, true),
        other => Some(CharKey::Unicode(other as u16)),
    }
}

/// Set-1 scancodes for a..z in alphabetical order.
const US_LOWER: [u8; 26] = [
    0x1e, 0x30, 0x2e, 0x20, 0x12, 0x21, 0x22, 0x23, 0x17, 0x24, 0x25, 0x26, 0x32, 0x31, 0x18, 0x19, 0x10, 0x13, 0x1f,
    0x14, 0x16, 0x2f, 0x11, 0x2d, 0x15, 0x2c,
];

fn kb_event(sc: u8, ext: bool, release: bool) -> FastPathInputEvent {
    let mut flags = KeyboardFlags::empty();
    if release {
        flags |= KeyboardFlags::RELEASE;
    }
    if ext {
        flags |= KeyboardFlags::EXTENDED;
    }
    FastPathInputEvent::KeyboardEvent(flags, sc)
}

/// Parses "ctrl+shift+esc" style combos into (scancode, extended, is_modifier).
fn parse_combo(combo: &str) -> anyhow::Result<Vec<(u8, bool, bool)>> {
    let mut out = Vec::new();
    for token in combo.split('+') {
        let t = token.trim();
        if t.is_empty() {
            continue;
        }
        let lower = t.to_ascii_lowercase();
        let key = match lower.as_str() {
            "ctrl" | "control" | "lctrl" => (0x1d, false, true),
            "rctrl" => (0x1d, true, true),
            "shift" | "lshift" => (0x2a, false, true),
            "rshift" => (0x36, false, true),
            "alt" | "lalt" => (0x38, false, true),
            "ralt" | "altgr" => (0x38, true, true),
            "win" | "lwin" | "meta" => (0x5b, true, true),
            "rwin" => (0x5c, true, true),
            "esc" | "escape" => (0x01, false, false),
            "enter" | "return" => (0x1c, false, false),
            "tab" => (0x0f, false, false),
            "space" => (0x39, false, false),
            "backspace" | "bs" => (0x0e, false, false),
            "capslock" => (0x3a, false, false),
            "delete" | "del" => (0xd3, true, false),
            "insert" | "ins" => (0xd2, true, false),
            "home" => (0xc7, true, false),
            "end" => (0xcf, true, false),
            "pgup" | "pageup" => (0xc9, true, false),
            "pgdn" | "pgdown" | "pagedown" => (0xd1, true, false),
            "up" => (0xc8, true, false),
            "down" => (0xd0, true, false),
            "left" => (0xcb, true, false),
            "right" => (0xcd, true, false),
            _ => {
                if let Some(rest) = lower.strip_prefix("0x") {
                    let sc = u8::from_str_radix(rest, 16).context("bad hex scancode")?;
                    (sc, false, false)
                } else if lower.len() == 1 && lower.as_bytes()[0].is_ascii_alphabetic() {
                    (US_LOWER[(lower.as_bytes()[0] - b'a') as usize], false, false)
                } else if lower.len() == 1 && lower.as_bytes()[0].is_ascii_digit() {
                    let d = lower.as_bytes()[0] - b'0';
                    (if d == 0 { 0x0b } else { 0x01 + d }, false, false)
                } else if lower.len() >= 2
                    && lower.as_bytes()[0] == b'f'
                    && lower[1..].parse::<u8>().map(|n| (1..=12).contains(&n)).unwrap_or(false)
                {
                    let n: u8 = lower[1..].parse()?;
                    (if n <= 10 { 0x3a + n } else if n == 11 { 0x57 } else { 0x59 }, false, false)
                } else {
                    anyhow::bail!("unknown key name '{t}'");
                }
            }
        };
        out.push(key);
    }
    if out.is_empty() {
        anyhow::bail!("empty key combo");
    }
    Ok(out)
}

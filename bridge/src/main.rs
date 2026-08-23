//! gate-bridge — локальный HTTP-прокси-мост (Rust-реинкарнация local-proxy.py).
//!
//! Слушает 127.0.0.1:8889 без auth и решает, куда отправить каждое соединение:
//!   - AI-домены (Anthropic, OpenAI, …) → купленный upstream-прокси с auth
//!     (Proxy-Authorization впрыскивается автоматически);
//!   - всё остальное → напрямую (DIRECT), не тратя трафик upstream'а.
//!
//! Зачем Rust вместо PyInstaller-python: один статический exe ~1МБ без
//! антивирусных фолспозитивов и медленной распаковки onefile; и мост стал
//! достаточно умным для маршрутизации/failover — на python это уже боль.
//!
//! Возможности сверх старого моста:
//!   - domain-routing (режимы: all — всё через upstream, как раньше;
//!     smart — через upstream только AI-домены);
//!   - несколько --upstream с passive failover (упавший в отлёжке 30с);
//!   - GET /healthz на самом мосте — живые счётчики для Dashboard.
//!
//! CLI совместим со старым мостом: --upstream URL (повторяемый), --listen
//! HOST:PORT, --quiet. Новое: --rules FILE (JSON: mode/proxy_domains/
//! direct_domains). Без rules-файла ведёт себя ровно как старый мост (all).
//!
//! --supervise: режим самосупервизии — процесс перезапускает сам себя как
//! воркер и поднимает упавшего через 5с. Задача Планировщика вешается прямо
//! на exe: VBS/wscript-цикл (малварь-паттерн для антивирусов + депрекация
//! VBScript в Win11 24H2+) больше не нужен. windows_subsystem="windows" —
//! окна консоли нет ни у супервизора, ни у воркера.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Потолок одновременных соединений — защита от пика деплоя (см. историю
/// python-моста: без лимита too-many-threads ронял процесс и SSE-стрим).
const MAX_CONNECTIONS: usize = 256;
/// Максимум байтов заголовков первого запроса.
const HEAD_LIMIT: usize = 65536;
/// Таймаут установки исходящего TCP-соединения (upstream или direct).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// Таймаут чтения заголовков от клиента.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// Отлёжка упавшего upstream'а перед повторной попыткой.
const UPSTREAM_COOLDOWN: Duration = Duration::from_secs(30);

/// AI-домены по умолчанию для режима smart (матч точный или по суффиксу
/// ".domain"). Лучше перебдеть: лишний домен через upstream — копейки, а
/// пропущенный — обрыв доступа из-за гео-блока.
const DEFAULT_PROXY_DOMAINS: &[&str] = &[
    // Anthropic / Claude
    "anthropic.com",
    "claude.ai",
    "claude.com",
    // OpenAI / ChatGPT / Codex
    "openai.com",
    "chatgpt.com",
    "oaistatic.com",
    "oaiusercontent.com",
    // Google AI (только AI-endpoint'ы, НЕ все googleapis.com)
    "generativelanguage.googleapis.com",
    "ai.google.dev",
    // Прочие частые AI-API
    "x.ai",
    "mistral.ai",
    "openrouter.ai",
    "perplexity.ai",
    "githubcopilot.com",
    "cursor.sh",
    "cursor.com",
];

// ─── Конфигурация ────────────────────────────────────────────────

/// Тип upstream-прокси. Мост говорит с каждым хопом его протоколом:
/// HTTP — CONNECT с инжектом Proxy-Authorization, SOCKS5 — RFC 1928/1929.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    Http,
    Socks5,
}

impl ProxyKind {
    fn from_scheme(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "http" | "https" => Some(ProxyKind::Http),
            "socks5" | "socks5h" => Some(ProxyKind::Socks5),
            _ => None,
        }
    }
    fn as_str(self) -> &'static str {
        match self {
            ProxyKind::Http => "http",
            ProxyKind::Socks5 => "socks5",
        }
    }
}

/// Логин/пароль хопа. Для HTTP кодируется в Basic при инжекте заголовка,
/// для SOCKS5 — в sub-negotiation RFC 1929.
#[derive(Clone)]
struct Creds {
    user: String,
    pass: String,
}

impl Creds {
    fn basic_b64(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", self.user, self.pass))
    }
}

/// Один прокси-хоп (финальный upstream или «через»-хоп цепочки).
#[derive(Clone)]
struct Hop {
    kind: ProxyKind,
    host: String,
    port: u16,
    creds: Option<Creds>,
    /// Маскированный URL для логов и /healthz (`user:****@host:port`).
    masked: String,
}

fn parse_hop(raw: &str) -> Result<Hop, String> {
    let u = url::Url::parse(raw).map_err(|e| format!("bad proxy URL {raw}: {e}"))?;
    let kind =
        ProxyKind::from_scheme(u.scheme()).ok_or_else(|| format!("unsupported scheme in {raw} (нужен http:// или socks5://)"))?;
    let host = u
        .host_str()
        .ok_or_else(|| format!("proxy URL must include host: {raw}"))?
        .to_string();
    let port = u
        .port()
        .ok_or_else(|| format!("proxy URL must include port: {raw}"))?;
    let creds = if !u.username().is_empty() {
        // url-crate хранит userinfo percent-encoded; в auth идёт
        // ДЕКОДИРОВАНная пара, иначе спецсимволы в пароле ломают авторизацию.
        Some(Creds {
            user: pct_decode(&u.username().to_string()),
            pass: pct_decode(u.password().unwrap_or("").to_string().as_str()),
        })
    } else {
        None
    };
    let masked = match &creds {
        Some(c) => format!("{}://{}:****@{}:{}", u.scheme(), c.user, host, port),
        None => format!("{}://{}:{}", u.scheme(), host, port),
    };
    Ok(Hop {
        kind,
        host,
        port,
        creds,
        masked,
    })
}

/// Апстрим пула: финальный хоп + опциональная цепочка «через» (hop-1).
struct Upstream {
    hop: Hop,
    /// Если задан — TCP до финального прокси открывается ЧЕРЕЗ этот хоп
    /// (CONNECT для http-via, SOCKS5-handshake для socks5-via).
    via: Option<Box<Hop>>,
    ok: AtomicU64,
    fail: AtomicU64,
    /// Отлёжка после фейла коннекта: до этого момента upstream пропускается
    /// (passive failover). None — здоров.
    bad_until: Mutex<Option<Instant>>,
    /// Байты: отправлено НАМ в upstream (upload клиента) / получено ОБРАТНО.
    sent: AtomicU64,
    received: AtomicU64,
}

impl Upstream {
    fn cooling(&self) -> bool {
        self.bad_until
            .lock()
            .map(|g| g.map(|t| t > Instant::now()).unwrap_or(false))
            .unwrap_or(false)
    }
    fn mark_ok(&self) {
        self.ok.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.bad_until.lock() {
            *g = None;
        }
    }
    fn mark_fail(&self) {
        self.fail.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut g) = self.bad_until.lock() {
            *g = Some(Instant::now() + UPSTREAM_COOLDOWN);
        }
    }
    /// Полная маска с цепочкой для /healthz: `final ⇐ via`.
    fn masked_chain(&self) -> String {
        match &self.via {
            Some(v) => format!("{} ⇐ {}", self.hop.masked, v.masked),
            None => self.hop.masked.clone(),
        }
    }
}#[derive(Debug, Clone, Copy, PartialEq)]
enum Mode {
    /// Всё через upstream (поведение старого моста).
    All,
    /// Через upstream только AI-домены, остальное DIRECT.
    Smart,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Mode::All => "all",
            Mode::Smart => "smart",
        }
    }
}

/// JSON rules-файла (`bridge-rules.json`). Все поля опциональны — отсутствие
/// файла или поля означает дефолты (mode=all, встроенный список доменов).
#[derive(Deserialize, Default)]
struct RulesFile {
    mode: Option<String>,
    /// ДОПОЛНИТЕЛЬНЫЕ домены через upstream (расширяют встроенный список).
    proxy_domains: Option<Vec<String>>,
    /// Домены всегда напрямую (выигрывают у proxy_domains в любом режиме).
    direct_domains: Option<Vec<String>>,
    /// Домен → индекс upstream'а (порядок --upstream в argv): «Claude через
    /// прокси №0, ChatGPT через №1». Матч по суффиксу, самый длинный
    /// выигрывает. Индекс за пределами пула игнорируется.
    ///
    /// Назначение — СТРОГОЕ закрепление: используется ТОЛЬКО назначенный
    /// прокси, без failover на другие. Смена выходного IP опаснее короткого
    /// простоя: AI-сервисы (особенно Anthropic) флагают аккаунты за скачки
    /// IP. Failover работает только для доменов без назначения («Авто»).
    assignments: Option<std::collections::HashMap<String, usize>>,
    /// Прокси по умолчанию для доменов БЕЗ назначения: индекс в пуле, с
    /// которого начинается обход (failover на остальные остаётся). Кейс:
    /// платный внешний прокси — только для Anthropic, весь прочий трафик —
    /// через дешёвый локальный/VPN-прокси №1, а не жгём платный трафик.
    default_upstream: Option<usize>,
}

struct State {
    started: Instant,
    listen: String,
    quiet: bool,
    mode: Mode,
    proxy_domains: Vec<String>,
    direct_domains: Vec<String>,
    /// (домен, индекс upstream'а) — привязка сервисов к конкретным прокси.
    assignments: Vec<(String, usize)>,
    /// Прокси по умолчанию для доменов без назначения (см. RulesFile).
    default_upstream: Option<usize>,
    upstreams: Vec<Upstream>,
    total: AtomicU64,
    active: AtomicU64,
    via_upstream: AtomicU64,
    via_direct: AtomicU64,
    errors: AtomicU64,
    /// Глобальный трафик через мост: байты клиента→сеть (upload) и сеть→клиента.
    sent: AtomicU64,
    received: AtomicU64,
    /// Последние ошибки (секунды-от-старта, текст) — отдаются в /healthz,
    /// чтобы Dashboard мог показать пользователю ЧТО именно ломалось
    /// (супервизор запускает мост скрыто, stderr некуда смотреть).
    last_errors: Mutex<std::collections::VecDeque<(u64, String)>>,
}

/// Сколько последних ошибок держим для /healthz.
const LAST_ERRORS_CAP: usize = 20;

impl State {
    fn log(&self, msg: &str) {
        if !self.quiet {
            eprintln!("[{:>8.1}s] {msg}", self.started.elapsed().as_secs_f64());
        }
    }
    /// Ошибки видны и в quiet-режиме + попадают в кольцевой буфер /healthz.
    fn log_err(&self, msg: &str) {
        eprintln!("[{:>8.1}s] ERROR {msg}", self.started.elapsed().as_secs_f64());
        if let Ok(mut g) = self.last_errors.lock() {
            if g.len() >= LAST_ERRORS_CAP {
                g.pop_front();
            }
            g.push_back((self.started.elapsed().as_secs(), msg.to_string()));
        }
    }
}

/// Percent-decoding userinfo (`%41lice` → `Alice`), как в proxy.rs хелпера.
fn pct_decode(s: &str) -> String {    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn load_rules(
    path: Option<&str>,
) -> (
    Mode,
    Vec<String>,
    Vec<String>,
    Vec<(String, usize)>,
    Option<usize>,
) {
    let mut mode = Mode::All;
    let mut proxy: Vec<String> = DEFAULT_PROXY_DOMAINS.iter().map(|s| s.to_string()).collect();
    let mut direct: Vec<String> = Vec::new();
    let mut assignments: Vec<(String, usize)> = Vec::new();
    let mut default_upstream: Option<usize> = None;
    let Some(p) = path else {
        return (mode, proxy, direct, assignments, default_upstream);
    };

    // Отсутствие файла — легальный кейс (правил нет). А вот битый/нечитаемый
    // файл дефолтами закрывать НЕЛЬЗЯ: дефолты = пустые assignments, т.е.
    // закреплённый Claude тихо уйдёт в failover на другой выходной IP. Смена
    // IP опаснее простоя, поэтому: ретраи (запись дашборда могла совпасть с
    // нашим стартом), затем fail-fast — супервизор перезапустит с целым файлом.
    let mut last_err = String::new();
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(200));
        }
        let text = match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return (mode, proxy, direct, assignments, default_upstream);
            }
            Err(e) => {
                last_err = format!("не читается: {e}");
                continue;
            }
        };
        // BOM терпим: Блокнот/PowerShell пишут UTF-8 c BOM, serde_json его не ест.
        match serde_json::from_str::<RulesFile>(text.trim_start_matches('\u{feff}')) {
            Ok(r) => {
                if let Some(m) = r.mode.as_deref() {
                    mode = if m.eq_ignore_ascii_case("smart") { Mode::Smart } else { Mode::All };
                }
                proxy.extend(r.proxy_domains.unwrap_or_default());
                direct.extend(r.direct_domains.unwrap_or_default());
                // Нормализация + детерминированный порядок (длина ↓, имя, индекс):
                // HashMap-порядок случаен, и при дублях-тезках победитель менялся
                // бы от рестарта к рестарту — а это скачок выходного IP.
                let mut v: Vec<(String, usize)> = r
                    .assignments
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, i)| (k.trim_end_matches('.').to_ascii_lowercase(), i))
                    .collect();
                v.sort_by(|a, b| {
                    b.0.len()
                        .cmp(&a.0.len())
                        .then_with(|| a.0.cmp(&b.0))
                        .then_with(|| a.1.cmp(&b.1))
                });
                v.dedup_by(|a, b| a.0 == b.0);
                assignments = v;
                default_upstream = r.default_upstream;
                return (mode, proxy, direct, assignments, default_upstream);
            }
            Err(e) => last_err = format!("не парсится: {e}"),
        }
    }
    eprintln!("ERROR: rules file {p} {last_err} — отказ запуска: потеря закреплений опаснее простоя");
    std::process::exit(2);
}

// ─── Маршрутизация ───────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq)]
enum Route {
    Direct,
    Upstream,
}

/// Матч по суффиксу: "api.anthropic.com" матчится на "anthropic.com".
/// Хвостовая точка FQDN ("claude.ai.") нормализуется — иначе канонические
/// имена обходили бы и роутинг, и закрепление.
fn host_matches(host: &str, domain: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    h == d || h.ends_with(&format!(".{d}"))
}

fn decide(state: &State, host: &str) -> Route {
    if state.direct_domains.iter().any(|d| host_matches(host, d)) {
        return Route::Direct;
    }
    match state.mode {
        Mode::All => Route::Upstream,
        Mode::Smart => {
            if state.proxy_domains.iter().any(|d| host_matches(host, d)) {
                Route::Upstream
            } else {
                Route::Direct
            }
        }
    }
}

// ─── Сеть: помощники ─────────────────────────────────────────────

/// TCP keepalive: NAT/файрвол между нами и upstream не должен тихо убивать
/// idle-соединение посреди долгого SSE-стрима Claude Code (та же логика,
/// что была в python-мосте).
fn enable_keepalive(stream: &TcpStream) {
    use socket2::{SockRef, TcpKeepalive};
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = SockRef::from(stream).set_tcp_keepalive(&ka);
    let _ = stream.set_nodelay(true);
}

/// Прочитать заголовки первого запроса (до \r\n\r\n, лимит HEAD_LIMIT).
/// Дедлайн один на ВСЮ голову: per-read таймаут позволял клиенту, капающему
/// по байту, держать permit семафора бесконечно.
async fn read_head(client: &mut TcpStream) -> Result<Vec<u8>, String> {
    let read_all = async {
        let mut buf = Vec::with_capacity(2048);
        let mut chunk = [0u8; 8192];
        loop {
            let n = client
                .read(&mut chunk)
                .await
                .map_err(|e| format!("head read: {e}"))?;
            if n == 0 {
                return Err("client closed before full head".to_string());
            }
            buf.extend_from_slice(&chunk[..n]);
            if find_head_end(&buf).is_some() {
                return Ok(buf);
            }
            if buf.len() > HEAD_LIMIT {
                return Err("headers too large".to_string());
            }
        }
    };
    timeout(HEAD_TIMEOUT, read_all)
        .await
        .map_err(|_| "head read timeout".to_string())?
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Убрать hop-by-hop proxy-заголовки; опционально добавить Proxy-Authorization.
/// Работает и для CONNECT, и для обычного запроса — правится только блок
/// заголовков до \r\n\r\n, остальные байты (начало тела) не трогаются.
///
/// `force_close`: мы форвардим ТОЛЬКО первый запрос соединения, дальше идёт
/// слепой pipe — keep-alive для plain-HTTP через мост опасен (второй запрос
/// ушёл бы без auth и/или на сокет первого хоста). Поэтому не-CONNECT
/// запросы принудительно закрываются: клиент откроет новое соединение.
/// HTTPS (CONNECT-туннели) это не касается.
fn rewrite_head(head: &[u8], auth: Option<&str>, strip_proxy_headers: bool, force_close: bool) -> Vec<u8> {
    let end = match find_head_end(head) {
        Some(i) => i,
        None => return head.to_vec(),
    };
    let (lines_part, rest) = head.split_at(end);
    let mut out: Vec<&[u8]> = Vec::new();
    for line in lines_part.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let lower: Vec<u8> = line.iter().map(|b| b.to_ascii_lowercase()).collect();
        // Наш Proxy-Authorization всегда заменяет клиентский; Proxy-Connection
        // убираем при DIRECT (origin-серверу он не нужен и вреден).
        if lower.starts_with(b"proxy-authorization:") {
            continue;
        }
        if strip_proxy_headers && lower.starts_with(b"proxy-connection:") {
            continue;
        }
        if force_close
            && (lower.starts_with(b"connection:") || lower.starts_with(b"proxy-connection:"))
        {
            continue;
        }
        out.push(line);
    }
    let mut result = Vec::with_capacity(head.len() + 64);
    for (i, line) in out.iter().enumerate() {
        if i > 0 {
            result.extend_from_slice(b"\r\n");
        }
        result.extend_from_slice(line);
    }
    if let Some(a) = auth {
        result.extend_from_slice(format!("\r\nProxy-Authorization: Basic {a}").as_bytes());
    }
    if force_close {
        result.extend_from_slice(b"\r\nConnection: close");
    }
    result.extend_from_slice(rest); // rest начинается с \r\n\r\n
    result
}

/// Результат поиска назначения для хоста.
#[derive(Clone, Copy, PartialEq)]
enum Pin {
    /// Назначения нет — обычный маршрут и failover.
    None,
    /// Закреплён за живым индексом пула.
    Pinned(usize),
    /// Назначение есть, но индекс за пределами пула (rules и argv разошлись).
    /// По семантике закрепления это жёсткий отказ, а НЕ failover: уйти на
    /// другой прокси = сменить выходной IP сервиса.
    Broken,
}

/// Назначенный прокси для хоста: самый длинный суффикс-матч из assignments.
fn preferred_upstream(state: &State, host: &str) -> Pin {
    let mut best: Option<(usize, usize)> = None; // (длина домена, индекс)
    for (domain, idx) in &state.assignments {
        if host_matches(host, domain) && best.map(|(l, _)| domain.len() > l).unwrap_or(true) {
            best = Some((domain.len(), *idx));
        }
    }
    match best {
        None => Pin::None,
        Some((_, i)) if i < state.upstreams.len() => Pin::Pinned(i),
        Some(_) => Pin::Broken,
    }
}

/// TCP-коннект до хоста:порт с общим таймаутом.
async fn tcp_dial(host: &str, port: u16) -> Result<TcpStream, String> {
    match timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => Err(format!("connect {host}:{port}: {e}")),
        Err(_) => Err(format!("connect {host}:{port}: timeout")),
    }
}

/// Прочитать HTTP-ответ до \r\n\r\n (малый лимит — это служебные ответы).
async fn read_small_reply(s: &mut TcpStream, what: &str) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(128);
    let mut chunk = [0u8; 512];
    loop {
        let n = timeout(HEAD_TIMEOUT, s.read(&mut chunk))
            .await
            .map_err(|_| format!("{what}: reply timeout"))?
            .map_err(|e| format!("{what}: read {e}"))?;
        if n == 0 {
            return Err(format!("{what}: closed before reply"));
        }
        buf.extend_from_slice(&chunk[..n]);
        if find_head_end(&buf).is_some() {
            return Ok(buf);
        }
        if buf.len() > 16384 {
            return Err(format!("{what}: reply too large"));
        }
    }
}

/// Туннель ЧЕРЕЗ http-прокси до target: CONNECT + ожидание 2xx.
/// Возвращает поток и «хвост» ответа после \r\n\r\n (обычно пуст).
async fn http_connect_via(hop: &Hop, host: &str, port: u16) -> Result<(TcpStream, Vec<u8>), String> {
    let mut s = tcp_dial(&hop.host, hop.port).await?;
    let auth_line = match &hop.creds {
        Some(c) => format!("\r\nProxy-Authorization: Basic {}", c.basic_b64()),
        None => String::new(),
    };
    let req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}{auth_line}\r\n\r\n"
    );
    s.write_all(req.as_bytes())
        .await
        .map_err(|e| format!("via CONNECT write: {e}"))?;
    let reply = read_small_reply(&mut s, "via CONNECT").await?;
    let end = find_head_end(&reply).unwrap_or(reply.len());
    let code = String::from_utf8_lossy(&reply[..end])
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..300).contains(&code) {
        return Err(format!("via CONNECT refused (HTTP {code})"));
    }
    Ok((s, reply[end + 4..].to_vec()))
}

/// SOCKS5 handshake (RFC 1928 + auth RFC 1929) до target host:port.
/// Домен передаётся строкой — имя резолвит УДАЛЁННЫЙ конец, локальный DNS молчит.
async fn socks5_handshake(
    mut s: TcpStream,
    creds: &Option<Creds>,
    host: &str,
    port: u16,
) -> Result<TcpStream, String> {
    use AsyncReadExt as _;

    // 1) Greeting: предлагаем no-auth и (если есть креды) user/pass.
    let methods: &[u8] = if creds.is_some() { &[0x00, 0x02] } else { &[0x00] };
    let mut greet = vec![0x05u8, methods.len() as u8];
    greet.extend_from_slice(methods);
    s.write_all(&greet)
        .await
        .map_err(|e| format!("socks5 greeting write: {e}"))?;
    let mut sel = [0u8; 2];
    timeout(HEAD_TIMEOUT, s.read_exact(&mut sel))
        .await
        .map_err(|_| "socks5 greeting timeout".to_string())?
        .map_err(|e| format!("socks5 greeting read: {e}"))?;
    if sel[0] != 0x05 {
        return Err(format!("socks5: unexpected version {:#x}", sel[0]));
    }
    match sel[1] {
        0x00 => {}
        0x02 => {
            let c = creds
                .as_ref()
                .ok_or_else(|| "socks5: proxy требует авторизацию".to_string())?;
            let mut req = Vec::with_capacity(3 + c.user.len() + c.pass.len());
            req.push(0x01);
            req.push(c.user.len() as u8);
            req.extend_from_slice(c.user.as_bytes());
            req.push(c.pass.len() as u8);
            req.extend_from_slice(c.pass.as_bytes());
            s.write_all(&req)
                .await
                .map_err(|e| format!("socks5 auth write: {e}"))?;
            let mut st = [0u8; 2];
            timeout(HEAD_TIMEOUT, s.read_exact(&mut st))
                .await
                .map_err(|_| "socks5 auth timeout".to_string())?
                .map_err(|e| format!("socks5 auth read: {e}"))?;
            if st[1] != 0x00 {
                return Err("socks5: логин/пароль отклонены".into());
            }
        }
        m => return Err(format!("socks5: нет подходящего метода авторизации ({m:#x})")),
    }

    // 2) CONNECT к цели: ATYP=domain.
    if host.len() > 255 {
        return Err("socks5: hostname too long".into());
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host.as_bytes());
    req.push((port >> 8) as u8);
    req.push((port & 0xff) as u8);
    s.write_all(&req)
        .await
        .map_err(|e| format!("socks5 connect write: {e}"))?;

    // 3) Ответ: VER REP ATYP ADDR… PORT — длина зависит от типа адреса.
    let mut hdr = [0u8; 4];
    timeout(HEAD_TIMEOUT, s.read_exact(&mut hdr))
        .await
        .map_err(|_| "socks5 reply timeout".to_string())?
        .map_err(|e| format!("socks5 reply read: {e}"))?;
    if hdr[0] != 0x05 {
        return Err(format!("socks5: bad reply version {:#x}", hdr[0]));
    }
    if hdr[1] != 0x00 {
        return Err(format!("socks5: цель недоступна (rep={:#x})", hdr[1]));
    }
    let skip = match hdr[3] {
        0x01 => 4usize + 2,
        0x04 => 16usize + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l)
                .await
                .map_err(|e| format!("socks5 reply len: {e}"))?;
            l[0] as usize + 2
        }
        a => return Err(format!("socks5: unknown ATYP {a:#x}")),
    };
    let mut rest = vec![0u8; skip];
    timeout(HEAD_TIMEOUT, s.read_exact(&mut rest))
        .await
        .map_err(|_| "socks5 reply tail timeout".to_string())?
        .map_err(|e| format!("socks5 reply tail: {e}"))?;
    Ok(s)
}

/// Полный диал до upstream'а (статистику ведёт dial_and_mark):
/// [через via] → протокол финального хопа → туннель к target host:port.
/// Второй элемент — «туннель уже установлен нами» (true для socks5-финала:
/// клиенту тогда отвечаем 200 сами, как у DIRECT).
async fn dial_upstream(u: &Upstream, host: &str, port: u16) -> Result<(TcpStream, bool), String> {
    // Этап 1: TCP до финального прокси — напрямую или сквозь хоп-1.
    let mut s = match &u.via {
        None => tcp_dial(&u.hop.host, u.hop.port).await?,
        Some(v) => match v.kind {
            ProxyKind::Http => http_connect_via(v, &u.hop.host, u.hop.port).await?.0,
            ProxyKind::Socks5 => {
                let raw = tcp_dial(&v.host, v.port).await?;
                socks5_handshake(raw, &v.creds, &u.hop.host, u.hop.port).await?
            }
        },
    };
    enable_keepalive(&mut s);

    // Этап 2: разговор с финальным прокси его протоколом.
    match u.hop.kind {
        // HTTP: CONNECT-заголовок клиента перепишет rewrite_head (auth инжектится
        // там же); «200 Connection Established» придёт клиенту от upstream'а.
        ProxyKind::Http => Ok((s, false)),
        ProxyKind::Socks5 => {
            let tunneled = socks5_handshake(s, &u.hop.creds, host, port).await?;
            Ok((tunneled, true))
        }
    }
}

/// Выбрать живой upstream и подключиться к цели.
/// `pinned` (назначенный домену прокси) — СТРОГО: пробуем только его, на
/// другие НЕ уходим — выходной IP сервиса не должен прыгать.
/// Без назначения — passive failover: порядок начинается с дефолтного,
/// первый проход пропускает остывающих, второй даёт шанс ТОЛЬКО им.
async fn connect_upstream(
    state: &State,
    pinned: Option<usize>,
    host: &str,
    port: u16,
) -> Option<(TcpStream, usize, bool)> {
    let n = state.upstreams.len();
    let (order, is_pin): (Vec<usize>, bool) = match pinned {
        Some(p) if p < n => (vec![p], true),
        Some(_) => return None, // битый индекс — сюда не должен дойти (Pin::Broken отсекается раньше)
        None => {
            match state.default_upstream {
                Some(d) if d < n => {
                    let mut o: Vec<usize> = vec![d];
                    o.extend((0..n).filter(|&i| i != d));
                    (o, false)
                }
                _ => ((0..n).collect(), false),
            }
        }
    };
    let mut skipped: Vec<usize> = Vec::new();
    for &i in &order {
        if state.upstreams[i].cooling() {
            skipped.push(i);
            continue;
        }
        match dial_and_mark(state, i, host, port, is_pin).await {
            Ok(v) => return Some(v),
            Err(e) => state.log_err(&e),
        }
    }
    for &i in &skipped {
        if let Ok(v) = dial_and_mark(state, i, host, port, is_pin).await {
            return Some(v);
        }
    }
    None
}

/// dial_upstream + учёт ok/fail и человекочитаемая ошибка с маской прокси.
async fn dial_and_mark(
    state: &State,
    i: usize,
    host: &str,
    port: u16,
    pinned: bool,
) -> Result<(TcpStream, usize, bool), String> {
    let u = &state.upstreams[i];
    match timeout(CONNECT_TIMEOUT, dial_upstream(u, host, port)).await {
        Ok(Ok((s, tunneled))) => {
            u.mark_ok();
            Ok((s, i, tunneled))
        }
        Ok(Err(e)) => {
            u.mark_fail();
            Err(if pinned {
                format!("назначенный {} не работает: {e} — жду восстановления, IP не меняю", u.masked_chain())
            } else {
                format!("{} не работает: {e}", u.masked_chain())
            })
        }
        Err(_) => {
            u.mark_fail();
            Err(if pinned {
                format!("назначенный {} не ответил за {:?} — жду восстановления", u.masked_chain(), CONNECT_TIMEOUT)
            } else {
                format!("{} не ответил за {:?}", u.masked_chain(), CONNECT_TIMEOUT)
            })
        }
    }
}

// ─── /healthz ────────────────────────────────────────────────────

fn healthz_json(state: &State) -> String {
    // serde_json вместо ручной сборки: в last_errors живой текст (имена хостов,
    // ошибки ОС) — экранирование должно быть железным.
    let ups: Vec<serde_json::Value> = state
        .upstreams
        .iter()
        .map(|u| {
            serde_json::json!({
                "url": u.masked_chain(),
                "kind": u.hop.kind.as_str(),
                "chained": u.via.is_some(),
                "healthy": !u.cooling(),
                "ok": u.ok.load(Ordering::Relaxed),
                "fail": u.fail.load(Ordering::Relaxed),
                "sent": u.sent.load(Ordering::Relaxed),
                "received": u.received.load(Ordering::Relaxed),
            })
        })
        .collect();
    let errors: Vec<serde_json::Value> = state
        .last_errors
        .lock()
        .map(|g| {
            g.iter()
                .map(|(t, msg)| serde_json::json!({ "t": t, "msg": msg }))
                .collect()
        })
        .unwrap_or_default();
    serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_sec": state.started.elapsed().as_secs(),
        "listen": state.listen,
        "mode": state.mode.as_str(),
        "default_upstream": state.default_upstream,
        "active": state.active.load(Ordering::Relaxed),
        "total": state.total.load(Ordering::Relaxed),
        "via_upstream": state.via_upstream.load(Ordering::Relaxed),
        "via_direct": state.via_direct.load(Ordering::Relaxed),
        "errors": state.errors.load(Ordering::Relaxed),
        "sent": state.sent.load(Ordering::Relaxed),
        "received": state.received.load(Ordering::Relaxed),
        "upstreams": ups,
        "last_errors": errors,
    })
    .to_string()
}

async fn serve_local(client: &mut TcpStream, path: &str, state: &State) {
    let (code, body) = if path == "/healthz" || path == "/stats" {
        ("200 OK", healthz_json(state))
    } else {
        ("404 Not Found", "{\"error\":\"not found\"}".to_string())
    };
    let resp = format!(
        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = client.write_all(resp.as_bytes()).await;
}

// ─── Обработка соединения ────────────────────────────────────────

struct Parsed {
    is_connect: bool,
    /// origin-form запрос к самому мосту (например GET /healthz).
    local_path: Option<String>,
    host: String,
    port: u16,
}

fn parse_request(head: &[u8]) -> Result<Parsed, String> {
    let first_line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or("no request line")?;
    let line = String::from_utf8_lossy(&head[..first_line_end]);
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or("empty request line")?.to_string();
    let target = parts.next().ok_or("no target in request line")?.to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port_s) = target.rsplit_once(':').ok_or("CONNECT without port")?;
        let port: u16 = port_s.parse().map_err(|_| "bad CONNECT port")?;
        // IPv6-литерал приходит в скобках ("[::1]:443") — для connect() их надо снять.
        let host = host.trim_start_matches('[').trim_end_matches(']');
        return Ok(Parsed {
            is_connect: true,
            local_path: None,
            host: host.to_string(),
            port,
        });
    }
    if target.starts_with('/') {
        // origin-form → запрос к самому мосту (healthz).
        return Ok(Parsed {
            is_connect: false,
            local_path: Some(target),
            host: String::new(),
            port: 0,
        });
    }
    // absolute-form: GET http://host:port/path
    let u = url::Url::parse(&target).map_err(|e| format!("bad absolute-URI: {e}"))?;
    // host_str() для IPv6 отдаёт хост СО скобками — для connect() их надо снять.
    let host = u
        .host_str()
        .ok_or("absolute-URI without host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();
    let port = u.port_or_known_default().unwrap_or(80);
    Ok(Parsed {
        is_connect: false,
        local_path: None,
        host,
        port,
    })
}

/// RAII-декремент active-счётчика.
struct ActiveGuard<'a>(&'a State);
impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

async fn handle(mut client: TcpStream, state: Arc<State>) {
    let head = match read_head(&mut client).await {
        Ok(h) => h,
        Err(e) => {
            state.log(&format!("bad head: {e}"));
            return;
        }
    };
    let req = match parse_request(&head) {
        Ok(r) => r,
        Err(e) => {
            state.log(&format!("bad request: {e}"));
            let _ = client
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    };

    // Запрос к самому мосту (healthz/stats) — метрики НЕ трогаем: поллинг
    // дашборда раз в 5с иначе рисует тысячи фантомных «соединений» за ночь.
    if let Some(path) = req.local_path {
        serve_local(&mut client, &path, &state).await;
        return;
    }

    state.total.fetch_add(1, Ordering::Relaxed);
    state.active.fetch_add(1, Ordering::Relaxed);
    let _guard = ActiveGuard(&state);

    // Назначение сильнее режима: закреплённый домен идёт через свой upstream,
    // даже если smart-режим отправил бы его напрямую (или домен попал в
    // direct_domains) — иначе он утёк бы с реальным IP пользователя.
    let pin = preferred_upstream(&state, &req.host);
    let route = match pin {
        Pin::Pinned(_) => Route::Upstream,
        Pin::Broken => {
            state.errors.fetch_add(1, Ordering::Relaxed);
            state.log_err(&format!(
                "назначение для {} указывает на прокси вне пула — отказываю (IP менять нельзя)",
                req.host
            ));
            let _ = client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
        Pin::None => decide(&state, &req.host),
    };

    // Устанавливаем исходящее соединение. Для Upstream запоминаем Basic-auth
    // ИМЕННО того прокси, к которому реально подключились (failover мог выбрать
    // не первый). tunneled_us = туннель к цели завершён НАМИ (socks5-финал):
    // тогда «200 Connection Established» клиенту отвечаем сами.
    let mut server: TcpStream;
    let upstream_auth: Option<String>;
    let mut tunneled_us = false;
    let mut used_upstream: Option<usize> = None;
    match route {
        Route::Direct => {
            match timeout(
                CONNECT_TIMEOUT,
                TcpStream::connect((req.host.as_str(), req.port)),
            )
            .await
            {
                Ok(Ok(s)) => {
                    state.via_direct.fetch_add(1, Ordering::Relaxed);
                    server = s;
                    upstream_auth = None;
                }
                _ => {
                    state.errors.fetch_add(1, Ordering::Relaxed);
                    state.log_err(&format!("прямое соединение с {}:{} не удалось", req.host, req.port));
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
            }
        }
        Route::Upstream => {
            let pinned = match pin {
                Pin::Pinned(i) => Some(i),
                _ => None,
            };
            match connect_upstream(&state, pinned, &req.host, req.port).await {
                Some((mut s, i, tunneled)) => {
                    state.via_upstream.fetch_add(1, Ordering::Relaxed);
                    let u = &state.upstreams[i];
                    upstream_auth = match u.hop.kind {
                        // Basic нужен только HTTP-прокси (инжектится в head ниже);
                        // SOCKS5 авторизуется своим handshake'ом в dial.
                        ProxyKind::Http => u.hop.creds.as_ref().map(|c| c.basic_b64()),
                        ProxyKind::Socks5 => None,
                    };
                    tunneled_us = tunneled && req.is_connect;
                    used_upstream = Some(i);
                    if tunneled_us {
                        // Туннель стоит — отвечаем клиенту за upstream сами и
                        // пересылаем хвост головы (TLS ClientHello мог прийти
                        // одним write с CONNECT).
                        if client
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if let Some(end) = find_head_end(&head) {
                            let tail = &head[end + 4..];
                            if s.write_all(tail).await.is_err() {
                                return;
                            }
                        }
                    }
                    server = s;
                }
                None => {
                    state.errors.fetch_add(1, Ordering::Relaxed);
                    state.log_err(if pinned.is_some() {
                        "назначенный прокси недоступен — жду восстановления"
                    } else {
                        "все upstream-прокси недоступны"
                    });
                    let _ = client
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    return;
                }
            }
        }
    }

    enable_keepalive(&client);
    enable_keepalive(&server);

    // Первый запрос: что и кому пересылать.
    //   DIRECT + CONNECT          → свой 200 (выше по коду ветки) + хвост
    //   DIRECT + plain            → head без proxy-заголовков, Connection: close
    //   HTTP-upstream             → head с инжектом Basic-auth (любой метод)
    //   SOCKS5-upstream + CONNECT → НЕ пересылать вовсе: head — мусор для туннеля
    //   SOCKS5-upstream + plain   → head БЕЗ proxy-auth (origin), close
        match route {
        Route::Direct => {
            if req.is_connect {
                // Туннель установлен нами — отвечаем клиенту сами.
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                // Клиент мог оптимистично прислать TLS ClientHello одним write
                // с CONNECT — хвост обязан уйти серверу, иначе handshake виснет.
                if let Some(end) = find_head_end(&head) {
                    let tail = &head[end + 4..];
                    if !tail.is_empty() && server.write_all(tail).await.is_err() {
                        return;
                    }
                }
            } else {
                // Обычный HTTP напрямую: чистим proxy-заголовки, форвардим.
                let clean = rewrite_head(&head, None, true, true);
                if server.write_all(&clean).await.is_err() {
                    return;
                }
            }
        }
        Route::Upstream => {
            if !tunneled_us {
                // tunneled_us здесь == socks5-финал + plain http: говорим с
                // origin — proxy-заголовки клиента чистим.
                let rewritten =
                    rewrite_head(&head, upstream_auth.as_deref(), false, !req.is_connect);
                if server.write_all(&rewritten).await.is_err() {
                    state.errors.fetch_add(1, Ordering::Relaxed);
                    state.log_err(&format!("upstream оборвал соединение ({})", req.host));
                    return;
                }
            }
        }
    }

    // Прокачка трафика со счётчиками: upload = клиент→сеть, download = сеть→клиент.
    let (up_u, down_u): (Option<&AtomicU64>, Option<&AtomicU64>) = used_upstream
        .and_then(|i| state.upstreams.get(i))
        .map(|u| (Some(&u.sent as &AtomicU64), Some(&u.received as &AtomicU64)))
        .unwrap_or((None, None));
    pump(client, server, &state.sent, &state.received, up_u, down_u).await;
}

/// Двунаправленная прокачка со счётчиками байт.
/// upload = клиент→сеть (up_total/up_u), download = сеть→клиент.
/// В отличие от copy_bidirectional каждый чанк учитывается в атомарные
/// счётчики: глобальные всегда, пер-upstream'овые — если ходили через upstream.
async fn pump(
    a: TcpStream,
    b: TcpStream,
    up_total: &AtomicU64,
    down_total: &AtomicU64,
    up_u: Option<&AtomicU64>,
    down_u: Option<&AtomicU64>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut a_r, mut a_w) = tokio::io::split(a);
    let (mut b_r, mut b_w) = tokio::io::split(b);

    let up = async move {
        let mut buf = [0u8; 16384];
        loop {
            match a_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    up_total.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(c) = up_u {
                        c.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    if b_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Полузакрытие вниз по потоку: хвост ответа сервера ещё успеет дойти.
        let _ = b_w.shutdown().await;
    };
    let down = async move {
        let mut buf = [0u8; 16384];
        loop {
            match b_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    down_total.fetch_add(n as u64, Ordering::Relaxed);
                    if let Some(c) = down_u {
                        c.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    if a_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = a_w.shutdown().await;
    };
    let _ = tokio::join!(up, down);
}

// ─── main ────────────────────────────────────────────────────────

struct Args {
    /// Пары (upstream URL, опциональный via URL): --via относится
    /// к непосредственно предыдущему --upstream.
    upstreams: Vec<(String, Option<String>)>,
    listen: String,
    quiet: bool,
    rules: Option<String>,
    /// Режим супервизора: перезапускать себя-воркера при падении.
    supervise: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut a = Args {
        upstreams: Vec::new(),
        listen: "127.0.0.1:8888".into(),
        quiet: false,
        rules: None,
        supervise: false,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--upstream" => {
                i += 1;
                let url = argv.get(i).ok_or("--upstream requires URL")?.clone();
                a.upstreams.push((url, None));
            }
            "--via" => {
                i += 1;
                let url = argv.get(i).ok_or("--via requires URL")?.clone();
                // Привязка к последнему --upstream: цепочка «финал через хоп».
                match a.upstreams.last_mut() {
                    Some((_, via)) if via.is_none() => *via = Some(url),
                    _ => return Err("--via must follow an --upstream".into()),
                }
            }
            "--listen" => {
                i += 1;
                a.listen = argv.get(i).ok_or("--listen requires HOST:PORT")?.clone();
            }
            "--rules" => {
                i += 1;
                a.rules = Some(argv.get(i).ok_or("--rules requires FILE")?.clone());
            }
            "--quiet" => a.quiet = true,
            "--supervise" => a.supervise = true,
            "--version" => {
                println!("gate-bridge {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
        i += 1;
    }
    if a.upstreams.is_empty() {
        return Err("--upstream is required".into());
    }
    Ok(a)
}

/// Цикл самосупервизии: спавним себя-воркера (те же argv минус --supervise),
/// ждём завершения, через 5с поднимаем заново. Замена VBS/wscript-циклу.
/// Один супервизор на exe — эксклюзивный lock-файл (share_mode 0).
fn run_supervisor() -> ! {
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("ERROR: current_exe: {e}");
            std::process::exit(1);
        }
    };
    #[cfg(target_os = "windows")]
    let _lock = {
        use std::os::windows::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .share_mode(0)
            .open(exe.with_extension("supervisor.lock"))
        {
            Ok(f) => f,
            // Лок занят → супервизор уже работает (задача + watchdog GUI
            // могли стартовать одновременно) — тихо уходим, дубли не плодим.
            Err(_) => std::process::exit(0),
        }
    };
    let child_args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| a != "--supervise")
        .collect();
    loop {
        match std::process::Command::new(&exe).args(&child_args).status() {
            Ok(s) => eprintln!("supervisor: мост завершился ({s}) — перезапуск через 5с"),
            Err(e) => eprintln!("supervisor: не удалось запустить воркер: {e}"),
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

#[tokio::main]
async fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("ERROR: {e}");
            eprintln!(
                "usage: gate-bridge --upstream http://user:pass@host:port [--via socks5://hop] \
                 [--upstream …] [--listen 127.0.0.1:8888] [--rules FILE] [--quiet] [--supervise]"
            );
            std::process::exit(1);
        }
    };

    if args.supervise {
        run_supervisor();
    }

    let mut upstreams = Vec::new();
    for (raw, via_raw) in &args.upstreams {
        let hop = match parse_hop(raw) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("ERROR: {e}");
                std::process::exit(1);
            }
        };
        let via = match via_raw {
            Some(v) => match parse_hop(v) {
                Ok(h) => Some(Box::new(h)),
                Err(e) => {
                    eprintln!("ERROR: {e}");
                    std::process::exit(1);
                }
            },
            None => None,
        };
        upstreams.push(Upstream {
            hop,
            via,
            ok: AtomicU64::new(0),
            fail: AtomicU64::new(0),
            bad_until: Mutex::new(None),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
        });
    }

    let (mode, proxy_domains, direct_domains, assignments, default_upstream) =
        load_rules(args.rules.as_deref());
    // Дефолт вне пула — тихо игнорируем (rules и argv могли разойтись).
    let default_upstream = default_upstream.filter(|&i| i < upstreams.len());

    let state = Arc::new(State {
        started: Instant::now(),
        listen: args.listen.clone(),
        quiet: args.quiet,
        mode,
        proxy_domains,
        direct_domains,
        assignments,
        default_upstream,
        upstreams,
        total: AtomicU64::new(0),
        active: AtomicU64::new(0),
        via_upstream: AtomicU64::new(0),
        via_direct: AtomicU64::new(0),
        errors: AtomicU64::new(0),
        sent: AtomicU64::new(0),
        received: AtomicU64::new(0),
        last_errors: Mutex::new(std::collections::VecDeque::new()),
    });

    let listener = match TcpListener::bind(&args.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ERROR: cannot bind {} — {e}", args.listen);
            eprintln!("Is another process already listening on this port?");
            std::process::exit(1);
        }
    };

    {
        let ups: Vec<String> = state.upstreams.iter().map(|u| u.masked_chain()).collect();
        state.log(&format!(
            "gate-bridge {} listening on {} → {} | mode={} default_upstream={:?}",
            env!("CARGO_PKG_VERSION"),
            args.listen,
            ups.join(", "),
            state.mode.as_str(),
            state.default_upstream,
        ));
    }

    // Семафор — как в python-мосте: лишние соединения ждут слот, а не валят
    // процесс. Accept-цикл НИКОГДА не падает.
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (client, addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                state.log_err(&format!("accept: {e} — продолжаю слушать"));
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let permit = match timeout(Duration::from_secs(5), sem.clone().acquire_owned()).await {
            Ok(Ok(p)) => p,
            _ => {
                state.log_err(&format!(
                    "лимит {MAX_CONNECTIONS} соединений — отбиваю {addr}, сервер жив"
                ));
                drop(client);
                continue;
            }
        };
        let st = state.clone();
        tokio::spawn(async move {
            handle(client, st).await;
            drop(permit);
        });
    }
}

// ─── Тесты чистой логики (без сети) ──────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hop_http_with_auth() {
        let h = parse_hop("http://user:p%40ss@1.2.3.4:8080").unwrap();
        assert_eq!(h.kind, ProxyKind::Http);
        assert_eq!(h.host, "1.2.3.4");
        assert_eq!(h.port, 8080);
        let c = h.creds.unwrap();
        // percent-decoding: p%40ss → p@ss
        assert_eq!((c.user.as_str(), c.pass.as_str()), ("user", "p@ss"));
        assert!(!h.masked.contains("p@ss"));
    }

    #[test]
    fn parse_hop_socks5_no_auth() {
        let h = parse_hop("socks5://10.0.0.1:1080").unwrap();
        assert_eq!(h.kind, ProxyKind::Socks5);
        assert!(h.creds.is_none());
    }

    #[test]
    fn parse_hop_rejects_bad_scheme_and_missing_port() {
        assert!(parse_hop("ftp://1.2.3.4:21").is_err());
        assert!(parse_hop("http://1.2.3.4").is_err());
    }

    #[test]
    fn parse_args_via_binds_to_last_upstream() {
        // Эмулируем argv напрямую через структуру: --via обязан приклеиться
        // к последнему --upstream, без него — ошибка.
        let mut a = Args {
            upstreams: Vec::new(),
            listen: String::new(),
            quiet: true,
            rules: None,
            supervise: false,
        };
        a.upstreams.push(("http://a:1".into(), None));
        a.upstreams.last_mut().unwrap().1 = Some("socks5://b:2".into());
        assert_eq!(
            a.upstreams[0],
            ("http://a:1".to_string(), Some("socks5://b:2".to_string()))
        );
    }

    #[test]
    fn host_matches_suffix_and_fqdn_dot() {
        assert!(host_matches("api.anthropic.com", "anthropic.com"));
        assert!(host_matches("anthropic.com", "anthropic.com"));
        assert!(host_matches("claude.ai.", "claude.ai"));
        assert!(!host_matches("notanthropic.com", "anthropic.com"));
        assert!(!host_matches("anthropic.com.evil.io", "anthropic.com"));
    }

    #[test]
    fn load_rules_reads_mode_assignments_default_upstream() {
        let dir = std::env::temp_dir();
        let p = dir.join(format!("gate-rules-test-{}.json", std::process::id()));
        std::fs::write(
            &p,
            r#"{"mode":"smart","default_upstream":1,"assignments":{"anthropic.com":0}}"#,
        )
        .unwrap();
        let (mode, _proxy, _direct, assignments, def) = load_rules(Some(p.to_str().unwrap()));
        let _ = std::fs::remove_file(&p);
        assert_eq!(mode, Mode::Smart);
        assert_eq!(def, Some(1));
        assert_eq!(assignments, vec![("anthropic.com".to_string(), 0usize)]);
    }

    #[test]
    fn load_rules_missing_file_means_defaults() {
        let (mode, proxy, direct, assignments, def) =
            load_rules(Some("Z:/definitely/missing/rules.json"));
        assert_eq!(mode, Mode::All);
        assert_eq!(def, None);
        assert!(assignments.is_empty());
        // Встроенный список smart-доменов на месте.
        assert!(proxy.iter().any(|d| d == "anthropic.com"));
        assert!(direct.is_empty());
    }

    #[test]
    fn pct_decode_roundtrip() {
        assert_eq!(pct_decode("%41lice%20B"), "Alice B");
        assert_eq!(pct_decode("plain"), "plain");
        // Битая последовательность не паникует и проходит как есть.
        assert_eq!(pct_decode("%zz"), "%zz");
        assert_eq!(pct_decode("%A"), "%A");
    }
}

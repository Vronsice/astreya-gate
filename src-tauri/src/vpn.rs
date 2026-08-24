//! Встроенный VPN-менеджер на движке sing-box (тот же, что в NekoBox).
//!
//! Архитектура: приложение хранит подписки и одиночные конфиги (ссылки),
//! парсит их в ноды, а для активной ноды генерирует минимальный конфиг
//! sing-box и держит процесс на локальном порту (по умолчанию 2080,
//! inbound mixed socks+http). Дальше этот порт — просто прокси в пуле
//! моста: default_upstream смотрит сюда, вся система ходит через VPN.
//!
//! Мониторинг: clash_api sing-box (`/connections`) даёт суммарные счётчики
//! трафика — фронт считает скорости по дельтам, как для моста.

use serde::{Deserialize, Serialize};

// ─── Модели ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnSubscription {
    pub id: String,
    pub name: String,
    pub url: String,
    /// Интервал автообновления в часах (0 = только вручную).
    #[serde(default)]
    pub interval_hours: u64,
    #[serde(default)]
    pub last_update: Option<u64>,
}

/// Узел VPN. Хранится ИСХОДНАЯ ссылка — параметры протокола парсим при
/// генерации конфига, чтобы не дублировать десяток полей каждого протокола.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnNode {
    pub id: String,
    pub name: String,
    /// Полная ссылка: vless://… / vmess://… / ss://… / trojan://… /
    /// hysteria2://… / tuic://…
    pub link: String,
    /// Короткое имя протокола для UI ("vless", "vmess", …).
    pub proto: String,
    pub server: String,
    pub port: u16,
    /// id подписки или "manual".
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub added_at: u64,
}

/// Результат разбора ссылки.
#[derive(Debug)]
pub struct ParsedLink {
    pub name: String,
    pub proto: &'static str,
    pub server: String,
    pub port: u16,
    /// Outbound-объект для конфига sing-box (тег проставит генератор).
    pub outbound: serde_json::Value,
}

// ─── Утилиты ─────────────────────────────────────────────────────

const SCHEMES: &[(&str, &str)] = &[
    ("vless", "vless"),
    ("vmess", "vmess"),
    ("ss", "ss"),
    ("trojan", "trojan"),
    ("hysteria2", "hysteria2"),
    ("hy2", "hysteria2"),
    ("tuic", "tuic"),
];

/// Распознать схему ссылки; вернуть каноничное имя протокола.
pub fn detect_scheme(link: &str) -> Option<&'static str> {
    let lower = link.trim().to_ascii_lowercase();
    for (s, canon) in SCHEMES {
        if lower.starts_with(&format!("{s}://")) {
            return Some(canon);
        }
    }
    None
}

/// Base64 в любом распространённом виде (std/urlsafe, c паддингом и без).
fn b64_any(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let t: String = s.trim().chars().filter(|c| !c.is_whitespace()).collect();
    if let Ok(v) = base64::engine::general_purpose::STANDARD.decode(&t) {
        return Ok(v);
    }
    if let Ok(v) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&t) {
        return Ok(v);
    }
    let padded = match t.len() % 4 {
        2 => format!("{t}=="),
        3 => format!("{t}="),
        _ => t.clone(),
    };
    base64::engine::general_purpose::STANDARD
        .decode(&padded)
        .map_err(|e| format!("base64: {e}"))
}

fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(&bytes[i + 1..i + 3]), 16)
            {
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

/// Плоский доступ к query-параметрам без url-crate (ссылки бывают «грязными»).
struct Query(std::collections::HashMap<String, String>);

impl Query {
    fn parse(q: &str) -> Self {
        let mut m = std::collections::HashMap::new();
        for pair in q.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            m.entry(k.to_ascii_lowercase())
                .or_insert_with(|| pct_decode(v));
        }
        Query(m)
    }
    fn get(&self, k: &str) -> Option<&str> {
        self.0.get(k).map(|s| s.as_str())
    }
    fn get_or(&self, k: &str, d: &str) -> String {
        self.get(k).unwrap_or(d).to_string()
    }
    fn truthy(&self, k: &str) -> bool {
        matches!(self.get(k), Some("1") | Some("true"))
    }
    fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
}

/// Уже отрезанная от схемы ссылка: тело/query/fragment.
struct RawLink<'a> {
    body: &'a str,
    query: &'a str,
    fragment: &'a str,
}

fn split_link<'a>(rest: &'a str) -> RawLink<'a> {
    let after = rest;
    let (before_frag, fragment) = match after.split_once('#') {
        Some((a, b)) => (a, b),
        None => (after, ""),
    };
    let (before_q, query) = match before_frag.split_once('?') {
        Some((a, b)) => (a, b),
        None => (before_frag, ""),
    };
    // body без пути ("/" после host:port у hysteria2 и пр.)
    let body = before_q.split('/').next().unwrap_or(before_q);
    RawLink {
        body,
        query,
        fragment,
    }
}

fn userpass(body: &str) -> (String, String) {
    match body.split_once(':') {
        Some((u, p)) => (pct_decode(u), pct_decode(p)),
        None => (pct_decode(body), String::new()),
    }
}

fn hostport(body: &str) -> Result<(String, u16), String> {
    let at = body.rfind('@').map(|i| i + 1).unwrap_or(0);
    let hp = &body[at..];
    let (host, port_s) = hp.rsplit_once(':').ok_or("нет порта")?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port_s.parse().map_err(|_| "битый порт")?;
    Ok((host.to_string(), port))
}

// ─── Парсеры протоколов ──────────────────────────────────────────

/// TLS-блок из query: security=tls|reality (+utls fp, insecure).
/// sni в ссылке без security= трактуем как tls — так делают все клиенты.
fn tls_block(q: &Query, sni_default: &str) -> Option<serde_json::Value> {
    let sec = q.get("security").unwrap_or("").to_ascii_lowercase();
    let has_reality = q.has("pbk");
    let enabled =
        sec == "tls" || sec == "reality" || has_reality || (sec.is_empty() && q.has("sni"));
    if !enabled {
        return None;
    }
    let reality = sec == "reality" || has_reality;
    let sni = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .unwrap_or(sni_default)
        .to_string();
    let mut t = serde_json::json!({ "enabled": true, "server_name": sni });
    if q.truthy("insecure") || q.truthy("allowinsecure") {
        t["insecure"] = serde_json::json!(true);
    }
    if let Some(fp) = q.get("fp").filter(|s| !s.is_empty()) {
        t["utls"] = serde_json::json!({ "enabled": true, "fingerprint": fp });
    } else if reality {
        // Reality-клиент в sing-box требует uTLS — ставим дефолтный отпечаток.
        t["utls"] = serde_json::json!({ "enabled": true, "fingerprint": "chrome" });
    }
    if reality {
        t["reality"] = serde_json::json!({
            "enabled": true,
            "public_key": q.get_or("pbk", ""),
            "short_id": q.get_or("sid", ""),
        });
    }
    Some(t)
}

/// Транспорт (ws/grpc/http/httpupgrade) из query; tcp → None.
fn transport_block(q: &Query, net: &str) -> Option<serde_json::Value> {
    match net {
        "ws" | "websocket" => {
            let mut t = serde_json::json!({ "type": "ws", "path": q.get_or("path", "/") });
            let host = q.get_or("host", "");
            if !host.is_empty() {
                t["headers"] = serde_json::json!({ "Host": host });
            }
            Some(t)
        }
        "grpc" => {
            let sn = q.get_or("servicename", "");
            let service_name = if sn.is_empty() { q.get_or("path", "") } else { sn };
            Some(serde_json::json!({
                "type": "grpc",
                "service_name": service_name,
            }))
        }
        "http" | "h2" => {
            let host = q.get_or("host", "");
            let hosts: Vec<String> = if host.is_empty() { vec![] } else { vec![host] };
            Some(serde_json::json!({
                "type": "http",
                "host": hosts,
                "path": q.get_or("path", "/"),
            }))
        }
        "httpupgrade" => {
            let mut t =
                serde_json::json!({ "type": "httpupgrade", "path": q.get_or("path", "/") });
            let host = q.get_or("host", "");
            if !host.is_empty() {
                t["host"] = serde_json::json!(host);
            }
            Some(t)
        }
        _ => None,
    }
}

fn name_from(fragment: &str, host: &str, port: u16) -> String {
    if fragment.is_empty() {
        format!("{host}:{port}")
    } else {
        pct_decode(fragment)
    }
}

fn parse_vless(rest: &str) -> Result<ParsedLink, String> {
    // vless://uuid@host:port?type=…&security=…&pbk=…&flow=…#name
    let raw = split_link(rest);
    let at = raw.body.find('@').ok_or("vless: нет @")?;
    let uuid = raw.body[..at].to_string();
    let (host, port) = hostport(&raw.body[at + 1..])?;
    let q = Query::parse(raw.query);
    let net = q.get_or("type", "tcp");

    let mut o = serde_json::json!({
        "type": "vless",
        "server": host,
        "server_port": port,
        "uuid": uuid,
    });
    let flow = q.get_or("flow", "");
    if !flow.is_empty() {
        o["flow"] = serde_json::json!(flow);
    }
    if let Some(tls) = tls_block(&q, &host) {
        // ALPN из ссылки (через ';'), если провайдер указал.
        if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
            let list: Vec<&str> = alpn.split(';').filter(|s| !s.is_empty()).collect();
            if !list.is_empty() {
                let mut t = tls.clone();
                t["alpn"] = serde_json::json!(list);
                o["tls"] = t;
            } else {
                o["tls"] = tls;
            }
        } else {
            o["tls"] = tls;
        }
    }
    if net == "xhttp" || net == "splithttp" {
        return Err(
            "транспорт XHTTP не поддерживается движком sing-box — выберите Reality/TCP-вариант ноды"
                .into(),
        );
    }
    if let Some(tr) = transport_block(&q, &net) {
        o["transport"] = tr;
    }
    Ok(ParsedLink {
        name: name_from(raw.fragment, &host, port),
        proto: "vless",
        server: host,
        port,
        outbound: o,
    })
}

fn parse_trojan(rest: &str) -> Result<ParsedLink, String> {
    // trojan://password@host:port?sni=&type=tcp#name
    let raw = split_link(rest);
    let at = raw.body.find('@').ok_or("trojan: нет @")?;
    let password = pct_decode(&raw.body[..at]);
    let (host, port) = hostport(&raw.body[at + 1..])?;
    let q = Query::parse(raw.query);
    let net = q.get_or("type", "tcp");

    let mut o = serde_json::json!({
        "type": "trojan",
        "server": host,
        "server_port": port,
        "password": password,
    });
    // Trojan без TLS бессмысленен; security=none встречается редко — уважаем.
    if q.get("security").map(|s| s.eq_ignore_ascii_case("none")) != Some(true) {
        o["tls"] = tls_block(&q, &host).unwrap_or_else(|| {
            serde_json::json!({ "enabled": true, "server_name": q.get_or("sni", &host) })
        });
    }
    if let Some(tr) = transport_block(&q, &net) {
        o["transport"] = tr;
    }
    Ok(ParsedLink {
        name: name_from(raw.fragment, &host, port),
        proto: "trojan",
        server: host,
        port,
        outbound: o,
    })
}

fn parse_ss(rest: &str) -> Result<ParsedLink, String> {
    // Варианты:
    //   ss://base64(method:pass)@host:port#name
    //   ss://base64(method:pass@host:port)#name   (целиком закодировано)
    //   ss://method:pass@host:port#name           (редкий открытый)
    let raw = split_link(rest);
    let body = raw.body;
    let (method, pass, host, port) = if body.contains('@') {
        let at = body.rfind('@').unwrap();
        let userinfo = &body[..at];
        let decoded = match b64_any(userinfo) {
            Ok(v) => String::from_utf8_lossy(&v).to_string(),
            Err(_) => pct_decode(userinfo),
        };
        let (m, p) = userpass(&decoded);
        let (h, pt) = hostport(&body[at + 1..])?;
        (m, p, h, pt)
    } else {
        let full = String::from_utf8_lossy(&b64_any(body)?).to_string();
        let at = full.rfind('@').ok_or("ss: не удалось разобрать")?;
        let (mp, hp) = (&full[..at], &full[at + 1..]);
        let (m, p) = userpass(mp);
        let (h, pt) = hostport(hp)?;
        (m, p, h, pt)
    };
    if method.is_empty() || pass.is_empty() {
        return Err("ss: пустые method/password".into());
    }
    let o = serde_json::json!({
        "type": "shadowsocks",
        "server": host,
        "server_port": port,
        "method": method,
        "password": pass,
    });
    Ok(ParsedLink {
        name: name_from(raw.fragment, &host, port),
        proto: "ss",
        server: host,
        port,
        outbound: o,
    })
}

/// Мини-urlencoded для сборки Query из полей vmess-json.
fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/'
            | b'?' | b'&' | b'=' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn parse_vmess(rest: &str) -> Result<ParsedLink, String> {
    // Канонический вид: vmess://base64(json{v,ps,add,port,id,aid,scy,net,…})
    // Альтернативный (некоторые клиенты): vmess://uuid@host:port?query#name
    let raw = split_link(rest);
    if raw.body.contains('@') {
        return parse_vmess_vless_style(rest);
    }
    let json_bytes = b64_any(raw.body)?;
    let v: serde_json::Value = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("vmess: битый JSON внутри base64: {e}"))?;
    let get_s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(|s| s.to_string());
    let get_i = |k: &str| -> u16 {
        v.get(k)
            .and_then(|x| x.as_u64())
            .or_else(|| v.get(k).and_then(|x| x.as_str()).and_then(|s| s.parse().ok()))
            .unwrap_or(0) as u16
    };
    let host = get_s("add").ok_or("vmess: нет add")?;
    let port = get_i("port");
    if port == 0 {
        return Err("vmess: порт 0".into());
    }
    let uuid = get_s("id").ok_or("vmess: нет id")?;
    let aid: u32 = v
        .get("aid")
        .and_then(|x| x.as_u64())
        .or_else(|| get_s("aid").and_then(|s| s.parse().ok()))
        .unwrap_or(0) as u32;
    let security = get_s("scy")
        .or_else(|| get_s("security"))
        .unwrap_or_else(|| "auto".into());

    let mut o = serde_json::json!({
        "type": "vmess",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "security": security,
        "alter_id": aid,
    });
    let net = get_s("net").unwrap_or_else(|| "tcp".into());
    let tls_on = matches!(get_s("tls").as_deref(), Some("tls") | Some("1") | Some("true"));
    if tls_on {
        let sni = get_s("sni").unwrap_or_else(|| host.clone());
        let mut t = serde_json::json!({ "enabled": true, "server_name": sni });
        if let Some(fp) = get_s("fp").filter(|s| !s.is_empty()) {
            t["utls"] = serde_json::json!({ "enabled": true, "fingerprint": fp });
        }
        let insecure = get_s("allowinsecure")
            .or_else(|| get_s("insecure"))
            .map(|s| s == "1" || s == "true")
            .unwrap_or(false);
        if insecure {
            t["insecure"] = serde_json::json!(true);
        }
        o["tls"] = t;
    }
    // Транспорт из плоских полей vmess-json.
    let qq = Query::parse(&format!(
        "type={net}&path={}&host={}&serviceName={}",
        urlencode(get_s("path").as_deref().unwrap_or("")),
        urlencode(get_s("host").as_deref().unwrap_or("")),
        urlencode(get_s("path").as_deref().unwrap_or("")),
    ));
    if let Some(tr) = transport_block(&qq, &net) {
        o["transport"] = tr;
    }
    let ps = get_s("ps").unwrap_or_default();
    Ok(ParsedLink {
        name: if ps.is_empty() {
            format!("{host}:{port}")
        } else {
            ps
        },
        proto: "vmess",
        server: host,
        port,
        outbound: o,
    })
}

/// vmess://uuid@host:port?… (не-base64 вариант): почти как vless.
fn parse_vmess_vless_style(rest: &str) -> Result<ParsedLink, String> {
    let mut parsed = parse_vless(rest)?;
    parsed.proto = "vmess";
    let mut o = parsed.outbound.clone();
    o["type"] = serde_json::json!("vmess");
    o["security"] = serde_json::json!("auto");
    o["alter_id"] = serde_json::json!(0);
    parsed.outbound = o;
    Ok(parsed)
}

fn parse_hysteria2(rest: &str) -> Result<ParsedLink, String> {
    // hysteria2://auth@host:port/?insecure=1&sni=x&obfs=salamander&obfs-password=y#name
    let raw = split_link(rest);
    let at = raw.body.find('@').ok_or("hy2: нет @")?;
    let auth = pct_decode(&raw.body[..at]);
    let (host, port) = hostport(&raw.body[at + 1..])?;
    let q = Query::parse(raw.query);

    let mut o = serde_json::json!({
        "type": "hysteria2",
        "server": host,
        "server_port": port,
        "password": auth,
        "tls": {
            "enabled": true,
            "server_name": q.get_or("sni", &host),
            "insecure": q.truthy("insecure"),
        },
    });
    if q.get_or("obfs", "") == "salamander" && q.has("obfs-password") {
        o["obfs"] = serde_json::json!({
            "type": "salamander",
            "password": q.get_or("obfs-password", ""),
        });
    }
    Ok(ParsedLink {
        name: name_from(raw.fragment, &host, port),
        proto: "hysteria2",
        server: host,
        port,
        outbound: o,
    })
}

fn parse_tuic(rest: &str) -> Result<ParsedLink, String> {
    // tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=#name
    let raw = split_link(rest);
    let at = raw.body.find('@').ok_or("tuic: нет @")?;
    let (uuid, password) = userpass(&raw.body[..at]);
    let (host, port) = hostport(&raw.body[at + 1..])?;
    let q = Query::parse(raw.query);

    let alpn = q.get_or("alpn", "h3");
    let o = serde_json::json!({
        "type": "tuic",
        "server": host,
        "server_port": port,
        "uuid": uuid,
        "password": password,
        "congestion_control": q.get_or("congestion_control", "bbr"),
        "udp_relay_mode": q.get_or("udp_relay_mode", "native"),
        "tls": {
            "enabled": true,
            "server_name": q.get_or("sni", &host),
            "alpn": alpn.split(';').filter(|s| !s.is_empty()).collect::<Vec<_>>(),
        },
    });
    Ok(ParsedLink {
        name: name_from(raw.fragment, &host, port),
        proto: "tuic",
        server: host,
        port,
        outbound: o,
    })
}

/// Главная точка входа: ссылка → ParsedLink (имя/протокол/хост/outbound).
pub fn parse_link(link: &str) -> Result<ParsedLink, String> {
    let link = link.trim();
    let canon = detect_scheme(link).ok_or(
        "неизвестная схема (нужна vless/vmess/ss/trojan/hysteria2/hy2/tuic)",
    )?;
    // Отрезаем схему по её ФАКТИЧЕСКОЙ длине (hy2:// короче hysteria2://).
    let sep = link.find("://").unwrap();
    let rest = &link[sep + 3..];
    match canon {
        "vless" => parse_vless(rest),
        "trojan" => parse_trojan(rest),
        "ss" => parse_ss(rest),
        "vmess" => parse_vmess(rest),
        "hysteria2" => parse_hysteria2(rest),
        "tuic" => parse_tuic(rest),
        _ => unreachable!("detect_scheme отдал неизвестную схему"),
    }
}

// ─── Подписки ────────────────────────────────────────────────────

/// Разобрать тело подписки в список сырых ссылок:
///   1) base64-блоб ссылок
///   2) plain-текст построчно
///   3) JSON-массив конфигов v2rayN (fmt=best у суб-конвертеров): каждый
///      элемент — полный конфиг с outbounds; конвертируем ОБРАТНО в
///      канонические ссылки, чтобы вся остальная архитектура (хранение,
///      UI, генерация конфига) осталась без изменений.
pub fn parse_subscription_body(body: &str) -> Vec<String> {
    let trimmed = body.trim();
    // v2rayN-массив: начинается с '[' и внутри есть outbounds.
    if trimmed.starts_with('[') {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) {
            if v.is_array() {
                let links: Vec<String> = v
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(v2rayn_config_to_link)
                    .collect();
                if !links.is_empty() {
                    return links;
                }
            }
        }
    }
    let text = match b64_any(body) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).to_string(),
        Err(_) => body.to_string(),
    };
    text.lines()
        .map(|l| l.trim().to_string())
        .filter(|l| detect_scheme(l).is_some())
        .collect()
}

// ─── Конвертер v2rayN-config → ссылка ───────────────────────────

/// Из одного элемента массива v2rayN вытащить основной outbound и собрать
/// каноническую ссылку протокола. None — протокол/транспорт не поддерживаем.
///
/// Выбор outbound'а: в одном конфиге бывает несколько вариантов одной ноды
/// (proxy, proxy-1…: reality+vision И xhttp+tls). sing-box не умеет XHTTP
/// (это транспорт Xray-ядра) — такие пропускаем и берём первый СОВМЕСТИМЫЙ,
/// предпочитая тег "proxy".
fn v2rayn_config_to_link(cfg: &serde_json::Value) -> Option<String> {
    let name = cfg
        .get("remarks")
        .and_then(|r| r.as_str())
        .unwrap_or("")
        .to_string();
    let outs = cfg.get("outbounds")?.as_array()?;
    let supported = ["vless", "vmess", "shadowsocks", "trojan", "hysteria2", "tuic"];
    let incompatible_net = ["xhttp", "splithttp"];

    let mut candidates: Vec<&serde_json::Value> = outs
        .iter()
        .filter(|o| {
            let p = o.get("protocol").and_then(|p| p.as_str()).unwrap_or("");
            if !supported.contains(&p) {
                return false;
            }
            let net = o
                .get("streamSettings")
                .and_then(|s| s.get("network"))
                .and_then(|n| n.as_str())
                .unwrap_or("tcp")
                .to_ascii_lowercase();
            !incompatible_net.contains(&net.as_str())
        })
        .collect();
    if candidates.is_empty() {
        return None;
    }
    // Тег "proxy" — главный вариант по конвенции v2rayN.
    if let Some(main) = candidates.iter().position(|o| {
        o.get("tag").and_then(|t| t.as_str()) == Some("proxy")
    }) {
        if main > 0 {
            candidates.rotate_left(main);
        }
    }
    let out = candidates[0];

    let proto = out.get("protocol")?.as_str()?;
    let settings = out.get("settings")?;
    let stream = out.get("streamSettings");

    let net = stream
        .and_then(|s| s.get("network"))
        .and_then(|n| n.as_str())
        .unwrap_or("tcp")
        .to_string();
    let security = stream
        .and_then(|s| s.get("security"))
        .and_then(|s| s.as_str())
        .unwrap_or("none")
        .to_string();
    let tls_s = stream.and_then(|s| s.get("tlsSettings"));
    let real_s = stream.and_then(|s| s.get("realitySettings"));
    let grpc_s = stream.and_then(|s| s.get("grpcSettings"));
    let ws_s = stream.and_then(|s| s.get("wsSettings"));
    let h2_s = stream.and_then(|s| s.get("httpSettings"));

    let sni = real_s
        .and_then(|r| r.get("serverName"))
        .or_else(|| tls_s.and_then(|t| t.get("serverName")))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    let fp = real_s
        .and_then(|r| r.get("fingerprint"))
        .or_else(|| tls_s.and_then(|t| t.get("fingerprint")))
        .and_then(|s| s.as_str())
        .unwrap_or("chrome");
    let insecure = tls_s
        .and_then(|t| t.get("allowInsecure"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false);

    let mut q: Vec<(String, String)> = Vec::new();
    let mut push = |k: &str, v: &str| {
        if !v.is_empty() {
            q.push((k.to_string(), urlencode(v)));
        }
    };

    match proto {
        "vless" => {
            let vnext = settings.get("vnext")?.as_array()?.first()?.clone();
            let host = vnext.get("address")?.as_str()?.to_string();
            let port = vnext.get("port")?.as_u64()? as u16;
            let user = vnext.get("users")?.as_array()?.first()?.clone();
            let uuid = user.get("id")?.as_str()?.to_string();
            let flow = user.get("flow").and_then(|f| f.as_str()).unwrap_or("");
            push("encryption", "none");
            if security == "reality" {
                push("security", "reality");
                push("sni", sni);
                push("fp", fp);
                if let Some(pbk) = real_s.and_then(|r| r.get("publicKey")).and_then(|s| s.as_str()) {
                    push("pbk", pbk);
                }
                if let Some(sid) = real_s.and_then(|r| r.get("shortId")).and_then(|s| s.as_str()) {
                    push("sid", sid);
                }
            } else if security == "tls" {
                push("security", "tls");
                push("sni", sni);
                if insecure {
                    push("allowInsecure", "1");
                }
            }
            if !flow.is_empty() {
                push("flow", flow);
            }
            push("type", &net);
            if let Some(p) = ws_s.and_then(|w| w.get("path")).and_then(|s| s.as_str()) {
                push("path", p);
            }
            if let Some(h) = ws_s
                .and_then(|w| w.get("headers"))
                .and_then(|h| h.get("Host"))
                .and_then(|s| s.as_str())
            {
                push("host", h);
            }
            if let Some(sn) = grpc_s.and_then(|g| g.get("serviceName")).and_then(|s| s.as_str()) {
                push("serviceName", sn);
            }
            let frag = urlencode(&name);
            Some(format!("vless://{uuid}@{host}:{port}?{}#{frag}", qs(&q)))
        }
        "vmess" => {
            let vnext = settings.get("vnext")?.as_array()?.first()?.clone();
            let host = vnext.get("address")?.as_str()?.to_string();
            let port = vnext.get("port")?.as_u64()? as u16;
            let user = vnext.get("users")?.as_array()?.first()?.clone();
            let id = user.get("id")?.as_str()?.to_string();
            let aid = user.get("alterId").and_then(|a| a.as_u64()).unwrap_or(0);
            let scy = user
                .get("security")
                .and_then(|s| s.as_str())
                .unwrap_or("auto");
            let tls_flag = if security == "tls" || security == "reality" { "tls" } else { "" };
            let payload = serde_json::json!({
                "v": "2",
                "ps": name,
                "add": host,
                "port": port.to_string(),
                "id": id,
                "aid": aid.to_string(),
                "scy": scy,
                "net": net,
                "type": "",
                "host": ws_s
                    .and_then(|w| w.get("headers"))
                    .and_then(|h| h.get("Host"))
                    .and_then(|s| s.as_str())
                    .unwrap_or(""),
                "path": ws_s.and_then(|w| w.get("path")).and_then(|s| s.as_str()).unwrap_or(""),
                "tls": tls_flag,
                "sni": sni,
                "fp": fp,
            });
            use base64::Engine;
            Some(format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(payload.to_string())
            ))
        }
        "shadowsocks" => {
            let srv = settings.get("servers")?.as_array()?.first()?.clone();
            let host = srv.get("address")?.as_str()?.to_string();
            let port = srv.get("port")?.as_u64()? as u16;
            let method = srv.get("method")?.as_str()?.to_string();
            let pass = srv.get("password")?.as_str()?.to_string();
            use base64::Engine;
            let ui = base64::engine::general_purpose::STANDARD
                .encode(format!("{method}:{pass}"));
            let frag = urlencode(&name);
            Some(format!("ss://{ui}@{host}:{port}#{frag}"))
        }
        "trojan" => {
            let srv = settings.get("servers")?.as_array()?.first()?.clone();
            let host = srv.get("address")?.as_str()?.to_string();
            let port = srv.get("port")?.as_u64()? as u16;
            let pass = srv.get("password")?.as_str()?.to_string();
            if security != "none" {
                push("security", "tls");
            }
            push("sni", sni);
            if insecure {
                push("allowInsecure", "1");
            }
            push("type", &net);
            let frag = urlencode(&name);
            Some(format!("trojan://{}@{host}:{port}?{}#{frag}", urlencode(&pass), qs(&q)))
        }
        // Остальные (hysteria2/tuic в v2rayN-формате редки и нестандартны) —
        // нода пропускается, остальные из массива импортируются.
        _ => None,
    }
}

/// Собрать query-строку из пар (значения уже urlencoded).
fn qs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Похоже ли тело на HTML-заглушку (антибот/ошибка провайдера).
fn looks_like_html(s: &str) -> bool {
    let head = s.trim_start().to_ascii_lowercase();
    head.starts_with("<!doctype") || head.starts_with("<html")
}

/// Скачать тело подписки. Цепочка попыток:
///   1) напрямую с нашим UA
///   2) напрямую с UA v2rayN (часть провайдеров отдаёт контент только
///      «своим» клиентам, иначе — HTML-заглушку)
///   3) через мост (подписка закрыта для прямого доступа без VPN)
pub async fn fetch_subscription(url: &str) -> Result<String, String> {
    let attempts: [(&str, bool); 3] = [
        ("AstreyaGate/1.0", false),
        ("v2rayN/6.45", false),
        ("AstreyaGate/1.0", true),
    ];
    let mut last_err = String::new();
    for (ua, via_bridge) in attempts {
        let mut builder = reqwest::Client::builder()
            .user_agent(ua)
            .timeout(std::time::Duration::from_secs(if via_bridge { 25 } else { 20 }));
        if via_bridge {
            let proxy = reqwest::Proxy::all(format!(
                "http://127.0.0.1:{}",
                crate::shim::LISTEN_PORT
            ))
            .map_err(|e| format!("bridge proxy: {e}"))?;
            builder = builder.proxy(proxy);
        }
        let client = builder.build().map_err(|e| format!("client: {e}"))?;
        match client.get(url).send().await {
            Ok(resp) => match resp.text().await {
                Ok(text) if !text.trim().is_empty() && !looks_like_html(&text) => {
                    return Ok(text);
                }
                Ok(_) => last_err = format!("UA {ua}: пустой ответ или HTML-заглушка"),
                Err(e) => last_err = format!("UA {ua}: тело не прочитано ({e})"),
            },
            Err(e) => last_err = format!("UA {ua}: {e}"),
        }
    }
    Err(format!("прямая и через мост недоступны ({last_err})"))
}

/// Уникальный id ноды/подписки: хеш строки + наносекунды.
pub fn node_id(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    h.write_u32(t);
    format!("n{:016x}", h.finish())
}

// ─── Генерация конфига sing-box ─────────────────────────────────

pub const VPN_PORT_DEFAULT: u16 = 2080;
pub const CLASH_API_PORT: u16 = 29090;

/// Полный конфиг sing-box для активной ноды: mixed-in на vpn_port,
/// outbound ноды (tag=proxy), direct-fallback, route по выбранному режиму,
/// clash_api для мониторинга трафика и delay-тестов.
pub fn build_config(
    node_outbound: serde_json::Value,
    port: u16,
    mode: TunnelRoute,
    whitelist: &[String],
) -> Result<serde_json::Value, String> {
    let mut o = node_outbound;
    o["tag"] = serde_json::json!("proxy");
    let rules = route_rules(mode, whitelist);
    let mut route = serde_json::json!({ "final": "proxy" });
    if !rules.is_empty() {
        route["rules"] = serde_json::json!(rules);
    }
    Ok(serde_json::json!({
        "log": { "level": "error" },
        "experimental": { "clash_api": { "external_controller": format!("127.0.0.1:{CLASH_API_PORT}") } },
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": port,
        }],
        "outbounds": [o, { "type": "direct", "tag": "direct" }],
        "route": route,
    }))
}

// ─── Процесс sing-box ────────────────────────────────────────────

use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

fn exe_path() -> Result<std::path::PathBuf, String> {
    // 1) Установленное приложение: resources/ рядом с нашим exe
    //    (%LOCALAPPDATA%\Programs\Astreya Gate\resources\sing-box.exe).
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let installed = dir.join("resources").join("sing-box.exe");
            if installed.exists() {
                return Ok(installed);
            }
        }
    }
    // 2) Dev-режим: resources/ рядом с манифестом крейта.
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let dev =
            std::path::PathBuf::from(dir).join("resources").join("sing-box.exe");
        if dev.exists() {
            return Ok(dev);
        }
    }
    Err("sing-box.exe не найден в ресурсах приложения — переустановите Astreya Gate".into())
}

fn config_dir() -> Result<std::path::PathBuf, String> {
    let d = dirs::config_dir()
        .ok_or_else(|| "не найден %APPDATA%".to_string())?
        .join("Astreya Gate")
        .join("sing-box");
    std::fs::create_dir_all(&d).map_err(|e| format!("mkdir: {e}"))?;
    Ok(d)
}

/// Запущен ли sing-box прямо сейчас (+PID/uptime).
#[derive(Debug, Clone, Serialize)]
pub struct VpnProcessStatus {
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_sec: Option<u64>,
}

pub fn process_status() -> VpnProcessStatus {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);
    for (_pid, proc) in sys.processes() {
        if proc.name().eq_ignore_ascii_case("sing-box.exe") {
            let now_epoch = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            return VpnProcessStatus {
                running: true,
                pid: Some(proc.pid().as_u32()),
                uptime_sec: Some(now_epoch.saturating_sub(proc.start_time())),
            };
        }
    }
    VpnProcessStatus {
        running: false,
        pid: None,
        uptime_sec: None,
    }
}

/// Запустить sing-box с конфигом активной ноды. Возвращает имя активной ноды.
pub fn start(active_node_link: &str, port: u16) -> Result<String, String> {
    let s = crate::settings::load();
    start_routed(
        active_node_link,
        port,
        TunnelRoute::from_str(&s.vpn_route_mode),
        &s.vpn_whitelist_sites,
    )
}

/// Собрать профиль из ВСЕХ валидных нод (selector-режим: мгновенное
/// переключение активной через clash-api) и скомпилировать конфиг.
fn compile_live_config(
    port: Option<u16>,
    tun: bool,
    mode: TunnelRoute,
    whitelist: &[String],
    active_node_link: &str,
) -> Result<(serde_json::Value, String), String> {
    let s = crate::settings::load();
    let mut nodes: Vec<crate::routing::NodeExit> = Vec::new();
    for n in &s.vpn_nodes {
        // Битые ссылки пропускаем — профиль собирается из живых.
        if parse_link(&n.link).is_ok() {
            nodes.push(crate::routing::NodeExit {
                id: n.id.clone(),
                name: n.name.clone(),
                link: n.link.clone(),
            });
        }
    }
    // Активная: по id из настроек, иначе по переданной ссылке.
    let mut active_id = s.vpn_active.clone();
    if !active_id
        .as_deref()
        .map(|id| nodes.iter().any(|n| n.id == id))
        .unwrap_or(false)
    {
        active_id = s
            .vpn_nodes
            .iter()
            .find(|n| n.link == active_node_link)
            .map(|n| n.id.clone());
    }
    let mut active_name = String::from("нода");
    if !active_id
        .as_deref()
        .map(|id| nodes.iter().any(|n| n.id == id))
        .unwrap_or(false)
    {
        // Ручная ссылка, которой нет в списке, — добавляем как отдельный выход.
        let parsed = parse_link(active_node_link)?;
        active_name = parsed.name.clone();
        nodes.push(crate::routing::NodeExit {
            id: String::from("active"),
            name: parsed.name,
            link: active_node_link.to_string(),
        });
        active_id = Some(String::from("active"));
    } else if let Some(id) = &active_id {
        if let Some(n) = s.vpn_nodes.iter().find(|n| &n.id == id) {
            active_name = n.name.clone();
        }
    }

    let profile = crate::routing::profile_from_nodes(
        String::from("live"),
        nodes,
        active_id,
        port,
        tun,
        mode,
        whitelist.to_vec(),
    );
    let cfg = crate::routing::compile(&profile, CLASH_API_PORT)?;
    Ok((cfg, active_name))
}

/// То же с явными параметрами маршрутизации (команды UI передают свежие).
pub fn start_routed(
    active_node_link: &str,
    port: u16,
    mode: TunnelRoute,
    whitelist: &[String],
) -> Result<String, String> {
    // Порт занят ДРУГИМ процессом (NekoBox/другой VPN-клиент)? Честная
    // ошибка сразу — иначе sing-box упадёт на bind, а проверка «порт
    // открыт?» увидела бы чужой порт и вернула ложный успех.
    if std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        std::time::Duration::from_millis(300),
    )
    .is_ok()
    {
        let who = crate::shim::process_name_on_port(port);
        return Err(format!(
            "порт {port} уже занят ({who}) — остановите другой VPN-клиент или смените порт VPN в настройках"
        ));
    }
    // Перезапуск поверх живого процесса — сначала стоп.
    stop();
    let (cfg, active_name) =
        compile_live_config(Some(port), false, mode, whitelist, active_node_link)?;
    let dir = config_dir()?;
    let cfg_path = dir.join("config.json");
    let text = serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&cfg_path, text).map_err(|e| format!("write config: {e}"))?;

    let exe = exe_path()?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["run", "-c"]).arg(&cfg_path);
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW | DETACHED_PROCESS — одной маской (повторный
        // вызов creation_flags перезаписал бы первый).
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        const DETACHED_PROCESS: u32 = 0x0000_0008;
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS);
    }
    cmd.spawn()
        .map_err(|e| format!("sing-box не запустился: {e}"))?;
    VPN_WANTED.store(true, Ordering::Relaxed);

    // Дать поднять listener; порт — честный признак живого туннеля.
    for _ in 0..20 {
        std::thread::sleep(std::time::Duration::from_millis(300));
        if std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
            std::time::Duration::from_millis(400),
        )
        .is_ok()
        {
            return Ok(active_name);
        }
    }
    Err("sing-box поднялся, но порт не открылся за 6с (нода недоступна или параметры неверны)".into())
}

/// Остановить все процессы sing-box. Возвращает сколько убито.
pub fn stop() -> usize {
    // Ручной стоп снимает ожидание watchdog'а и убирает системный прокси
    // браузеров (иначе он указывал бы на мёртвый порт).
    VPN_WANTED.store(false, Ordering::Relaxed);
    if SYS_PROXY_WANTED.load(Ordering::Relaxed) {
        let _ = sys_proxy_disable();
    }
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);
    let mut killed = 0usize;
    for (_pid, proc) in sys.processes() {
        if proc.name().eq_ignore_ascii_case("sing-box.exe") && proc.kill() {
            killed += 1;
        }
    }
    if killed > 0 {
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    killed
}

// ─── Мониторинг (clash_api) ──────────────────────────────────────

/// Мгновенное переключение активной ноды через selector (clash-api),
/// без перезапуска туннеля. Работает, если конфиг собран компилятором
/// в selector-режиме; иначе вызывающий делает фолбэк на рестарт.
pub async fn switch_node_live(node_id: &str) -> Result<(), String> {
    let tag = format!("node-{node_id}");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .map_err(|e| format!("client: {e}"))?;
    let base = format!("http://127.0.0.1:{CLASH_API_PORT}/proxies/proxy");
    let resp = client
        .put(&base)
        .json(&serde_json::json!({ "name": tag }))
        .send()
        .await
        .map_err(|e| format!("clash-api недоступна: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("clash-api: HTTP {}", resp.status()));
    }
    // Проверяем, что селектор реально переключился.
    let v: serde_json::Value = client
        .get(&base)
        .send()
        .await
        .map_err(|e| format!("clash-api: {e}"))?
        .json()
        .await
        .map_err(|e| format!("clash-api: {e}"))?;
    let now = v.get("now").and_then(|x| x.as_str()).unwrap_or("");
    if now == tag {
        Ok(())
    } else {
        Err(format!("селектор не переключился (now={now})"))
    }
}

/// Суммарный трафик из /connections: байт всего upload/download с запуска.
#[derive(Debug, Clone, Serialize)]
pub struct VpnTraffic {
    pub up_total: u64,
    pub down_total: u64,
}

pub async fn traffic_totals() -> Option<VpnTraffic> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .ok()?;
    let v: serde_json::Value = client
        .get(format!("http://127.0.0.1:{CLASH_API_PORT}/connections"))
        .send()
        .await
        .ok()?
        .json()
        .await
        .ok()?;
    Some(VpnTraffic {
        up_total: v.get("uploadTotal")?.as_u64().unwrap_or(0),
        down_total: v.get("downloadTotal")?.as_u64().unwrap_or(0),
    })
}

/// Реальный delay-тест активной ноды через clash API (как в nekobox):
/// HTTP GET generate_204 сквозь туннель. Возвращает миллисекунды.
pub async fn real_delay_ms(timeout_ms: u64) -> Result<u64, String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_millis(timeout_ms + 1500))
        .build()
        .map_err(|e| format!("client: {e}"))?;
    let started = std::time::Instant::now();
    let url = format!(
        "http://127.0.0.1:{CLASH_API_PORT}/proxies/proxy/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout={timeout_ms}"
    );
    let resp = client.get(url).send().await.map_err(|e| format!("{e}"))?;
    if !resp.status().is_success() {
        let code = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(if body.contains("timeout") || code.as_u16() == 504 {
            "нода не ответила".into()
        } else {
            format!("delay-test: HTTP {code}")
        });
    }
    Ok(started.elapsed().as_millis() as u64)
}

/// Дешёвый TCP-pинг до сервера ноды (без протокола) — для списка всех нод.
pub async fn tcp_ping(server: &str, port: u16, timeout_ms: u64) -> Option<u64> {
    let addr = format!("{server}:{port}");
    let probe = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut a| a.next())
            .and_then(|sa| {
                let t = std::time::Instant::now();
                std::net::TcpStream::connect_timeout(
                    &sa,
                    std::time::Duration::from_millis(timeout_ms),
                )
                .ok()
                .map(|_| t.elapsed().as_millis() as u64)
            })
    });
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms + 2000),
        probe,
    )
    .await
    .ok()
    .and_then(|r| r.ok().flatten())
}

// ─── Режимы маршрутизации туннеля ────────────────────────────────

/// Как трафик ходит ВНУТРИ туннеля sing-box:
///   All       — всё через VPN (дефолт);
///   Smart     — популярные RU-сервисы напрямую, остальное через VPN;
///   Whitelist — через VPN только сайты из списка, остальное напрямую.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelRoute {
    All,
    Smart,
    Whitelist,
}

impl TunnelRoute {
    pub fn from_str(s: &str) -> Self {
        match s {
            "smart" => TunnelRoute::Smart,
            "whitelist" => TunnelRoute::Whitelist,
            _ => TunnelRoute::All,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            TunnelRoute::All => "all",
            TunnelRoute::Smart => "smart",
            TunnelRoute::Whitelist => "whitelist",
        }
    }
}

/// Базовый набор RU-доменов для Smart-режима (суффикс-матч sing-box).
/// Осознанно без geosite-базы: ноль внешних зависимостей при первом запуске.
pub const SMART_DIRECT_DOMAINS: &[&str] = &[
    "yandex.ru", "yandex.net", "ya.ru", "yastatic.net", "yandexcloud.net",
    "mail.ru", "list.ru", "bk.ru", "inbox.ru", "imgsmail.ru",
    "vk.com", "vk.ru", "vkontakte.ru", "userapi.com", "vk-cdn.net", "vkuser.net",
    "ok.ru", "odnoklassniki.ru",
    "sberbank.ru", "sber.ru", "sberbank.com",
    "gosuslugi.ru", "nalog.gov.ru", "moedelo.org",
    "tinkoff.ru", "tbank.ru",
    "avito.ru", "avito.st",
    "wildberries.ru", "wbbasket.ru",
    "ozon.ru", "ozonru.net",
    "mts.ru", "beeline.ru", "rt.ru", "megafon.ru",
    "rutube.ru", "dzen.ru",
    "pochta.ru", "russianpost.ru",
    "mos.ru", "gov.spb.ru",
    "sbis.ru", "kontur.ru",
    "1c.ru", "1c-bitrix.ru",
];

fn route_rules(mode: TunnelRoute, whitelist: &[String]) -> Vec<serde_json::Value> {
    let mut rules = Vec::new();
    match mode {
        TunnelRoute::All => {}
        TunnelRoute::Smart => {
            let domains: Vec<String> =
                SMART_DIRECT_DOMAINS.iter().map(|d| d.to_string()).collect();
            rules.push(serde_json::json!({
                "domain_suffix": domains,
                "outbound": "direct",
            }));
        }
        TunnelRoute::Whitelist => {
            if !whitelist.is_empty() {
                rules.push(serde_json::json!({
                    "domain_suffix": whitelist,
                    "outbound": "proxy",
                }));
            }
        }
    }
    rules
}

// ─── Deep-links (astreya:// и совместимость happ://add) ──────────

/// Что сделать со ссылкой, пришедшей из браузера/буфера.
#[derive(Debug, Clone)]
pub enum Deeplink {
    /// Добавить подписку по URL.
    AddSubscription { name: String, url: String },
    /// Добавить одиночные конфиги (одна или несколько ссылок).
    AddLinks(Vec<String>),
}

/// Разобрать deep-link:
///   astreya://add/<base64url(url)>   |   astreya://<https-url>
///   happ://add/<base64url(url)>      (совместимость со ссылками Happ)
///   happ://crypt2/…                  → ошибка (закрытый формат Happ)
/// Плейн-ссылки протоколов тоже проходят — импорт из буфера тем же путём.
pub fn parse_deeplink(input: &str) -> Result<Deeplink, String> {
    let input = input.trim();
    let lower = input.to_ascii_lowercase();

    if lower.starts_with("happ://crypt") {
        return Err("Зашифрованные happ-crypt ссылки расшифровывает только сам Happ. Попросите у провайдера обычную ссылку подписки.".into());
    }

    // Схема add-импорта: <scheme>add/<payload>
    for scheme in ["astreya://", "happ://"] {
        let with_add = format!("{scheme}add/");
        if lower.starts_with(&with_add) {
            let payload = &input[with_add.len()..];
            let decoded = b64_any(payload).ok().and_then(|v| String::from_utf8(v).ok());
            let candidate = decoded.unwrap_or_else(|| payload.to_string());
            return deeplink_payload_to_action(candidate.trim().to_string());
        }
    }

    // Голая схема без /add/: astreya://https://sub.url
    for scheme in ["astreya://", "happ://"] {
        if lower.starts_with(scheme) && !lower.starts_with(&format!("{scheme}routing")) {
            let rest = input[scheme.len()..].trim_start_matches('/');
            return deeplink_payload_to_action(rest.to_string());
        }
    }

    // Плейн-протокольные ссылки (одна или несколько строк) из буфера обмена.
    let links: Vec<String> = parse_subscription_body(input);
    if !links.is_empty() {
        return Ok(Deeplink::AddLinks(links));
    }
    if input.starts_with("http://") || input.starts_with("https://") {
        return Ok(Deeplink::AddSubscription {
            name: String::new(),
            url: input.to_string(),
        });
    }
    Err("Не похоже на ссылку подписки или конфига".into())
}

fn deeplink_payload_to_action(payload: String) -> Result<Deeplink, String> {
    if payload.is_empty() {
        return Err("Пустой payload deep-link".into());
    }
    if payload.starts_with("http://") || payload.starts_with("https://") {
        return Ok(Deeplink::AddSubscription {
            name: String::new(),
            url: payload,
        });
    }
    let links: Vec<String> = parse_subscription_body(&payload);
    if !links.is_empty() {
        return Ok(Deeplink::AddLinks(links));
    }
    Err("Внутри deep-link не найдено ни URL подписки, ни ссылок конфигов".into())
}

// ─── Фоновое обновление подписок ─────────────────────────────────

/// Общая логика обновления (команда UI и фоновый таймер).
/// Возвращает (кол-во обновлённых подписок, кол-во нод после замены).
pub async fn refresh_subscriptions_inner(
    only_ids: Option<Vec<String>>,
    skip_fresh: bool,
) -> Result<(usize, usize), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut snap = crate::settings::load();
    if snap.vpn_subscriptions.is_empty() {
        return Ok((0, 0));
    }
    let targets: Vec<VpnSubscription> = match &only_ids {
        Some(ids) => snap
            .vpn_subscriptions
            .iter()
            .filter(|x| ids.contains(&x.id))
            .cloned()
            .collect(),
        None => snap.vpn_subscriptions.clone(),
    };

    let mut updated = 0usize;
    for sub in targets {
        // Фоновый прогон уважает интервалы; ручной («Обновить») — нет.
        if skip_fresh {
            if let Some(lu) = sub.last_update {
                if sub.interval_hours > 0
                    && now.saturating_sub(lu) < sub.interval_hours * 3600
                {
                    continue;
                }
            }
        }
        let body =
            fetch_subscription(&sub.url).await.map_err(|e| format!("«{}»: {e}", sub.name))?;
        let links = parse_subscription_body(&body);
        if links.is_empty() {
            return Err(format!("«{}»: в ответе нет ни одной ссылки", sub.name));
        }
        let mut nodes: Vec<VpnNode> = snap
            .vpn_nodes
            .iter()
            .filter(|n| n.source != sub.id)
            .cloned()
            .collect();
        let mut skipped = 0usize;
        let mut skip_reason = String::new();
        for l in links {
            let parsed = match parse_link(&l) {
                Ok(p) => p,
                Err(e) => {
                    skipped += 1;
                    if skip_reason.is_empty() {
                        skip_reason = e;
                    }
                    continue;
                }
            };
            nodes.push(VpnNode {
                id: node_id(&l),
                name: parsed.name,
                link: l,
                proto: parsed.proto.to_string(),
                server: parsed.server,
                port: parsed.port,
                source: sub.id.clone(),
                added_at: now,
            });
        }
        if nodes.is_empty() && skipped > 0 {
            return Err(format!(
                "«{}»: ни одна нода не поддерживается (пример: {skip_reason})",
                sub.name
            ));
        }
        snap.vpn_nodes = nodes;
        if skipped > 0 {
            tracing::info!("подписка «{}»: пропущено нод: {skipped}", sub.name);
        }
        updated += 1;
        let _ = crate::settings::set_vpn_last_update(&sub.id, now);
    }
    crate::settings::set_vpn_data(snap.vpn_subscriptions.clone(), snap.vpn_nodes)?;
    let total = crate::settings::load().vpn_nodes.len();
    Ok((updated, total))
}

// ─── Системный режим (TUN) ───────────────────────────────────────
// Перехват ВСЕГО трафика через виртуальный адаптер (как Happ/TUN-режимы).
// sing-box обязан работать с правами администратора: регистрируем задачу
// Планировщика AstreyaGateTUN c RunLevel Highest (один UAC при включении),
// дальше Start/Stop-ScheduledTask без UAC.

const TUN_TASK: &str = "AstreyaGateTUN";

/// Конфиг TUN-варианта: tun-inbound с auto_route + DNS через туннель +
/// hijack порта 53 + auto_detect_interface (защита от петли) + те же
/// правила маршрутизации, что у прокси-режима.
pub fn build_config_tun(
    node_outbound: serde_json::Value,
    mode: TunnelRoute,
    whitelist: &[String],
) -> Result<serde_json::Value, String> {
    let mut o = node_outbound;
    o["tag"] = serde_json::json!("proxy");
    let mut rules = vec![
        // Сниффер: определяем домен из TLS SNI/HTTP Host для domain-правил.
        serde_json::json!({ "action": "sniff" }),
        // Весь DNS перехватываем — иначе утечка мимо туннеля/фейловый резолв.
        serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }),
    ];
    rules.extend(route_rules(mode, whitelist));
    // Локальные/LAN-адреса всегда напрямую (роутер, принтер, localhost-сервисы).
    rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));

    let final_out = if mode == TunnelRoute::Whitelist {
        "direct"
    } else {
        "proxy"
    };
    Ok(serde_json::json!({
        "log": { "level": "error" },
        "experimental": { "clash_api": { "external_controller": format!("127.0.0.1:{CLASH_API_PORT}") } },
        "dns": {
            // Новый формат DNS (sing-box 1.12+): legacy address-строки удалены в 1.14.
            "servers": [
                { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy" },
                { "type": "local", "tag": "local", "detour": "direct" }
            ],
            "final": "remote",
            "strategy": "prefer_ipv4"
        },
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "astreya0",
            "address": ["172.19.0.1/30"],
            "mtu": 1400,
            "auto_route": true,
            "strict_route": false,
            "stack": "mixed"
        }],
        "outbounds": [o, { "type": "direct", "tag": "direct" }],
        "route": {
            "rules": rules,
            "final": final_out,
            "auto_detect_interface": true,
            "default_domain_resolver": { "server": "remote" }
        }
    }))
}

fn exe_path_any() -> Result<std::path::PathBuf, String> {
    // Для задач Планировщика нужен УСТАНОВЛЕННЫЙ путь: рядом лежит wintun.dll,
    // и права на папку стабильны после установки. Dev-fallback сохранён.
    exe_path()
}

pub fn write_tun_config(link: &str) -> Result<std::path::PathBuf, String> {
    let s = crate::settings::load();
    let (cfg, _) = compile_live_config(
        None,
        true,
        TunnelRoute::from_str(&s.vpn_route_mode),
        &s.vpn_whitelist_sites,
        link,
    )?;
    let dir = config_dir()?;
    let path = dir.join("config-tun.json");
    let text = serde_json::to_string_pretty(&cfg).map_err(|e| format!("serialize: {e}"))?;
    std::fs::write(&path, text).map_err(|e| format!("write config-tun: {e}"))?;
    Ok(path)
}

/// Зарегистрировать задачу AstreyaGateTUN (RunLevel Highest → один UAC).
/// Аргументы задачи фиксируются при регистрации, поэтому register вызывается
/// перед КАЖДЫМ включением TUN — перезаписывает действие с актуальным конфигом.
pub fn tun_register(config_path: &std::path::Path) -> Result<(), String> {
    let exe = exe_path_any()?;
    // wintun.dll обязан лежать рядом с sing-box.exe.
    let dll = exe.parent().unwrap().join("wintun.dll");
    if !dll.exists() {
        return Err("рядом с sing-box.exe нет wintun.dll — переустановите приложение".into());
    }
    let user = "$env:USERDOMAIN\\$env:USERNAME";
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
         $action = New-ScheduledTaskAction -Execute '{exe}' -Argument 'run -c \"{cfg}\"'; \
         $principal = New-ScheduledTaskPrincipal -UserId \"{user}\" -LogonType Interactive -RunLevel Highest; \
         $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan) -MultipleInstances IgnoreNew; \
         Register-ScheduledTask -TaskName '{task}' -Action $action -Principal $principal -Settings $settings -Force | Out-Null; \
         Write-Output 'TUN_TASK_OK'",
        exe = exe.to_string_lossy().replace('\'', "''"),
        cfg = config_path.to_string_lossy().replace('\'', "''"),
        task = TUN_TASK,
    );
    run_elevated(&script)
}

/// Запустить TUN через задачу (без UAC — задача уже Highest).
pub fn tun_start() -> Result<(), String> {
    crate::tasks::run_ps_public(&format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
         Start-ScheduledTask -TaskName '{TUN_TASK}'; Write-Output 'STARTED'"
    ))
    .filter(|o| o.contains("STARTED"))
    .ok_or_else(|| String::from("задача AstreyaGateTUN не зарегистрирована"))?;
    // Ждём поднятия процесса до 8с.
    for _ in 0..16 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if process_status().running {
            return Ok(());
        }
    }
    Err("sing-box (TUN) не поднялся за 8с — смотри журнал задачи или параметры ноды".into())
}

/// Остановить TUN: гасим задачу и добиваем процессы (страховка от
/// «осиротевшего» воркера задачи).
pub fn tun_stop() -> usize {
    let _ = crate::tasks::run_ps_public(&format!(
        "Stop-ScheduledTask -TaskName '{TUN_TASK}' -ErrorAction SilentlyContinue; Write-Output 'DONE'"
    ));
    stop()
}

/// Статус TUN для UI.
#[derive(Debug, Clone, Serialize)]
pub struct TunStatus {
    pub registered: bool,
    pub state: Option<String>,
    pub running_process: bool,
}

pub fn tun_status() -> TunStatus {
    let out = crate::tasks::run_ps_public(&format!(
        "$t = Get-ScheduledTask -TaskName '{TUN_TASK}' -ErrorAction SilentlyContinue; \
         if ($t) {{ Write-Output ('STATE:' + $t.State) }} else {{ Write-Output 'MISSING' }}"
    ))
    .unwrap_or_default();
    let registered = out.contains("STATE:");
    let state = out
        .lines()
        .find_map(|l| l.strip_prefix("STATE:"))
        .map(|s| s.trim().to_string());
    TunStatus {
        registered,
        state,
        running_process: process_status().running,
    }
}

/// Запуск elevated PowerShell (один UAC) с ожиданием результата.
fn run_elevated(inner_script: &str) -> Result<(), String> {
    use std::process::Command;
    let tmp = dirs::config_dir()
        .map(|d| d.join("Astreya Gate"))
        .unwrap_or_else(std::env::temp_dir);
    let _ = std::fs::create_dir_all(&tmp);
    let script_path = tmp.join("astreyagate-tun.ps1");
    let result_path = tmp.join("astreyagate-tun-result.txt");
    let _ = std::fs::remove_file(&result_path);

    let full_inner = format!(
        "$ErrorActionPreference='Continue'; \
         try {{ {inner} }} catch {{ Set-Content -LiteralPath '{res}' -Value ('ERR:' + $_.Exception.Message); exit 1 }}; \
         Set-Content -LiteralPath '{res}' -Value 'OK'; exit 0",
        inner = inner_script,
        res = result_path.to_string_lossy().replace('\'', "''"),
    );
    std::fs::write(&script_path, &full_inner)
        .map_err(|e| format!("не записать временный скрипт: {e}"))?;

    let wrapper = format!(
        "$p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden \
           -ArgumentList '-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File','{script}'; \
         exit $p.ExitCode",
        script = script_path.to_string_lossy().replace('\'', "''"),
    );
    let mut cmd = Command::new("powershell.exe");
    cmd.args([
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        &wrapper,
    ]);
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let status = cmd
        .status()
        .map_err(|e| format!("UAC-запрос не запущен: {e}"))?;

    let result = std::fs::read_to_string(&result_path).unwrap_or_default();
    let _ = std::fs::remove_file(&script_path);
    let _ = std::fs::remove_file(&result_path);

    if result.trim() == "OK" {
        Ok(())
    } else if let Some(err) = result.trim().strip_prefix("ERR:") {
        Err(format!("TUN-регистрация: {err}"))
    } else if !status.success() {
        Err("Запрос прав администратора отклонён".into())
    } else {
        Err("Не удалось подтвердить регистрацию задачи TUN".into())
    }
}

// ─── Watchdog VPN + системный прокси для браузеров ───────────────
//
// Принцип отказоустойчивости: восстановление НИКОГДА не должно требовать
// ни работающей сети, ни внешней помощи. Поэтому:
//   - туннель, включённый пользователем, поднимается watchdog'ом сам;
//   - системный прокси браузеров автоматически выключается при смерти
//     туннеля — нет «мёртвого захвата» трафика;
//   - на рабочем столе лежит аварийный .bat, сбрасывающий всю сетевую
//     обвязку в базовое состояние (создаётся/обновляется при старте).

use std::sync::atomic::{AtomicBool, Ordering};

/// Пользователь включал туннель и ожидает, что он работает.
pub static VPN_WANTED: AtomicBool = AtomicBool::new(false);
/// Пользователь включал системный прокси браузеров.
static SYS_PROXY_WANTED: AtomicBool = AtomicBool::new(false);

const WININET_PATH: &str = r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

/// Системный прокси Windows (WinINET) → локальный порт туннеля.
/// Chrome/Edge/Opera и Firefox (в дефолтном режиме) ходят через него.
pub fn sys_proxy_enable(port: u16) -> Result<(), String> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
         Set-ItemProperty -Path '{p}' -Name ProxyEnable -Value 1 -Type DWord; \
         Set-ItemProperty -Path '{p}' -Name ProxyServer -Value '127.0.0.1:{port}' -Type String; \
         Set-ItemProperty -Path '{p}' -Name ProxyOverride -Value 'localhost;127.0.0.1;<local>' -Type String; \
         Write-Output 'OK'",
        p = WININET_PATH,
    );
    crate::tasks::run_ps_public(&script)
        .filter(|o| o.contains("OK"))
        .ok_or_else(|| String::from("не удалось включить системный прокси"))?;
    SYS_PROXY_WANTED.store(true, Ordering::Relaxed);
    crate::browser::notify_wininet();
    Ok(())
}

pub fn sys_proxy_disable() -> Result<(), String> {
    let script = format!(
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; \
         Set-ItemProperty -Path '{p}' -Name ProxyEnable -Value 0 -Type DWord; \
         Write-Output 'OK'",
        p = WININET_PATH,
    );
    crate::tasks::run_ps_public(&script)
        .filter(|o| o.contains("OK"))
        .ok_or_else(|| String::from("не удалось выключить системный прокси"))?;
    SYS_PROXY_WANTED.store(false, Ordering::Relaxed);
    crate::browser::notify_wininet();
    Ok(())
}

pub fn sys_proxy_enabled() -> bool {
    let out = crate::tasks::run_ps_public(&format!(
        "(Get-ItemProperty -Path '{p}' -ErrorAction SilentlyContinue).ProxyEnable",
        p = WININET_PATH
    ))
    .unwrap_or_default();
    out.trim() == "1"
}

/// Watchdog: 5-секундный цикл. Две обязанности:
///   1) туннель, включённый пользователем, умер → поднять;
///   2) системный прокси был включён, а туннель умер → ВЫКЛЮЧИТЬ прокси
///      (иначе браузер без интернета из-за мёртвого 127.0.0.1).
pub fn spawn_vpn_watchdog() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let mut fail_streak = 0u32;
        loop {
            std::thread::sleep(std::time::Duration::from_secs(5));
            let running = process_status().running;

            // Мёртвый туннель + включённый системный прокси → снять прокси.
            if SYS_PROXY_WANTED.load(Ordering::Relaxed) && !running {
                if let Err(e) = sys_proxy_disable() {
                    tracing::warn!("watchdog: не снять системный прокси: {e}");
                } else {
                    tracing::warn!("watchdog VPN: туннель мёртв — системный прокси браузеров выключен (защита от чёрного экрана)");
                }
            }

            // Включённый пользователем туннель умер → поднять заново.
            if VPN_WANTED.load(Ordering::Relaxed) && !running {
                let s = crate::settings::load();
                let node = s
                    .vpn_nodes
                    .iter()
                    .find(|n| Some(n.id.as_str()) == s.vpn_active.as_deref())
                    .map(|n| n.link.clone());
                match node {
                    Some(link) => match start(&link, s.vpn_port) {
                        Ok(_) => {
                            fail_streak = 0;
                            tracing::info!("watchdog VPN: туннель восстановлен");
                        }
                        Err(e) => {
                            fail_streak += 1;
                            tracing::warn!("watchdog VPN: попытка {fail_streak}: {e}");
                            // 6 неудач подряд: перестаём долбить — вероятно,
                            // порт занят другим клиентом.
                            if fail_streak >= 6 {
                                VPN_WANTED.store(false, Ordering::Relaxed);
                                tracing::warn!("watchdog VPN: сдался после 6 неудач — включи туннель вручную");
                            }
                        }
                    },
                    None => VPN_WANTED.store(false, Ordering::Relaxed),
                }
            }
        }
    });
}

// ─── Тесты парсеров ссылок ───────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vless_reality_ws_full() {
        let p = parse_link(
            "vless://8f2c-uuid@example.com:443?encryption=none&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179&type=ws&host=cdn.example.com&path=%2Fws&flow=xtls-rprx-vision#%F0%9F%87%A9Reality",
        )
        .unwrap();
        assert_eq!(p.proto, "vless");
        assert_eq!(p.server, "example.com");
        assert_eq!(p.port, 443);
        assert!(p.name.contains("Reality"));
        assert_eq!(p.outbound["uuid"], "8f2c-uuid");
        assert_eq!(p.outbound["flow"], "xtls-rprx-vision");
        assert_eq!(p.outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(
            p.outbound["tls"]["reality"]["public_key"],
            "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"
        );
        assert_eq!(p.outbound["transport"]["type"], "ws");
        assert_eq!(p.outbound["transport"]["headers"]["Host"], "cdn.example.com");
    }

    #[test]
    fn vmess_base64_json() {
        let json = serde_json::json!({
            "v":"2","ps":"Нода VM","add":"vm.host.io","port":443,"id":"aaa-bbb",
            "aid":0,"scy":"auto","net":"ws","host":"front.io","path":"/ray",
            "tls":"tls","sni":"front.io"
        });
        use base64::Engine;
        let link = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(json.to_string())
        );
        let p = parse_link(&link).unwrap();
        assert_eq!(p.proto, "vmess");
        assert_eq!(p.name, "Нода VM");
        assert_eq!(p.server, "vm.host.io");
        assert_eq!(p.port, 443);
        assert_eq!(p.outbound["security"], "auto");
        assert_eq!(p.outbound["alter_id"], 0);
        assert_eq!(p.outbound["tls"]["enabled"], true);
        assert_eq!(p.outbound["transport"]["type"], "ws");
    }

    #[test]
    fn vmess_vless_style_link() {
        let p = parse_link("vmess://some-uuid@9.9.9.9:2053?type=tcp&security=tls&sni=x.com#alt-vmess").unwrap();
        assert_eq!(p.proto, "vmess");
        assert_eq!(p.outbound["type"], "vmess");
        assert_eq!(p.outbound["security"], "auto");
        assert_eq!(p.outbound["server"], "9.9.9.9");
        // UUID должен сохраниться ЦЕЛИКОМ (не съеден длиной чужой схемы).
        assert_eq!(p.outbound["uuid"], "some-uuid");
    }

    #[test]
    fn ss_userinfo_b64() {
        use base64::Engine;
        let ui = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:testpass");
        let p = parse_link(&format!("ss://{ui}@1.3.5.7:8388#SS-node")).unwrap();
        assert_eq!(p.proto, "ss");
        assert_eq!(p.outbound["method"], "aes-256-gcm");
        assert_eq!(p.outbound["password"], "testpass");
        assert_eq!(p.name, "SS-node");
    }

    #[test]
    fn ss_fully_encoded() {
        use base64::Engine;
        let inner = base64::engine::general_purpose::STANDARD
            .encode("chacha20-ietf-poly1305:pw123@10.1.2.3:9994");
        let p = parse_link(&format!("ss://{inner}#enc")).unwrap();
        assert_eq!(p.outbound["method"], "chacha20-ietf-poly1305");
        assert_eq!(p.server, "10.1.2.3");
        assert_eq!(p.port, 9994);
    }

    #[test]
    fn trojan_basic() {
        let p = parse_link(
            "trojan://hunter2@t.example.net:443?sni=t.example.net&type=tcp#TrojanMain",
        )
        .unwrap();
        assert_eq!(p.proto, "trojan");
        assert_eq!(p.outbound["password"], "hunter2");
        assert_eq!(p.outbound["tls"]["enabled"], true);
        assert_eq!(p.outbound["tls"]["server_name"], "t.example.net");
    }

    #[test]
    fn hysteria2_short_scheme_with_obfs() {
        // ВАЖНО: hy2:// — короткая схема; раньше парсер резал по длине
        // hysteria2:// и портил auth. Этот тест фиксирует регрессию.
        let p = parse_link(
            "hy2://letmein@hy.example.org:36712/?insecure=1&sni=hy.example.org&obfs=salamander&obfs-password=obfspw#Hy2%20fast",
        )
        .unwrap();
        assert_eq!(p.proto, "hysteria2");
        assert_eq!(p.port, 36712);
        assert_eq!(p.outbound["password"], "letmein");
        assert_eq!(p.outbound["obfs"]["type"], "salamander");
        assert_eq!(p.outbound["obfs"]["password"], "obfspw");
        assert_eq!(p.outbound["tls"]["insecure"], true);
        assert_eq!(p.name, "Hy2 fast");
    }

    #[test]
    fn hysteria2_long_scheme() {
        let p = parse_link("hysteria2://pw@h.io:1?insecure=0#long").unwrap();
        assert_eq!(p.outbound["password"], "pw");
        assert_eq!(p.name, "long");
    }

    #[test]
    fn tuic_basic() {
        let p = parse_link(
            "tuic://u-111:secret@tuic.example.io:443?congestion_control=bbr&alpn=h3&sni=tuic.example.io&TUICTest",
        )
        .unwrap();
        assert_eq!(p.proto, "tuic");
        assert_eq!(p.outbound["congestion_control"], "bbr");
        assert_eq!(p.outbound["tls"]["alpn"][0], "h3");
    }

    #[test]
    fn subscription_body_plain_and_b64() {
        let plain = "trojan://a@b.c:443#x\nhttps://example.com/ignore-me\nss://YWVzLTI1Ni1nY206cHdAMS4yLjMuNDo0NDMjc3M=\n";
        assert_eq!(parse_subscription_body(plain).len(), 2);
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.encode(plain);
        assert_eq!(parse_subscription_body(&blob).len(), 2);
    }

    #[test]
    fn subscription_v2rayn_json_array() {
        // fmt=best у суб-конвертеров отдаёт массив ПОЛНЫХ конфигов v2rayN.
        // Регресс-тест на реальный формат подписки пользователя.
        let body = serde_json::json!([
            {
                "remarks": "🇩🇪 Германия Reality",
                "outbounds": [
                    { "tag": "proxy", "protocol": "vless",
                      "settings": { "vnext": [{ "address": "de.example.com", "port": 443,
                        "users": [{ "id": "uuid-1", "flow": "xtls-rprx-vision", "encryption": "none" }] }] },
                      "streamSettings": { "network": "tcp", "security": "reality",
                        "realitySettings": { "serverName": "www.microsoft.com", "publicKey": "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", "shortId": "6ba8", "fingerprint": "chrome" } } },
                    { "tag": "direct", "protocol": "freedom" }
                ]
            },
            {
                "remarks": "🇳🇱 SS",
                "outbounds": [
                    { "tag": "proxy", "protocol": "shadowsocks",
                      "settings": { "servers": [{ "address": "nl.example.com", "port": 8388, "method": "aes-256-gcm", "password": "p@ss w" }] } },
                    { "tag": "direct", "protocol": "freedom" }
                ]
            },
            {
                "remarks": "служебный",
                "outbounds": [ { "tag": "direct", "protocol": "freedom" } ]
            }
        ])
        .to_string();
        let links = parse_subscription_body(&body);
        assert_eq!(links.len(), 2, "freedom-only конфиг пропускается");

        // Первая нода конвертируется в валидный vless и обратно парсится.
        assert!(links[0].starts_with("vless://"));
        assert!(links[0].contains("security=reality"));
        assert!(links[0].contains("pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc"));
        let parsed = parse_link(&links[0]).unwrap();
        assert_eq!(parsed.server, "de.example.com");
        assert_eq!(parsed.outbound["flow"], "xtls-rprx-vision");
        assert_eq!(parsed.outbound["tls"]["reality"]["short_id"], "6ba8");

        // Вторая — в ss с пробелом в пароле (percent-encoding туда-обратно).
        assert!(links[1].starts_with("ss://"));
        let parsed2 = parse_link(&links[1]).unwrap();
        assert_eq!(parsed2.outbound["password"], "p@ss w");
        assert_eq!(parsed2.outbound["method"], "aes-256-gcm");
    }

    #[test]
    fn subscription_v2rayn_trojan_and_vmess() {
        let body = serde_json::json!([
            {
                "remarks": "Troj node",
                "outbounds": [
                    { "tag": "proxy", "protocol": "trojan",
                      "settings": { "servers": [{ "address": "t.io", "port": 443, "password": "pw1" }] },
                      "streamSettings": { "network": "tcp", "security": "tls",
                        "tlsSettings": { "serverName": "t.io", "allowInsecure": true } } }
                ]
            },
            {
                "remarks": "VM node",
                "outbounds": [
                    { "tag": "proxy", "protocol": "vmess",
                      "settings": { "vnext": [{ "address": "v.io", "port": 443,
                        "users": [{ "id": "vm-uuid", "alterId": 0, "security": "auto" }] }] },
                      "streamSettings": { "network": "ws", "security": "tls",
                        "tlsSettings": { "serverName": "v.io" },
                        "wsSettings": { "path": "/ray", "headers": { "Host": "front.io" } } } }
                ]
            }
        ])
        .to_string();
        let links = parse_subscription_body(&body);
        assert_eq!(links.len(), 2);

        let t = parse_link(&links[0]).unwrap();
        assert_eq!(t.proto, "trojan");
        assert_eq!(t.outbound["password"], "pw1");
        assert_eq!(t.outbound["tls"]["insecure"], true);

        assert!(links[1].starts_with("vmess://"));
        let v = parse_link(&links[1]).unwrap();
        assert_eq!(v.proto, "vmess");
        assert_eq!(v.server, "v.io");
        assert_eq!(v.outbound["transport"]["path"], "/ray");
        assert_eq!(v.outbound["transport"]["headers"]["Host"], "front.io");
        assert_eq!(v.name, "VM node");
    }

    #[test]
    fn subscription_v2rayn_prefers_reality_over_xhttp() {
        // Реальный кейс провайдера: у ноды два outbound'а — XHTTP+TLS (не
        // поддерживается sing-box) и Reality+vision. Конвертер обязан взять
        // Reality, иначе нода «подключается», но не пропускает трафик.
        let body = serde_json::json!([
            {
                "remarks": "DE Германия",
                "outbounds": [
                    { "tag": "proxy", "protocol": "vless",
                      "settings": { "vnext": [{ "address": "static.1o0.net", "port": 443,
                        "users": [{ "id": "uuid-x", "encryption": "none", "flow": "" }] }] },
                      "streamSettings": { "network": "xhttp", "security": "tls",
                        "tlsSettings": { "serverName": "static.1o0.net", "fingerprint": "firefox" },
                        "xhttpSettings": { "mode": "packet-up", "path": "/yjG2FoRf" } } },
                    { "tag": "proxy-1", "protocol": "vless",
                      "settings": { "vnext": [{ "address": "static.1o0.net", "port": 443,
                        "users": [{ "id": "uuid-x", "encryption": "none", "flow": "xtls-rprx-vision" }] }] },
                      "streamSettings": { "network": "tcp", "security": "reality",
                        "realitySettings": { "serverName": "static-cdn.1o0.net", "fingerprint": "firefox",
                          "publicKey": "87wWQkyS_4sBlSYgQQS0P_eL1yzg_xNt01ErwyQAFGA", "shortId": "b4730202e64b101c" } } },
                    { "tag": "direct", "protocol": "freedom" }
                ]
            }
        ])
        .to_string();
        let links = parse_subscription_body(&body);
        assert_eq!(links.len(), 1, "XHTTP-вариант отфильтрован, Reality взят");
        let parsed = parse_link(&links[0]).unwrap();
        assert_eq!(parsed.outbound["flow"], "xtls-rprx-vision");
        assert_eq!(parsed.outbound["tls"]["reality"]["enabled"], true);
        assert_eq!(
            parsed.outbound["tls"]["reality"]["public_key"],
            "87wWQkyS_4sBlSYgQQS0P_eL1yzg_xNt01ErwyQAFGA"
        );
        assert_eq!(parsed.outbound["tls"]["server_name"], "static-cdn.1o0.net");
        // Транспорт не должен попасть в конфиг (tcp без transport-блока).
        assert!(parsed.outbound.get("transport").is_none());
    }

    #[test]
    fn vless_xhttp_link_rejected_with_clear_error() {
        let err = parse_link(
            "vless://u@h.io:443?type=xhttp&security=tls&path=%2Fx#xhttp-node",
        )
        .unwrap_err();
        assert!(err.contains("XHTTP"), "понятное сообщение, получено: {err}");
    }

    #[test]
    fn garbage_links_rejected() {
        assert!(parse_link("vless://no-at-sign").is_err());
        assert!(parse_link("http://not-a-proxy").is_err());
        assert!(parse_link("vmess://!!!not-base64!!!").is_err());
    }

    /// Локальная проверка реального тела подписки:
    ///   SUB_BODY_FILE=path cargo test real_subscription_body
    /// Без переменной (CI) мгновенно проходит.
    #[test]
    fn real_subscription_body() {
        let Ok(path) = std::env::var("SUB_BODY_FILE") else {
            return;
        };
        if path.is_empty() {
            return;
        }
        let body = std::fs::read_to_string(&path).expect("читаю файл тела");
        let links = parse_subscription_body(&body);
        assert!(!links.is_empty(), "из реального тела не извлеклась ни одна ссылка");
        let bad: Vec<&String> = links
            .iter()
            .filter(|l| parse_link(l).is_err())
            .collect();
        assert!(
            bad.is_empty(),
            "битых ссылок {} из {}: первый пример: {:?}",
            bad.len(),
            links.len(),
            bad.first().map(|s| &s[..s.len().min(120)])
        );
    }

    // ─── Deep-links ───

    use base64::Engine as _;

    #[test]
    fn deeplink_add_subscription_b64() {
        let url = "https://provider.example/sub?token=abc";
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(url);
        for scheme in ["astreya", "happ"] {
            let d = parse_deeplink(&format!("{scheme}://add/{payload}")).unwrap();
            match d {
                Deeplink::AddSubscription { url: u, .. } => assert_eq!(u, url),
                other => panic!("ожидали AddSubscription, получено {other:?}"),
            }
        }
    }

    #[test]
    fn deeplink_plain_url_without_base64() {
        let d = parse_deeplink("astreya://add/https://sub.io/list").unwrap();
        match d {
            Deeplink::AddSubscription { url, .. } => assert_eq!(url, "https://sub.io/list"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn deeplink_happ_crypt_is_clear_error() {
        assert!(parse_deeplink("happ://crypt2/AAAA").is_err());
    }

    #[test]
    fn deeplink_clipboard_with_config_links() {
        let text = "trojan://pw@h.io:443#n1\nvless://u@v.io:443?#n2";
        let d = parse_deeplink(text).unwrap();
        match d {
            Deeplink::AddLinks(links) => assert_eq!(links.len(), 2),
            other => panic!("{other:?}"),
        }
    }

    // ─── Режимы маршрутизации ───

    #[test]
    fn route_all_has_no_rules() {
        let cfg = build_config(
            serde_json::json!({"type":"direct"}),
            2080,
            TunnelRoute::All,
            &[],
        )
        .unwrap();
        assert!(cfg["route"].get("rules").is_none());
    }

    #[test]
    fn route_smart_directs_ru_domains() {
        let cfg = build_config(
            serde_json::json!({"type":"direct"}),
            2080,
            TunnelRoute::Smart,
            &[],
        )
        .unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["outbound"], "direct");
        assert!(rules[0]["domain_suffix"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d == "gosuslugi.ru"));
    }

    #[test]
    fn route_whitelist_proxies_listed_sites() {
        let wl = vec!["openai.com".to_string(), "netflix.com".to_string()];
        let cfg = build_config(
            serde_json::json!({"type":"direct"}),
            2080,
            TunnelRoute::Whitelist,
            &wl,
        )
        .unwrap();
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["outbound"], "proxy");
        assert!(rules[0]["domain_suffix"].as_array().unwrap().len() == 2);
        assert_eq!(cfg["route"]["final"], "proxy"); // финал не мешает правилу
    }

    // ─── Системный режим (TUN) ───

    #[test]
    fn tun_config_structure_is_complete() {
        let cfg = build_config_tun(
            serde_json::json!({"type":"vless","uuid":"u","server":"s","server_port":443}),
            TunnelRoute::Smart,
            &[],
        )
        .unwrap();
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
        assert_eq!(cfg["inbounds"][0]["auto_route"], true);
        assert_eq!(cfg["inbounds"][0]["interface_name"], "astreya0");
        assert_eq!(cfg["dns"]["final"], "remote");
        assert_eq!(cfg["dns"]["servers"][0]["detour"], "proxy");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["action"] == "hijack-dns"));
        assert!(rules.iter().any(|r| r["action"] == "sniff"));
        assert!(rules
            .iter()
            .any(|r| r["outbound"] == "direct"
                && r.get("ip_is_private") == Some(&serde_json::json!(true))));
        assert_eq!(cfg["route"]["auto_detect_interface"], true);
    }

    #[test]
    fn tun_whitelist_final_direct() {
        let wl = vec!["openai.com".to_string()];
        let cfg =
            build_config_tun(serde_json::json!({"type":"direct"}), TunnelRoute::Whitelist, &wl)
                .unwrap();
        assert_eq!(cfg["route"]["final"], "direct");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        // [0]=sniff [1]=dns-hijack [2]=whitelist→proxy
        assert_eq!(rules[2]["outbound"], "proxy");
    }
}

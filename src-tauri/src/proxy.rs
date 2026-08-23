use serde::{Deserialize, Serialize};
use url::Url;
#[allow(unused_imports)]
use tracing::warn;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    pub url: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub label: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct ProxyCheckResult {
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub status_code: Option<u16>,
    pub error: Option<String>,
    pub ip: Option<String>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub isp: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IpApiResponse {
    status: String,
    query: Option<String>,
    #[serde(rename = "countryCode")]
    country_code: Option<String>,
    country: Option<String>,
    isp: Option<String>,
    message: Option<String>,
}

pub fn parse(input: &str) -> Result<ProxyConfig, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Пустая строка".into());
    }
    // Формат многих прокси-провайдеров: `ip:port:user:pass` (4 части, 3
    // двоеточия, без схемы). URL::parse такое не съест — конвертируем в
    // канонический http://user:pass@host:port до разбора.
    let normalized = match normalize_provider_format(trimmed) {
        Some(u) => u,
        None => trimmed.to_string(),
    };
    let with_scheme = if normalized.starts_with("http://") || normalized.starts_with("https://") {
        normalized
    } else {
        format!("http://{normalized}")
    };

    let parsed = Url::parse(&with_scheme).map_err(|e| format!("Не получилось разобрать URL: {e}"))?;

    let host = parsed
        .host_str()
        .ok_or_else(|| "В URL не указан адрес (host)".to_string())?
        .to_string();
    let port = parsed
        .port()
        .ok_or_else(|| "В URL не указан порт (например, :8000)".to_string())?;
    // url-crate отдаёт userinfo в percent-encoded сериализации — для хранения
    // и показа в UI нужен декодированный вид (RFC 3986: consumer декодирует).
    let username = pct_decode(&parsed.username().to_string());
    let password = pct_decode(parsed.password().unwrap_or("").to_string().as_str());

    if username.is_empty() || password.is_empty() {
        return Err("В URL нет логина или пароля. Формат: http://user:pass@host:port".into());
    }

    Ok(ProxyConfig {
        url: with_scheme,
        host,
        port,
        username,
        password,
        label: "Основной".to_string(),
    })
}

/// `ip:port:user:pass` → `http://user:pass@ip:port`.
///
/// Распознаём ТОЛЬКО явный провайдерский формат: ровно 3 двоеточия, первая
/// часть похожа на host (не схема, не путь), вторая — на порт. Логин/пароль
/// URL-энкодим: спецсимволы в паролях ломали бы повторный Url::parse.
fn normalize_provider_format(s: &str) -> Option<String> {
    if s.contains("://") || s.contains('@') || s.contains('/') {
        return None;
    }
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 {
        return None;
    }
    let (host, port, user, pass) = (parts[0], parts[1], parts[2], parts[3]);
    if host.is_empty() || user.is_empty() {
        return None;
    }
    let port_ok = port.parse::<u16>().is_ok();
    let host_ok = host
        .split('.')
        .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
    if !(port_ok && host_ok) {
        return None;
    }
    let enc = |v: &str| {
        let mut out = String::new();
        for b in v.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    };
    Some(format!("http://{}:{}@{host}:{port}", enc(user), enc(pass)))
}

/// Percent-decoding userinfo (`%41lice` → `Alice`). Некорректные
/// последовательности пропускаем как есть — не наша задача валидировать.
fn pct_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = bytes.get(i + 1..i + 3);
            if let Some(h) = hex {
                if let Ok(v) = u8::from_str_radix(&String::from_utf8_lossy(h), 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn fail(error: impl Into<String>) -> ProxyCheckResult {    ProxyCheckResult {
        reachable: false,
        latency_ms: None,
        status_code: None,
        error: Some(error.into()),
        ip: None,
        country_code: None,
        country_name: None,
        isp: None,
    }
}

pub async fn check(url: &str) -> ProxyCheckResult {
    let proxy = match reqwest::Proxy::all(url) {
        Ok(p) => p,
        Err(e) => return fail(format!("Неверный URL прокси: {e}")),
    };

    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => return fail(format!("Не удалось собрать клиент: {e}")),
    };

    let start = std::time::Instant::now();
    // ip-api.com отдаёт IP, страну и провайдера за один запрос — и заодно проверяет
    // что прокси вообще работает (ходим на внешний хост).
    let resp = match client
        .get("http://ip-api.com/json/?fields=status,message,query,countryCode,country,isp")
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            let msg = if e.is_timeout() {
                "Прокси не ответил за 10 секунд".to_string()
            } else if e.is_connect() {
                "Не удалось подключиться к прокси (проверьте адрес и порт)".to_string()
            } else {
                format!("Ошибка: {e}")
            };
            return fail(msg);
        }
    };

    let elapsed = start.elapsed().as_millis() as u64;
    let status_code = resp.status().as_u16();

    if !resp.status().is_success() {
        return ProxyCheckResult {
            reachable: false,
            latency_ms: Some(elapsed),
            status_code: Some(status_code),
            error: Some(format!("ip-api.com вернул код {status_code}")),
            ip: None,
            country_code: None,
            country_name: None,
            isp: None,
        };
    }

    let parsed: IpApiResponse = match resp.json().await {
        Ok(j) => j,
        Err(e) => return fail(format!("Не получилось разобрать ответ: {e}")),
    };

    if parsed.status != "success" {
        return fail(parsed.message.unwrap_or_else(|| "ip-api.com не смог определить IP".into()));
    }

    ProxyCheckResult {
        reachable: true,
        latency_ms: Some(elapsed),
        status_code: Some(status_code),
        error: None,
        ip: parsed.query,
        country_code: parsed.country_code.map(|c| c.to_lowercase()),
        country_name: parsed.country,
        isp: parsed.isp,
    }
}

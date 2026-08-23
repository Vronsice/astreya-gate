//! Персистентные настройки Astreya Gate в `%APPDATA%\Astreya Gate\settings.json`.
//!
//! Зачем: после установки шим запоминает прокси в .vbs (в Startup-папке), но
//! сам Dashboard должен знать его чтобы показывать в UI и предлагать смену.
//! Также хранится флаг autostart-окна (отдельно от autostart-шима).

use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::apps::AppProfile;

/// Все мутации настроек — под одной блокировкой: tauri-команды конкурентны,
/// а load-modify-save без неё теряет чужие изменения (второй писатель молча
/// откатывает, например, только что сохранённый пул прокси).
static SETTINGS_LOCK: Mutex<()> = Mutex::new(());

fn with_settings<F>(f: F) -> Result<Settings, String>
where
    F: FnOnce(&mut Settings) -> Result<(), String>,
{
    let _g = SETTINGS_LOCK
        .lock()
        .map_err(|_| "settings lock poisoned".to_string())?;
    let mut s = load();
    f(&mut s)?;
    save(&s)?;
    Ok(s)
}

const SETTINGS_FILE: &str = "settings.json";
const APP_DIR: &str = "Astreya Gate";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    /// URL купленного upstream-прокси `http://login:pass@ip:port`.
    /// Хранится в открытом виде — это локальный файл пользователя.
    #[serde(default)]
    pub proxy_url: Option<String>,
    /// Запускать Dashboard в трее при логине Windows.
    #[serde(default)]
    pub autostart_dashboard: bool,
    /// Профили приложений (какие проксируем). Сеются пресетами при первом
    /// запуске; пользователь включает/выключает и добавляет свои.
    #[serde(default)]
    pub app_profiles: Vec<AppProfile>,
    /// Включён ли killswitch (firewall fail-closed). Отражает НАМЕРЕНИЕ
    /// пользователя; фактические правила проверяются отдельно в firewall.rs.
    #[serde(default)]
    pub killswitch_enabled: bool,
    /// Режим маршрутизации моста: "all" (всё через upstream, как раньше) |
    /// "smart" (через upstream только AI-домены, остальное напрямую).
    /// None = "all" — консервативный дефолт для старых установок.
    #[serde(default)]
    pub route_mode: Option<String>,
    /// Прокси-пул (до 5). [0] — основной; proxy_url держится с ним в синхроне
    /// для обратной совместимости (vbs/старый код читают proxy_url).
    /// Пустой список = легаси-установка, пул из одного proxy_url.
    #[serde(default)]
    pub proxies: Vec<String>,
    /// Назначения «сервис → индекс прокси в пуле»: ключи — группы из
    /// tasks::SERVICE_GROUPS ("anthropic", "openai", …). Отсутствие ключа =
    /// авто (основной + failover).
    #[serde(default)]
    pub proxy_assignments: std::collections::HashMap<String, usize>,
    /// Пользовательские имена (тэги) прокси: URL → имя («Немецкий», «Резерв»).
    #[serde(default)]
    pub proxy_labels: std::collections::HashMap<String, String>,
    /// Цепочки: URL финального прокси → URL хопа-1 («через который»).
    /// Отсутствие ключа = прямое подключение к прокси.
    #[serde(default)]
    pub proxy_vias: std::collections::HashMap<String, String>,
    /// Прокси по умолчанию для трафика без назначения: индекс в пуле.
    /// None = первый прокси пула (историческое поведение). Кейс: платный
    /// внешний — только Anthropic (назначение), всё остальное (opencode,
    /// git, npm…) — через дешёвый локальный/VPN-прокси, не жгём платный.
    #[serde(default)]
    pub default_upstream: Option<usize>,
    /// Режим PAC для браузеров: "whitelist" | "blacklist" (см. browser.rs).
    #[serde(default)]
    pub browser_mode: Option<String>,
    /// Список сайтов для PAC (домены, по одному; суффикс-матч).
    #[serde(default)]
    pub browser_sites: Vec<String>,
    /// Чужие настройки системного прокси Windows, перезаписанные при
    /// включении PAC. Выключение возвращает их (контракт как у saved_proxy_env).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_browser_proxy: Option<std::collections::HashMap<String, String>>,
    /// Чужие прокси-переменные (корпоративный прокси, свой VPN-тул), которые
    /// мы перезаписали при включении системного проксирования. «Выключить»
    /// возвращает их, а не стирает настройку пользователя насовсем.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_proxy_env: Option<std::collections::HashMap<String, String>>,
    /// VPN: подписки (URL + интервал автообновления).
    #[serde(default)]
    pub vpn_subscriptions: Vec<crate::vpn::VpnSubscription>,
    /// VPN: все ноды (из подписок и одиночные конфиги).
    #[serde(default)]
    pub vpn_nodes: Vec<crate::vpn::VpnNode>,
    /// VPN: активная нода (id) — для старта sing-box.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_active: Option<String>,
    /// Локальный порт VPN-прокси (mixed inbound sing-box). Дефолт 2080.
    #[serde(default = "default_vpn_port")]
    pub vpn_port: u16,
    /// Режим маршрутизации туннеля: "all" | "smart" | "whitelist".
    #[serde(default = "default_vpn_route")]
    pub vpn_route_mode: String,
    /// Сайты для whitelist-режима (через VPN только они).
    #[serde(default)]
    pub vpn_whitelist_sites: Vec<String>,
    /// Поднимать туннель при старте приложения (если была активная нода).
    #[serde(default)]
    pub vpn_autostart: bool,
}

fn default_vpn_port() -> u16 {
    crate::vpn::VPN_PORT_DEFAULT
}

fn default_vpn_route() -> String {
    "all".into()
}

/// Полный пул прокси: proxies, а для легаси-установок — единственный proxy_url.
pub fn effective_proxies(s: &Settings) -> Vec<String> {
    if !s.proxies.is_empty() {
        s.proxies.clone()
    } else {
        s.proxy_url.clone().into_iter().collect()
    }
}

fn settings_path() -> Result<PathBuf, String> {
    let base = dirs::config_dir()
        .ok_or_else(|| "Не нашёл папку %APPDATA%".to_string())?;
    Ok(base.join(APP_DIR).join(SETTINGS_FILE))
}

pub fn load() -> Settings {
    let path = match settings_path() {
        Ok(p) => p,
        Err(_) => return Settings::default(),
    };
    let Ok(text) = fs::read_to_string(&path) else {
        return Settings::default();
    };
    serde_json::from_str(&text).unwrap_or_default()
}

pub fn save(settings: &Settings) -> Result<(), String> {
    let path = settings_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Не смог создать {}: {e}", parent.display()))?;
    }
    let text = serde_json::to_string_pretty(settings)
        .map_err(|e| format!("serialize: {e}"))?;
    // Атомарно (tmp + rename): параллельный читатель не должен увидеть
    // обрезанный JSON и молча откатиться к Settings::default().
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, text)
        .map_err(|e| format!("Не смог записать {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &path)
        .map_err(|e| format!("Не смог заменить {}: {e}", path.display()))?;
    Ok(())
}

/// Перемапить индексы назначений на новый порядок пула ПО URL: назначение
/// обязано продолжать указывать на ТОТ ЖЕ прокси (тот же выходной IP), как бы
/// пул ни переставляли/укорачивали. Съехавший индекс = закреплённый Claude
/// молча уезжает на другой IP. Назначения на исчезнувший URL снимаются
/// (сервис возвращается в «Авто»).
fn remap_assignments(s: &mut Settings, old_pool: &[String], new_pool: &[String]) {
    s.proxy_assignments = std::mem::take(&mut s.proxy_assignments)
        .into_iter()
        .filter_map(|(svc, idx)| {
            let url = old_pool.get(idx)?;
            let new_idx = new_pool.iter().position(|u| u == url)?;
            Some((svc, new_idx))
        })
        .collect();
}

pub fn set_proxy_url(url: String) -> Result<Settings, String> {
    with_settings(|s| {
        // Основной прокси и пул держим в синхроне: [0] всегда = proxy_url.
        let old_pool = effective_proxies(s);
        let mut new_pool = old_pool.clone();
        if let Some(pos) = new_pool.iter().position(|u| *u == url) {
            // URL уже в пуле — «сделать основным» перестановкой, не дублируя.
            new_pool.remove(pos);
            new_pool.insert(0, url.clone());
        } else if new_pool.is_empty() {
            new_pool.push(url.clone());
        } else {
            new_pool[0] = url.clone();
        }
        remap_assignments(s, &old_pool, &new_pool);
        s.proxy_labels.retain(|u, _| new_pool.contains(u));
        s.proxy_vias.retain(|u, _| new_pool.contains(u));
        s.proxy_url = Some(url);
        s.proxies = new_pool;
        Ok(())
    })
}

/// Заменить пул целиком (1..=5, [0] — основной). Индексы назначений
/// перемапливаются по URL; назначения на удалённые прокси снимаются.
pub fn set_proxies(urls: Vec<String>) -> Result<Settings, String> {
    if urls.is_empty() || urls.len() > 5 {
        return Err("Пул прокси: от 1 до 5 адресов".into());
    }
    with_settings(|s| {
        let old_pool = effective_proxies(s);
        remap_assignments(s, &old_pool, &urls);
        s.proxy_labels.retain(|url, _| urls.contains(url));
        s.proxy_vias.retain(|url, _| urls.contains(url));
        s.proxy_url = Some(urls[0].clone());
        s.proxies = urls;
        Ok(())
    })
}

/// Задать/убрать цепочку для прокси пула (None = убрать, прямое подключение).
pub fn set_proxy_via(url: String, via: Option<String>) -> Result<Settings, String> {
    with_settings(|s| {
        match via {
            Some(v) => {
                if v == url {
                    return Err("Хоп-1 не может быть самим прокси".into());
                }
                s.proxy_vias.insert(url, v);
            }
            None => {
                s.proxy_vias.remove(&url);
            }
        }
        Ok(())
    })
}

// ─── VPN: подписки и ноды ────────────────────────────────────────

/// Сохранить весь VPN-блок (подписки + ноды) одним вызовом: страница «VPN»
/// работает со снимком целиком, атомарность важнее гранулярности.
pub fn set_vpn_data(
    subscriptions: Vec<crate::vpn::VpnSubscription>,
    nodes: Vec<crate::vpn::VpnNode>,
) -> Result<Settings, String> {
    with_settings(|s| {
        s.vpn_subscriptions = subscriptions;
        s.vpn_nodes = nodes;
        // Активная нода могла исчезнуть при обновлении подписки.
        if let Some(id) = &s.vpn_active {
            if !s.vpn_nodes.iter().any(|n| &n.id == id) {
                s.vpn_active = None;
            }
        }
        Ok(())
    })
}

pub fn set_vpn_active(node_id: Option<String>) -> Result<Settings, String> {
    with_settings(|s| {
        if let Some(id) = &node_id {
            if !s.vpn_nodes.iter().any(|n| &n.id == id) {
                return Err("Нода не найдена".into());
            }
        }
        s.vpn_active = node_id;
        Ok(())
    })
}

pub fn set_vpn_last_update(sub_id: &str, ts: u64) -> Result<(), String> {
    with_settings(|s| {
        if let Some(sub) = s.vpn_subscriptions.iter_mut().find(|x| x.id == sub_id) {
            sub.last_update = Some(ts);
        }
        Ok(())
    })
    .map(|_| ())
}

/// Режим маршрутизации туннеля + белый список. При работающем движке
/// команда UI перезапускает его сама (здесь только сохранение).
pub fn set_vpn_route(mode: String, whitelist: Vec<String>) -> Result<Settings, String> {
    let mode = match mode.as_str() {
        "smart" => "smart",
        "whitelist" => "whitelist",
        _ => "all",
    };
    let mut seen = std::collections::HashSet::new();
    let sites: Vec<String> = whitelist
        .iter()
        .map(|x| {
            x.trim()
                .to_ascii_lowercase()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("www.")
                .split('/')
                .next()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_string()
        })
        .filter(|d| !d.is_empty() && d.contains('.'))
        .filter(|d| seen.insert(d.clone()))
        .collect();
    with_settings(|s| {
        s.vpn_route_mode = mode.into();
        s.vpn_whitelist_sites = sites;
        Ok(())
    })
}

pub fn set_vpn_autostart(v: bool) -> Result<Settings, String> {
    with_settings(|s| {
        s.vpn_autostart = v;
        Ok(())
    })
}

/// Задать/убрать имя (тэг) прокси. Пустое имя = убрать.
pub fn set_proxy_label(url: String, label: String) -> Result<Settings, String> {
    with_settings(|s| {
        let label = label.trim().to_string();
        if label.is_empty() {
            s.proxy_labels.remove(&url);
        } else {
            s.proxy_labels.insert(url, label);
        }
        Ok(())
    })
}

pub fn set_proxy_assignments(
    map: std::collections::HashMap<String, usize>,
) -> Result<Settings, String> {
    with_settings(|s| {
        let pool_len = effective_proxies(s).len();
        s.proxy_assignments = map.into_iter().filter(|(_, idx)| *idx < pool_len).collect();
        Ok(())
    })
}

/// Задать/убрать прокси-по-умолчанию. Индекс обязан указывать в пул.
pub fn set_default_upstream(index: Option<usize>) -> Result<Settings, String> {
    with_settings(|s| {
        if let Some(i) = index {
            let pool_len = effective_proxies(s).len();
            if i >= pool_len {
                return Err(format!(
                    "Индекс {i} вне пула (в пуле {pool_len} прокси)"
                ));
            }
        }
        s.default_upstream = index;
        Ok(())
    })
}

/// Сохранить настройки браузеров (режим + список сайтов). Домены
/// нормализуем: lowercase, без схемы/пути/хвостовой точки.
pub fn set_browser_config(mode: String, sites: Vec<String>) -> Result<Settings, String> {
    let mode = if mode.eq_ignore_ascii_case("blacklist") {
        "blacklist"
    } else {
        "whitelist"
    };
    let mut seen = std::collections::HashSet::new();
    let normalized: Vec<String> = sites
        .iter()
        .map(|s| {
            s.trim()
                .to_ascii_lowercase()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("www.")
                .split('/')
                .next()
                .unwrap_or("")
                .trim_end_matches('.')
                .to_string()
        })
        .filter(|d| !d.is_empty() && d.contains('.'))
        .filter(|d| seen.insert(d.clone()))
        .collect();
    with_settings(|s| {
        s.browser_mode = Some(mode.into());
        s.browser_sites = normalized;
        Ok(())
    })
}

/// Снимок чужих настроек системного прокси Windows (см. browser.rs).
pub fn set_saved_browser_proxy(
    value: Option<std::collections::HashMap<String, String>>,
) -> Result<Settings, String> {
    with_settings(|s| {
        s.saved_browser_proxy = value;
        Ok(())
    })
}

/// Загрузить настройки, гарантируя что встроенные пресеты присутствуют.
///
/// При первом запуске (или после апдейта, добавившего новый пресет) сеет
/// недостающие builtin-профили, сохраняя пользовательский `enabled` у уже
/// существующих. Кастомные профили не трогает.
pub fn load_with_presets() -> Settings {
    let _g = SETTINGS_LOCK.lock().ok();
    let mut s = load();
    let presets = crate::apps::builtin_presets();
    let mut changed = false;

    for preset in presets {
        if let Some(existing) = s.app_profiles.iter_mut().find(|p| p.id == preset.id) {
            // Профиль уже есть — обновим только автодетект-поля (путь/AppID могли
            // появиться если приложение поставили позже), сохранив enabled.
            if existing.exe_path.is_none() && preset.exe_path.is_some() {
                existing.exe_path = preset.exe_path.clone();
                changed = true;
            }
            if existing.app_id.is_none() && preset.app_id.is_some() {
                existing.app_id = preset.app_id.clone();
                changed = true;
            }
        } else {
            s.app_profiles.push(preset);
            changed = true;
        }
    }

    if changed {
        let _ = save(&s);
    }
    s
}

/// Заменить список профилей целиком (UI прислал новое состояние enabled/добавил своё).
/// UI шлёт runtime-снимок, где exe_path/app_id пустеют, если приложение в
/// момент опроса недоступно (отключённый диск, «не найдено») — надёжные
/// сохранённые автодетект-поля пустотой не затираем.
pub fn set_profiles(profiles: Vec<AppProfile>) -> Result<Settings, String> {
    with_settings(|s| {
        let old = std::mem::take(&mut s.app_profiles);
        s.app_profiles = profiles
            .into_iter()
            .map(|mut p| {
                if let Some(prev) = old.iter().find(|o| o.id == p.id) {
                    if p.exe_path.is_none() {
                        p.exe_path = prev.exe_path.clone();
                    }
                    if p.app_id.is_none() {
                        p.app_id = prev.app_id.clone();
                    }
                }
                p
            })
            .collect();
        Ok(())
    })
}

/// Снимок чужих env-переменных до перезаписи (None = снять снимок).
pub fn set_saved_proxy_env(
    value: Option<std::collections::HashMap<String, String>>,
) -> Result<Settings, String> {
    with_settings(|s| {
        s.saved_proxy_env = value;
        Ok(())
    })
}

pub fn set_killswitch(enabled: bool) -> Result<Settings, String> {
    with_settings(|s| {
        s.killswitch_enabled = enabled;
        Ok(())
    })
}

pub fn set_route_mode(mode: String) -> Result<Settings, String> {
    with_settings(|s| {
        s.route_mode = Some(mode);
        Ok(())
    })
}

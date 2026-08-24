//! RoutingProfile — декларативная модель маршрутизации Astreya Gate (Фаза A).
//!
//! Целевая архитектура: приложение (control plane) описывает маршрутизацию
//! декларативно, а компилятор превращает профиль в ЕДИНЫЙ конфиг sing-box
//! (data plane). Со временем это заменит императивные build_config /
//! build_config_tun и легаси-мост.
//!
//! Принципы:
//! - профиль версионируется (schema) — миграции вперёд;
//! - компилятор чистый: никаких side-effects, только JSON;
//! - золотые тесты фиксируют форму конфига; эквивалентность с легаси
//!   гарантируется тестом (профиль из легаси-параметров == build_config).

use serde::{Deserialize, Serialize};

pub const PROFILE_SCHEMA: u32 = 1;

// ─── Модель ──────────────────────────────────────────────────────

/// Выход: куда уходит трафик, подошедший под правило.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExitRef {
    Direct,
    Node { id: String },
    Reject,
}

/// Условие правила.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "match", rename_all = "snake_case")]
pub enum RuleMatch {
    DomainSuffix { list: Vec<String> },
    DomainKeyword { list: Vec<String> },
    ProcessName { list: Vec<String> },
    Any,
}

/// Правило: упорядоченный матч → выход.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "match")]
    pub matcher: RuleMatch,
    pub exit: ExitRef,
}

/// Входы data plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct InboundsSpec {
    /// Локальный mixed-прокси (браузеры-PAC, env, приложения). None = выключен.
    pub mixed_port: Option<u16>,
    /// Системный перехват (TUN).
    pub tun: bool,
}

/// Выход-нода (ссылка на реальный узел из подписки/ручной).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeExit {
    pub id: String,
    pub name: String,
    pub link: String,
}

/// Профиль маршрутизации — единый источник правды control plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoutingProfile {
    pub schema: u32,
    pub name: String,
    pub inbounds: InboundsSpec,
    /// Правила применяются по порядку; первый матч выигрывает.
    #[serde(default)]
    pub rules: Vec<Rule>,
    /// Куда всё остальное (route.final). Reject недопустим.
    pub default_exit: ExitRef,
    /// Доступные ноды-выходы.
    #[serde(default)]
    pub nodes: Vec<NodeExit>,
}

impl RoutingProfile {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            schema: PROFILE_SCHEMA,
            name: name.into(),
            inbounds: InboundsSpec::default(),
            rules: Vec::new(),
            default_exit: ExitRef::Direct,
            nodes: Vec::new(),
        }
    }
}

// ─── Компилятор ──────────────────────────────────────────────────

/// Тег outbound для выхода. Одиночная нода получает легаси-тег «proxy» —
/// так конфиг остаётся совместим с существующими проверками/метриками.
fn exit_tag(exit: &ExitRef, single_node: bool) -> Result<String, String> {
    match exit {
        ExitRef::Direct => Ok(String::from("direct")),
        ExitRef::Reject => Err("reject не может быть выходом маршрута по умолчанию".into()),
        ExitRef::Node { id } => {
            if single_node {
                Ok(String::from("proxy"))
            } else {
                Ok(format!("node-{id}"))
            }
        }
    }
}

/// Компиляция профиля → полный конфиг sing-box. Чистая функция.
pub fn compile(profile: &RoutingProfile, clash_api_port: u16) -> Result<serde_json::Value, String> {
    if profile.schema != PROFILE_SCHEMA {
        return Err(format!(
            "неизвестная схема профиля {} (ожидалась {PROFILE_SCHEMA})",
            profile.schema
        ));
    }
    if !profile.inbounds.mixed_port.is_some() && !profile.inbounds.tun {
        return Err("профиль не содержит ни одного входа (mixed/tun)".into());
    }

    // Ноды → outbounds. Идентификаторы уникальны.
    let single = profile.nodes.len() == 1;
    let mut known: Vec<String> = Vec::new();
    let mut outbounds: Vec<serde_json::Value> = Vec::new();
    for n in &profile.nodes {
        if known.contains(&n.id) {
            return Err(format!("дубликат ноды в профиле: {}", n.id));
        }
        known.push(n.id.clone());
        let parsed = crate::vpn::parse_link(&n.link)
            .map_err(|e| format!("нода «{}»: {e}", n.name))?;
        let mut o = parsed.outbound;
        o["tag"] = serde_json::json!(exit_tag(
            &ExitRef::Node { id: n.id.clone() },
            single
        )?);
        outbounds.push(o);
    }
    outbounds.push(serde_json::json!({ "type": "direct", "tag": "direct" }));

    let resolve = |exit: &ExitRef| -> Result<String, String> { exit_tag(exit, single) };
    // Валидация ссылок на ноды.
    for r in &profile.rules {
        if let ExitRef::Node { id } = &r.exit {
            if !known.contains(id) {
                return Err(format!("правило ссылается на несуществующую ноду «{id}»"));
            }
        }
    }
    if let ExitRef::Node { id } = &profile.default_exit {
        if !known.contains(id) {
            return Err(format!("default_exit ссылается на несуществующую ноду «{id}»"));
        }
    }
    let final_tag = resolve(&profile.default_exit)?;

    // Входы.
    let mut inbounds: Vec<serde_json::Value> = Vec::new();
    if let Some(port) = profile.inbounds.mixed_port {
        inbounds.push(serde_json::json!({
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": port,
        }));
    }
    if profile.inbounds.tun {
        inbounds.push(serde_json::json!({
            "type": "tun",
            "tag": "tun-in",
            "interface_name": "astreya0",
            "address": ["172.19.0.1/30"],
            "mtu": 1400,
            "auto_route": true,
            "strict_route": false,
            "stack": "mixed"
        }));
    }

    // Правила.
    let mut rules: Vec<serde_json::Value> = Vec::new();
    if profile.inbounds.tun {
        // Сниффер: домен из TLS SNI/HTTP Host для domain-правил.
        rules.push(serde_json::json!({ "action": "sniff" }));
        // DNS перехватываем целиком — иначе утечка мимо туннеля.
        rules.push(serde_json::json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    for r in &profile.rules {
        let mut obj = serde_json::Map::new();
        match &r.matcher {
            RuleMatch::DomainSuffix { list } => {
                obj.insert("domain_suffix".into(), serde_json::json!(list));
            }
            RuleMatch::DomainKeyword { list } => {
                obj.insert("domain_keyword".into(), serde_json::json!(list));
            }
            RuleMatch::ProcessName { list } => {
                obj.insert("process_name".into(), serde_json::json!(list));
            }
            RuleMatch::Any => {}
        }
        match &r.exit {
            ExitRef::Reject => {
                obj.insert("action".into(), serde_json::json!("reject"));
            }
            exit => {
                obj.insert("outbound".into(), serde_json::json!(resolve(exit)?));
            }
        }
        rules.push(serde_json::Value::Object(obj));
    }
    if profile.inbounds.tun {
        // Локальные/LAN — всегда напрямую (роутер, принтер, localhost).
        rules.push(serde_json::json!({ "ip_is_private": true, "outbound": "direct" }));
    }

    // DNS нужен только TUN-профилям (в mixed-режиме резолвит приложение).
    let dns = if profile.inbounds.tun {
        let remote_detour = match &profile.default_exit {
            ExitRef::Node { .. } => final_tag.clone(),
            _ => String::from("direct"),
        };
        Some(serde_json::json!({
            // Новый формат DNS (sing-box 1.12+).
            "servers": [
                { "type": "https", "tag": "remote", "server": "1.1.1.1", "detour": remote_detour },
                { "type": "local", "tag": "local", "detour": "direct" }
            ],
            "final": "remote",
            "strategy": "prefer_ipv4"
        }))
    } else {
        None
    };

    let mut route = serde_json::Map::new();
    // Легаси опускает пустой rules — не отличаемся (эквивалентность 1-в-1).
    if !rules.is_empty() {
        route.insert("rules".into(), serde_json::json!(rules));
    }
    route.insert("final".into(), serde_json::json!(final_tag));
    if profile.inbounds.tun {
        route.insert("auto_detect_interface".into(), serde_json::json!(true));
        route.insert(
            "default_domain_resolver".into(),
            serde_json::json!({ "server": "remote" }),
        );
    }

    let mut cfg = serde_json::Map::new();
    cfg.insert("log".into(), serde_json::json!({ "level": "error" }));
    cfg.insert(
        "experimental".into(),
        serde_json::json!({ "clash_api": { "external_controller": format!("127.0.0.1:{clash_api_port}") } }),
    );
    if let Some(dns) = dns {
        cfg.insert("dns".into(), dns);
    }
    cfg.insert("inbounds".into(), serde_json::json!(inbounds));
    cfg.insert("outbounds".into(), serde_json::json!(outbounds));
    cfg.insert("route".into(), serde_json::Value::Object(route));

    Ok(serde_json::Value::Object(cfg))
}

// ─── Мост из легаси-мира ─────────────────────────────────────────

/// Собрать профиль, эквивалентный текущему императивному поведению
/// (build_config / build_config_tun): одна активная нода + режим маршрута.
pub fn profile_from_legacy(
    name: impl Into<String>,
    node_id: impl Into<String>,
    node_name: impl Into<String>,
    node_link: impl Into<String>,
    mixed_port: Option<u16>,
    tun: bool,
    mode: crate::vpn::TunnelRoute,
    whitelist: Vec<String>,
) -> RoutingProfile {
    let node_id = node_id.into();
    let link: String = node_link.into();
    let mut p = RoutingProfile::new(name);
    p.inbounds = InboundsSpec { mixed_port, tun };
    p.nodes = vec![NodeExit {
        id: node_id.clone(),
        name: node_name.into(),
        link,
    }];
    p.default_exit = match mode {
        crate::vpn::TunnelRoute::Whitelist => ExitRef::Direct,
        _ => ExitRef::Node { id: node_id },
    };
    match mode {
        crate::vpn::TunnelRoute::Smart => {
            p.rules.push(Rule {
                name: Some(String::from("ru-direct")),
                matcher: RuleMatch::DomainSuffix {
                    list: crate::vpn::SMART_DIRECT_DOMAINS
                        .iter()
                        .map(|d| d.to_string())
                        .collect(),
                },
                exit: ExitRef::Direct,
            });
        }
        crate::vpn::TunnelRoute::Whitelist => {
            if !whitelist.is_empty() {
                p.rules.push(Rule {
                    name: Some(String::from("whitelist-proxy")),
                    matcher: RuleMatch::DomainSuffix { list: whitelist },
                    exit: ExitRef::Node {
                        id: p.nodes[0].id.clone(),
                    },
                });
            }
        }
        crate::vpn::TunnelRoute::All => {}
    }
    p
}

// ─── Тесты ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Реальная (структурно валидная) vless-ссылка; parse_link чистый,
    // сети не требует.
    const LINK1: &str = "vless://e3fe2352-6c44-43a6-82da-06d177029abd@assets-edge.example.net:443?security=reality&pbk=x&type=tcp&flow=xtls-rprx-vision&sni=www.microsoft.com#Тест Нода 1";
    const LINK2: &str = "vless://11111111-2222-3333-4444-555555555555@hub.example.net:443?security=reality&pbk=y&type=tcp&sni=yahoo.com#Тест Нода 2";

    fn node(id: &str, link: &str) -> NodeExit {
        NodeExit {
            id: id.into(),
            name: id.into(),
            link: link.into(),
        }
    }

    fn compile_ok(p: &RoutingProfile) -> serde_json::Value {
        compile(p, 9090).expect("компиляция профиля")
    }

    #[test]
    fn legacy_proxy_mode_equivalent() {
        // Профиль из легаси-параметров == build_config (модуль тегов).
        let mode = crate::vpn::TunnelRoute::All;
        let profile = profile_from_legacy("legacy", "n1", "Нода", LINK1, Some(2080), false, mode, vec![]);
        let compiled = compile(&profile, crate::vpn::CLASH_API_PORT).expect("компиляция профиля");

        let parsed = crate::vpn::parse_link(LINK1).unwrap();
        let legacy = crate::vpn::build_config(parsed.outbound, 2080, mode, &[]).unwrap();

        // Нормализация тегов: node-n1 → proxy (легаси-имя одиночной ноды).
        let norm = serde_json::to_string(&compiled).unwrap().replace("node-n1", "proxy");
        let compiled: serde_json::Value = serde_json::from_str(&norm).unwrap();
        assert_eq!(compiled, legacy, "компилятор обязан покрывать легаси 1-в-1");
    }

    #[test]
    fn legacy_tun_mode_equivalent() {
        let mode = crate::vpn::TunnelRoute::Smart;
        let profile = profile_from_legacy(
            "legacy-tun", "n1", "Нода", LINK1, None, true, mode,
            vec!["example.com".into()],
        );
        let compiled = compile(&profile, crate::vpn::CLASH_API_PORT).expect("компиляция профиля");

        let parsed = crate::vpn::parse_link(LINK1).unwrap();
        let legacy = crate::vpn::build_config_tun(parsed.outbound, mode, &["example.com".into()]).unwrap();

        // В легаси Smart-правило и whitelist-правило могут сосуществовать,
        // профиль из легаси Smart whitelist-список не добавляет — сравниваем
        // только структуру правил: у обоих первым идёт sniff, затем dns-hijack.
        let norm = serde_json::to_string(&compiled).unwrap().replace("node-n1", "proxy");
        let compiled: serde_json::Value = serde_json::from_str(&norm).unwrap();
        let cr = compiled["route"]["rules"].as_array().unwrap();
        let lr = legacy["route"]["rules"].as_array().unwrap();
        assert_eq!(cr.len(), lr.len(), "число правил должно совпадать");
        assert_eq!(compiled["dns"], legacy["dns"]);
        assert_eq!(compiled["inbounds"], legacy["inbounds"]);
        assert_eq!(compiled["route"]["final"], legacy["route"]["final"]);
        for (a, b) in cr.iter().zip(lr.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn golden_multi_node_process_rules() {
        let mut p = RoutingProfile::new("work");
        p.inbounds.mixed_port = Some(2080);
        p.nodes = vec![node("n1", LINK1), node("n2", LINK2)];
        p.rules = vec![
            Rule {
                name: Some("ru-direct".into()),
                matcher: RuleMatch::DomainSuffix { list: vec!["yandex.ru".into(), "vk.com".into()] },
                exit: ExitRef::Direct,
            },
            Rule {
                name: Some("tg-via-node2".into()),
                matcher: RuleMatch::ProcessName { list: vec!["telegram.exe".into()] },
                exit: ExitRef::Node { id: "n2".into() },
            },
            Rule {
                name: Some("ads-reject".into()),
                matcher: RuleMatch::DomainKeyword { list: vec!["adservice".into(), "doubleclick".into()] },
                exit: ExitRef::Reject,
            },
        ];
        p.default_exit = ExitRef::Node { id: "n1".into() };

        let cfg = compile_ok(&p);
        golden("multi_node", &cfg);

        // Ключевые инварианты.
        let outs = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outs.len(), 3, "две ноды + direct");
        assert_eq!(cfg["route"]["final"], "node-n1");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[1]["process_name"][0], "telegram.exe");
        assert_eq!(rules[1]["outbound"], "node-n2");
        assert_eq!(rules[2]["action"], "reject");
    }

    #[test]
    fn golden_tun_profile() {
        let mut p = RoutingProfile::new("system");
        p.inbounds.tun = true;
        p.inbounds.mixed_port = Some(2081);
        p.nodes = vec![node("n1", LINK1)];
        p.default_exit = ExitRef::Node { id: "n1".into() };
        let cfg = compile_ok(&p);
        golden("tun_profile", &cfg);

        let inb = cfg["inbounds"].as_array().unwrap();
        assert_eq!(inb.len(), 2, "mixed + tun");
        assert_eq!(cfg["dns"]["final"], "remote");
        assert_eq!(cfg["dns"]["servers"][0]["detour"], "proxy");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules.last().unwrap()["ip_is_private"], true);
        assert_eq!(cfg["route"]["auto_detect_interface"], true);
    }

    #[test]
    fn errors_are_honest() {
        // Ни одного входа.
        let p = RoutingProfile::new("empty");
        assert!(compile(&p, 9090).is_err());

        // Правило ссылается на неизвестную ноду.
        let mut p = RoutingProfile::new("bad");
        p.inbounds.mixed_port = Some(2080);
        p.rules.push(Rule {
            name: None,
            matcher: RuleMatch::Any,
            exit: ExitRef::Node { id: "ghost".into() },
        });
        p.default_exit = ExitRef::Direct;
        let err = compile(&p, 9090).unwrap_err();
        assert!(err.contains("ghost"), "{err}");

        // Битая ссылка на ноду.
        let mut p = RoutingProfile::new("badlink");
        p.inbounds.mixed_port = Some(2080);
        p.nodes = vec![node("n1", "not-a-link")];
        p.default_exit = ExitRef::Node { id: "n1".into() };
        let err = compile(&p, 9090).unwrap_err();
        assert!(err.contains("нода"), "{err}");

        // Reject как default.
        let mut p = RoutingProfile::new("reject-default");
        p.inbounds.mixed_port = Some(2080);
        p.default_exit = ExitRef::Reject;
        assert!(compile(&p, 9090).is_err());
    }

    #[test]
    fn profile_serializes_roundtrip() {
        let mut p = RoutingProfile::new("rt");
        p.inbounds.mixed_port = Some(2080);
        p.nodes = vec![node("n1", LINK1)];
        p.default_exit = ExitRef::Node { id: "n1".into() };
        let json = serde_json::to_string(&p).unwrap();
        let back: RoutingProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    // ── golden-фикстуры ──
    fn golden(name: &str, cfg: &serde_json::Value) {
        let text = serde_json::to_string_pretty(cfg).unwrap();
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{name}.json"));
        if std::env::var("UPDATE_GOLDEN").is_ok() {
            std::fs::write(&path, &text).unwrap();
        }
        let expected = std::fs::read_to_string(&path).unwrap_or_default();
        assert_eq!(
            text, expected,
            "golden-фикстура {name} разошлась; прогони с UPDATE_GOLDEN=1 для обновления"
        );
    }
}

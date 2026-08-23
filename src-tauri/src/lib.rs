mod apps;
mod browser;
mod commands;
mod env_proxy;
mod firewall;
mod monitor;
mod proxy;
mod settings;
mod shim;
mod system;
mod tasks;
mod vpn;
mod vscode_config;

use tauri::{
    tray::{MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager, WindowEvent,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "astreya_gate_lib=info".into()),
        )
        .init();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            // Второй запуск: показать окно; если несли deep-link — импортировать.
            if let Some(win) = app.get_webview_window("main") {
                let _ = win.show();
                let _ = win.set_focus();
            }
            for a in argv {
                let lower = a.to_ascii_lowercase();
                if lower.starts_with("astreya://") || lower.starts_with("happ://") {
                    let app_h = app.clone();
                    tauri::async_runtime::spawn(async move {
                        match commands::vpn_import_inner(&a).await {
                            Ok(msg) => tracing::info!("deep-link: {msg}"),
                            Err(e) => tracing::warn!("deep-link: {e}"),
                        }
                    });
                }
            }
        }))
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--tray"]),
        ))
        .invoke_handler(tauri::generate_handler![
            commands::detect_node,
            commands::detect_python,
            commands::parse_proxy,
            commands::check_proxy,
            commands::run_install,
            commands::launch_claude_desktop,
            commands::launch_claude_code,
            commands::detect_cursor,
            commands::setup_cursor,
            commands::launch_cursor,
            // Shim control
            commands::shim_status,
            commands::shim_start,
            commands::shim_stop,
            commands::shim_restart,
            commands::shim_test,
            commands::shim_script_path,
            // Settings
            commands::settings_get,
            commands::settings_set_proxy,
            // App profiles
            commands::apps_list,
            commands::apps_set,
            commands::apps_add_custom,
            commands::apps_remove,
            commands::apps_launch,
            commands::apps_create_shortcut,
            // Killswitch
            commands::killswitch_status,
            commands::killswitch_enable,
            commands::killswitch_disable,
            // Global env (главный выключатель)
            commands::global_proxy_env,
            commands::set_global_proxy_env,
            commands::clear_global_proxy_env,
            // Автозапуск моста (Планировщик)
            commands::bridge_task_status,
            commands::bridge_task_register,
            // Мост: здоровье и маршрутизация
            commands::bridge_health,
            commands::bridge_exe_legacy,
            commands::bridge_set_route_mode,
            commands::bridge_update,
            commands::wizard_install,
            // Прокси-пул
            commands::proxies_get,
            commands::proxies_set,
            commands::proxy_assignments_get,
            commands::proxy_assignments_set,
            commands::proxy_labels_get,
            commands::proxy_label_set,
            commands::proxy_vias_get,
            commands::proxy_via_set,
            commands::proxy_default_get,
            commands::proxy_default_set,
            commands::proxies_ping,
            // Браузеры (PAC)
            commands::browsers_status,
            commands::browsers_configure,
            commands::browsers_enable,
            commands::browsers_disable,
            // VPN (sing-box)
            commands::vpn_overview,
            commands::vpn_add_subscription,
            commands::vpn_remove_subscription,
            commands::vpn_refresh_subscription,
            commands::vpn_add_link,
            commands::vpn_remove_node,
            commands::vpn_set_active,
            commands::vpn_start,
            commands::vpn_stop,
            commands::vpn_ping_all,
            commands::vpn_real_delay,
            commands::vpn_import,
            commands::vpn_set_route,
            commands::vpn_set_autostart,
            commands::vpn_tun_status,
            commands::vpn_tun_enable,
            commands::vpn_tun_disable,
            // Окна (трей-попап)
            commands::show_main_window,
            commands::quit_app,
        ])
        .setup(|app| {
            let handles = setup_tray(app.handle())?;

            // Deep-link первого запуска (astreya://… в argv).
            let launch_deeplink: Option<String> = std::env::args()
                .find(|a| {
                    let l = a.to_ascii_lowercase();
                    l.starts_with("astreya://") || l.starts_with("happ://")
                });
            if let Some(dl) = launch_deeplink {
                let app_h = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    match commands::vpn_import_inner(&dl).await {
                        Ok(msg) => tracing::info!("deep-link: {msg}"),
                        Err(e) => tracing::warn!("deep-link: {e}"),
                    }
                });
            }

            // Регистрация схемы astreya:// (HKCU — без прав администратора).
            std::thread::spawn(commands::register_url_scheme);

            // Фоновое автообновление подписок: раз в 30 мин, каждая — по
            // своему интервалу (свежие пропускаются внутри).
            {
                let app_h = app.handle().clone();
                std::thread::spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_secs(1800));
                    let app_h2 = app_h.clone();
                    let r = tauri::async_runtime::block_on(async move {
                        crate::vpn::refresh_subscriptions_inner(None, true).await
                    });
                    match r {
                        Ok((0, _)) => {}
                        Ok((n, total)) => tracing::info!(
                            "автообновление подписок: {n} шт., нод теперь {total}"
                        ),
                        Err(e) => {
                            let _ = app_h2;
                            tracing::warn!("автообновление подписок: {e}")
                        }
                    }
                });
            }

            // Автоподключение туннеля при старте, если включено и есть нода.
            {
                let s = crate::settings::load();
                if s.vpn_autostart && s.vpn_active.is_some() {
                    std::thread::spawn(|| {
                        // Дать системе/сети устаканиться после логина.
                        std::thread::sleep(std::time::Duration::from_secs(3));
                        let st = crate::settings::load();
                        if let Some(node) = st
                            .vpn_nodes
                            .iter()
                            .find(|n| Some(n.id.as_str()) == st.vpn_active.as_deref())
                        {
                            match crate::vpn::start(&node.link, st.vpn_port) {
                                Ok(name) => {
                                    tracing::info!("автостарт VPN: подключено «{name}»")
                                }
                                Err(e) => tracing::warn!("автостарт VPN: {e}"),
                            }
                        }
                    });
                }
            }

            // Трей-монитор: живая иконка (зелёная/жёлтая/красная точка),
            // tooltip со счётчиками и системные уведомления о переходах
            // (мост упал/ожил, upstream лежит, высокий пинг).
            monitor::spawn(app.handle().clone(), handles);

            // Watchdog: авто-подъём упавшего шима (корневой фикс «деплой роняет
            // мост → Claude Code теряет связь»). Фоновый поток, переживает любые
            // ошибки, поднимает шим за ~5с после падения. Второй эшелон после
            // RestartOnFailure Планировщика (тот работает и без нашего GUI).
            shim::spawn_watchdog();

            // Миграция старых установок: .vbs в Startup → задача Планировщика
            // с автоперезапуском. Фоново — PS-вызовы медленные, UI не ждёт.
            std::thread::spawn(tasks::migrate_from_startup_vbs);

            // Если запущены с флагом --tray (после автозапуска Windows) —
            // прячем главное окно при старте, видна только иконка в трее.
            let args: Vec<String> = std::env::args().collect();
            if args.iter().any(|a| a == "--tray") {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            match event {
                WindowEvent::CloseRequested { api, .. } => {
                    // Close-to-tray: крестик прячет окно, не закрывает приложение.
                    // Полный выход — только через меню трея "Выход".
                    api.prevent_close();
                    let _ = window.hide();
                }
                // Трей-попап: light dismiss — потерял фокус → спрятался
                // (паттерн Tailscale/WARP).
                WindowEvent::Focused(false) if window.label() == "tray" => {
                    let _ = window.hide();
                }
                _ => {}
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn setup_tray(app: &tauri::AppHandle) -> tauri::Result<monitor::TrayHandles> {
    // Нативного меню НЕТ намеренно: Windows не даёт его стилизовать, и оно
    // выглядело «как у старых приложух». Любой клик (левый и правый) открывает
    // фирменный попап — паттерн Cloudflare WARP. Вся функциональность меню
    // (статус, тест, тумблеры, рестарт/стоп, выход) живёт в попапе.
    let tray = TrayIconBuilder::with_id("main-tray")
        .icon(app.default_window_icon().unwrap().clone())
        .tooltip("Astreya Gate")
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button_state: MouseButtonState::Up,
                position,
                ..
            } = event
            {
                show_tray_popup(tray.app_handle(), position.x, position.y);
            }
        })
        .build(app)?;

    Ok(monitor::TrayHandles { tray })
}

/// Показать трей-попап у точки клика (physical px). Позиция: над курсором,
/// правый край примерно под иконкой (таскбар Windows обычно снизу справа);
/// клампится в границы монитора — на случай таскбара сверху/сбоку.
fn show_tray_popup(app: &tauri::AppHandle, cx: f64, cy: f64) {
    // Окно объявлено в tauri.conf.json и создаётся при старте; если его нет
    // (создание упало) — создаём на лету, иначе клик по трею «молчит».
    let win = match app.get_webview_window("tray") {
        Some(w) => w,
        None => {
            match tauri::WebviewWindowBuilder::new(
                app,
                "tray",
                tauri::WebviewUrl::App("index.html?view=tray".into()),
            )
            .title("Astreya Gate")
            .inner_size(332.0, 404.0)
            .resizable(false)
            .decorations(false)
            .transparent(true)
            .shadow(false)
            .always_on_top(true)
            .skip_taskbar(true)
            .visible(false)
            .focused(false)
            .build()
            {
                Ok(w) => w,
                Err(e) => {
                    tracing::warn!("не удалось создать окно трей-попапа: {e}");
                    return;
                }
            }
        }
    };
    // Повторный клик при открытом попапе: blur уже спрятал его до того, как
    // пришёл Click, так что здесь попап почти всегда скрыт — просто покажем.
    // Позиция над курсором + кламп в границы монитора клика.
    let place = |w: f64, h: f64| -> (f64, f64) {
        let mut x = cx - w + 24.0;
        let mut y = cy - h - 8.0;
        if let Ok(monitors) = win.available_monitors() {
            let m = monitors.iter().find(|m| {
                let p = m.position();
                let s = m.size();
                cx >= p.x as f64
                    && cx < p.x as f64 + s.width as f64
                    && cy >= p.y as f64
                    && cy < p.y as f64 + s.height as f64
            });
            if let Some(m) = m {
                let (mx, my) = (m.position().x as f64, m.position().y as f64);
                let (mw, mh) = (m.size().width as f64, m.size().height as f64);
                x = x.clamp(mx + 8.0, (mx + mw - w - 8.0).max(mx + 8.0));
                // Таскбар сверху: клик в верхней трети экрана → попап под курсором.
                if y < my + 8.0 {
                    y = cy + 16.0;
                }
                y = y.clamp(my + 8.0, (my + mh - h - 8.0).max(my + 8.0));
            }
        }
        (x, y)
    };

    let size = win.outer_size().unwrap_or(tauri::PhysicalSize::new(332, 424));
    let (x, y) = place(size.width as f64, size.height as f64);
    let _ = win.set_position(tauri::PhysicalPosition::new(x, y));
    // Смешанные DPI: перенос окна на монитор с другим масштабом меняет его
    // physical-размер — первый кламп считался по старому. Перемеряем и, если
    // размер сменился, позиционируем ещё раз по фактическому.
    if let Ok(after) = win.outer_size() {
        if after.width != size.width || after.height != size.height {
            let (x2, y2) = place(after.width as f64, after.height as f64);
            let _ = win.set_position(tauri::PhysicalPosition::new(x2, y2));
        }
    }
    let _ = win.show();
    let _ = win.set_focus();
}

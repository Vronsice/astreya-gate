import { invoke } from "@tauri-apps/api/core";
import type {
  AppProfile,
  AppProfileStatus,
  AppSettings,
  BridgeHealth,
  BridgeTaskStatus,
  BrowserMode,
  BrowserStatus,
  CursorInfo,
  CursorSetupResult,
  GlobalProxyEnv,
  KillswitchStatus,
  NodeInfo,
  ProxyCheckResult,
  ProxyConfig,
  ProxyPing,
  PythonInfo,
  RoutingRule,
  ShimStatus,
  ShimTestResult,
  ShortcutTarget,
  VpnOverview,
  WizardInstallResult,
} from "./types";

export async function detectNode(): Promise<NodeInfo> {
  return invoke<NodeInfo>("detect_node");
}

export async function detectPython(): Promise<PythonInfo> {
  return invoke<PythonInfo>("detect_python");
}

// ─── Cursor IDE ──────────────────────────────────────────────────

export async function detectCursor(): Promise<CursorInfo> {
  return invoke<CursorInfo>("detect_cursor");
}

export async function setupCursor(): Promise<CursorSetupResult> {
  return invoke<CursorSetupResult>("setup_cursor");
}

export async function launchCursor(): Promise<void> {
  return invoke<void>("launch_cursor");
}

export async function parseProxy(url: string): Promise<ProxyConfig> {
  return invoke<ProxyConfig>("parse_proxy", { url });
}

export async function checkProxy(url: string): Promise<ProxyCheckResult> {
  return invoke<ProxyCheckResult>("check_proxy", { url });
}

export async function runInstall(params: {
  mode: "code" | "desktop" | "both" | null;
  cursor: boolean;
  proxyUrl: string;
}): Promise<void> {
  return invoke<void>("run_install", params);
}

/** Установка нового мастера одним вызовом (прогресс — событие "wizard:step"). */
export async function wizardInstall(proxyUrl: string): Promise<WizardInstallResult> {
  return invoke<WizardInstallResult>("wizard_install", { proxyUrl });
}

// ─── Shim control ────────────────────────────────────────────────

export async function shimStatus(): Promise<ShimStatus> {
  return invoke<ShimStatus>("shim_status");
}

export async function shimStart(): Promise<void> {
  return invoke<void>("shim_start");
}

export async function shimStop(): Promise<number> {
  return invoke<number>("shim_stop");
}

export async function shimRestart(): Promise<void> {
  return invoke<void>("shim_restart");
}

export async function shimTest(): Promise<ShimTestResult> {
  return invoke<ShimTestResult>("shim_test");
}

export async function shimScriptPath(): Promise<string | null> {
  return invoke<string | null>("shim_script_path");
}

// ─── Settings ────────────────────────────────────────────────────

export async function settingsGet(): Promise<AppSettings> {
  return invoke<AppSettings>("settings_get");
}

export async function settingsSetProxy(url: string): Promise<AppSettings> {
  return invoke<AppSettings>("settings_set_proxy", { url });
}

// ─── App profiles ────────────────────────────────────────────────

export async function appsList(): Promise<AppProfileStatus[]> {
  return invoke<AppProfileStatus[]>("apps_list");
}

export async function appsSet(
  profiles: AppProfile[],
): Promise<AppProfileStatus[]> {
  return invoke<AppProfileStatus[]>("apps_set", { profiles });
}

export async function appsAddCustom(
  name: string,
  exePath: string,
): Promise<AppProfileStatus[]> {
  return invoke<AppProfileStatus[]>("apps_add_custom", { name, exePath });
}

export async function appsRemove(id: string): Promise<AppProfileStatus[]> {
  return invoke<AppProfileStatus[]>("apps_remove", { id });
}

export async function appsLaunch(id: string): Promise<void> {
  return invoke<void>("apps_launch", { id });
}

export async function appsCreateShortcut(
  id: string,
  target: ShortcutTarget,
): Promise<string> {
  return invoke<string>("apps_create_shortcut", { id, target });
}

// ─── Killswitch ──────────────────────────────────────────────────

export async function killswitchStatus(): Promise<KillswitchStatus> {
  return invoke<KillswitchStatus>("killswitch_status");
}

export async function killswitchEnable(): Promise<KillswitchStatus> {
  return invoke<KillswitchStatus>("killswitch_enable");
}

export async function killswitchDisable(): Promise<KillswitchStatus> {
  return invoke<KillswitchStatus>("killswitch_disable");
}

// ─── Global proxy env (главный выключатель) ──────────────────────

export async function globalProxyEnv(): Promise<GlobalProxyEnv> {
  return invoke<GlobalProxyEnv>("global_proxy_env");
}

/** Включить системное проксирование: HTTP(S)_PROXY → мост (User scope). */
export async function setGlobalProxyEnv(): Promise<GlobalProxyEnv> {
  return invoke<GlobalProxyEnv>("set_global_proxy_env");
}

export async function clearGlobalProxyEnv(): Promise<GlobalProxyEnv> {
  return invoke<GlobalProxyEnv>("clear_global_proxy_env");
}

// ─── Автозапуск моста (Планировщик задач) ────────────────────────

export async function bridgeTaskStatus(): Promise<BridgeTaskStatus> {
  return invoke<BridgeTaskStatus>("bridge_task_status");
}

export async function bridgeTaskRegister(): Promise<BridgeTaskStatus> {
  return invoke<BridgeTaskStatus>("bridge_task_register");
}

// ─── Мост: /healthz и маршрутизация ──────────────────────────────

/** Живые счётчики моста. Кидает, если мост не отвечает или старый (python). */
export async function bridgeHealth(): Promise<BridgeHealth> {
  return invoke<BridgeHealth>("bridge_health");
}

/** Установленный exe моста — легаси-python (без /healthz)? Кэшируется по mtime. */
export async function bridgeExeLegacy(): Promise<boolean> {
  return invoke<boolean>("bridge_exe_legacy");
}

export async function bridgeSetRouteMode(mode: "smart" | "all"): Promise<void> {
  return invoke<void>("bridge_set_route_mode", { mode });
}

/** Обновить установленный мост из ресурсов приложения (stop → copy → start). */
export async function bridgeUpdate(): Promise<string> {
  return invoke<string>("bridge_update");
}

// ─── Прокси-пул ──────────────────────────────────────────────────

/** Пул прокси (1..5 URL, [0] — основной). */
export async function proxiesGet(): Promise<string[]> {
  return invoke<string[]>("proxies_get");
}

/** Заменить пул: валидация + перерегистрация задачи + рестарт моста. */
export async function proxiesSet(urls: string[]): Promise<string[]> {
  return invoke<string[]>("proxies_set", { urls });
}

export async function proxyAssignmentsGet(): Promise<Record<string, number>> {
  return invoke<Record<string, number>>("proxy_assignments_get");
}

export async function proxyAssignmentsSet(
  assignments: Record<string, number>,
): Promise<void> {
  return invoke<void>("proxy_assignments_set", { assignments });
}

/** Лёгкий TCP-пинг всего пула (параллельно). */
export async function proxiesPing(): Promise<ProxyPing[]> {
  return invoke<ProxyPing[]>("proxies_ping");
}

/** Имена (тэги) прокси: URL → имя. */
export async function proxyLabelsGet(): Promise<Record<string, string>> {
  return invoke<Record<string, string>>("proxy_labels_get");
}

/** Задать/убрать имя прокси (пустое = убрать). */
export async function proxyLabelSet(
  url: string,
  label: string,
): Promise<Record<string, string>> {
  return invoke<Record<string, string>>("proxy_label_set", { url, label });
}

// ─── Цепочки (via) ───────────────────────────────────────────────

/** Цепочки: URL финального прокси → URL хопа-1. */
export async function proxyViasGet(): Promise<Record<string, string>> {
  return invoke<Record<string, string>>("proxy_vias_get");
}

/** Задать/убрать цепочку (via=null — прямое подключение). */
export async function proxyViaSet(
  url: string,
  via: string | null,
): Promise<Record<string, string>> {
  return invoke<Record<string, string>>("proxy_via_set", { url, via });
}

// ─── Прокси по умолчанию ─────────────────────────────────────────

/** Прокси по умолчанию для трафика без назначения (индекс пула или null). */
export async function proxyDefaultGet(): Promise<number | null> {
  return invoke<number | null>("proxy_default_get");
}

/** Задать прокси по умолчанию (null = первый прокси пула). */
export async function proxyDefaultSet(index: number | null): Promise<void> {
  return invoke<void>("proxy_default_set", { index });
}

// ─── Браузеры (PAC) ──────────────────────────────────────────────

export async function browsersStatus(): Promise<BrowserStatus> {
  return invoke<BrowserStatus>("browsers_status");
}

/** Сохранить режим + список сайтов (PAC переписывается, реестр не трогается). */
export async function browsersConfigure(
  mode: BrowserMode,
  sites: string[],
): Promise<void> {
  return invoke<void>("browsers_configure", { mode, sites });
}

export async function browsersEnable(): Promise<BrowserStatus> {
  return invoke<BrowserStatus>("browsers_enable");
}

export async function browsersDisable(): Promise<BrowserStatus> {
  return invoke<BrowserStatus>("browsers_disable");
}

// ─── VPN (sing-box) ──────────────────────────────────────────────

export async function vpnOverview(): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_overview");
}

export async function vpnAddSubscription(name: string, url: string): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_add_subscription", { name, url });
}

export async function vpnRemoveSubscription(id: string): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_remove_subscription", { id });
}

/** Обновить одну подписку (id=null — все). */
export async function vpnRefreshSubscription(id: string | null): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_refresh_subscription", { id });
}

export async function vpnAddLink(link: string): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_add_link", { link });
}

export async function vpnRemoveNode(id: string): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_remove_node", { id });
}

export async function vpnSetActive(id: string | null): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_set_active", { id });
}

export async function vpnStart(): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_start");
}

export async function vpnStop(): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_stop");
}

/** TCP-пинг всех нод: nodeId → мс или null. */
export async function vpnPingAll(): Promise<Record<string, number | null>> {
  return invoke<Record<string, number | null>>("vpn_ping_all");
}

/** Реальный delay-тест активной ноды через туннель. */
export async function vpnRealDelay(): Promise<number> {
  return invoke<number>("vpn_real_delay");
}

/** Импорт deep-link / ссылки из буфера (astreya://, happ://add, плейн-ссылки). */
export async function vpnImport(input: string): Promise<string> {
  return invoke<string>("vpn_import", { input });
}

/** Режим маршрутизации туннеля + белый список. */
export async function vpnSetRoute(
  mode: "all" | "smart" | "whitelist",
  whitelist: string[],
): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_set_route", { mode, whitelist });
}

/** Автоподключение туннеля при старте приложения. */
export async function vpnSetAutostart(v: boolean): Promise<VpnOverview> {
  return invoke<VpnOverview>("vpn_set_autostart", { v });
}

// ─── VPN: системный режим (TUN) ──────────────────────────────────

export interface TunStatus {
  registered: boolean;
  state?: string;
  running_process: boolean;
}

export async function vpnTunStatus(): Promise<TunStatus> {
  return invoke<TunStatus>("vpn_tun_status");
}

/** Включение потребует один UAC-запрос на регистрацию задачи. */
export async function vpnTunEnable(): Promise<TunStatus> {
  return invoke<TunStatus>("vpn_tun_enable");
}

export async function vpnTunDisable(): Promise<TunStatus> {
  return invoke<TunStatus>("vpn_tun_disable");
}

// ─── VPN: системный прокси браузеров ─────────────────────────────

/** WinINET-прокси на порт туннеля. Авто-выключается при смерти туннеля. */
export async function vpnSystemProxySet(v: boolean): Promise<boolean> {
  return invoke<boolean>("vpn_system_proxy_set", { v });
}

export async function vpnSystemProxyGet(): Promise<boolean> {
  return invoke<boolean>("vpn_system_proxy_get");
}

// ─── VPN: пользовательские правила маршрутизации ─────────────────

export async function vpnRulesGet(): Promise<RoutingRule[]> {
  return invoke<RoutingRule[]>("vpn_rules_get");
}

/** Добавить/заменить правило (по имени). Туннель перезапустится сам. */
export async function vpnRuleSave(rule: RoutingRule): Promise<RoutingRule[]> {
  return invoke<RoutingRule[]>("vpn_rule_save", { rule });
}

export async function vpnRuleRemove(name: string): Promise<RoutingRule[]> {
  return invoke<RoutingRule[]>("vpn_rule_remove", { name });
}

// ─── Окна (для трей-попапа) ──────────────────────────────────────

/** Показать главное окно (из трей-попапа). */
export async function showMainWindow(): Promise<void> {
  return invoke<void>("show_main_window");
}

/** Полный выход из приложения (мост продолжает работать — он отдельный процесс). */
export async function quitApp(): Promise<void> {
  return invoke<void>("quit_app");
}

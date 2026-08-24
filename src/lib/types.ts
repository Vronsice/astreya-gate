export type InstallMode = "code" | "desktop" | "both";

export interface ProxyConfig {
  url: string;
  host: string;
  port: number;
  username: string;
  password: string;
  label: string;
}

export interface NodeInfo {
  installed: boolean;
  version?: string;
  npm_prefix?: string;
  prefix_in_program_files: boolean;
}

export interface PythonInfo {
  installed: boolean;
  version?: string;
  command?: string;
}

export interface CursorInfo {
  installed: boolean;
  exe_path?: string;
  shortcut_exists: boolean;
}

export interface CursorSetupResult {
  ok: boolean;
  found: boolean;
  message: string;
}

export interface ProxyCheckResult {
  reachable: boolean;
  latency_ms?: number;
  status_code?: number;
  error?: string;
  ip?: string;
  country_code?: string;
  country_name?: string;
  isp?: string;
}

/** Новый мастер: 3 шага (прокси → установка → готово). */
export type WizardStep = "proxy" | "install" | "done";

/** Результат wizard_install: честная проверка + состояние env. */
export interface WizardInstallResult {
  test: ShimTestResult;
  env_on: boolean;
}

// ─── Dashboard / Shim ────────────────────────────────────────────

export interface ShimStatus {
  running: boolean;
  pid?: number;
  uptime_sec?: number;
  listen?: string;
  /** URL с замаскированным паролем: http://user:****@host:port */
  upstream_masked?: string;
  upstream_host?: string;
  upstream_port?: number;
}

export interface ShimTestResult {
  ok: boolean;
  latency_ms?: number;
  error?: string;
  external_ip?: string;
}

// ─── App-level navigation ────────────────────────────────────────

export type AppView =
  | "home"
  | "map"
  | "nodes"
  | "rules"
  | "bridge"
  | "browsers"
  | "guide"
  | "settings"
  | "wizard";

// ─── Persistent settings (mirror of Rust Settings) ───────────────

export interface AppSettings {
  proxy_url?: string;
  autostart_dashboard: boolean;
  app_profiles?: AppProfile[];
  killswitch_enabled?: boolean;
  /** "all" | "smart" (None = "all"). */
  route_mode?: string;
  /** Прокси по умолчанию для трафика без назначения (индекс пула). */
  default_upstream?: number;
}

// ─── App profiles (проксируемые приложения) ──────────────────────

export type LaunchKind = "exe_flag" | "msix" | "custom";

export interface AppProfile {
  id: string;
  name: string;
  kind: LaunchKind;
  exe_path?: string;
  app_id?: string;
  process_names: string[];
  enabled: boolean;
  builtin: boolean;
}

/** Runtime-статус профиля (mirror of Rust AppProfileStatus). */
export interface AppProfileStatus {
  id: string;
  name: string;
  kind: LaunchKind;
  enabled: boolean;
  builtin: boolean;
  installed: boolean;
  location?: string;
  desktop_shortcut: boolean;
  process_names: string[];
}

export type ShortcutTarget = "desktop" | "start_menu";

// ─── Killswitch ──────────────────────────────────────────────────

export interface KillswitchStatus {
  active: boolean;
  rule_count: number;
  blocked_processes: string[];
}

// ─── Global proxy env (главный выключатель) ──────────────────────

export interface GlobalProxyEnv {
  present: boolean;
  /** Все значения указывают на наш мост (127.0.0.1:8889). */
  points_to_bridge: boolean;
  /** [name, value] пары. */
  values: [string, string][];
}

// ─── Автозапуск моста (Планировщик задач) ────────────────────────

export interface BridgeTaskStatus {
  registered: boolean;
  /** Ready / Running / Disabled. */
  state?: string;
}

// ─── Мост: /healthz и маршрутизация ──────────────────────────────

export interface BridgeUpstreamHealth {
  url: string;
  healthy: boolean;
  ok: number;
  fail: number;
  /** Тип финального хопа ("http" | "socks5"); мост 1.5.0+. */
  kind?: string;
  /** Цепочка: подключение через хоп-1. */
  chained?: boolean;
  /** Трафик через upstream: байт отправлено/получено (мост 1.5.0+). */
  sent?: number;
  received?: number;
}

/** Ошибка из кольцевого буфера моста: секунды-от-старта + текст. */
export interface BridgeErrorEntry {
  t: number;
  msg: string;
}

export interface BridgeHealth {
  status: string;
  version: string;
  uptime_sec: number;
  listen: string;
  /** "smart" — через upstream только AI-домены; "all" — весь трафик. */
  mode: string;
  active: number;
  total: number;
  via_upstream: number;
  via_direct: number;
  errors: number;
  /** Глобальный трафик моста: байт отправлено/получено (мост 1.5.0+). */
  sent?: number;
  received?: number;
  upstreams: BridgeUpstreamHealth[];
  /** Последние ошибки (мост 1.1.0+; у старых может отсутствовать). */
  last_errors?: BridgeErrorEntry[];
}

// ─── Прокси-пул ──────────────────────────────────────────────────

/** TCP-пинг одного прокси из пула. ms=null — не подключились. */
export interface ProxyPing {
  url: string;
  host: string;
  port: number;
  ms: number | null;
}

/** Группы сервисов для назначений (mirror tasks::SERVICE_GROUPS). */
export type ServiceGroup =
  | "anthropic"
  | "openai"
  | "google"
  | "openrouter"
  | "telegram"
  | "other_ai";

// ─── Браузеры (PAC) ──────────────────────────────────────────────

export type BrowserMode = "whitelist" | "blacklist";

/** Статус PAC-интеграции (mirror of Rust BrowserStatus). */
export interface BrowserStatus {
  /** Наш PAC сейчас прописан системным. */
  active: boolean;
  system_auto_config_url?: string;
  mode: BrowserMode;
  sites: string[];
  pac_path?: string;
}

// ─── VPN: правила маршрутизации (RoutingProfile) ─────────────────

export type RuleExit =
  | { type: "direct" }
  | { type: "node"; id: string }
  | { type: "pool" }
  | { type: "selector" }
  | { type: "reject" };

export type RuleMatch =
  | { match: "domain_suffix"; list: string[] }
  | { match: "domain_keyword"; list: string[] }
  | { match: "process_name"; list: string[] }
  | { match: "any" };

/** Зеркало routing::Rule (Rust). */
export interface RoutingRule {
  name?: string;
  match: RuleMatch;
  exit: RuleExit;
}

// ─── VPN (sing-box) ──────────────────────────────────────────────

export interface VpnSubscription {
  id: string;
  name: string;
  url: string;
  /** Интервал автообновления в часах (0 = вручную). */
  interval_hours: number;
  last_update?: number;
}

export interface VpnNode {
  id: string;
  name: string;
  link: string;
  /** "vless" | "vmess" | "ss" | "trojan" | "hysteria2" | "tuic" */
  proto: string;
  server: string;
  port: number;
  /** id подписки или "manual". */
  source: string;
  added_at: number;
}

export interface VpnProcessStatus {
  running: boolean;
  pid?: number;
  uptime_sec?: number;
}

/** Снимок страницы VPN. Скорости считаем на фронте по дельтам totals. */
export interface VpnOverview {
  subscriptions: VpnSubscription[];
  nodes: VpnNode[];
  active: string | null;
  port: number;
  process: VpnProcessStatus;
  /** Режим маршрутизации туннеля. */
  route_mode: "all" | "smart" | "whitelist";
  whitelist_sites: string[];
  autostart: boolean;
  up_total?: number;
  down_total?: number;
}

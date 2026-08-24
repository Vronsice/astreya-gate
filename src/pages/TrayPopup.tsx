import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  Activity,
  ChevronDown,
  ExternalLink,
  Globe,
  Loader2,
  LogOut,
  Power,
  Zap,
} from "lucide-react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Toggle } from "../components/Toggle";
import { StatusOrb } from "../components/StatusOrb";
import {
  bridgeSetRouteMode,
  clearGlobalProxyEnv,
  setGlobalProxyEnv,
  quitApp,
  shimTest,
  showMainWindow,
  vpnOverview,
  vpnPingAll,
  vpnSetActive,
  vpnStart,
  vpnStop,
  vpnSystemProxyGet,
  vpnSystemProxySet,
} from "../lib/api";
import { formatUptime, useStatus } from "../lib/status";
import { cleanNodeName } from "../lib/nodeNames";
import type { VpnOverview } from "../lib/types";
import { cn } from "../lib/cn";

/* Флаг из имени ноды («ch Швейцария» → 🇨🇭). Иначе — глобус. */
function flagOf(name: string): string {
  const m = name.match(/^([a-z]{2})\b/i);
  if (!m) return "🌐";
  return m[1].toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

const fmtSpeed = (bps?: number) =>
  bps === undefined || bps === null
    ? "—"
    : bps >= 1_048_576
      ? `${(bps / 1_048_576).toFixed(1)} МБ/с`
      : bps >= 1024
        ? `${Math.round(bps / 1024)} КБ/с`
        : `${Math.round(bps)} Б/с`;

/*
  Трей-попап = мини-приложение (паттерн Tailscale/WARP): VPN-герой с
  питанием и сменой ноды наверху, тумблеры ниже, мост — строкой статуса.
  Окно прозрачное, скрывается по blur (Rust), панель прижата к трею.
*/
export function TrayPopup() {
  const { status, health, refresh, env, setEnv } = useStatus();

  const [ov, setOv] = useState<VpnOverview | null>(null);
  const [pings, setPings] = useState<Record<string, number> | null>(null);
  const [sysProxy, setSysProxy] = useState<boolean | null>(null);
  const [speed, setSpeed] = useState<{ up: number; down: number } | null>(null);
  const [busy, setBusy] = useState<"power" | "node" | "best" | "test" | "sysproxy" | "env" | "route" | null>(null);
  const [listOpen, setListOpen] = useState(false);
  const [testResult, setResult] = useState<string | null>(null);
  const [actionError, setError] = useState<string | null>(null);

  const lastTotals = useRef<{ t: number; up: number; down: number } | null>(null);
  const failFlash = (e: unknown) => {
    setError(String(e));
    window.setTimeout(() => setError(null), 6000);
  };

  const loadVpn = useCallback(async () => {
    try {
      const o = await vpnOverview();
      const now = Date.now() / 1000;
      if (lastTotals.current && o.up_total !== undefined && o.down_total !== undefined) {
        const dt = now - lastTotals.current.t;
        if (dt > 0.5) {
          setSpeed({
            up: Math.max(0, (o.up_total - lastTotals.current.up) / dt),
            down: Math.max(0, (o.down_total - lastTotals.current.down) / dt),
          });
        }
      }
      if (o.up_total !== undefined && o.down_total !== undefined) {
        lastTotals.current = { t: now, up: o.up_total, down: o.down_total };
      }
      setOv(o);
    } catch {
      /* трей переживает недоступность бэкенда */
    }
  }, []);

  useEffect(() => {
    void loadVpn();
    void vpnSystemProxyGet().then(setSysProxy).catch(() => setSysProxy(null));
    const iv = window.setInterval(() => void loadVpn(), 2000);
    return () => window.clearInterval(iv);
  }, [loadVpn]);

  const vpnRunning = ov?.process.running ?? false;
  const activeNode = useMemo(
    () => ov?.nodes.find((n) => n.id === ov.active) ?? null,
    [ov],
  );

  const ensurePings = useCallback(async () => {
    if (pings) return pings;
    const r = await vpnPingAll();
    const clean: Record<string, number> = {};
    for (const [k, v] of Object.entries(r)) if (v !== null && v > 0) clean[k] = v;
    setPings(clean);
    return clean;
  }, [pings]);

  const power = async () => {
    setBusy("power");
    setError(null);
    try {
      if (vpnRunning) {
        setOv(await vpnStop());
      } else {
        if (!ov?.active) {
          setError("Сначала выбери ноду в приложении");
          return;
        }
        setOv(await vpnStart());
      }
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };

  /* Сменить ноду: выбор + перезапуск туннеля, если он был поднят. */
  const switchNode = async (id: string) => {
    setBusy("node");
    setError(null);
    try {
      let o = await vpnSetActive(id);
      if (o.process.running) {
        o = await vpnStop();
        o = await vpnStart();
      }
      setOv(o);
      setListOpen(false);
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };

  const bestNode = async () => {
    setBusy("best");
    setError(null);
    try {
      const p = await ensurePings();
      const best = Object.entries(p).sort((a, b) => a[1] - b[1])[0];
      if (!best) {
        setError("Все ноды недоступны — обнови подписку");
        return;
      }
      await switchNode(best[0]);
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };

  const toggleSysProxy = async () => {
    setBusy("sysproxy");
    setError(null);
    try {
      setSysProxy(await vpnSystemProxySet(!(sysProxy ?? false)));
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };

  const envOn = (env?.present ?? false) && (env?.points_to_bridge ?? false);
  const smartOn = health?.mode === "smart";
  const toggleEnv = async () => {
    setBusy("env");
    setError(null);
    try {
      setEnv(envOn ? await clearGlobalProxyEnv() : await setGlobalProxyEnv());
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };
  const toggleSmart = async () => {
    setBusy("route");
    setError(null);
    try {
      await bridgeSetRouteMode(smartOn ? "all" : "smart");
      await refresh();
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };

  const runTest = async () => {
    setBusy("test");
    setError(null);
    try {
      const r = await shimTest();
      setResult(r.ok ? `${r.external_ip ?? "OK"} · ${r.latency_ms ?? "—"} мс` : r.error ?? "ошибка");
      window.setTimeout(() => setResult(null), 6000);
    } catch (e) {
      failFlash(e);
    } finally {
      setBusy(null);
    }
  };

  const openApp = async () => {
    await showMainWindow();
    await getCurrentWindow().hide();
  };

  const sortedNodes = useMemo(() => {
    if (!ov) return [];
    return [...ov.nodes]
      .sort((a, b) => (pings?.[a.id] ?? 99999) - (pings?.[b.id] ?? 99999))
      .slice(0, 14);
  }, [ov, pings]);

  const orb = !ov ? ("loading" as const) : vpnRunning ? ("ok" as const) : ("down" as const);

  const row = "flex items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-vb-surface-2/50 disabled:opacity-60";

  return (
    <div
      className="flex h-screen w-screen flex-col justify-end p-2.5"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) void getCurrentWindow().hide();
      }}
    >
      <div className="flex flex-col overflow-hidden rounded-lg border border-vb-border bg-vb-bg shadow-[0_16px_48px_rgba(0,0,0,0.55)]">
        {/* ── VPN-герой ── */}
        <div className="flex items-center gap-3 px-4 pb-3 pt-4">
          <StatusOrb state={orb} size={11} />
          <div className="min-w-0 flex-1">
            <div className="text-[14px] font-semibold leading-tight text-vb-fg">
              {!ov ? "Проверяю…" : vpnRunning ? "Защищено" : "Выключено"}
            </div>
            <div className="truncate tnum text-[11px] text-vb-silver-faint">
              {vpnRunning
                ? `${activeNode?.name ?? "нода"}${
                    speed ? ` · ↓ ${fmtSpeed(speed.down)} · ↑ ${fmtSpeed(speed.up)}` : ""
                  }${ov?.process.uptime_sec ? ` · ${formatUptime(ov.process.uptime_sec)}` : ""}`
                : ov?.active
                  ? `нода: ${activeNode ? cleanNodeName(activeNode.name) : "—"}`
                  : "нода не выбрана"}
            </div>
          </div>
          {busy === "power" ? (
            <Loader2 className="h-5 w-5 shrink-0 animate-spin text-vb-silver-dim" />
          ) : (
            <button
              type="button"
              onClick={power}
              disabled={busy !== null || !ov}
              title={vpnRunning ? "Отключить VPN" : "Включить VPN"}
              className={cn(
                "flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition-all active:scale-[0.92] disabled:opacity-40",
                vpnRunning
                  ? "bg-vb-emerald/15 text-vb-emerald hover:bg-vb-emerald/25"
                  : "bg-vb-surface text-vb-silver-dim hover:bg-vb-surface-2 hover:text-vb-emerald",
              )}
            >
              <Power className="h-4 w-4" strokeWidth={2.2} />
            </button>
          )}
        </div>

        {/* ── Смена ноды ── */}
        <button
          type="button"
          onClick={() => void ensurePings().catch(() => {})}
          onMouseDown={() => setListOpen((v) => !v)}
          disabled={!ov || ov.nodes.length === 0}
          className={cn(row, "border-y border-vb-border/60 py-2 disabled:opacity-40")}
        >
          <span className="text-[15px] leading-none">{activeNode ? flagOf(activeNode.name) : <Globe className="h-4 w-4 text-vb-silver-dim" />}</span>
          <span className="min-w-0 flex-1 truncate text-[13px] font-medium text-vb-silver">
            {activeNode?.name ?? "Выбрать ноду"}
          </span>
          {pings && activeNode && pings[activeNode.id] && (
            <span className="tnum text-[11px] text-vb-silver-faint">{pings[activeNode.id]} мс</span>
          )}
          <ChevronDown className={cn("h-3.5 w-3.5 text-vb-silver-faint transition-transform", listOpen && "rotate-180")} />
        </button>

        <AnimatePresence>
          {listOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className="overflow-hidden border-b border-vb-border/60"
            >
              <div className="max-h-40 overflow-y-auto py-1">
                {sortedNodes.map((n) => (
                  <button
                    key={n.id}
                    type="button"
                    onClick={() => void switchNode(n.id)}
                    disabled={busy !== null}
                    className="flex w-full items-center gap-2.5 px-4 py-1.5 text-left transition-colors hover:bg-vb-surface-2/60 disabled:opacity-50"
                  >
                    <span className="text-[13px] leading-none">{flagOf(n.name)}</span>
                    <span className="min-w-0 flex-1 truncate text-[12.5px] text-vb-silver">{cleanNodeName(n.name)}</span>
                    <span className={cn("tnum text-[11px]", pings?.[n.id] ? "text-vb-silver-faint" : "text-vb-loss/70")}>
                      {pings?.[n.id] ? `${pings[n.id]} мс` : "—"}
                    </span>
                    {n.id === ov?.active && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-vb-emerald" />}
                  </button>
                ))}
              </div>
              <button
                type="button"
                onClick={bestNode}
                disabled={busy !== null}
                className={cn(row, "w-full border-t border-vb-border/40 py-2 text-vb-emerald disabled:opacity-50")}
              >
                {busy === "best" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                <span className="text-[13px] font-semibold">Лучшая нода</span>
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* ── Тумблеры ── */}
        <div className="flex flex-col">
          <button type="button" onClick={toggleSysProxy} disabled={busy !== null || sysProxy === null} className={row}>
            <Globe className="h-4 w-4 shrink-0 text-vb-silver-dim" strokeWidth={1.9} />
            <span className="min-w-0 flex-1 text-[13px] font-medium text-vb-silver">Браузеры через VPN</span>
            <span className="pointer-events-none">
              <Toggle checked={sysProxy ?? false} onChange={toggleSysProxy} disabled={busy !== null || sysProxy === null} label="Браузеры через VPN" />
            </span>
          </button>
          <button type="button" onClick={toggleEnv} disabled={busy !== null || env === null} className={row}>
            <Activity className="h-4 w-4 shrink-0 text-vb-silver-dim" strokeWidth={1.9} />
            <span className="min-w-0 flex-1 text-[13px] font-medium text-vb-silver">Системное проксирование</span>
            <span className="pointer-events-none">
              <Toggle checked={envOn} onChange={toggleEnv} disabled={busy !== null || env === null} label="Системный прокси" />
            </span>
          </button>
          <button type="button" onClick={smartOn !== undefined ? toggleSmart : undefined} disabled={busy !== null || !health} className={row}>
            <Zap className="h-4 w-4 shrink-0 text-vb-silver-dim" strokeWidth={1.9} />
            <span className="min-w-0 flex-1 text-[13px] font-medium text-vb-silver">Умная маршрутизация</span>
            {health ? (
              <span className="pointer-events-none">
                <Toggle checked={smartOn} onChange={toggleSmart} disabled={busy !== null} label="Умная маршрутизация" />
              </span>
            ) : (
              <span className="text-[11px] text-vb-silver-faint">н/д</span>
            )}
          </button>
        </div>

        {/* ── Ошибка / тест ── */}
        <AnimatePresence>
          {actionError && (
            <motion.p
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
              className="overflow-hidden px-4 pb-1 text-[11px] leading-snug text-vb-loss"
            >
              {actionError}
            </motion.p>
          )}
        </AnimatePresence>

        <div className="px-4 pb-1 pt-0.5">
          <button
            type="button"
            onClick={runTest}
            disabled={busy !== null}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-vb-border bg-vb-surface px-3 py-2 text-[13px] font-medium text-vb-silver transition-colors hover:border-vb-border-strong hover:bg-vb-surface-2 active:scale-[0.98] disabled:opacity-40"
          >
            {busy === "test" ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Activity className="h-3.5 w-3.5" />}
            Тест соединения
          </button>
          <AnimatePresence>
            {testResult && (
              <motion.p
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
                className="tnum overflow-hidden pt-1.5 text-center text-[12px] text-vb-silver-dim"
              >
                {testResult}
              </motion.p>
            )}
          </AnimatePresence>
        </div>

        {/* ── Мост + футер ── */}
        <div className="flex items-center justify-between border-t border-vb-border/60 px-2 py-1.5">
          <button
            type="button"
            onClick={openApp}
            className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] font-medium text-vb-silver-dim transition-colors hover:bg-vb-surface-2 hover:text-vb-silver active:scale-[0.97]"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Открыть приложение
          </button>
          <span className="tnum text-[10.5px] text-vb-silver-faint" title="Мост прокси-хаба">
            {status?.running ? `мост · ${formatUptime(health?.uptime_sec ?? status.uptime_sec)}` : "мост остановлен"}
          </span>
          <button
            type="button"
            onClick={() => void quitApp()}
            className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] font-medium text-vb-silver-faint transition-colors hover:bg-vb-loss/10 hover:text-vb-loss active:scale-[0.97]"
            title="Полностью выйти (фоновые сервисы продолжат работать)"
          >
            <LogOut className="h-3.5 w-3.5" />
            Выход
          </button>
        </div>
      </div>
    </div>
  );
}

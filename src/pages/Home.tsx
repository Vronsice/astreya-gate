import { useCallback, useEffect, useRef, useState } from "react";
import { motion } from "framer-motion";
import {
  Gauge,
  Globe,
  Loader2,
  MonitorUp,
  Power,
  Search,
  Zap,
} from "lucide-react";
import { StatusOrb } from "../components/StatusOrb";
import { Toggle } from "../components/Toggle";
import {
  vpnOverview,
  vpnPingAll,
  vpnRealDelay,
  vpnSetActive,
  vpnSetAutostart,
  vpnSetRoute,
  vpnStart,
  vpnStop,
  vpnSystemProxyGet,
  vpnSystemProxySet,
  vpnTunDisable,
  vpnTunEnable,
  vpnTunStatus,
} from "../lib/api";
import { formatUptime } from "../lib/status";
import { cleanNodeName, flagOf } from "../lib/nodeNames";
import type { VpnOverview } from "../lib/types";
import { fadeInUp, staggerContainer } from "../lib/motion";
import { cn } from "../lib/cn";

const fmtSpeed = (bps?: number) =>
  bps === undefined || bps === null
    ? "—"
    : bps >= 1_048_576
      ? `${(bps / 1_048_576).toFixed(1)} МБ/с`
      : bps >= 1024
        ? `${Math.round(bps / 1024)} КБ/с`
        : `${Math.round(bps)} Б/с`;

/*
  Пульт — домашний экран: одна кнопка питания, сетка стран, тумблеры.
  Никаких графов: то, что человек делает в 95% случаев — 2 клика.
  Схема маршрутизации для продвинутых живёт отдельно («Схема»).
*/
export function Home({ onNavigate }: { onNavigate?: (v: import("../lib/types").AppView) => void }) {
  const [ov, setOv] = useState<VpnOverview | null>(null);
  const [sysProxy, setSysProxy] = useState<boolean | null>(null);
  const [tun, setTun] = useState<boolean | null>(null);
  const [speed, setSpeed] = useState<{ up: number; down: number } | null>(null);
  const [pings, setPings] = useState<Record<string, number> | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const lastTotals = useRef<{ t: number; up: number; down: number } | null>(null);

  const flash = (m: string) => {
    setError(m);
    window.setTimeout(() => setError(null), 5000);
  };

  const load = useCallback(async () => {
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
      /* переживаем */
    }
  }, []);

  useEffect(() => {
    void load();
    void vpnSystemProxyGet().then(setSysProxy).catch(() => setSysProxy(null));
    void vpnTunStatus().then((t) => setTun(t.running_process)).catch(() => setTun(null));
    void vpnPingAll()
      .then((r) => {
        const clean: Record<string, number> = {};
        for (const [k, v] of Object.entries(r)) if (v !== null && v > 0) clean[k] = v;
        setPings(clean);
      })
      .catch(() => {});
    const iv = window.setInterval(() => {
      if (!document.hidden) void load();
    }, 2000);
    return () => window.clearInterval(iv);
  }, [load]);

  const running = ov?.process.running ?? false;
  const activeNode = ov?.nodes.find((n) => n.id === ov.active) ?? null;

  const act = async (key: string, fn: () => Promise<unknown>, after?: () => void) => {
    setBusy(key);
    setError(null);
    try {
      await fn();
      after?.();
    } catch (e) {
      flash(String(e));
    } finally {
      setBusy(null);
    }
  };

  const pickCountry = async (id: string) => {
    await act(`pick:${id}`, async () => {
      const o = await vpnSetActive(id);
      setOv(o);
    });
  };

  const power = () =>
    act("power", async () => {
      const o = running ? await vpnStop() : await vpnStart();
      setOv(o);
    });

  const realDelay = () =>
    act("delay", async () => {
      const ms = await vpnRealDelay();
      flash(`Задержка через туннель: ${ms} мс`);
    });

  /* Страны: группировка нод по чистому имени, мин. задержка в группе. */
  const countries = (() => {
    const map = new Map<string, { id: string; name: string; label: string; flag: string; ms: number }>();
    for (const n of ov?.nodes ?? []) {
      const label = cleanNodeName(n.name);
      const flag = flagOf(n.name);
      const key = `${flag}|${label}`;
      const ms = pings?.[n.id];
      const prev = map.get(key);
      if (!prev || (ms !== undefined && (prev.ms === undefined || ms < prev.ms))) {
        map.set(key, {
          id: prev && (prev.ms !== undefined || ms === undefined) ? prev.id : n.id,
          name: prev?.name && (prev.ms !== undefined || ms === undefined) ? prev.name : n.name,
          label,
          flag,
          ms: ms !== undefined && (prev?.ms === undefined || ms < prev.ms) ? ms : (prev?.ms ?? ms ?? 0),
        });
      }
    }
    return [...map.values()].sort((a, b) => {
      const am = a.ms || 99999;
      const bm = b.ms || 99999;
      return am - bm;
    });
  })();

  const filtered = countries.filter(
    (c) =>
      !query.trim() ||
      c.label.toLowerCase().includes(query.trim().toLowerCase()),
  );

  const activeLabel = activeNode ? cleanNodeName(activeNode.name) : null;

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[760px] flex-col gap-5 px-8 py-7"
    >
      {/* ── Герой: питание + статус ── */}
      <motion.section variants={fadeInUp} className="surface-card flex items-center gap-6 p-6">
        <button
          type="button"
          onClick={power}
          disabled={busy === "power" || !ov}
          title={running ? "Отключить VPN" : "Включить VPN"}
          className={cn(
            "relative flex h-24 w-24 shrink-0 items-center justify-center rounded-full transition-all active:scale-[0.95] disabled:opacity-50",
            running
              ? "bg-vb-emerald/15 text-vb-emerald ring-2 ring-vb-emerald/40 hover:bg-vb-emerald/25"
              : "bg-vb-surface text-vb-silver-dim ring-1 ring-vb-border hover:text-vb-emerald hover:ring-vb-emerald/40",
          )}
        >
          {running && (
            <span className="absolute inset-0 animate-ping rounded-full bg-vb-emerald/10" />
          )}
          {busy === "power" ? (
            <Loader2 className="h-8 w-8 animate-spin" />
          ) : (
            <Power className="h-9 w-9" strokeWidth={2} />
          )}
        </button>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2.5">
            <StatusOrb state={!ov ? "loading" : running ? "ok" : "down"} size={10} />
            <span className="text-[20px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
              {running ? "Защищено" : "Выключено"}
            </span>
            {running && activeNode && (
              <span className="text-[26px] leading-none">{flagOf(activeNode.name)}</span>
            )}
          </div>
          <div className="tnum mt-1 truncate text-[13px] text-vb-silver-dim">
            {running
              ? `${activeLabel ?? "нода"} · ↓ ${fmtSpeed(speed?.down)} · ↑ ${fmtSpeed(speed?.up)} · ${formatUptime(ov?.process.uptime_sec)}`
              : ov?.active
                ? `Выбрана: ${activeLabel} — нажми питание`
                : "Выбери страну ниже и нажми питание"}
          </div>
          {running && (
            <button
              type="button"
              onClick={realDelay}
              disabled={busy === "delay"}
              className="mt-2 flex items-center gap-1.5 rounded-lg border border-vb-border px-2.5 py-1 text-[11.5px] font-medium text-vb-silver transition-colors hover:border-vb-border-strong hover:bg-vb-surface-2 active:scale-[0.97] disabled:opacity-40"
            >
              {busy === "delay" ? <Loader2 className="h-3 w-3 animate-spin" /> : <Gauge className="h-3 w-3" />}
              Реальная задержка
            </button>
          )}
        </div>
      </motion.section>

      {error && (
        <motion.div variants={fadeInUp} className="rounded-lg border border-vb-loss/30 bg-vb-loss/10 px-3.5 py-2.5 text-[12.5px] text-vb-loss">
          {error}
        </motion.div>
      )}

      {/* ── Тумблеры защиты ── */}
      <motion.section variants={fadeInUp} className="grid grid-cols-3 gap-3">
        <div className="surface-card flex items-center justify-between gap-2 p-3.5">
          <span className="min-w-0 truncate text-[12.5px] font-medium text-vb-silver">Браузеры</span>
          <Toggle
            checked={sysProxy ?? false}
            onChange={(v) => act("sys", async () => setSysProxy(await vpnSystemProxySet(v)))}
            disabled={busy !== null || sysProxy === null}
            label="Браузеры через VPN"
          />
        </div>
        <div className="surface-card flex items-center justify-between gap-2 p-3.5">
          <span className="min-w-0 truncate text-[12.5px] font-medium text-vb-silver">Системный</span>
          <Toggle
            checked={tun ?? false}
            onChange={(v) =>
              act("tun", async () => {
                const t = v ? await vpnTunEnable() : await vpnTunDisable();
                setTun(t.running_process);
              })
            }
            disabled={busy !== null || tun === null}
            label="Системный режим (TUN)"
          />
        </div>
        <div className="surface-card flex items-center justify-between gap-2 p-3.5">
          <span className="min-w-0 truncate text-[12.5px] font-medium text-vb-silver">Автостарт</span>
          <Toggle
            checked={ov?.autostart ?? false}
            onChange={(v) =>
              act("auto", async () => {
                await vpnSetAutostart(v);
                setOv(await vpnOverview());
              })
            }
            disabled={busy !== null || !ov}
            label="Подключать при запуске"
          />
        </div>
      </motion.section>

      {/* ── Режим маршрутизации ── */}
      <motion.section variants={fadeInUp} className="surface-card flex items-center gap-2 p-3">
        <span className="px-1 text-[12px] text-vb-silver-faint">Маршрут:</span>
        {(
          [
            ["all", "Всё через VPN"],
            ["smart", "Умный"],
            ["whitelist", "Белый список"],
          ] as const
        ).map(([m, label]) => (
          <button
            key={m}
            type="button"
            disabled={busy !== null || !ov || ov.route_mode === m}
            onClick={() => act("route", async () => setOv(await vpnSetRoute(m, ov!.whitelist_sites)))}
            className={cn(
              "rounded-lg border px-3 py-1.5 text-[12px] font-medium transition-colors disabled:opacity-40",
              ov?.route_mode === m
                ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
                : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
            )}
          >
            {label}
          </button>
        ))}
      </motion.section>

      {/* ── Страны ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="flex items-center gap-2">
          <Globe className="h-4 w-4 text-vb-emerald" />
          <h2 className="text-[15px] font-semibold text-vb-fg">Страна выхода</h2>
          <span className="text-[11.5px] text-vb-silver-faint">
            клик — выбрать и переключиться мгновенно
          </span>
          <div className="flex-1" />
          <button
            type="button"
            disabled={busy !== null || countries.length === 0}
            onClick={() => {
              const best = countries.find((c) => c.ms > 0) ?? countries[0];
              if (best) void pickCountry(best.id);
            }}
            className="flex items-center gap-1.5 rounded-lg border border-vb-border px-2.5 py-1 text-[12px] font-medium text-vb-silver transition-colors hover:border-vb-border-strong hover:bg-vb-surface-2 disabled:opacity-35"
          >
            <Zap className="h-3.5 w-3.5" />
            Самая быстрая
          </button>
        </div>

        {countries.length > 10 && (
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-vb-silver-faint" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Поиск страны…"
              className="w-full rounded-lg border border-vb-border bg-vb-surface-2 py-2 pl-9 pr-3 text-[12.5px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
            />
          </div>
        )}

        <div className="grid grid-cols-3 gap-2">
          {filtered.map((c) => {
            const isActive = !!activeNode && flagOf(activeNode.name) === c.flag && activeLabel === c.label;
            return (
              <button
                key={`${c.flag}-${c.label}`}
                type="button"
                onClick={() => void pickCountry(c.id)}
                disabled={busy !== null}
                className={cn(
                  "flex items-center gap-2.5 rounded-xl border px-3 py-2.5 text-left transition-all active:scale-[0.98] disabled:opacity-50",
                  isActive
                    ? "border-vb-emerald/60 bg-vb-emerald/[0.08]"
                    : "border-vb-border bg-vb-surface hover:border-vb-border-strong",
                )}
              >
                <span className="text-[20px] leading-none">{c.flag}</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-[12.5px] font-medium text-vb-fg">{c.label}</span>
                  <span
                    className={cn(
                      "tnum block text-[10.5px]",
                      c.ms === 0 ? "text-vb-silver-faint" : c.ms > 800 ? "text-vb-warn" : "text-vb-silver-faint",
                    )}
                  >
                    {c.ms > 0 ? `${c.ms} мс` : "замерить"}
                  </span>
                </span>
                {isActive && running && (
                  <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-vb-emerald" />
                )}
              </button>
            );
          })}
          {filtered.length === 0 && (
            <p className="col-span-3 py-2 text-[12.5px] text-vb-silver-dim">
              Ничего не найдено. Ноды берутся из подписки — раздел «Ноды».
            </p>
          )}
        </div>
      </motion.section>

      {/* ── Ссылка на схему ── */}
      <motion.button
        variants={fadeInUp}
        type="button"
        onClick={() => onNavigate?.("map")}
        className="flex items-center justify-center gap-2 rounded-lg border border-vb-border px-3 py-2 text-[12px] font-medium text-vb-silver-faint transition-colors hover:border-vb-border-strong hover:text-vb-silver"
      >
        <MonitorUp className="h-3.5 w-3.5" />
        Схема маршрутизации (для продвинутых)
      </motion.button>
    </motion.div>
  );
}

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  Panel,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useEdgesState,
  useNodesState,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AppWindow,
  Globe,
  Loader2,
  MonitorUp,
  Plus,
  Power,
  TerminalSquare,
  Waypoints,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import { StatusOrb } from "../components/StatusOrb";
import { Toggle } from "../components/Toggle";
import {
  bridgeSetRouteMode,
  browsersDisable,
  browsersEnable,
  browsersStatus,
  clearGlobalProxyEnv,
  setGlobalProxyEnv,
  shimStart,
  shimStop,
  vpnAddLink,
  vpnOverview,
  vpnPingAll,
  vpnRuleRemove,
  vpnRuleSave,
  vpnRulesGet,
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
import { formatUptime, useStatus } from "../lib/status";
import type { AppView, BridgeHealth, RoutingRule, VpnOverview } from "../lib/types";
import { cn } from "../lib/cn";
import "@xyflow/react/dist/style.css";

/* ── утилиты ─────────────────────────────────────────────────── */

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

interface MapData {
  ov: VpnOverview | null;
  sysProxy: boolean | null;
  pac: boolean | null;
  speed: { up: number; down: number } | null;
  pings: Record<string, number> | null;
}

const EMPTY_LIVE: MapData = { ov: null, sysProxy: null, pac: null, speed: null, pings: null };

/* ── кастомные узлы ──────────────────────────────────────────── */

function NodeShell({
  active,
  problem,
  selected,
  children,
  handles = "lr",
  compact,
}: {
  active: boolean;
  problem?: boolean;
  selected: boolean;
  children: React.ReactNode;
  handles?: "lr" | "l" | "r";
  compact?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded-xl border bg-vb-bg/95 shadow-lg backdrop-blur transition-colors",
        compact ? "w-[190px] px-3 py-2" : "w-[210px] px-3 py-2.5",
        problem
          ? "border-vb-loss/60"
          : active
            ? "border-vb-emerald/50"
            : "border-vb-border",
        selected && "ring-1 ring-vb-emerald/60",
      )}
    >
      {handles.includes("l") && <Handle type="target" position={Position.Left} className="!bg-vb-silver-faint" />}
      {children}
      {handles.includes("r") && <Handle type="source" position={Position.Right} className="!bg-vb-silver-faint" />}
    </div>
  );
}

function MetricChip({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className="rounded-md bg-vb-surface px-2 py-1">
      <div className={cn("tnum text-[12px] font-semibold leading-none", accent ? "text-vb-emerald" : "text-vb-fg")}>{value}</div>
      <div className="mt-0.5 text-[9px] uppercase tracking-[0.05em] text-vb-silver-faint">{label}</div>
    </div>
  );
}

type SourceNodeData = { live: MapData; active: boolean };
function BrowserNode({ data, selected }: NodeProps) {
  const d = (data as unknown as SourceNodeData) ?? { live: EMPTY_LIVE, active: false };
  const live = d.live ?? EMPTY_LIVE;
  const via = live.sysProxy === true ? "через VPN-туннель" : live.pac === true ? "через мост (PAC)" : "напрямую, без VPN";
  return (
    <NodeShell active={!!d.active} selected={selected} handles="r">
      <div className="flex items-center gap-2">
        <Globe className="h-4 w-4 text-vb-silver-dim" />
        <span className="text-[13px] font-semibold text-vb-fg">Браузеры</span>
      </div>
      <div className={cn("mt-1 text-[11px]", d.active ? "text-vb-emerald" : "text-vb-silver-faint")}>{via}</div>
    </NodeShell>
  );
}

function AppsNode({ data, selected }: NodeProps) {
  const d = (data as unknown as SourceNodeData) ?? { live: EMPTY_LIVE, active: false };
  return (
    <NodeShell active={!!d.active} selected={selected} handles="r">
      <div className="flex items-center gap-2">
        <AppWindow className="h-4 w-4 text-vb-silver-dim" />
        <span className="text-[13px] font-semibold text-vb-fg">Приложения</span>
      </div>
      <div className="mt-1 text-[11px] text-vb-silver-faint">через мост-диспетчер</div>
    </NodeShell>
  );
}

function EnvNode({ data, selected }: NodeProps) {
  const d = (data as unknown as SourceNodeData) ?? { live: EMPTY_LIVE, active: false };
  return (
    <NodeShell active={!!d.active} selected={selected} handles="r">
      <div className="flex items-center gap-2">
        <TerminalSquare className="h-4 w-4 text-vb-silver-dim" />
        <span className="text-[13px] font-semibold text-vb-fg">Система (env)</span>
      </div>
      <div className={cn("mt-1 text-[11px]", d.active ? "text-vb-emerald" : "text-vb-silver-faint")}>
        {d.active ? "HTTP_PROXY → мост" : "переменные не заданы"}
      </div>
    </NodeShell>
  );
}

type VpnNodeData = { live: MapData };
function TunnelNode({ data, selected }: NodeProps) {
  const live = (data as unknown as VpnNodeData | undefined)?.live ?? EMPTY_LIVE;
  const running = live.ov?.process.running ?? false;
  const node = live.ov?.nodes.find((n) => n.id === live.ov?.active);
  return (
    <NodeShell active={running} selected={selected}>
      <div className="flex items-center gap-2">
        <Wifi className={cn("h-4 w-4", running ? "text-vb-emerald" : "text-vb-silver-dim")} />
        <span className="min-w-0 flex-1 text-[13px] font-semibold text-vb-fg">VPN-туннель</span>
        {running ? (
          <button
            type="button"
            onClick={() => void vpnStop().catch(() => {})}
            className="flex h-6 w-6 items-center justify-center rounded-full bg-vb-emerald/15 text-vb-emerald transition-colors hover:bg-vb-emerald/25"
            title="Выключить"
          >
            <Power className="h-3 w-3" />
          </button>
        ) : (
          <button
            type="button"
            onClick={() => void vpnStart().catch(() => {})}
            className="flex h-6 w-6 items-center justify-center rounded-full bg-vb-surface text-vb-silver-dim transition-colors hover:text-vb-emerald"
            title="Включить"
          >
            <Power className="h-3 w-3" />
          </button>
        )}
      </div>
      <div className="mt-1 truncate text-[11px] text-vb-silver-faint">
        {running
          ? `${node?.name ?? "нода"} · ${formatUptime(live.ov?.process.uptime_sec)}`
          : "выключен"}
      </div>
      {running && live.speed && (
        <div className="mt-2 grid grid-cols-2 gap-1.5">
          <MetricChip label="приём" value={fmtSpeed(live.speed.down)} accent />
          <MetricChip label="отдача" value={fmtSpeed(live.speed.up)} />
        </div>
      )}
    </NodeShell>
  );
}

function BridgeNode({ data, selected }: NodeProps) {
  const d = (data as unknown as { live: MapData; health: BridgeHealth | null }) ?? { live: EMPTY_LIVE, health: null };
  const running = d.health != null;
  const smart = d.health?.mode === "smart";
  return (
    <NodeShell active={running} selected={selected}>
      <div className="flex items-center gap-2">
        <Waypoints className={cn("h-4 w-4", running ? "text-vb-emerald" : "text-vb-silver-dim")} />
        <span className="text-[13px] font-semibold text-vb-fg">Мост · 2080</span>
      </div>
      <div className="mt-1 text-[11px] text-vb-silver-faint">
        {running ? (smart ? "умная маршрутизация" : "весь трафик через пул") : "остановлен"}
      </div>
      {running && d.health != null && (
        <div className="mt-2 grid grid-cols-2 gap-1.5">
          <MetricChip label="через пул" value={String(d.health.via_upstream)} />
          <MetricChip label="напрямую" value={String(d.health.via_direct)} />
        </div>
      )}
    </NodeShell>
  );
}

type ExitNodeData = { name: string; flag: string; sub: string; active: boolean; problem?: boolean; live: MapData };
function ExitNode({ data, selected }: NodeProps) {
  const d = (data as unknown as ExitNodeData) ?? { live: EMPTY_LIVE, name: "", flag: "", sub: "", active: false };
  return (
    <NodeShell active={!!d.active} problem={d.problem} selected={selected} handles="l" compact>
      <div className="flex items-center gap-2">
        <span className="text-[15px] leading-none">{d.flag}</span>
        <span className="min-w-0 flex-1 truncate text-[13px] font-semibold text-vb-fg">{d.name}</span>
        {d.active && <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-vb-emerald" />}
      </div>
      <div className={cn("mt-0.5 truncate text-[11px]", d.active ? "text-vb-emerald" : "text-vb-silver-faint")}>{d.sub}</div>
    </NodeShell>
  );
}

const nodeTypes = {
  browsers: BrowserNode,
  apps: AppsNode,
  env: EnvNode,
  tunnel: TunnelNode,
  bridge: BridgeNode,
  exit: ExitNode,
};

/* ── страница ────────────────────────────────────────────────── */

function RouteMap({ onNavigate }: { onNavigate?: (v: AppView) => void }) {
  const { health, env } = useStatus();
  const [live, setLive] = useState<MapData>(EMPTY_LIVE);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [addOpen, setAddOpen] = useState(false);
  const [addText, setAddText] = useState("");
  const [notice, setNotice] = useState<string | null>(null);
  const [rules, setRules] = useState<RoutingRule[] | null>(null);
  const [tun, setTun] = useState<{ running_process: boolean } | null>(null);
  const lastTotals = useRef<{ t: number; up: number; down: number } | null>(null);

  const flash = (m: string) => {
    setNotice(m);
    window.setTimeout(() => setNotice(null), 5000);
  };

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const o = await vpnOverview();
        const now = Date.now() / 1000;
        let speed = live.speed;
        if (lastTotals.current && o.up_total !== undefined && o.down_total !== undefined) {
          const dt = now - lastTotals.current.t;
          if (dt > 0.5) {
            speed = {
              up: Math.max(0, (o.up_total - lastTotals.current.up) / dt),
              down: Math.max(0, (o.down_total - lastTotals.current.down) / dt),
            };
          }
        }
        if (o.up_total !== undefined && o.down_total !== undefined) {
          lastTotals.current = { t: now, up: o.up_total, down: o.down_total };
        }
        if (alive) setLive((p) => ({ ...p, ov: o, speed }));
      } catch {
        /* переживаем */
      }
      try {
        const b = await browsersStatus();
        if (alive) setLive((p) => ({ ...p, pac: b.active }));
      } catch {
        /* переживаем */
      }
    };
    void tick();
    void vpnSystemProxyGet().then((v) => alive && setLive((p) => ({ ...p, sysProxy: v }))).catch(() => {});
    void vpnRulesGet().then((r) => alive && setRules(r)).catch(() => {});
    void vpnTunStatus()
      .then((t) => alive && setTun({ running_process: t.running_process }))
      .catch(() => {});
    void vpnRulesGet().then((r) => alive && setRules(r)).catch(() => {});
    void vpnPingAll()
      .then((r) => {
        const clean: Record<string, number> = {};
        for (const [k, v] of Object.entries(r)) if (v !== null && v > 0) clean[k] = v;
        if (alive) setLive((p) => ({ ...p, pings: clean }));
      })
      .catch(() => {});
    const iv = window.setInterval(() => void tick(), 2000);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const envOn = (env?.present ?? false) && (env?.points_to_bridge ?? false);
  const vpnRunning = live.ov?.process.running ?? false;
  const activeNode = live.ov?.nodes.find((n) => n.id === live.ov?.active) ?? null;
  const bridgeRunning = health !== null;
  const smart = health?.mode === "smart";
  const poolTotal = health?.upstreams.length ?? 0;
  const poolOk = health ? health.upstreams.filter((u) => u.healthy).length : 0;

  /* Выходы-ноды: топ-5 по задержке (активная — всегда в списке). */
  const nodeExits = useMemo(() => {
    const nodes = [...(live.ov?.nodes ?? [])].sort(
      (a, b) => (live.pings?.[a.id] ?? 99999) - (live.pings?.[b.id] ?? 99999),
    );
    const top = nodes.slice(0, 5);
    if (activeNode && !top.some((n) => n.id === activeNode.id)) top.unshift(activeNode);
    return top.slice(0, 6);
  }, [live.ov, live.pings, activeNode]);

  const initialNodes = useMemo<Node[]>(() => [
    { id: "browsers", type: "browsers", position: { x: 0, y: 30 }, data: {} },
    { id: "apps", type: "apps", position: { x: 0, y: 180 }, data: {} },
    { id: "env", type: "env", position: { x: 0, y: 330 }, data: {} },
    { id: "tunnel", type: "tunnel", position: { x: 300, y: 30 }, data: {} },
    { id: "bridge", type: "bridge", position: { x: 300, y: 250 }, data: {} },
    { id: "exit-direct", type: "exit", position: { x: 600, y: 30 }, data: {} },
    { id: "exit-pool", type: "exit", position: { x: 600, y: 130 }, data: {} },
    // node-выходы добавляются динамически ниже
  ], []);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  /* Живые данные → узлы. */
  useEffect(() => {
    setNodes((prev) => {
      const base = prev.filter((n) => !n.id.startsWith("node-"));
      const exitNodes: Node[] = nodeExits.map((n, i) => ({
        id: `node-${n.id}`,
        type: "exit",
        position: { x: 600, y: 240 + i * 78 },
        data: {
          live,
          name: n.name,
          flag: flagOf(n.name),
          sub:
            live.pings?.[n.id]
              ? `${live.pings[n.id]} мс`
              : "задержка не измерена",
          active: n.id === live.ov?.active && vpnRunning,
        },
        deletable: false,
      }));
      const withData = base.map((n) => {
        if (n.id === "browsers")
          return { ...n, data: { live, active: live.sysProxy === true || live.pac === true } };
        if (n.id === "apps") return { ...n, data: { live, active: bridgeRunning } };
        if (n.id === "env") return { ...n, data: { live, active: envOn } };
        if (n.id === "tunnel") return { ...n, data: { live } };
        if (n.id === "bridge") return { ...n, data: { live, health } };
        if (n.id === "exit-direct")
          return {
            ...n,
            data: {
              live,
              name: "Напрямую",
              flag: "🇷🇺",
              sub: smart ? "RU-домены мимо VPN" : "не используется",
              active: bridgeRunning && smart,
            },
          };
        if (n.id === "exit-pool")
          return {
            ...n,
            data: {
              live,
              name: `Прокси-пул${poolTotal ? ` · ${poolOk}/${poolTotal}` : ""}`,
              flag: "🛰️",
              sub: poolTotal ? `${poolOk} живых из ${poolTotal}` : "пул пуст",
              active: bridgeRunning && poolOk > 0,
              problem: bridgeRunning && poolTotal > 0 && poolOk === 0,
            },
          };
        return n;
      });
      return [...withData, ...exitNodes];
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, envOn, health, nodeExits, vpnRunning, bridgeRunning, smart, poolTotal, poolOk]);

  /* ── Проводка: каждое ребро = реальное действие ── */
  const act = async (fn: () => Promise<unknown>, okMsg?: string) => {
    setBusy(true);
    try {
      await fn();
      if (okMsg) flash(okMsg);
    } catch (e) {
      flash(String(e));
    } finally {
      setBusy(false);
    }
  };

  const connectToNode = async (nodeId: string) => {
    await act(async () => {
      // Бэкенд сам переключает селектор на лету (без рестарта туннеля),
      // при недоступности — рестартит. Здесь только фиксируем результат.
      const o = await vpnSetActive(nodeId);
      setLive((p) => ({ ...p, ov: o }));
    }, "нода переключена");
  };

  const onConnectEdge = (source: string, target: string) => {
    if (busy) return;
    if (source === "browsers" && target === "tunnel") return void act(() => vpnSystemProxySet(true), "браузеры → туннель");
    if (source === "browsers" && target === "bridge") return void act(() => browsersEnable(), "браузеры → мост (PAC)");
    if (source === "apps" && target === "bridge") return void act(() => shimStart(), "мост запущен");
    if (source === "env" && target === "bridge") return void act(() => setGlobalProxyEnv(), "env → мост");
    if (source === "bridge" && target === "exit-direct") return void act(() => bridgeSetRouteMode("smart"), "умная маршрутизация");
    if (source === "bridge" && target === "exit-pool") return void act(() => shimStart(), "мост запущен");
    if (source === "tunnel" && target.startsWith("node-")) return void connectToNode(target.slice(5));
  };

  /* Удаление ребра = выключить соответствующую проводку. */
  const disconnectEdge = (edge: Edge) => {
    const [ , s, ...rest ] = edge.id.split("-");
    const source = s;
    const target = rest.join("-");
    if (source === "browsers" && target === "tunnel") return void act(() => vpnSystemProxySet(false));
    if (source === "browsers" && target === "bridge") return void act(() => browsersDisable());
    if (source === "env" && target === "bridge") return void act(() => clearGlobalProxyEnv());
    if (source === "bridge" && target === "exit-direct") return void act(() => bridgeSetRouteMode("all"));
    if ((source === "apps" && target === "bridge") || (source === "bridge" && target === "exit-pool"))
      return void act(() => shimStop());
    if (source === "tunnel" && target.startsWith("node-")) return void act(() => vpnStop());
  };

  /* Рёбра из реального состояния. */
  useEffect(() => {
    const mk = (id: string, source: string, target: string, on: boolean, label?: string): Edge => ({
      id,
      source,
      target,
      animated: on,
      deletable: true,
      label,
      labelShowBg: true,
      labelBgStyle: { fill: "#14171c", fillOpacity: 0.9 },
      labelBgPadding: [6, 3],
      labelBgBorderRadius: 6,
      style: { stroke: on ? "#34d399" : "#2a2f38", strokeWidth: on ? 2 : 1.4 },
      markerEnd: on ? { type: MarkerType.ArrowClosed, color: "#34d399" } : undefined,
    });
    const list: Edge[] = [
      mk("e-browsers-tunnel", "browsers", "tunnel", live.sysProxy === true && vpnRunning, live.sysProxy ? "системный прокси" : "проведи связь"),
      mk("e-browsers-bridge", "browsers", "bridge", live.pac === true && bridgeRunning, live.pac ? "PAC" : undefined),
      mk("e-apps-bridge", "apps", "bridge", bridgeRunning),
      mk("e-env-bridge", "env", "bridge", envOn && bridgeRunning),
      mk("e-bridge-direct", "bridge", "exit-direct", bridgeRunning && smart),
      mk("e-bridge-pool", "bridge", "exit-pool", bridgeRunning && poolOk > 0),
    ];
    if (activeNode) {
      list.push(mk(`e-tunnel-node-${activeNode.id}`, "tunnel", `node-${activeNode.id}`, vpnRunning));
    }
    setEdges(list);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, vpnRunning, bridgeRunning, envOn, smart, poolOk, activeNode]);

  const orbState = !live.ov ? ("loading" as const) : vpnRunning ? ("ok" as const) : ("down" as const);

  const selectedNode = nodes.find((n) => n.id === selected);

  const addNode = async () => {
    const input = addText.trim();
    if (!input) return;
    setBusy(true);
    try {
      const o = await vpnAddLink(input);
      setLive((p) => ({ ...p, ov: o }));
      flash("нода добавлена");
      setAddText("");
      setAddOpen(false);
    } catch (e) {
      flash(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full flex-col gap-3">
      {/* ── Панель управления движком (дом-пульт) ── */}
      <div className="flex shrink-0 items-center gap-3 rounded-xl border border-vb-border bg-vb-bg px-4 py-3">
        <StatusOrb state={orbState} size={11} />
        <div className="min-w-0">
          <div className="text-[14px] font-semibold leading-tight text-vb-fg">
            {vpnRunning ? "Защищено" : "Выключено"}
          </div>
          <div className="tnum truncate text-[11px] text-vb-silver-faint">
            {vpnRunning
              ? `${activeNode?.name ?? "нода"}${
                  live.speed ? ` · ↓ ${fmtSpeed(live.speed.down)} · ↑ ${fmtSpeed(live.speed.up)}` : ""
                }`
              : live.ov?.active
                ? `нода: ${activeNode?.name ?? "—"}`
                : "нода не выбрана"}
          </div>
        </div>

        <button
          type="button"
          onClick={() => act(() => (vpnRunning ? vpnStop() : vpnStart()))}
          disabled={busy}
          title={vpnRunning ? "Выключить туннель" : "Включить туннель"}
          className={cn(
            "ml-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition-all active:scale-[0.92] disabled:opacity-40",
            vpnRunning
              ? "bg-vb-emerald/15 text-vb-emerald hover:bg-vb-emerald/25"
              : "bg-vb-surface text-vb-silver-dim hover:bg-vb-surface-2 hover:text-vb-emerald",
          )}
        >
          {busy ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Power className="h-4 w-4" strokeWidth={2.2} />
          )}
        </button>

        <div className="mx-1 h-8 w-px shrink-0 bg-vb-border/70" />

        {/* Режим маршрутизации */}
        <div className="flex shrink-0 gap-1.5">
          {(
            [
              ["all", "Всё"],
              ["smart", "Умный"],
              ["whitelist", "Белый список"],
            ] as const
          ).map(([m, label]) => (
            <button
              key={m}
              type="button"
              disabled={busy || !live.ov}
              onClick={() =>
                live.ov &&
                live.ov.route_mode !== m &&
                act(() => vpnSetRoute(m, live.ov!.whitelist_sites))
              }
              className={cn(
                "rounded-lg border px-3 py-1.5 text-[12px] font-medium transition-colors disabled:opacity-40",
                live.ov?.route_mode === m
                  ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
                  : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
              )}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="flex-1" />

        {/* Системный режим (TUN) */}
        <button
          type="button"
          disabled={busy}
          onClick={() =>
            act(async () => {
              const t = tun?.running_process
                ? await vpnTunDisable()
                : await vpnTunEnable();
              setTun({ running_process: t.running_process });
            })
          }
          title="Системный режим: перехват всего трафика Windows (TUN). Требует прав администратора."
          className={cn(
            "flex shrink-0 items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[12px] font-medium transition-colors disabled:opacity-40",
            tun?.running_process
              ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
              : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
          )}
        >
          <MonitorUp className="h-3.5 w-3.5" />
          Системный режим
        </button>

        {/* Автоподключение */}
        <label className="flex shrink-0 cursor-pointer items-center gap-2 text-[12px] text-vb-silver">
          Автостарт
          <Toggle
            checked={live.ov?.autostart ?? false}
            onChange={(v) => act(() => vpnSetAutostart(v))}
            disabled={busy || !live.ov}
            label="Подключать при запуске"
          />
        </label>
      </div>

      <div className="relative flex min-h-0 flex-1 gap-3">
      <div className="min-w-0 flex-1 overflow-hidden rounded-xl border border-vb-border bg-vb-bg">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={(c) => c.source && c.target && onConnectEdge(c.source, c.target)}
          onEdgesDelete={(eds) => eds.forEach(disconnectEdge)}
          nodeTypes={nodeTypes}
          onNodeClick={(_, n) => setSelected(n.id)}
          onPaneClick={() => setSelected(null)}
          deleteKeyCode={["Backspace", "Delete"]}
          fitView
          fitViewOptions={{ padding: 0.12 }}
          proOptions={{ hideAttribution: true }}
          minZoom={0.4}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} color="#2a2f38" />
          <Controls showInteractive={false} position="bottom-right" />
          <Panel position="top-right">
            <div className="flex items-center gap-2">
              {notice && (
                <span className="rounded-lg border border-vb-border bg-vb-bg/95 px-3 py-1.5 text-[11px] text-vb-silver">
                  {notice}
                </span>
              )}
              <button
                type="button"
                onClick={() => setAddOpen(true)}
                className="flex items-center gap-1.5 rounded-lg border border-vb-border bg-vb-bg/95 px-3 py-1.5 text-[12px] font-medium text-vb-silver transition-colors hover:border-vb-border-strong hover:text-vb-fg"
              >
                <Plus className="h-3.5 w-3.5" />
                Нода
              </button>
            </div>
          </Panel>
        </ReactFlow>

        {/* Диалог добавления ноды */}
        <AnimatePresence>
          {addOpen && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="absolute inset-0 z-20 flex items-center justify-center bg-black/50 p-6"
              onMouseDown={(e) => e.target === e.currentTarget && setAddOpen(false)}
            >
              <motion.div
                initial={{ scale: 0.96, y: 8 }}
                animate={{ scale: 1, y: 0 }}
                exit={{ scale: 0.96, y: 8 }}
                className="w-full max-w-md rounded-xl border border-vb-border bg-vb-bg p-4 shadow-2xl"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[14px] font-semibold text-vb-fg">Добавить ноду</span>
                  <button type="button" onClick={() => setAddOpen(false)} className="rounded-lg p-1.5 text-vb-silver-dim hover:bg-vb-surface-2 hover:text-vb-silver">
                    <X className="h-4 w-4" />
                  </button>
                </div>
                <textarea
                  value={addText}
                  onChange={(e) => setAddText(e.target.value)}
                  placeholder={"vless://…\nvmess://…\nss://…\nили ссылка подписки https://…"}
                  rows={5}
                  autoFocus
                  className="mt-3 w-full resize-none rounded-lg border border-vb-border bg-vb-surface p-3 font-mono text-[12px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-emerald/50"
                />
                <button
                  type="button"
                  onClick={addNode}
                  disabled={busy || !addText.trim()}
                  className="mt-3 flex w-full items-center justify-center gap-2 rounded-lg bg-vb-emerald px-3 py-2 text-[13px] font-semibold text-black transition-colors hover:bg-vb-emerald-bright disabled:opacity-40"
                >
                  <Plus className="h-4 w-4" />
                  Добавить
                </button>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Панель действий выбранного узла ── */}
      <AnimatePresence>
        {selectedNode && (
          <motion.aside
            initial={{ opacity: 0, x: 24 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 24 }}
            transition={{ duration: 0.18, ease: [0.22, 1, 0.36, 1] }}
            className="w-[280px] shrink-0 overflow-y-auto rounded-xl border border-vb-border bg-vb-bg p-4"
          >
            <MapPanel
              id={selectedNode.id}
              live={live}
              busy={busy}
              health={health}
              rules={rules}
              onRuleSave={async (proc, exit) => {
                setBusy(true);
                try {
                  setRules(
                    await vpnRuleSave({
                      name: `app-${proc.toLowerCase()}`,
                      match: { match: "process_name", list: [proc] },
                      exit,
                    }),
                  );
                  flash(`правило: ${proc} → применено`);
                } catch (e) {
                  flash(String(e));
                } finally {
                  setBusy(false);
                }
              }}
              onRuleRemove={async (name) => {
                setBusy(true);
                try {
                  setRules(await vpnRuleRemove(name));
                } catch (e) {
                  flash(String(e));
                } finally {
                  setBusy(false);
                }
              }}
              onSwitchNode={connectToNode}
              onToggleSysProxy={() => act(() => vpnSystemProxySet(!(live.sysProxy ?? false)))}
              onTogglePac={() => act(() => (live.pac ? browsersDisable() : browsersEnable()))}
              onToggleSmart={() =>
                act(() =>
                  live.ov
                    ? vpnSetRoute(live.ov.route_mode === "all" ? "smart" : "all", live.ov.whitelist_sites)
                    : bridgeSetRouteMode("all"),
                )
              }
              onPower={() => act(() => (vpnRunning ? vpnStop() : vpnStart()))}
              onNavigate={(v) => {
                setSelected(null);
                onNavigate?.(v);
              }}
            />
          </motion.aside>
        )}
      </AnimatePresence>
      </div>
    </div>
  );
}

/* ── панель действий ─────────────────────────────────────────── */

function MapPanel({
  id,
  live,
  busy,
  health,
  rules,
  onRuleSave,
  onRuleRemove,
  onSwitchNode,
  onToggleSysProxy,
  onTogglePac,
  onToggleSmart,
  onPower,
  onNavigate,
}: {
  id: string;
  live: MapData;
  busy: boolean;
  health: BridgeHealth | null;
  rules: RoutingRule[] | null;
  onRuleSave: (proc: string, exit: RoutingRule["exit"]) => void;
  onRuleRemove: (name: string) => void;
  onSwitchNode: (id: string) => void;
  onToggleSysProxy: () => void;
  onTogglePac: () => void;
  onToggleSmart: () => void;
  onPower: () => void;
  onNavigate: (v: AppView) => void;
}) {
  const titles: Record<string, string> = {
    browsers: "Браузеры",
    apps: "Приложения",
    env: "Система (env)",
    tunnel: "VPN-туннель",
    bridge: "Мост-диспетчер",
    "exit-direct": "Напрямую",
    "exit-pool": "Прокси-пул",
  };

  const btn =
    "flex w-full items-center justify-center gap-2 rounded-lg border border-vb-border bg-vb-surface px-3 py-2 text-[13px] font-medium text-vb-silver transition-colors hover:border-vb-border-strong hover:bg-vb-surface-2 active:scale-[0.98] disabled:opacity-40";

  const topNodes = useMemo(
    () =>
      [...(live.ov?.nodes ?? [])]
        .sort((a, b) => (live.pings?.[a.id] ?? 99999) - (live.pings?.[b.id] ?? 99999))
        .slice(0, 8),
    [live.ov, live.pings],
  );

  const isNodeExit = id.startsWith("node-");

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Zap className="h-4 w-4 text-vb-emerald" />
        <span className="text-[14px] font-semibold text-vb-fg">
          {isNodeExit ? (live.ov?.nodes.find((n) => `node-${n.id}` === id)?.name ?? "Нода") : (titles[id] ?? id)}
        </span>
      </div>

      {(id === "tunnel" || isNodeExit) && (
        <>
          <button type="button" className={btn} onClick={onPower} disabled={busy}>
            <Power className="h-3.5 w-3.5" />
            {live.ov?.process.running ? "Выключить туннель" : "Включить туннель"}
          </button>
          <div className="text-[11px] uppercase tracking-[0.06em] text-vb-silver-faint">Нода</div>
          <div className="flex flex-col gap-1">
            {topNodes.map((n) => (
              <button
                key={n.id}
                type="button"
                onClick={() => onSwitchNode(n.id)}
                disabled={busy}
                className={cn(
                  "flex items-center gap-2 rounded-lg px-2.5 py-1.5 text-left transition-colors hover:bg-vb-surface-2/60 disabled:opacity-50",
                  n.id === live.ov?.active && "bg-vb-emerald/[0.08]",
                )}
              >
                <span className="text-[13px] leading-none">{flagOf(n.name)}</span>
                <span className="min-w-0 flex-1 truncate text-[12.5px] text-vb-silver">{n.name}</span>
                <span className="tnum text-[11px] text-vb-silver-faint">
                  {live.pings?.[n.id] ? `${live.pings[n.id]} мс` : "—"}
                </span>
              </button>
            ))}
          </div>
        </>
      )}

      {id === "browsers" && (
        <>
          <p className="text-[12px] leading-relaxed text-vb-silver-dim">
            Проведи связь «Браузеры → VPN-туннель» (системный прокси) или «Браузеры → Мост» (PAC с правилами).
          </p>
          <button type="button" className={btn} onClick={onToggleSysProxy} disabled={busy || live.sysProxy === null}>
            {live.sysProxy ? "Отключить прокси браузеров" : "Браузеры → VPN-туннель"}
          </button>
          <button type="button" className={btn} onClick={onTogglePac} disabled={busy || live.pac === null}>
            {live.pac ? "Отключить PAC (мост)" : "Браузеры → Мост (PAC)"}
          </button>
        </>
      )}

      {id === "bridge" && (
        <>
          <p className="text-[12px] leading-relaxed text-vb-silver-dim">
            Диспетчер для приложений: решает по правилам, что идёт напрямую, а что через прокси-пул.
          </p>
          <button type="button" className={btn} onClick={onToggleSmart} disabled={busy || !health}>
            {health?.mode === "smart" ? "Пустить всё через пул" : "Включить умную маршрутизацию"}
          </button>
          <button type="button" className={btn} onClick={() => onNavigate("bridge")}>
            Настроить пул прокси
          </button>
        </>
      )}

      {id === "apps" && (
        <RuleEditor rules={rules} busy={busy} health={health} onSave={onRuleSave} onRemove={onRuleRemove} live={live} />
      )}

      {id === "env" && (
        <p className="text-[12px] leading-relaxed text-vb-silver-dim">
          Проведи связь «Система → Мост», чтобы консольные утилиты шли через его правила. Снять связь — удалить ребро (Delete).
        </p>
      )}

      {id === "exit-direct" && (
        <p className="text-[12px] leading-relaxed text-vb-silver-dim">
          RU-домены (Яндекс, VK, банки) ходят без прокси — быстро и без блокировок. Связь «Мост → Напрямую» = умная маршрутизация.
        </p>
      )}

      {id === "exit-pool" && (
        <>
          <p className="text-[12px] leading-relaxed text-vb-silver-dim">
            {health
              ? `Живых прокси: ${health.upstreams.filter((u) => u.healthy).length} из ${health.upstreams.length}.`
              : "Мост остановлен."}
          </p>
          <button type="button" className={btn} onClick={() => onNavigate("bridge")}>
            Открыть «Прокси»
          </button>
        </>
      )}
    </div>
  );
}

/* ── Редактор per-app правил (process_name → выход) ────────────── */

function exitLabel(exit: RoutingRule["exit"], live: MapData): string {
  if (exit.type === "direct") return "напрямую";
  if (exit.type === "pool") return "прокси-пул";
  if (exit.type === "selector") return "активная нода";
  if (exit.type === "reject") return "блокировка";
  const n = live.ov?.nodes.find((x) => x.id === exit.id);
  return n ? `${flagOf(n.name)} ${n.name}` : `нода ${exit.id}`;
}

function matchLabel(r: RoutingRule): string {
  switch (r.match.match) {
    case "process_name":
      return r.match.list.join(", ");
    case "domain_suffix":
      return `домены: ${r.match.list.slice(0, 2).join(", ")}${r.match.list.length > 2 ? "…" : ""}`;
    case "domain_keyword":
      return `ключевые: ${r.match.list.join(", ")}`;
    default:
      return "весь трафик";
  }
}

function RuleEditor({
  rules,
  busy,
  health,
  onSave,
  onRemove,
  live,
}: {
  rules: RoutingRule[] | null;
  busy: boolean;
  health: BridgeHealth | null;
  onSave: (proc: string, exit: RoutingRule["exit"]) => void;
  onRemove: (name: string) => void;
  live: MapData;
}) {
  const [proc, setProc] = useState("");
  const [exitKind, setExitKind] = useState<"selector" | "direct" | "pool">("selector");

  return (
    <>
      <p className="text-[12px] leading-relaxed text-vb-silver-dim">
        Правило: приложение (по имени процесса) → выход. Применяется перезапуском
        туннеля; надёжнее всего работает в системном режиме (TUN).
      </p>
      <div className="flex flex-col gap-2">
        <input
          value={proc}
          onChange={(e) => setProc(e.target.value)}
          placeholder="имя процесса, напр. telegram.exe"
          className="w-full rounded-lg border border-vb-border bg-vb-surface px-3 py-2 font-mono text-[12px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-emerald/50"
        />
        <div className="flex gap-1.5">
          {(
            [
              ["selector", "Активная нода"],
              ["direct", "Напрямую"],
              ["pool", "Пул"],
            ] as const
          ).map(([k, label]) => (
            <button
              key={k}
              type="button"
              onClick={() => setExitKind(k)}
              disabled={k === "pool" && (health?.upstreams.length ?? 0) === 0}
              className={cn(
                "flex-1 rounded-lg border px-2 py-1.5 text-[11.5px] font-medium transition-colors",
                exitKind === k
                  ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
                  : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
              )}
            >
              {label}
            </button>
          ))}
        </div>
        <button
          type="button"
          onClick={() => {
            const p = proc.trim();
            if (!p) return;
            onSave(p, { type: exitKind } as RoutingRule["exit"]);
            setProc("");
          }}
          disabled={busy || !proc.trim()}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-vb-emerald px-3 py-2 text-[13px] font-semibold text-black transition-colors hover:bg-vb-emerald-bright disabled:opacity-40"
        >
          <Plus className="h-4 w-4" />
          Добавить правило
        </button>
      </div>

      {rules && rules.length > 0 && (
        <div className="flex flex-col gap-1">
          <div className="text-[11px] uppercase tracking-[0.06em] text-vb-silver-faint">
            Правила ({rules.length})
          </div>
          {rules.map((r) => (
            <div
              key={r.name ?? matchLabel(r)}
              className="flex items-center gap-2 rounded-lg bg-vb-surface px-2.5 py-1.5"
            >
              <span className="min-w-0 flex-1 truncate text-[12px] text-vb-silver">
                <span className="font-mono text-vb-fg">{matchLabel(r)}</span>
                <span className="text-vb-silver-faint"> → </span>
                {exitLabel(r.exit, live)}
              </span>
              {r.name && (
                <button
                  type="button"
                  onClick={() => onRemove(r.name!)}
                  disabled={busy}
                  className="rounded-md p-1 text-vb-silver-faint transition-colors hover:bg-vb-loss/10 hover:text-vb-loss disabled:opacity-40"
                  title="Удалить правило"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/* Обёртка: ReactFlow требует провайдер для fitView. */
export function RouteMapPage(props: { onNavigate?: (v: AppView) => void }) {
  return (
    <ReactFlowProvider>
      <RouteMap {...props} />
    </ReactFlowProvider>
  );
}

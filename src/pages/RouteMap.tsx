import { useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
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
  Power,
  TerminalSquare,
  Waypoints,
  Wifi,
  Zap,
} from "lucide-react";
import {
  bridgeSetRouteMode,
  vpnOverview,
  vpnPingAll,
  vpnSetActive,
  vpnSetRoute,
  vpnStart,
  vpnStop,
  vpnSystemProxyGet,
  vpnSystemProxySet,
} from "../lib/api";
import { formatUptime, useStatus } from "../lib/status";
import type { AppView, BridgeHealth, VpnOverview } from "../lib/types";
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

/* ── данные карты ────────────────────────────────────────────── */

interface MapData {
  ov: VpnOverview | null;
  sysProxy: boolean | null;
  speed: { up: number; down: number } | null;
  pings: Record<string, number> | null;
}

/* ── кастомные узлы ──────────────────────────────────────────── */

/* Дефолт на первый рендер: ReactFlow монтирует узлы с data:{} до того,
   как эффект наполнит их живыми данными — без дефолта будет TypeError. */
const EMPTY_LIVE: MapData = { ov: null, sysProxy: null, speed: null, pings: null };

function NodeShell({
  active,
  problem,
  selected,
  children,
  handles = "lr",
}: {
  active: boolean;
  problem?: boolean;
  selected: boolean;
  children: React.ReactNode;
  handles?: "lr" | "l" | "r";
}) {
  return (
    <div
      className={cn(
        "w-[210px] rounded-xl border bg-vb-bg/95 px-3 py-2.5 shadow-lg backdrop-blur transition-colors",
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

type SourceNodeData = { live: MapData; envOn: boolean; active: boolean };
function BrowserNode({ data, selected }: NodeProps) {
  const d = (data as unknown as SourceNodeData) ?? { live: EMPTY_LIVE, envOn: false, active: false };
  return (
    <NodeShell active={d.active} selected={selected} handles="r">
      <div className="flex items-center gap-2">
        <Globe className="h-4 w-4 text-vb-silver-dim" />
        <span className="text-[13px] font-semibold text-vb-fg">Браузеры</span>
      </div>
      <div className={cn("mt-1 text-[11px]", d.active ? "text-vb-emerald" : "text-vb-silver-faint")}>
        {d.active ? "через VPN-туннель" : "напрямую, без VPN"}
      </div>
    </NodeShell>
  );
}

function AppsNode({ data, selected }: NodeProps) {
  const d = (data as unknown as SourceNodeData) ?? { live: EMPTY_LIVE, envOn: false, active: false };
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
  const d = (data as unknown as SourceNodeData) ?? { live: EMPTY_LIVE, envOn: false, active: false };
  return (
    <NodeShell active={d.active} selected={selected} handles="r">
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

type ExitNodeData = { live: MapData; name: string; flag: string; sub: string; active: boolean; problem?: boolean };
function ExitNode({ data, selected }: NodeProps) {
  const d = (data as unknown as ExitNodeData) ?? { live: EMPTY_LIVE, name: "", flag: "", sub: "", active: false };
  return (
    <NodeShell active={d.active} problem={d.problem} selected={selected} handles="l">
      <div className="flex items-center gap-2">
        <span className="text-[15px] leading-none">{d.flag}</span>
        <span className="min-w-0 flex-1 truncate text-[13px] font-semibold text-vb-fg">{d.name}</span>
      </div>
      <div className={cn("mt-1 truncate text-[11px]", d.active ? "text-vb-emerald" : "text-vb-silver-faint")}>{d.sub}</div>
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

export function RouteMap({ onNavigate }: { onNavigate?: (v: AppView) => void }) {
  const { health, env } = useStatus();
  const [live, setLive] = useState<MapData>({ ov: null, sysProxy: null, speed: null, pings: null });
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const lastTotals = useRef<{ t: number; up: number; down: number } | null>(null);

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
    };
    void tick();
    void vpnSystemProxyGet().then((v) => alive && setLive((p) => ({ ...p, sysProxy: v }))).catch(() => {});
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

  /* Позиции фиксированы: карта — схема, а не песочница. */
  const initialNodes = useMemo<Node[]>(() => [
    { id: "browsers", type: "browsers", position: { x: 0, y: 20 }, data: {} },
    { id: "apps", type: "apps", position: { x: 0, y: 170 }, data: {} },
    { id: "env", type: "env", position: { x: 0, y: 320 }, data: {} },
    { id: "tunnel", type: "tunnel", position: { x: 300, y: 20 }, data: {} },
    { id: "bridge", type: "bridge", position: { x: 300, y: 240 }, data: {} },
    { id: "exit-node", type: "exit", position: { x: 600, y: 20 }, data: {} },
    { id: "exit-direct", type: "exit", position: { x: 600, y: 190 }, data: {} },
    { id: "exit-pool", type: "exit", position: { x: 600, y: 340 }, data: {} },
  ], []);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);

  /* Живые данные → узлы (позиции и drag не трогаем). */
  useEffect(() => {
    setNodes((prev) =>
      prev.map((n) => {
        if (n.id === "browsers") return { ...n, data: { live, envOn, active: !!live.sysProxy } };
        if (n.id === "apps") return { ...n, data: { live, envOn, active: bridgeRunning } };
        if (n.id === "env") return { ...n, data: { live, envOn, active: envOn } };
        if (n.id === "tunnel") return { ...n, data: { live } };
        if (n.id === "bridge") return { ...n, data: { live, health } };
        if (n.id === "exit-node")
          return {
            ...n,
            data: {
              live,
              name: activeNode?.name ?? "Нода не выбрана",
              flag: activeNode ? flagOf(activeNode.name) : "🌐",
              sub: !vpnRunning
                ? "туннель выключен"
                : live.pings && activeNode && live.pings[activeNode.id]
                  ? `${live.pings[activeNode.id]} мс · выход через ноду`
                  : "выход через ноду",
              active: vpnRunning,
              problem: vpnRunning && !activeNode,
            },
          };
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
              sub: poolTotal ? `${poolOk} живых из ${poolTotal}` : "пул пуст — добавь в «Прокси»",
              active: bridgeRunning && poolOk > 0,
              problem: bridgeRunning && poolTotal > 0 && poolOk === 0,
            },
          };
        return n;
      }),
    );
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live, envOn, health, busy, activeNode, vpnRunning, bridgeRunning, smart, poolTotal, poolOk]);

  /* Рёбра: анимируются, когда по ним реально идёт трафик. */
  useEffect(() => {
    const mk = (id: string, source: string, target: string, on: boolean, label?: string): Edge => ({
      id,
      source,
      target,
      animated: on,
      label,
      labelShowBg: true,
      labelBgStyle: { fill: "var(--vb-surface, #14171c)", fillOpacity: 0.9 },
      labelBgPadding: [6, 3],
      labelBgBorderRadius: 6,
      style: {
        stroke: on ? "#34d399" : "var(--vb-border, #2a2f38)",
        strokeWidth: on ? 2 : 1.4,
      },
      markerEnd: on ? { type: MarkerType.ArrowClosed, color: "#34d399" } : undefined,
    });
    setEdges([
      mk("e-b", "browsers", "tunnel", !!live.sysProxy && vpnRunning, live.sysProxy ? "системный прокси" : undefined),
      mk("e-a", "apps", "bridge", bridgeRunning),
      mk("e-e", "env", "bridge", envOn && bridgeRunning),
      mk("e-t", "tunnel", "exit-node", vpnRunning && !!activeNode),
      mk("e-bd", "bridge", "exit-direct", bridgeRunning && smart),
      mk("e-bp", "bridge", "exit-pool", bridgeRunning && poolOk > 0),
    ]);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live.sysProxy, vpnRunning, bridgeRunning, envOn, smart, poolOk, activeNode]);

  /* Панель редактирования выбранного узла. */
  const selectedNode = nodes.find((n) => n.id === selected);

  const switchNode = async (id: string) => {
    setBusy(true);
    try {
      let o = await vpnSetActive(id);
      if (o.process.running) {
        o = await vpnStop();
        o = await vpnStart();
      }
      setLive((p) => ({ ...p, ov: o }));
    } catch {
      /* переживаем */
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex h-full gap-3">
      <div className="min-w-0 flex-1 overflow-hidden rounded-xl border border-vb-border bg-vb-bg">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          nodeTypes={nodeTypes}
          onNodeClick={(_, n) => setSelected(n.id)}
          onPaneClick={() => setSelected(null)}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          proOptions={{ hideAttribution: true }}
          nodesDraggable
          edgesFocusable={false}
          minZoom={0.5}
        >
          <Background variant={BackgroundVariant.Dots} gap={22} size={1.4} color="var(--vb-border, #2a2f38)" />
          <Controls showInteractive={false} position="bottom-right" />
        </ReactFlow>
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
              envOn={envOn}
              onSwitchNode={switchNode}
              onToggleSysProxy={async () => {
                setBusy(true);
                try {
                  const v = await vpnSystemProxySet(!(live.sysProxy ?? false));
                  setLive((p) => ({ ...p, sysProxy: v }));
                } finally {
                  setBusy(false);
                }
              }}
              onToggleSmart={async () => {
                setBusy(true);
                try {
                  if (live.ov) {
                    await vpnSetRoute(live.ov.route_mode === "all" ? "smart" : "all", live.ov.whitelist_sites);
                  } else {
                    await bridgeSetRouteMode("all");
                  }
                } finally {
                  setBusy(false);
                }
              }}
              onPower={async () => {
                setBusy(true);
                try {
                  const o = vpnRunning ? await vpnStop() : await vpnStart();
                  setLive((p) => ({ ...p, ov: o }));
                } finally {
                  setBusy(false);
                }
              }}
              onNavigate={(v) => {
                setSelected(null);
                onNavigate?.(v);
              }}
            />
          </motion.aside>
        )}
      </AnimatePresence>
    </div>
  );
}

/* ── панель действий ─────────────────────────────────────────── */

function MapPanel({
  id,
  live,
  busy,
  health,
  envOn,
  onSwitchNode,
  onToggleSysProxy,
  onToggleSmart,
  onPower,
  onNavigate,
}: {
  id: string;
  live: MapData;
  busy: boolean;
  health: BridgeHealth | null;
  envOn: boolean;
  onSwitchNode: (id: string) => void;
  onToggleSysProxy: () => void;
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
    "exit-node": "Активная нода",
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

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Zap className="h-4 w-4 text-vb-emerald" />
        <span className="text-[14px] font-semibold text-vb-fg">{titles[id] ?? id}</span>
      </div>

      {(id === "tunnel" || id === "exit-node") && (
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
            Системный прокси отправляет Chrome, Edge и Opera через VPN-туннель. При падении туннеля отключается сам.
          </p>
          <button type="button" className={btn} onClick={onToggleSysProxy} disabled={busy || live.sysProxy === null}>
            {live.sysProxy ? "Отключить прокси браузеров" : "Включить прокси браузеров"}
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
          <button type="button" className={btn} onClick={() => onNavigate("proxies")}>
            Настроить пул прокси
          </button>
        </>
      )}

      {id === "apps" && (
        <>
          <p className="text-[12px] leading-relaxed text-vb-silver-dim">
            Назначь конкретным приложениям маршрут: напрямую, через пул или через цепочку.
          </p>
          <button type="button" className={btn} onClick={() => onNavigate("apps")}>
            Открыть «Приложения»
          </button>
        </>
      )}

      {id === "env" && (
        <p className="text-[12px] leading-relaxed text-vb-silver-dim">
          {envOn
            ? "Глобальные переменные HTTP_PROXY указывают на мост: консольные утилиты и часть приложений пойдут через его правила."
            : "Переменные не заданы. Включи «Системное проксирование» в трее, если нужно направить консольные утилиты через мост."}
        </p>
      )}

      {id === "exit-direct" && (
        <p className="text-[12px] leading-relaxed text-vb-silver-dim">
          RU-домены (Яндекс, VK, банки) ходят без прокси — быстро и без блокировок. Управляется режимом «Умный» на мосте.
        </p>
      )}

      {id === "exit-pool" && (
        <>
          <p className="text-[12px] leading-relaxed text-vb-silver-dim">
            {health
              ? `Живых прокси: ${health.upstreams.filter((u) => u.healthy).length} из ${health.upstreams.length}.`
              : "Мост остановлен."}
          </p>
          <button type="button" className={btn} onClick={() => onNavigate("proxies")}>
            Открыть «Прокси»
          </button>
        </>
      )}
    </div>
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

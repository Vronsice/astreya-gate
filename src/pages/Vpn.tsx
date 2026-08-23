import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  AlertTriangle,
  Check,
  ClipboardPaste,
  Gauge,
  Loader2,
  Play,
  Plus,
  RefreshCw,
  Square,
  Trash2,
  Wifi,
} from "lucide-react";
import { Button } from "../components/Button";
import { InfoTip } from "../components/InfoTip";
import { Toggle } from "../components/Toggle";
import {
  vpnAddLink,
  vpnAddSubscription,
  vpnImport,
  vpnOverview,
  vpnPingAll,
  vpnRealDelay,
  vpnRefreshSubscription,
  vpnRemoveNode,
  vpnRemoveSubscription,
  vpnSetActive,
  vpnSetAutostart,
  vpnSetRoute,
  vpnStart,
  vpnStop,
  vpnTunDisable,
  vpnTunEnable,
  vpnTunStatus,
  type TunStatus,
} from "../lib/api";
import { formatBytes } from "../lib/format";
import type { VpnNode, VpnOverview } from "../lib/types";
import { fadeInUp, staggerContainer } from "../lib/motion";
import { cn } from "../lib/cn";

/*
  VPN: подписки и одиночные конфиги на движке sing-box. Локальный порт
  (2080) — это просто SOCKS/HTTP-прокси: мост уже смотрит туда как на
  дефолтный upstream, поэтому замена nekobox'а бесшовна.
*/

const PROTO_BADGE: Record<string, string> = {
  vless: "border-vb-emerald/40 text-vb-emerald",
  vmess: "border-sky-400/40 text-sky-300",
  ss: "border-violet-400/40 text-violet-300",
  trojan: "border-amber-400/40 text-amber-300",
  hysteria2: "border-pink-400/40 text-pink-300",
  tuic: "border-teal-400/40 text-teal-300",
};

function ago(ts?: number): string {
  if (!ts) return "никогда";
  const m = Math.floor((Date.now() / 1000 - ts) / 60);
  if (m < 1) return "только что";
  if (m < 60) return `${m} мин назад`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h} ч назад`;
  return `${Math.floor(h / 24)} дн назад`;
}

export function Vpn() {
  const [ov, setOv] = useState<VpnOverview | null>(null);
  const [tun, setTun] = useState<TunStatus | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pings, setPings] = useState<Record<string, number | null>>({});
  const [pingBusy, setPingBusy] = useState(false);
  const [realMs, setRealMs] = useState<number | null>(null);

  // Формы
  const [subName, setSubName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [linkInput, setLinkInput] = useState("");
  /** Черновик белого списка (режим whitelist). */
  const [wlText, setWlText] = useState("");
  const [importMsg, importMsgSet] = useState<string | null>(null);

  // Синхронизируем черновик белого списка со снимком (после load/act).
  useEffect(() => {
    if (ov) setWlText(ov.whitelist_sites.join("\n"));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ov?.whitelist_sites.join("\n")]);

  // Скорости по дельтам totals между опросами.
  const prevTotals = useRef<{ t: number; up: number; down: number } | null>(null);
  const [speed, setSpeed] = useState<{ up: number; down: number } | null>(null);

  const adopt = useCallback((v: VpnOverview) => {
    setOv(v);
    if (v.up_total != null && v.down_total != null) {
      const now = Date.now();
      const p = prevTotals.current;
      if (p && now > p.t && v.up_total >= p.up && v.down_total >= p.down) {
        const dt = (now - p.t) / 1000;
        setSpeed({ up: (v.up_total - p.up) / dt, down: (v.down_total - p.down) / dt });
      }
      prevTotals.current = { t: now, up: v.up_total, down: v.down_total };
    } else {
      setSpeed(null);
      prevTotals.current = null;
    }
  }, []);

  const load = useCallback(async () => {
    try {
      adopt(await vpnOverview());
    } catch (e) {
      setError(String(e));
    }
    setTun(await vpnTunStatus().catch(() => null));
  }, [adopt]);

  useEffect(() => {
    void load();
    const id = window.setInterval(() => {
      if (!document.hidden) void load();
    }, 5000);
    return () => window.clearInterval(id);
  }, [load]);

  const act = async (key: string, fn: () => Promise<VpnOverview>) => {
    setBusy(key);
    setError(null);
    try {
      adopt(await fn());
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const pingAll = async () => {
    setPingBusy(true);
    try {
      setPings(await vpnPingAll());
    } catch {
      /* ignore */
    } finally {
      setPingBusy(false);
    }
  };

  const running = ov?.process.running ?? false;
  const activeNode = ov?.nodes.find((n) => n.id === ov.active) ?? null;
  const subById = new Map((ov?.subscriptions ?? []).map((s) => [s.id, s]));

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[680px] flex-col gap-5 px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="flex items-center gap-2.5 text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          <Wifi className="h-6 w-6 text-vb-emerald" strokeWidth={1.9} />
          VPN
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Подписки и конфиги на движке sing-box · локальный прокси 127.0.0.1:{ov?.port ?? 2080}
        </p>
      </motion.header>

      {/* ── Статус движка ── */}
      <motion.section variants={fadeInUp} className="surface-card p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <span
              className={cn(
                "h-2.5 w-2.5 shrink-0 rounded-full",
                running ? "bg-vb-emerald" : "bg-vb-border-strong",
              )}
            />
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-[14px] font-semibold text-vb-fg">
                  {running ? "Подключено" : "Остановлено"}
                </span>
                {activeNode && (
                  <span className="truncate text-[12px] text-vb-silver-dim">
                    · {activeNode.name}
                  </span>
                )}
              </div>
              <div className="tnum truncate text-[11px] text-vb-silver-faint">
                {running
                  ? `↑${formatBytes(speed?.up)} /с ↓${formatBytes(speed?.down)}/с${realMs ? ` · задержка ${realMs} мс` : ""}`
                  : "Выберите ноду ниже и запустите туннель"}
              </div>
            </div>
          </div>
          {busy === "start" || busy === "stop" ? (
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-vb-silver-dim" />
          ) : running ? (
            <Button variant="danger" size="sm" onClick={() => void act("stop", vpnStop)}>
              <Square className="h-3 w-3" /> Стоп
            </Button>
          ) : (
            <Button size="sm" onClick={() => void act("start", vpnStart)}>
              <Play className="h-3 w-3" /> Подключить
            </Button>
          )}
        </div>

        {/* Реальный delay-тест активной ноды — как в nekobox */}
        <AnimatePresence>
          {running && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <button
                type="button"
                disabled={busy === "delay"}
                onClick={async () => {
                  setBusy("delay");
                  setError(null);
                  try {
                    setRealMs(await vpnRealDelay());
                  } catch (e) {
                    setRealMs(null);
                    setError(`Delay-тест: ${e}`);
                  } finally {
                    setBusy(null);
                  }
                }}
                className="mt-3 flex items-center gap-1.5 rounded-lg border border-vb-border px-2.5 py-1 text-[12px] font-medium text-vb-silver transition-colors hover:border-vb-border-strong hover:bg-vb-surface-2 active:scale-[0.97]"
              >
                {busy === "delay" ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Gauge className="h-3 w-3" />
                )}
                Замерить реальную задержку (через туннель)
              </button>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Автоподключение при старте приложения */}
        <div className="mt-3 flex items-center justify-between border-t border-vb-border/60 pt-3">
          <div className="flex items-center gap-2">
            <span className="text-[12.5px] text-vb-silver">
              Подключать при запуске приложения
            </span>
            <InfoTip>
              Туннель поднимется автоматически через пару секунд после старта
              Astreya Gate — на той же активной ноде.
            </InfoTip>
          </div>
          <Toggle
            checked={ov?.autostart ?? false}
            onChange={(v) => void act("autostart", () => vpnSetAutostart(v))}
            disabled={busy !== null}
            label="Автоподключение"
          />
        </div>
      </motion.section>

      {/* ── Режим маршрутизации туннеля ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="flex items-center gap-2">
          <h2 className="text-[15px] font-semibold text-vb-fg">Маршрутизация туннеля</h2>
          <InfoTip>
            Какие сайты ходят через VPN, а какие напрямую. Правила работают
            внутри туннеля sing-box и применяются к трафику, который в него
            попал (локальный порт 2080).
          </InfoTip>
        </div>
        {(
          [
            {
              id: "all" as const,
              title: "Всё через VPN",
              desc: "Весь трафик туннеля идёт через активную ноду. Максимальная приватность.",
            },
            {
              id: "smart" as const,
              title: "Умный",
              desc: "Популярные RU-сервисы (Яндекс, VK, банки, Госуслуги…) идут напрямую без VPN — быстро и без блокировок. Остальное — через VPN.",
            },
            {
              id: "whitelist" as const,
              title: "Белый список",
              desc: "Через VPN идут только перечисленные ниже сайты, всё остальное — напрямую.",
            },
          ]
        ).map((m) => (
          <button
            key={m.id}
            type="button"
            onClick={() => {
              if (!ov || ov.route_mode === m.id) return;
              void act("route", () => vpnSetRoute(m.id, ov.whitelist_sites));
            }}
            className={
              "rounded-lg border px-3.5 py-2.5 text-left transition-colors duration-150 " +
              (ov?.route_mode === m.id
                ? "border-vb-emerald/50 bg-vb-emerald/10"
                : "border-vb-border hover:border-vb-border-strong")
            }
          >
            <div className="text-[13px] font-medium text-vb-fg">{m.title}</div>
            <div className="mt-0.5 text-[12px] leading-relaxed text-vb-silver-dim">
              {m.desc}
            </div>
          </button>
        ))}

        {/* Белый список для соответствующего режима */}
        <AnimatePresence>
          {ov?.route_mode === "whitelist" && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <textarea
                value={wlText}
                onChange={(e) => setWlText(e.target.value)}
                spellCheck={false}
                rows={6}
                placeholder={"openai.com\nnetflix.com"}
                className="w-full resize-y rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2.5 font-mono text-[12.5px] leading-relaxed text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
              />
              <Button
                variant="secondary"
                size="sm"
                className="mt-2"
                disabled={busy !== null}
                onClick={() => {
                  const sites = wlText
                    .split(/\r?\n/)
                    .map((x) => x.trim())
                    .filter(Boolean);
                  void act("route", () => vpnSetRoute("whitelist", sites));
                }}
              >
                Применить список
              </Button>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.section>

      {/* ── Импорт ── */}
      <motion.section variants={fadeInUp} className="surface-card p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-[14px] font-semibold text-vb-fg">Импорт из буфера</span>
              <InfoTip>
                Понимает ссылки подписок (https://…), happ://add/…, astreya://add/…
                и одиночные конфиги vless/vmess/ss/trojan/hysteria2/tuic —
                можно вставлять сразу несколько строк.
              </InfoTip>
            </div>
            {importMsg && (
              <div className="mt-0.5 truncate text-[11.5px] text-vb-emerald">{importMsg}</div>
            )}
          </div>
          <Button
            variant="secondary"
            size="sm"
            disabled={busy !== null}
            onClick={async () => {
              setBusy("import");
              setError(null);
              try {
                const text = await navigator.clipboard.readText();
                importMsgSet(await vpnImport(text));
              } catch (e) {
                setError(String(e));
              } finally {
                setBusy(null);
              }
            }}
          >
            <ClipboardPaste className="h-3.5 w-3.5" /> Вставить и добавить
          </Button>
        </div>
      </motion.section>

      {error && (
        <motion.div variants={fadeInUp} className="flex items-start gap-2 rounded-lg border border-vb-loss/30 bg-vb-loss/10 px-3.5 py-2.5 text-[12.5px] text-vb-loss">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.9} />
          <span className="break-all">{error}</span>
        </motion.div>
      )}

      {/* ── Системный режим (TUN) ── */}
      <motion.section variants={fadeInUp} className="surface-card p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "h-2 w-2 shrink-0 rounded-full",
                  tun?.running_process ? "bg-vb-emerald" : "bg-vb-border-strong",
                )}
              />
              <span className="text-[14px] font-semibold text-vb-fg">Системный режим</span>
              {tun?.state && (
                <span className="rounded-md border border-vb-border bg-vb-surface-2 px-1.5 py-px text-[10px] text-vb-silver-faint">
                  задача: {tun.state}
                </span>
              )}
            </div>
            <p className="mt-1 text-[12px] leading-relaxed text-vb-silver-dim">
              Перехватывает <b>весь</b> трафик Windows через виртуальный адаптер —
              даже приложения без поддержки прокси. Включение попросит права
              администратора один раз.
            </p>
          </div>
          {busy === "tun" ? (
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-vb-silver-dim" />
          ) : (
            <Toggle
              checked={!!tun?.running_process}
              onChange={async (v) => {
                if (!ov?.active) {
                  setError("Сначала выберите ноду — она станет системным VPN");
                  return;
                }
                setBusy("tun");
                setError(null);
                try {
                  setTun(v ? await vpnTunEnable() : await vpnTunDisable());
                } catch (e) {
                  setError(String(e));
                } finally {
                  setBusy(null);
                  void load();
                }
              }}
              disabled={busy !== null || !ov?.active}
              label="Системный режим"
            />
          )}
        </div>
        {!ov?.active && (
          <p className="mt-2 text-[11px] text-vb-silver-faint">
            Выберите ноду ниже — затем включите режим.
          </p>
        )}
      </motion.section>

      {/* ── Подписки ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <h2 className="text-[15px] font-semibold text-vb-fg">Подписки</h2>
            <InfoTip>
              URL провайдера VPN: приложение скачивает список нод, парсит ссылки
              (base64 или plain) и обновляет их по кнопке. Прямая загрузка не
              удалась → автоматически повторяет через мост.
            </InfoTip>
          </div>
        </div>

        {(ov?.subscriptions ?? []).length === 0 && (
          <p className="text-[12.5px] text-vb-silver-dim">Пока нет ни одной подписки.</p>
        )}
        <div className="divide-y divide-vb-border/70">
          {(ov?.subscriptions ?? []).map((s) => (
            <div key={s.id} className="flex items-center gap-3 py-2.5">
              <div className="min-w-0 flex-1">
                <div className="truncate text-[13px] font-medium text-vb-fg">{s.name}</div>
                <div className="truncate font-mono text-[10.5px] text-vb-silver-faint">
                  {(ov?.nodes ?? []).filter((n) => n.source === s.id).length} нод · обновлено: {ago(s.last_update)}
                </div>
              </div>
              {busy === `refresh:${s.id}` ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-vb-silver-dim" />
              ) : (
                <button
                  type="button"
                  onClick={() => void act(`refresh:${s.id}`, () => vpnRefreshSubscription(s.id))}
                  className="rounded-lg p-1.5 text-vb-silver-faint transition-colors hover:bg-vb-surface-2 hover:text-vb-silver"
                  title="Обновить сейчас"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                </button>
              )}
              <button
                type="button"
                onClick={() => void act(`del-sub:${s.id}`, () => vpnRemoveSubscription(s.id))}
                disabled={busy !== null}
                className="rounded-lg p-1.5 text-vb-silver-faint transition-colors hover:bg-vb-loss/10 hover:text-vb-loss disabled:opacity-35"
                title="Удалить подписку и её ноды"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          ))}
        </div>

        <div className="flex gap-2">
          <input
            value={subName}
            onChange={(e) => setSubName(e.target.value)}
            placeholder="Название (необязательно)"
            className="w-[160px] rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2 text-[12.5px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
          />
          <input
            value={subUrl}
            onChange={(e) => setSubUrl(e.target.value)}
            placeholder="https://провайдер/подписка"
            className="min-w-0 flex-1 rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2 font-mono text-[12px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
          />
          <Button
            variant="secondary"
            size="sm"
            disabled={!subUrl.trim() || busy !== null}
            onClick={async () => {
              await act("add-sub", () => vpnAddSubscription(subName, subUrl.trim()));
              setSubName("");
              setSubUrl("");
            }}
          >
            <Plus className="h-3.5 w-3.5" /> Добавить
          </Button>
        </div>
      </motion.section>

      {/* ── Свой конфиг ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-2.5 p-4">
        <div className="flex items-center gap-2">
          <h2 className="text-[15px] font-semibold text-vb-fg">Свой конфиг</h2>
          <InfoTip>
            Вставьте одну ссылку целиком: vless://, vmess://, ss://, trojan://,
            hysteria2:// (hy2://) или tuic://. Параметры Reality, WS/gRPC,
            obfs поддерживаются.
          </InfoTip>
        </div>
        <div className="flex gap-2">
          <input
            value={linkInput}
            onChange={(e) => setLinkInput(e.target.value)}
            placeholder="vless://uuid@host:443?security=reality&…#Имя"
            className="min-w-0 flex-1 rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2 font-mono text-[12px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
          />
          <Button
            variant="secondary"
            size="sm"
            disabled={!linkInput.trim() || busy !== null}
            onClick={async () => {
              await act("add-link", () => vpnAddLink(linkInput.trim()));
              setLinkInput("");
            }}
          >
            <Plus className="h-3.5 w-3.5" /> Добавить
          </Button>
        </div>
      </motion.section>

      {/* ── Ноды ── */}
      <motion.section variants={fadeInUp} className="surface-card divide-y divide-vb-border/70">
        <div className="flex items-center justify-between px-4 pb-2 pt-3">
          <div className="flex items-center gap-2">
            <h2 className="text-[15px] font-semibold text-vb-fg">
              Ноды ({ov?.nodes.length ?? 0})
            </h2>
            <InfoTip>
              «Задержка» — время отклика сервера ноды (TCP). Активная нода
              помечена галочкой: при работающем туннеле её смена переподключает
              движок автоматически.
            </InfoTip>
          </div>
          <button
            type="button"
            onClick={() => void pingAll()}
            disabled={pingBusy || (ov?.nodes.length ?? 0) === 0}
            className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] font-medium text-vb-silver-dim transition-colors hover:bg-vb-surface-2 hover:text-vb-silver disabled:opacity-35"
          >
            {pingBusy ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Gauge className="h-3.5 w-3.5" />
            )}
            Задержка всех
          </button>
        </div>

        {(ov?.nodes ?? []).length === 0 && (
          <p className="px-4 pb-4 text-[12.5px] text-vb-silver-dim">
            Нод нет — добавьте подписку или свой конфиг выше.
          </p>
        )}
        {(ov?.nodes ?? []).map((n: VpnNode) => {
          const isActive = ov?.active === n.id;
          const ms = pings[n.id];
          return (
            <div key={n.id} className="flex items-center gap-3 px-4 py-2.5">
              {isActive && busy !== `set:${n.id}` ? (
                <Check className="h-4 w-4 shrink-0 text-vb-emerald" strokeWidth={2.2} />
              ) : busy === `set:${n.id}` ? (
                <Loader2 className="h-4 w-4 shrink-0 animate-spin text-vb-silver-dim" />
              ) : (
                <button
                  type="button"
                  onClick={() => void act(`set:${n.id}`, () => vpnSetActive(n.id))}
                  className="h-4 w-4 shrink-0 rounded-full border border-vb-border-strong transition-colors hover:border-vb-emerald"
                  title="Сделать активной"
                />
              )}
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="truncate text-[13px] text-vb-fg">{n.name}</span>
                  <span
                    className={cn(
                      "shrink-0 rounded-md border px-1.5 py-px text-[10px] font-medium",
                      PROTO_BADGE[n.proto] ?? "border-vb-border text-vb-silver-dim",
                    )}
                  >
                    {n.proto}
                  </span>
                </div>
                <div className="tnum truncate text-[10.5px] text-vb-silver-faint">
                  {n.server}:{n.port}
                  {n.source !== "manual" &&
                    ` · ${subById.get(n.source)?.name ?? "подписка"}`}
                </div>
              </div>
              {ms !== undefined && (
                <span
                  className={cn(
                    "tnum shrink-0 font-mono text-[11px]",
                    ms === null ? "text-vb-loss" : ms > 800 ? "text-vb-warn" : "text-vb-silver",
                  )}
                >
                  {ms === null ? "недоступен" : `${ms} мс`}
                </span>
              )}
              <button
                type="button"
                onClick={() => void act(`del:${n.id}`, () => vpnRemoveNode(n.id))}
                disabled={busy !== null}
                className="shrink-0 rounded-lg p-1.5 text-vb-silver-faint transition-colors hover:bg-vb-loss/10 hover:text-vb-loss disabled:opacity-35"
                title="Удалить ноду"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          );
        })}
      </motion.section>

      {/* ── Как связано с мостом ── */}
      <motion.section variants={fadeInUp} className="rounded-lg border border-vb-border bg-vb-surface-2/40 p-4 text-[12.5px] leading-relaxed text-vb-silver-dim">
        Локальный порт этого туннеля — обычный прокси в системе Astreya Gate:
        он уже стоит как «прокси по умолчанию» в разделе «Прокси», поэтому весь
        трафик без закреплений (opencode, Telegram, браузерные списки PAC)
        автоматически идёт через активную ноду. Claude остаётся на платном
        прокси поверх VPN — цепочка собирается сама.
      </motion.section>
    </motion.div>
  );
}

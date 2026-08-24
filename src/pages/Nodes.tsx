import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Check,
  ClipboardPaste,
  Gauge,
  Loader2,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { Button } from "../components/Button";
import { InfoTip } from "../components/InfoTip";
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
} from "../lib/api";
import type { VpnNode, VpnOverview } from "../lib/types";
import { fadeInUp, staggerContainer } from "../lib/motion";
import { cn } from "../lib/cn";

/*
  Ноды: источники выходов движка — подписки, одиночные конфиги, список нод
  с задержками. Управление туннелем и маршрутами — на Карте (домашний экран).
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

export function Nodes() {
  const [ov, setOv] = useState<VpnOverview | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pings, setPings] = useState<Record<string, number | null>>({});
  const [pingBusy, setPingBusy] = useState(false);
  const [realMs, setRealMs] = useState<number | null>(null);

  // Формы
  const [subName, setSubName] = useState("");
  const [subUrl, setSubUrl] = useState("");
  const [linkInput, setLinkInput] = useState("");
  const [importMsg, importMsgSet] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setOv(await vpnOverview());
    } catch (e) {
      setError(String(e));
    }
  }, []);

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
      setOv(await fn());
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
  const subById = new Map((ov?.subscriptions ?? []).map((s) => [s.id, s]));

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[680px] flex-col gap-5 px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          Ноды
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Выходы движка: подписки и свои конфиги · порт 127.0.0.1:{ov?.port ?? 2080}
        </p>
      </motion.header>

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

      {/* ── Подписки ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="flex items-center gap-2">
          <h2 className="text-[15px] font-semibold text-vb-fg">Подписки</h2>
          <InfoTip>
            URL провайдера VPN: приложение скачивает список нод, парсит ссылки
            (base64 или plain) и обновляет их по кнопке. Прямая загрузка не
            удалась → автоматически повторяет через мост.
          </InfoTip>
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
              «Задержка» — время отклика сервера ноды. Смена активной ноды при
              работающем туннеле происходит мгновенно, без разрыва соединений.
            </InfoTip>
          </div>
          <div className="flex items-center gap-1">
            {running && (
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
                className="flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] font-medium text-vb-silver-dim transition-colors hover:bg-vb-surface-2 hover:text-vb-silver disabled:opacity-35"
                title="Реальная задержка активной ноды через туннель"
              >
                {busy === "delay" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Gauge className="h-3.5 w-3.5" />
                )}
                {realMs ? `${realMs} мс` : "Реальная"}
              </button>
            )}
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
                  title="Сделать активной (мгновенно, без разрыва)"
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
    </motion.div>
  );
}

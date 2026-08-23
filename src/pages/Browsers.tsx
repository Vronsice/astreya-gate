import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  Compass,
  Loader2,
  Power,
  Save,
} from "lucide-react";
import { Button } from "../components/Button";
import { InfoTip } from "../components/InfoTip";
import { Toggle } from "../components/Toggle";
import { fadeInUp, staggerContainer } from "../lib/motion";
import {
  browsersConfigure,
  browsersDisable,
  browsersEnable,
  browsersStatus,
} from "../lib/api";
import type { BrowserMode, BrowserStatus } from "../lib/types";

/*
  Браузеры: выборочные сайты через мост (PAC-файл), остальное — напрямую.
  Три блока: статус системной интеграции, режим+список сайтов, сохранение.
*/
export function Browsers() {
  const [status, setStatus] = useState<BrowserStatus | null>(null);
  const [mode, setMode] = useState<BrowserMode>("whitelist");
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [savedFlash, setSavedFlash] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const adopt = useCallback((s: BrowserStatus) => {
    setStatus(s);
    setMode(s.mode);
    setText(s.sites.join("\n"));
  }, []);

  const load = useCallback(async () => {
    try {
      adopt(await browsersStatus());
    } catch (e) {
      setError(String(e));
    }
  }, [adopt]);

  useEffect(() => {
    void load();
  }, [load]);

  const parseSites = (): string[] | null => {
    const sites = text
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) =>
        s
          .replace(/^https?:\/\//i, "")
          .replace(/^www\./i, "")
          .split("/")[0]
          .toLowerCase(),
      )
      .filter(Boolean);
    const bad = sites.find((s) => !s.includes("."));
    if (bad) {
      setError(`«${bad}» — не похоже на домен. Нужен вид: example.com`);
      return null;
    }
    return Array.from(new Set(sites));
  };

  const handleSave = async () => {
    const sites = parseSites();
    if (!sites) return;
    setBusy(true);
    setError(null);
    try {
      await browsersConfigure(mode, sites);
      setSavedFlash(true);
      setTimeout(() => setSavedFlash(false), 1800);
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const handleToggle = async (next: boolean) => {
    setBusy(true);
    setError(null);
    try {
      if (next) {
        // Перед включением всегда сохраняем текущее состояние формы:
        // PAC должен соответствовать тому, что человек видит на экране.
        const sites = parseSites();
        if (!sites) return;
        await browsersConfigure(mode, sites);
        adopt(await browsersEnable());
      } else {
        adopt(await browsersDisable());
      }
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[620px] flex-col gap-5 px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="flex items-center gap-2.5 text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          <Compass className="h-6 w-6 text-vb-emerald" strokeWidth={1.9} />
          Браузеры
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Выбранные сайты — через прокси, остальные — с реальным IP
        </p>
      </motion.header>

      {/* ── Как это работает ── */}
      <motion.section variants={fadeInUp} className="surface-card p-4 text-[12.5px] leading-relaxed text-vb-silver-dim">
        Приложение пишет PAC-файл и прописывает его системным настройкам
        Windows. Chrome и Edge подхватывают его автоматически, Firefox — в
        режиме «использовать системные настройки» (стоит по умолчанию).
        <div className="mt-2">
          <b className="text-vb-silver">Как читать правило:</b> сайт из списка
          уходит в мост <code className="text-vb-emerald">127.0.0.1:8889</code>
          , а дальше работает доменная маршрутизация из раздела «Прокси»
          (anthropic.com → внешний прокси, всё прочее → дефолтный). Сайта нет
          в списке → браузер ходит напрямую с твоим обычным IP.
        </div>
      </motion.section>

      {/* ── Статус + тумблер ── */}
      <motion.section variants={fadeInUp} className="surface-card p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-vb-surface-2 text-vb-silver-dim">
              <Power className="h-4 w-4" strokeWidth={1.9} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-[14px] font-semibold text-vb-fg">
                  Системная интеграция
                </span>
                <InfoTip>
                  Прописывает наш PAC в настройки прокси Windows (HKCU,
                  без прав администратора). Чужие настройки, если были,
                  сохраняются и возвращаются при выключении.
                </InfoTip>
              </div>
              <div className="truncate text-[11px] text-vb-silver-faint">
                {status === null
                  ? "Проверяю…"
                  : status.active
                    ? "PAC активен — браузеры маршрутизируются"
                    : status.system_auto_config_url
                      ? `Занято чужой настройкой: ${status.system_auto_config_url}`
                      : "Выключено — браузеры работают как обычно"}
              </div>
            </div>
          </div>
          {status === null || busy ? (
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-vb-silver-dim" />
          ) : (
            <Toggle
              checked={status.active}
              onChange={handleToggle}
              disabled={busy}
              label="Системная интеграция"
            />
          )}
        </div>
      </motion.section>

      {/* ── Режим ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="text-[14px] font-semibold text-vb-fg">Режим списка</div>
        {(
          [
            {
              id: "whitelist" as BrowserMode,
              title: "Белый список",
              desc: "Перечисленные сайты — через мост, всё остальное — напрямую с реальным IP. Безопасный вариант: забытый сайт просто не проксируется.",
            },
            {
              id: "blacklist" as BrowserMode,
              title: "Чёрный список",
              desc: "ВСЁ через мост, кроме перечисленного. Строгий вариант: новый незнакомый сайт по умолчанию уйдёт через прокси.",
            },
          ]
        ).map((m) => (
          <button
            key={m.id}
            type="button"
            onClick={() => setMode(m.id)}
            className={
              "rounded-lg border px-3.5 py-3 text-left transition-colors duration-150 " +
              (mode === m.id
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
      </motion.section>

      {/* ── Список сайтов ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="flex items-center gap-2">
          <span className="text-[14px] font-semibold text-vb-fg">Список сайтов</span>
          <InfoTip>
            По одному домену на строку. Поддомены учитываются автоматически:
            anthropic.com покроет и console.anthropic.com. Схему и путь писать
            не нужно — «https://a.b/c» превратится в «a.b».
          </InfoTip>
        </div>
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          spellCheck={false}
          rows={9}
          placeholder={"anthropic.com\nopenai.com\nchatgpt.com"}
          className="w-full resize-y rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2.5 font-mono text-[12.5px] leading-relaxed text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
        />
      </motion.section>

      {error && (
        <motion.div variants={fadeInUp} className="flex items-start gap-2 rounded-lg border border-vb-loss/30 bg-vb-loss/10 px-3.5 py-2.5 text-[12.5px] text-vb-loss">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" strokeWidth={1.9} />
          <span className="break-all">{error}</span>
        </motion.div>
      )}

      {/* ── Сохранение ── */}
      <motion.div variants={fadeInUp} className="flex items-center gap-3">
        <Button onClick={handleSave} disabled={busy || status === null}>
          {busy ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : savedFlash ? (
            <CheckCircle2 className="h-4 w-4" />
          ) : (
            <Save className="h-4 w-4" strokeWidth={1.9} />
          )}
          {savedFlash ? "Сохранено" : "Сохранить"}
        </Button>
        <span className="text-[11px] leading-tight text-vb-silver-faint">
          Изменения применяются к уже открытым браузерам за пару секунд.
        </span>
      </motion.div>

      {/* ── Предупреждение про WebRTC ── */}
      <motion.section variants={fadeInUp} className="rounded-lg border border-amber-400/25 bg-amber-400/[0.07] p-4 text-[12.5px] leading-relaxed text-vb-silver-dim">
        <div className="mb-1 flex items-center gap-2 font-semibold text-amber-300">
          <AlertTriangle className="h-4 w-4" strokeWidth={1.9} />
          Честное предупреждение: WebRTC
        </div>
        PAC-прокси перехватывает HTTP(S)-трафик страниц. Веб-камеры и звонки
        идут по протоколу WebRTC поверх UDP — он может сообщить сайту твой
        реальный IP в обход прокси. Для приватности в браузере включи блокировку
        WebRTC (расширение uBlock Origin: «Предотвратить установку WebRTC через
        не-прокси адреса») или отключи WebRTC совсем.
      </motion.section>
    </motion.div>
  );
}

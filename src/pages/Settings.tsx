import { useCallback, useEffect, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import { Download, Loader2, Power, RefreshCw } from "lucide-react";
import {
  disable as autostartDisable,
  enable as autostartEnable,
  isEnabled as autostartIsEnabled,
} from "@tauri-apps/plugin-autostart";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";
import { getVersion } from "@tauri-apps/api/app";
import { Button } from "../components/Button";
import { Toggle } from "../components/Toggle";
import { InfoTip } from "../components/InfoTip";
import { useStatus } from "../lib/status";
import { fadeInUp, staggerContainer } from "../lib/motion";

/** Интервал фоновой автопроверки обновлений: раз в сутки. */
const UPDATE_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000;
const LAST_UPDATE_CHECK_KEY = "astreya-gate-last-update-check";

type UpdatePhase = "idle" | "checking" | "latest" | "error";

/** Инлайн-разметка заметок: **жирный** → strong, остальное — как есть. */
function inlineMd(s: string): ReactNode[] {
  return s.split(/(\*\*[^*]+\*\*)/g).map((p, i) =>
    p.startsWith("**") && p.endsWith("**") && p.length > 4 ? (
      <strong key={i} className="font-semibold text-vb-silver">
        {p.slice(2, -2)}
      </strong>
    ) : (
      <span key={i}>{p}</span>
    ),
  );
}

/**
 * Заметки релиза: Markdown-лайт (абзацы, "- " буллеты, **жирный**).
 * Рисуем компактными списками вместо сырого текста с пустыми строками.
 */
function NotesText({ text }: { text: string }) {
  const lines = text.split(/\r?\n/);
  return (
    <div className="mt-1 flex flex-col gap-1 text-[12px] leading-relaxed text-vb-silver-dim">
      {lines.map((raw, i) => {
        const line = raw.trim();
        if (!line) return <div key={i} className="h-1.5" />;
        const bullet = /^[-•*]\s+/.test(line);
        const content = bullet ? line.replace(/^[-•*]\s+/, "") : line;
        return bullet ? (
          <div key={i} className="flex gap-2">
            <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-vb-emerald/70" />
            <span>{inlineMd(content)}</span>
          </div>
        ) : (
          <p key={i}>{inlineMd(content)}</p>
        );
      })}
    </div>
  );
}

/*
  Настройки: автозапуск GUI и версии. Прокси-пул и назначения живут в
  своём разделе «Прокси» (сайдбар) — здесь только системное.
*/
export function Settings() {
  const { health, task } = useStatus();

  const [autostart, setAutostart] = useState<boolean | null>(null);
  const [autostartBusy, setAutostartBusy] = useState(false);
  const [autostartError, setAutostartError] = useState<string | null>(null);
  const [appVersion, setAppVersion] = useState<string>("");
  const [updatePhase, setUpdatePhase] = useState<UpdatePhase>("idle");
  const [updateAvail, setUpdateAvail] = useState<Update | null>(null);
  const [updateMsg, setUpdateMsg] = useState<string | null>(null);
  const [dlBusy, setDlBusy] = useState(false);

  /** Ручная/фоновая проверка. null от check() = мы на последней версии. */
  const checkNow = useCallback(async () => {
    setUpdatePhase("checking");
    setUpdateMsg(null);
    try {
      const result = await check();
      if (result) {
        setUpdateAvail(result);
        setUpdatePhase("idle");
      } else {
        setUpdateAvail(null);
        setUpdatePhase("latest");
        localStorage.setItem(LAST_UPDATE_CHECK_KEY, String(Date.now()));
      }
    } catch (e) {
      // Нет сети / endpoint недоступен — мягкая ошибка, не ломает UI.
      setUpdatePhase("error");
      setUpdateMsg(String(e));
    }
  }, []);

  const load = useCallback(async () => {
    setAutostart(await autostartIsEnabled().catch(() => false));
    setAppVersion(await getVersion().catch(() => ""));
    // Фоновая автопроверка: не чаще раза в сутки.
    const last = Number(localStorage.getItem(LAST_UPDATE_CHECK_KEY) ?? 0);
    if (Date.now() - last > UPDATE_CHECK_INTERVAL_MS) {
      void checkNow().then(() => {
        // «Последняя версия» после автопроверки тихо сворачивается;
        // найденный апдейт остаётся висеть с кнопкой установки.
        setUpdatePhase((p) => (p === "latest" ? "idle" : p));
      });
    }
  }, [checkNow]);

  useEffect(() => {
    void load();
  }, [load]);

  const handleAutostartToggle = async () => {
    setAutostartBusy(true);
    setAutostartError(null);
    try {
      if (autostart) {
        await autostartDisable();
        setAutostart(false);
      } else {
        await autostartEnable();
        setAutostart(true);
      }
    } catch {
      setAutostartError(
        "Не получилось изменить автозапуск (нет прав в Windows). Можно вручную через Пуск → Автозагрузка.",
      );
    } finally {
      setAutostartBusy(false);
    }
  };

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[620px] flex-col px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          Настройки
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Автозапуск и сведения о приложении
        </p>
      </motion.header>

      {/* ── Автозапуск GUI ── */}
      <motion.section variants={fadeInUp} className="surface-card mt-5 p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-vb-surface-2 text-vb-silver-dim">
              <Power className="h-4 w-4" strokeWidth={1.9} />
            </div>
            <div className="flex min-w-0 items-center gap-2">
              <div className="text-[14px] font-semibold text-vb-fg">
                Запускать с Windows
              </div>
              <InfoTip>
                Astreya Gate стартует свёрнутым в трей при входе в Windows.
                Сам мост от этого не зависит — он автостартует отдельной
                задачей Планировщика и работает даже без открытого приложения.
              </InfoTip>
            </div>
          </div>
          {autostart === null ? (
            <Loader2 className="h-4 w-4 shrink-0 animate-spin text-vb-silver-dim" />
          ) : (
            <Toggle
              checked={autostart}
              onChange={handleAutostartToggle}
              disabled={autostartBusy}
              label="Автозапуск"
            />
          )}
        </div>
        {autostartError && (
          <p className="mt-3 pl-11 text-[12px] text-vb-warn">{autostartError}</p>
        )}
      </motion.section>

      {/* ── Обновления ── */}
      <motion.section variants={fadeInUp} className="surface-card mt-4 p-4">
        <div className="flex items-center justify-between gap-4">
          <div className="flex min-w-0 items-center gap-3">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-vb-surface-2 text-vb-silver-dim">
              <RefreshCw className="h-4 w-4" strokeWidth={1.9} />
            </div>
            <div className="flex min-w-0 items-center gap-2">
              <span className="text-[14px] font-semibold text-vb-fg">Обновления</span>
              <InfoTip>
                Приложение само проверяет новые версии раз в сутки (тихо).
                Проверка идёт на GitHub Releases, пакет подписан — неподписанный
                файл установить невозможно. Установка: скачивание → проверка
                подписи → перезапуск приложения. Мост при этом продолжает
                работать.
              </InfoTip>
            </div>
          </div>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => void checkNow()}
            disabled={updatePhase === "checking" || dlBusy}
          >
            {updatePhase === "checking" ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              "Проверить"
            )}
          </Button>
        </div>

        {updateAvail && (
          <div className="mt-3 rounded-lg border border-vb-emerald/30 bg-vb-emerald/[0.06] p-3">
            <div className="text-[13px] font-medium text-vb-fg">
              Доступна версия {updateAvail.version}
            </div>
            {updateAvail.body && <NotesText text={updateAvail.body} />}
            <Button
              size="sm"
              className="mt-2.5"
              disabled={dlBusy}
              onClick={async () => {
                setDlBusy(true);
                try {
                  await updateAvail.downloadAndInstall();
                  // Апдейт применён установщиком — перезапускаемся.
                  await relaunch();
                } catch (e) {
                  setUpdatePhase("error");
                  setUpdateMsg(String(e));
                  setDlBusy(false);
                }
              }}
            >
              {dlBusy ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Скачиваю…
                </>
              ) : (
                <>
                  <Download className="h-3.5 w-3.5" /> Установить и перезапустить
                </>
              )}
            </Button>
          </div>
        )}
        {updatePhase === "latest" && (
          <p className="mt-3 text-[12px] text-vb-emerald">
            У вас последняя версия ({appVersion || "текущая"}).
          </p>
        )}
        {updatePhase === "error" && updateMsg && (
          <p className="mt-3 break-all text-[12px] text-vb-warn">
            Не удалось проверить обновления: {updateMsg}
          </p>
        )}
      </motion.section>

      {/* ── О приложении ── */}
      <motion.section variants={fadeInUp} className="surface-card mt-4 divide-y divide-vb-border/70">
        <div className="flex items-center justify-between px-4 py-3">
          <span className="text-[13px] text-vb-silver-dim">Astreya Gate</span>
          <span className="font-mono text-[12px] text-vb-silver">
            {appVersion ? `v${appVersion}` : "—"}
          </span>
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <span className="text-[13px] text-vb-silver-dim">Мост (gate-bridge)</span>
          <span className="font-mono text-[12px] text-vb-silver">
            {health ? `v${health.version}` : "—"}
          </span>
        </div>
        <div className="flex items-center justify-between px-4 py-3">
          <span className="text-[13px] text-vb-silver-dim">Автозапуск моста</span>
          <span className="font-mono text-[12px] text-vb-silver">
            {task === null ? "—" : task.registered ? "Планировщик задач" : "легаси (.vbs)"}
          </span>
        </div>
      </motion.section>
    </motion.div>
  );
}

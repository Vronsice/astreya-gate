import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { Titlebar } from "./components/Titlebar";
import { Sidebar, NAV_ORDER } from "./components/Sidebar";
import { WizardShell } from "./components/WizardShell";
import { StepProxy } from "./wizard/StepProxy";
import { StepInstall } from "./wizard/StepInstall";
import { StepDone } from "./wizard/StepDone";
import { RouteMapPage } from "./pages/RouteMap";
import { Home } from "./pages/Home";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { Nodes } from "./pages/Nodes";
import { Rules } from "./pages/Rules";
import { Bridge } from "./pages/Bridge";
import { Browsers } from "./pages/Browsers";
import { Guide } from "./pages/Guide";
import { Settings } from "./pages/Settings";
import { TrayPopup } from "./pages/TrayPopup";
import { StatusProvider } from "./lib/status";
import { settingsGet, shimScriptPath, shimStatus } from "./lib/api";
import type { AppView, WizardInstallResult, WizardStep } from "./lib/types";

/** Окно трей-попапа рендерит тот же bundle с ?view=tray. */
const IS_TRAY = new URLSearchParams(window.location.search).get("view") === "tray";

/*
  Direction-aware переход между разделами: контент уезжает в сторону,
  противоположную движению по навигации. Тайминги короткие (exit 100ms +
  enter 160ms): mode="wait" играет их ПОСЛЕДОВАТЕЛЬНО, длинные тайминги
  ощущались как «долго листается».
*/
const viewVariants = {
  enter: (dir: number) => ({ opacity: 0, y: 14 * dir }),
  center: {
    opacity: 1,
    y: 0,
    transition: { duration: 0.16, ease: [0.22, 1, 0.36, 1] as const },
  },
  exit: (dir: number) => ({
    opacity: 0,
    y: -10 * dir,
    transition: { duration: 0.1, ease: [0.22, 1, 0.36, 1] as const },
  }),
};

function App() {
  // ─── Top-level routing ───────────────────────────────────────
  // На старте определяем: установлен ли уже мост → Обзор, иначе Wizard.
  const [view, setView] = useState<AppView | null>(IS_TRAY ? "home" : null);
  const prevIndex = useRef(0);
  const [direction, setDirection] = useState(1);

  useEffect(() => {
    if (IS_TRAY) return;
    void (async () => {
      try {
        // 3 признака что мост уже установлен (хватит любого):
        //   1) есть proxy_url в settings.json
        //   2) на диске лежит установленный мост
        //   3) мост-процесс прямо сейчас запущен
        const [s, scriptPath, status] = await Promise.all([
          settingsGet().catch(() => null),
          shimScriptPath().catch(() => null),
          shimStatus().catch(() => null),
        ]);
        const installed = !!s?.proxy_url || !!scriptPath || !!status?.running;
        setView(installed ? "home" : "wizard");
      } catch {
        setView("wizard");
      }
    })();
  }, []);

  const navigate = (next: AppView) => {
    const nextIdx = NAV_ORDER.indexOf(next);
    const prevIdx = prevIndex.current;
    setDirection(nextIdx >= prevIdx ? 1 : -1);
    prevIndex.current = nextIdx;
    setView(next);
  };

  // ─── Wizard state: 3 шага (прокси → установка → готово) ──────
  const [step, setStep] = useState<WizardStep>("proxy");
  const [wizProxyUrl, setWizProxyUrl] = useState<string | null>(null);
  const [wizResult, setWizResult] = useState<WizardInstallResult | null>(null);

  // ─── Трей-попап: отдельная вьюха в прозрачном окне ───────────
  if (IS_TRAY) {
    return (
      <StatusProvider>
        <TrayPopup />
      </StatusProvider>
    );
  }

  // ─── Wizard (первый запуск): 3 шага, без легаси-режимов ──────
  // StatusProvider и здесь: логотип в сайдбаре показывает живой статус.
  if (view === "wizard") {
    return (
      <StatusProvider>
        <div className="flex h-screen w-screen flex-col overflow-hidden">
          <Titlebar />
          <div className="min-h-0 flex-1">
            <WizardShell step={step}>
              {step === "proxy" && (
                <StepProxy
                  initialUrl={wizProxyUrl}
                  onNext={(url) => {
                    setWizProxyUrl(url);
                    setStep("install");
                  }}
                />
              )}
              {step === "install" && wizProxyUrl && (
                <StepInstall
                  proxyUrl={wizProxyUrl}
                  onBack={() => setStep("proxy")}
                  onDone={(r) => {
                    setWizResult(r);
                    setStep("done");
                  }}
                />
              )}
              {step === "done" && wizResult && (
                <StepDone result={wizResult} onFinish={() => setView("home")} />
              )}
            </WizardShell>
          </div>
        </div>
      </StatusProvider>
    );
  }

  // ─── App shell: titlebar + sidebar + контент ─────────────────
  return (
    <StatusProvider>
      <div className="flex h-screen w-screen flex-col overflow-hidden">
        <Titlebar />
        <div className="flex min-h-0 flex-1">
          {view !== null && <Sidebar view={view} onNavigate={navigate} />}
          <main className="min-h-0 flex-1 overflow-y-auto">
            <ErrorBoundary>
            <AnimatePresence mode="wait" custom={direction}>
              <motion.div
                key={view ?? "loading"}
                custom={direction}
                variants={viewVariants}
                initial="enter"
                animate="center"
                exit="exit"
                /* Карте (React Flow) нужна точная высота родителя: min-h-full
                   даёт height:auto, и канва схлопывается в ноль. */
                className={view === "map" ? "h-full" : "min-h-full"}
              >
                {view === "home" ? (
                  <Home onNavigate={navigate} />
                ) : view === "map" ? (
                  <RouteMapPage onNavigate={navigate} />
                ) : view === "nodes" ? (
                  <Nodes />
                ) : view === "rules" ? (
                  <Rules />
                ) : view === "bridge" ? (
                  <Bridge />
                ) : view === "browsers" ? (
                  <Browsers />
                ) : view === "guide" ? (
                  <Guide />
                ) : view === "settings" ? (
                  <Settings />
                ) : (
                  <div className="h-full w-full" />
                )}
              </motion.div>
            </AnimatePresence>
            </ErrorBoundary>
          </main>
        </div>
      </div>
    </StatusProvider>
  );
}

export default App;

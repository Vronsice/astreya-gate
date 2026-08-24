import { useState } from "react";
import { motion } from "framer-motion";
import { Blocks } from "lucide-react";
import { Proxies } from "./Proxies";
import { Apps } from "./Apps";
import { InfoTip } from "../components/InfoTip";
import { fadeInUp, staggerContainer } from "../lib/motion";
import { cn } from "../lib/cn";

/*
  AI-мост: легаси-диспетчер для AI-сервисов (прокси-пул, цепочки,
  назначения по сервисам). Управление VPN — на Карте; этот раздел
  про то, какой upstream используют консольные AI-инструменты.
*/

type Tab = "proxies" | "apps";

export function Bridge() {
  const [tab, setTab] = useState<Tab>("proxies");

  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[680px] flex-col gap-5 px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="flex items-center gap-2.5 text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          <Blocks className="h-6 w-6 text-vb-emerald" strokeWidth={1.9} />
          AI-мост
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Прокси-пул и назначения для AI-сервисов (Claude, OpenAI, …) · порт 127.0.0.1:2080
        </p>
      </motion.header>

      <motion.div variants={fadeInUp} className="flex gap-1.5">
        {(
          [
            ["proxies", "Прокси"],
            ["apps", "Приложения"],
          ] as const
        ).map(([k, label]) => (
          <button
            key={k}
            type="button"
            onClick={() => setTab(k)}
            className={cn(
              "rounded-lg border px-4 py-1.5 text-[13px] font-medium transition-colors",
              tab === k
                ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
                : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
            )}
          >
            {label}
          </button>
        ))}
        <div className="flex-1" />
        <InfoTip>
          Пул здесь — upstream'ы для AI-инструментов (платные прокси поверх VPN
          собираются в цепочки автоматически). Общий VPN-туннель управляется на
          Карте; его ноды настраиваются в разделе «Ноды».
        </InfoTip>
      </motion.div>

      {tab === "proxies" ? <Proxies /> : <Apps />}
    </motion.div>
  );
}

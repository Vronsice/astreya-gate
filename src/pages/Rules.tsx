import { useCallback, useEffect, useState } from "react";
import { motion } from "framer-motion";
import { ListChecks, Loader2, Plus, Trash2 } from "lucide-react";
import { InfoTip } from "../components/InfoTip";
import { vpnOverview, vpnRuleRemove, vpnRuleSave, vpnRulesGet } from "../lib/api";
import type { RoutingRule } from "../lib/types";
import { fadeInUp, staggerContainer } from "../lib/motion";
import { cn } from "../lib/cn";

/*
  Правила маршрутизации: процесс/домен → выход. Сохраняются в профиль
  и компилируются в конфиг движка; изменение перезапускает туннель.
*/

type MatchKind = "process_name" | "domain_suffix" | "domain_keyword";

const MATCH_LABEL: Record<MatchKind, { title: string; hint: string; placeholder: string }> = {
  process_name: {
    title: "Приложение",
    hint: "Имя процесса Windows. Надёжнее всего работает в системном режиме (TUN).",
    placeholder: "telegram.exe",
  },
  domain_suffix: {
    title: "Домены",
    hint: "Домен и все поддомены. По одному в строке или через запятую.",
    placeholder: "openai.com, chatgpt.com",
  },
  domain_keyword: {
    title: "Ключевые слова",
    hint: "Подстрока в домене. Например: ads — заблокирует adservice.google.com.",
    placeholder: "ads, tracking",
  },
};

function exitLabel(exit: RoutingRule["exit"], nodeNames: Map<string, string>): string {
  switch (exit.type) {
    case "direct":
      return "напрямую";
    case "pool":
      return "прокси-пул";
    case "selector":
      return "активная нода";
    case "reject":
      return "блокировка";
    case "node":
      return nodeNames.get(exit.id) ?? `нода ${exit.id.slice(0, 8)}`;
  }
}

export function Rules() {
  const [rules, setRules] = useState<RoutingRule[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [kind, setKind] = useState<MatchKind>("process_name");
  const [values, setValues] = useState("");
  const [exitKind, setExitKind] = useState<"selector" | "direct" | "node" | "pool" | "reject">("selector");
  const [nodeId, setNodeId] = useState<string>("");
  const [ov, setOv] = useState<{ nodes: { id: string; name: string }[]; pool_count: number }>({
    nodes: [],
    pool_count: 0,
  });

  const load = useCallback(async () => {
    try {
      setRules(await vpnRulesGet());
    } catch (e) {
      setError(String(e));
    }
    try {
      const o = await vpnOverview();
      setOv({ nodes: o.nodes.map((n) => ({ id: n.id, name: n.name })), pool_count: 0 });
    } catch {
      /* переживаем */
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const nodeNames = new Map(ov.nodes.map((n) => [n.id, n.name]));

  const save = async (rule: RoutingRule) => {
    setBusy(true);
    setError(null);
    try {
      setRules(await vpnRuleSave(rule));
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const exitOptions: { id: typeof exitKind; label: string }[] = [
    { id: "selector", label: "Активная нода" },
    { id: "direct", label: "Напрямую" },
    ...(ov.nodes.length > 0 ? [{ id: "node" as const, label: "Нода…" }] : []),
    { id: "pool", label: "Пул" },
    { id: "reject", label: "Блок" },
  ];

  const submit = () => {
    const list = values
      .split(/[\n,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    if (list.length === 0) return;
    if (exitKind === "node" && !nodeId) return;
    const exit: RoutingRule["exit"] =
      exitKind === "reject"
        ? { type: "reject" }
        : exitKind === "node"
          ? { type: "node", id: nodeId }
          : ({ type: exitKind } as RoutingRule["exit"]);
    if (kind === "process_name") {
      for (const p of list) {
        void save({
          name: `app-${p.toLowerCase()}`,
          match: { match: "process_name", list: [p] },
          exit,
        });
      }
    } else {
      void save({
        name: `${kind}-${Date.now().toString(36)}`,
        match: { match: kind, list },
        exit,
      });
    }
    setValues("");
  };

  const remove = async (name: string) => {
    setBusy(true);
    setError(null);
    try {
      setRules(await vpnRuleRemove(name));
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
      className="mx-auto flex w-full max-w-[680px] flex-col gap-5 px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          Правила
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Куда ходит трафик: приложение или домен → выход. Применяются в порядке следования.
        </p>
      </motion.header>

      {/* ── Добавить правило ── */}
      <motion.section variants={fadeInUp} className="surface-card flex flex-col gap-3 p-4">
        <div className="flex items-center gap-2">
          <h2 className="text-[15px] font-semibold text-vb-fg">Новое правило</h2>
          <InfoTip>
            Правила компилируются в конфиг движка поверх режимов маршрутизации.
            Изменение правила перезапускает туннель автоматически (1–2 сек).
          </InfoTip>
        </div>

        <div className="flex gap-1.5">
          {(Object.keys(MATCH_LABEL) as MatchKind[]).map((k) => (
            <button
              key={k}
              type="button"
              onClick={() => setKind(k)}
              className={cn(
                "flex-1 rounded-lg border px-2 py-1.5 text-[12px] font-medium transition-colors",
                kind === k
                  ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
                  : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
              )}
            >
              {MATCH_LABEL[k].title}
            </button>
          ))}
        </div>
        <p className="text-[11.5px] leading-relaxed text-vb-silver-faint">{MATCH_LABEL[kind].hint}</p>

        <textarea
          value={values}
          onChange={(e) => setValues(e.target.value)}
          rows={kind === "process_name" ? 2 : 3}
          spellCheck={false}
          placeholder={MATCH_LABEL[kind].placeholder}
          className="w-full resize-y rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2.5 font-mono text-[12.5px] text-vb-fg outline-none placeholder:text-vb-silver-faint focus:border-vb-border-strong"
        />

        <div className="flex items-center gap-2 text-[12.5px] text-vb-silver">
          <span className="shrink-0">→</span>
          <div className="flex flex-1 gap-1.5">
            {exitOptions.map((o) => (
              <button
                key={o.id}
                type="button"
                onClick={() => setExitKind(o.id)}
                disabled={busy}
                className={cn(
                  "flex-1 rounded-lg border px-2 py-1.5 text-[11.5px] font-medium transition-colors disabled:opacity-40",
                  exitKind === o.id
                    ? "border-vb-emerald/50 bg-vb-emerald/[0.08] text-vb-emerald"
                    : "border-vb-border bg-vb-surface text-vb-silver-dim hover:text-vb-silver",
                )}
              >
                {o.label}
              </button>
            ))}
          </div>
        </div>

        {exitKind === "node" && (
          <select
            value={nodeId}
            onChange={(e) => setNodeId(e.target.value)}
            className="rounded-lg border border-vb-border bg-vb-surface-2 px-3 py-2 text-[12.5px] text-vb-fg outline-none focus:border-vb-border-strong"
          >
            <option value="">— выбери ноду —</option>
            {ov.nodes.map((n) => (
              <option key={n.id} value={n.id}>
                {n.name}
              </option>
            ))}
          </select>
        )}

        <button
          type="button"
          onClick={submit}
          disabled={busy || !values.trim() || (exitKind === "node" && !nodeId)}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-vb-emerald px-3 py-2 text-[13px] font-semibold text-black transition-colors hover:bg-vb-emerald-bright disabled:opacity-40"
        >
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Добавить правило
        </button>
      </motion.section>

      {error && (
        <motion.div variants={fadeInUp} className="rounded-lg border border-vb-loss/30 bg-vb-loss/10 px-3.5 py-2.5 text-[12.5px] text-vb-loss">
          {error}
        </motion.div>
      )}

      {/* ── Список правил ── */}
      <motion.section variants={fadeInUp} className="surface-card divide-y divide-vb-border/70">
        <div className="flex items-center gap-2 px-4 pb-2 pt-3">
          <ListChecks className="h-4 w-4 text-vb-emerald" />
          <h2 className="text-[15px] font-semibold text-vb-fg">
            Действующие правила ({rules?.length ?? 0})
          </h2>
        </div>
        {rules !== null && rules.length === 0 && (
          <p className="px-4 pb-4 text-[12.5px] text-vb-silver-dim">
            Правил нет — весь трафик туннеля идёт по режиму маршрутизации с Карты.
          </p>
        )}
        {(rules ?? []).map((r) => (
          <div key={r.name ?? JSON.stringify(r)} className="flex items-center gap-3 px-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="truncate text-[13px] text-vb-fg">{matchText(r)}</div>
              <div className="truncate text-[11px] text-vb-silver-faint">
                {exitLabel(r.exit, nodeNames)}
                {r.name?.startsWith("app-") ? " · приложение" : ""}
              </div>
            </div>
            <button
              type="button"
              onClick={() => r.name && void remove(r.name)}
              disabled={busy || !r.name}
              className="shrink-0 rounded-lg p-1.5 text-vb-silver-faint transition-colors hover:bg-vb-loss/10 hover:text-vb-loss disabled:opacity-35"
              title="Удалить правило"
            >
              {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
            </button>
          </div>
        ))}
      </motion.section>
    </motion.div>
  );
}

function matchText(r: RoutingRule): string {
  switch (r.match.match) {
    case "process_name":
      return `${r.match.list.join(", ")} (процесс)`;
    case "domain_suffix":
      return `${r.match.list.join(", ")} (домены)`;
    case "domain_keyword":
      return `${r.match.list.join(", ")} (ключевые слова)`;
    default:
      return "весь трафик";
  }
}

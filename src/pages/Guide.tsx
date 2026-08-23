import { motion } from "framer-motion";
import {
  AlertTriangle,
  ArrowDown,
  BookOpen,
  Globe,
  Layers,
  Lock,
  ShieldCheck,
} from "lucide-react";
import { InfoTip } from "../components/InfoTip";
import { fadeInUp, staggerContainer } from "../lib/motion";

/*
  Гид: подробные объяснения модели работы и рецептов настройки.
  Это не справка «для галочки» — здесь живёт вся ментальная модель системы:
  три слоя защиты, кто через что ходит и как проверить, что ничего не течёт.
*/

function Section({
  title,
  icon: Icon,
  children,
}: {
  title: string;
  icon: typeof Layers;
  children: React.ReactNode;
}) {
  return (
    <motion.section variants={fadeInUp} className="surface-card p-5">
      <h2 className="flex items-center gap-2.5 text-[16px] font-bold text-vb-fg">
        <Icon className="h-[18px] w-[18px] text-vb-emerald" strokeWidth={1.9} />
        {title}
      </h2>
      <div className="mt-3 flex flex-col gap-2.5 text-[13px] leading-relaxed text-vb-silver-dim">
        {children}
      </div>
    </motion.section>
  );
}

function Recipe({
  what,
  how,
}: {
  what: string;
  how: string[];
}) {
  return (
    <div className="rounded-lg border border-vb-border/70 bg-vb-surface-2/40 p-3.5">
      <div className="text-[13px] font-semibold text-vb-fg">{what}</div>
      <ol className="mt-1.5 flex flex-col gap-1 pl-4 [list-style:decimal] marker:text-vb-silver-faint">
        {how.map((step, i) => (
          <li key={i} className="text-[12.5px] leading-relaxed">
            {step}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function Guide() {
  return (
    <motion.div
      variants={staggerContainer}
      initial="hidden"
      animate="show"
      className="mx-auto flex w-full max-w-[680px] flex-col gap-5 px-8 py-7"
    >
      <motion.header variants={fadeInUp}>
        <h1 className="flex items-center gap-2.5 text-[24px] font-bold leading-tight tracking-[-0.02em] text-vb-fg">
          <BookOpen className="h-6 w-6 text-vb-emerald" strokeWidth={1.9} />
          Как всё работает
        </h1>
        <p className="mt-0.5 text-[13px] text-vb-silver-dim">
          Ментальная модель системы: три слоя защиты и рецепты настройки
        </p>
      </motion.header>

      {/* ── Большая картина ── */}
      <Section title="Большая картина" icon={Layers}>
        <p>
          Все приложения на компьютере делятся по тому, <b className="text-vb-silver">куда</b> они
          ходят в интернет. Наша задача — чтобы трафик AI-сервисов уходил через
          купленный прокси (иначе Anthropic/OpenAI видят твой настоящий IP или
          блокируют регион), а остальной трафик жил своей жизнью — через
          локальный VPN-прокси или напрямую.
        </p>
        <pre className="overflow-x-auto rounded-lg border border-vb-border bg-black/30 p-3.5 font-mono text-[11px] leading-relaxed text-vb-silver">{` Claude Code ──┐
 ChatGPT ──────┤    ┌──────────────────┐   anthropic.com → платный прокси
 opencode ─────┼──▶ │ мост 127.0.0.1:8889 │── openai.com   → платный прокси
 Браузер ──────┘    └──────────────────┘── openrouter.ai → дефолтный прокси
                          │  (решает по домену)── telegram.org → дефолтный
                     сайты вне списка → браузер идёт напрямую`}</pre>
        <p>
          Ключевая идея: приложениям достаточно уметь ходить в
          <code className="mx-1 text-vb-emerald">127.0.0.1:8889</code>— а мост уже
          решает, какой upstream использовать для каждого домена. Менять
          прокси, добавлять резервные, закреплять сервисы — всё в одном месте,
          без перенастройки каждого приложения.
        </p>
      </Section>

      {/* ── Три слоя защиты ── */}
      <Section title="Три слоя защиты от утечки IP" icon={ShieldCheck}>
        <div className="rounded-lg border border-vb-border/70 p-3.5">
          <div className="text-[13px] font-semibold text-vb-fg">
            Слой 1 — переменные окружения (HTTP_PROXY / HTTPS_PROXY)
          </div>
          <p className="mt-1">
            Прописываются глобально (User scope) и указывают на мост. Любой
            новый процесс наследует их автоматически: терминалы VS Code,
            claude CLI, git, npm. Это «вежливая просьба»: curl и git её
            слушаются, но некоторые программы (браузеры, часть Electron-приложений,
            node-fetch в отдельных версиях) игнорируют.
          </p>
        </div>
        <div className="rounded-lg border border-vb-border/70 p-3.5">
          <div className="text-[13px] font-semibold text-vb-fg">
            Слой 2 — мост с инжектом авторизации
          </div>
          <p className="mt-1">
            Мост принимает соединения на 127.0.0.1:8889 без логина-пароля и сам
            подписывает запросы перед отправкой в купленный прокси. Плюс
            маршрутизирует по доменам: закреплённый сервис (например,
            anthropic.com) ходит строго через свой прокси — выходной IP не
            «прыгает», за что AI-сервисы банят аккаунты.
          </p>
        </div>
        <div className="rounded-lg border border-vb-loss/25 bg-vb-loss/[0.04] p-3.5">
          <div className="text-[13px] font-semibold text-vb-loss">
            Слой 3 — Killswitch (файрвол) — единственная жёсткая гарантия
          </div>
          <p className="mt-1">
            Windows Firewall физически запрещает выбранным процессам любой
            исходящий трафик, кроме loopback. Даже если приложение игнорирует
            прокси или мост упал — наружу оно выйти НЕ сможет, реальный IP не
            уйдёт никогда. Loopback (127.0.0.1) файрвол не фильтрует, поэтому
            доступ к мосту сохраняется. Включается в разделе «Обзор» →
            Killswitch; нужен один клик UAC.
          </p>
        </div>
        <p>
          <b className="text-vb-silver">Правило:</b> env — удобство, мост —
          интеллект, файрвол — гарантия. Для «ни при каких условиях не спалить
          IP» держи killswitch включённым для AI-приложений.
        </p>
      </Section>

      {/* ── Рецепты ── */}
      <Section title="Рецепты настройки" icon={Globe}>
        <Recipe
          what="Claude Code (терминал и VS Code) — через платный прокси"
          how={[
            "«Прокси» → добавь платный прокси первым в пуле (формат ip:port:user:pass понимается автоматически).",
            "«Прокси» → назначение «Anthropic» → этот прокси. Закрепление строгое: IP не меняется даже при сбоях.",
            "«Обзор» → включи тумблер «Системное проксирование» — глобальные env встанут на мост.",
            "Перезапусти VS Code (env читается при старте процесса) — готово.",
          ]}
        />
        <Recipe
          what="opencode, git, npm и весь прочий CLI — через системный VPN-прокси"
          how={[
            "«Прокси» → добавь второй записью свой локальный прокси (например http://127.0.0.1:2080).",
            "«Прокси» → «Прокси по умолчанию» → выбери этот локальный. Всё, что не закреплено явно, пойдёт через него.",
            "Проверь: «Обзор» → тест показывает внешний IP — он должен совпадать с IP VPN, а не платного прокси.",
          ]}
        />
        <Recipe
          what="ChatGPT Desktop и Codex"
          how={[
            "Раздел «Приложения» → включи профиль ChatGPT Codex — запускай его кнопкой или ярлыком «(proxy)»: он стартует с --proxy-server на мост.",
            "Внутри VS Code Codex наследует глобальные env из слоя 1 — отдельная настройка не нужна.",
            "Для жёсткой гарантии включи на нём killswitch (Обзор).",
          ]}
        />
        <Recipe
          what="Telegram / AyuGram"
          how={[
            "Настройки приложения → «Данные и память» → «Прокси» → добавить HTTP-прокси.",
            "Адрес: 127.0.0.1, порт 8889, без логина и пароля.",
            "Дальше работает доменная маршрутизация: telegram.org уедет в дефолтный прокси (или закрепи группу «Telegram» отдельно).",
          ]}
        />
        <Recipe
          what="Браузеры: конкретные сайты через прокси"
          how={[
            "Раздел «Браузеры» → режим «Белый список».",
            "Добавь сайты (anthropic.com, chatgpt.com…) и включи системную интеграцию.",
            "Сайты из списка идут в мост (и дальше по правилам «Прокси»), остальные — напрямую с реальным IP.",
          ]}
        />
      </Section>

      {/* ── Чек-лист приватности ── */}
      <Section title="Чек-лист «не спалиться»" icon={Lock}>
        <ul className="flex flex-col gap-1.5 [list-style:disc] pl-4 marker:text-vb-emerald">
          <li>
            После каждой смены пула жми «Проверить» в Обзоре: показанный IP —
            это то, что увидит сайт. Должен быть IP прокси, не твой.
          </li>
          <li>
            Killswitch включён для всех приложений, которые работают с
            AI-аккаунтами. Он же спасает при падении моста: без него упавший
            мост = трафик молча пойдёт напрямую.
          </li>
          <li>
            Не закрепляй один и тот же AI-аккаунт за разными прокси «на
            пробу» — скачки выходного IP между странами триггерят антифрод
            Anthropic/OpenAI. Закрепил — оставь.
          </li>
          <li>
            Браузеры: помни про WebRTC (см. раздел «Браузеры») — он умеет
            обходить прокси поверх UDP. Блокируй расширением.
          </li>
          <li>
            DNS: HTTPS через CONNECT резолвит имя удалённый прокси — твоего
            DNS-запроса наружу нет. Прямые сайты (белый список PAC) резолвятся
            локально — так и задумано.
          </li>
        </ul>
      </Section>

      {/* ── Надёжность ── */}
      <Section title="Что делает систему надёжной" icon={AlertTriangle}>
        <ul className="flex flex-col gap-1.5 [list-style:disc] pl-4 marker:text-vb-silver-faint">
          <li>
            Мост перезапускается сам: супервизор внутри exe + задача Планировщика
            с рестартом + watchdog в GUI. Три эшелона — упавший мост оживает за
            ~5 секунд.
          </li>
          <li>
            Passive failover: если в пуле несколько прокси, отвалившийся
            исключается на 30 секунд, трафик уходит на живой. Но закреплённые
            сервисы (anthropic.com и т.п.) НИКОГДА не переезжают на чужой IP —
            лучше ошибка, чем смена IP.
          </li>
          <li>
            Правила (rules.json) пишутся атомарно; битый файл = отказ запуска
            моста, а не тихая потеря закреплений.
          </li>
          <li>
            Все настройки хранятся в %APPDATA%\Astreya Gate\settings.json;
            чужие env-переменные и настройки системного прокси снимаются
            «снимком» и возвращаются при выключении.
          </li>
        </ul>
        <p className="flex items-center gap-1.5 pt-1 text-[12px] text-vb-silver-faint">
          <ArrowDown className="h-3.5 w-3.5" strokeWidth={1.9} />
          Вопросы по конкретному экрану — иконки «?» рядом с настройками.
          <InfoTip>Эта подсказка тоже часть гида. Да, рекурсия.</InfoTip>
        </p>
      </Section>
    </motion.div>
  );
}

/*
  Имена нод из подписок — маркетинговый шум: «🇫🇮 Финляндия · 🎮 Игры и торренты»,
  «❗ Срок: 27.09.20», «📰 Новости: t.me/…». Для интерфейса нужно чистое:
  страна/город + флаг. Здесь единая нормализация для всех экранов.
*/

/** Флаг из имени («ch Швейцария» → 🇨🇭) или из emoji-флага в самом имени. */
export function flagOf(name: string): string {
  const flagEmoji = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u);
  if (flagEmoji) return flagEmoji[0];
  const m = name.match(/^([a-z]{2})\b/i);
  if (!m) return "🌐";
  return m[1].toUpperCase().replace(/./g, (c) => String.fromCodePoint(127397 + c.charCodeAt(0)));
}

/** Убрать emoji/декор в начале и хвосте строки. */
function stripDecor(s: string): string {
  return s
    .replace(/^[\s\p{Extended_Pictographic}\u200d\uFE0F*·•\-—–|]+/u, "")
    .replace(/[\s\p{Extended_Pictographic}\u200d\uFE0F*·•|]+$/u, "")
    .trim();
}

/** Чистое имя ноды для интерфейса: без флагов, дат, «торрентов» и t.me. */
export function cleanNodeName(name: string): string {
  let s = name.trim();
  // Убрать префикс страны («fi », «ch Швейцария» оставит «Швейцария»).
  s = s.replace(/^[a-z]{2}\s+/i, (m, off: number) => (off === 0 ? "" : m));
  // Разбить по разделителям провайдеров.
  const parts = s.split(/\s*[·|—–]\s*|\s{2,}/).map(stripDecor).filter(Boolean);
  // Выбрать первую осмысленную часть: без цифр-дат и ссылок.
  const good = parts.find(
    (p) =>
      p.length >= 3 &&
      !/\d{1,2}[./]\d{1,2}/.test(p) &&
      !/t\.me|http|срок|до \d/i.test(p),
  );
  s = good ?? parts[0] ?? name;
  // Хвост «(что-то)» и мусорные суффиксы.
  s = s.replace(/\s*\(.*?\)\s*$/, "").trim();
  if (s.length > 28) s = `${s.slice(0, 27).trim()}…`;
  return s || name;
}

/** {flag, label} одним вызовом. */
export function nodeDisplay(name: string): { flag: string; label: string } {
  return { flag: flagOf(name), label: cleanNodeName(name) };
}

/** Человекочитаемые байты: 0 Б / 12 КБ / 340 МБ / 1.5 ГБ. */
export function formatBytes(n: number | null | undefined): string {
  if (n == null || !isFinite(n)) return "—";
  if (n < 1024) return `${Math.round(n)} Б`;
  const units = ["КБ", "МБ", "ГБ", "ТБ"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 100 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

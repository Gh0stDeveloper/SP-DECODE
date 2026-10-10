export const locales = ["es", "en", "pt-BR", "ar"] as const;
export type Locale = (typeof locales)[number];

export const languageNames: Record<Locale, string> = {
  es: "Español",
  en: "English",
  "pt-BR": "Português",
  ar: "العربية",
};

export function isLocale(value: string): value is Locale {
  return locales.some((locale) => locale === value);
}
export function localePath(locale: Locale, segment = ""): string {
  return `/${locale}${segment ? `/${segment.replace(/^[/]+/, "")}` : ""}`;
}
export function localeDirection(locale: Locale): "ltr" | "rtl" {
  return locale === "ar" ? "rtl" : "ltr";
}
export const siteUrl = (process.env.NEXT_PUBLIC_SITE_URL || "https://sp-decode.vercel.app").replace(/\/$/, "");
export const links = {
  github: "https://github.com/Gh0stDeveloper/SP-DECODE",
  issues: "https://github.com/Gh0stDeveloper/SP-DECODE/issues",
  stable: "https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.4",
  preview: "https://github.com/Gh0stDeveloper/SP-DECODE/releases/tag/v1.0.5-rc.1",
  releases: "https://github.com/Gh0stDeveloper/SP-DECODE/releases",
  developer: "https://github.com/Gh0stDeveloper",
  dm: "https://t.me/Gh0stDeveloper",
  channel: "https://t.me/GhostDeve",
  community: "https://t.me/CodeBreakersHub",
  docs: "https://github.com/Gh0stDeveloper/SP-DECODE/tree/main/docs/android",
  parity: "https://github.com/Gh0stDeveloper/SP-DECODE/blob/main/docs/android/REAL_DECODER_PARITY_TRIAGE.md",
  license: "https://github.com/Gh0stDeveloper/SP-DECODE",
} as const;

"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Globe2 } from "lucide-react";
import { languageNames, locales, localeDirection, type Locale } from "@/lib/i18n";
const codes:Record<Locale,string>={es:"ES",en:"EN","pt-BR":"PT",ar:"AR"};
export function LocaleSwitcher({locale}:{locale:Locale}){
 const pathname=usePathname()||"/es"; const parts=pathname.split("/").filter(Boolean);const suffix=parts.slice(1).join("/");
 return <details className="language-picker"><summary aria-label="Choose language"><Globe2 size={17}/><span>{codes[locale]}</span></summary>
 <div className="lang-options">{locales.map(target=><Link key={target} href={`/${target}${suffix?"/"+suffix:""}`} hrefLang={target} className={target===locale?"is-active":""} dir={localeDirection(target)}>{languageNames[target]}</Link>)}</div>
 </details>;
}

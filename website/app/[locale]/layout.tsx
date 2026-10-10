import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { locales, isLocale, localeDirection, localePath } from "@/lib/i18n";
import { SiteShell } from "@/components/SiteShell";
import { copy } from "@/lib/content";
export function generateStaticParams(){return locales.map((locale)=>({locale}));}
export async function generateMetadata({params}:{params:Promise<{locale:string}>}):Promise<Metadata>{
 const {locale}=await params;
 if(!isLocale(locale))return {};
 const t=copy[locale];
 return {title:"SP-DECODE",description:t.hero,alternates:{canonical:localePath(locale),languages:Object.fromEntries(locales.map(l=>[l,localePath(l)]))}};
}
export default async function LocaleLayout({children,params}:{children:React.ReactNode;params:Promise<{locale:string}>}) {
 const {locale}=await params;
 if(!isLocale(locale))notFound();
 return <div lang={locale} dir={localeDirection(locale)}><SiteShell locale={locale}>{children}</SiteShell></div>;
}

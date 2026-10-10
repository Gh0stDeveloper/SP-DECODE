import Link from "next/link";
import { Download, Github, House, LayoutGrid, Mail, ShieldCheck, Menu, X } from "lucide-react";
import { LocaleSwitcher } from "./LocaleSwitcher";
import { ActiveNav } from "./ActiveNav";
import { copy } from "@/lib/content";
import { links, localeDirection, localePath, type Locale } from "@/lib/i18n";

export function Logo({compact = false}: {compact?: boolean}) {
  return <span className="brand"><span className="brand-mark" aria-hidden="true"><ShieldCheck size={23} strokeWidth={1.9}/></span><span className="brand-words"><strong>SP-DECODE</strong>{!compact && <small>GHOST DEVELOPER</small>}</span></span>;
}



export function SiteShell({locale, segment="", children}: {locale:Locale;segment?:string;children:React.ReactNode}) {
  const t=copy[locale];const root=localePath(locale);
  const nav=[
   {href:root,label:t.nav[0]},
   {href:localePath(locale,"features"),label:t.nav[1]},
   {href:localePath(locale,"downloads"),label:t.nav[2]},
   {href:localePath(locale,"support"),label:t.nav[3]},
  ];
  return <div className="site" dir={localeDirection(locale)}>
    <header className="topbar">
      <div className="container header-content">
        <Link href={root} className="logo-link" aria-label="SP-DECODE home"><Logo/></Link>
        <ActiveNav locale={locale} labels={t.nav}/>
        <div className="header-actions">
          <LocaleSwitcher locale={locale}/>
          <a className="header-github" href={links.github} target="_blank" rel="noopener noreferrer" aria-label="SP-DECODE source code on GitHub"><Github size={19}/></a>
        </div>
      </div>
    </header>
    <main id="main">{children}</main>
    <footer className="footer"><div className="container">
      <div className="footer-top">
       <div><Logo/><p className="footer-description">{t.hero}</p></div>
       <div className="footer-links">
        <Link href={localePath(locale,"features")}>{t.featuresLabel}</Link><Link href={localePath(locale,"downloads")}>{t.nav[2]}</Link>
        <Link href={localePath(locale,"privacy")}>{t.privacyLabel}</Link>
        <Link href={localePath(locale,"terms")}>{t.termsLabel}</Link>
        <Link href={localePath(locale,"license")}>{t.licenseLabel}</Link>
        <Link href={localePath(locale,"support")}>{t.supportLabel}</Link>
        <a href={links.github} target="_blank" rel="noopener noreferrer">GitHub</a>
       </div>
      </div>
      <div className="footer-bottom"><span>© {new Date().getFullYear()} SP-DECODE · {t.footerNote}</span><span>Android · Kotlin · Compose</span></div>
    </div></footer>
    <nav className="bottom-dock" aria-label="Mobile navigation">
      <Link href={root}><House size={20}/><span>{t.nav[0]}</span></Link>
      <Link href={localePath(locale,"features")}><LayoutGrid size={20}/><span>{t.nav[1]}</span></Link>
      <Link href={localePath(locale,"downloads")}><Download size={20}/><span>{t.nav[2]}</span></Link>
      <Link href={localePath(locale,"support")}><Mail size={20}/><span>{t.nav[3]}</span></Link>
    </nav>
  </div>;
}

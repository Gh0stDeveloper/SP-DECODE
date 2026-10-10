import Link from "next/link";
import { Download, Globe2, Github, House, LayoutGrid, Mail, ShieldCheck } from "lucide-react";
import { copy } from "@/lib/content";
import { languageNames, links, locales, localeDirection, localePath, type Locale } from "@/lib/i18n";

export function Logo({compact = false}: {compact?: boolean}) {
  return <span className="brand"><span className="brand-mark" aria-hidden="true"><ShieldCheck size={23} strokeWidth={1.9}/></span><span className="brand-words"><strong>SP-DECODE</strong>{!compact && <small>GHOST DEVELOPER</small>}</span></span>;
}

const languageCodes: Record<Locale,string>={es:"ES",en:"EN","pt-BR":"PT",ar:"AR"};

export function SiteShell({locale, segment="", children}: {locale:Locale;segment?:string;children:React.ReactNode}) {
  const t=copy[locale];const root=localePath(locale);
  const nav=[
   {href:root,label:t.nav[0]},
   {href:localePath(locale,"features"),label:t.nav[1]},
   {href:root+"#downloads",label:t.nav[2]},
   {href:localePath(locale,"support"),label:t.nav[3]},
  ];
  return <div className="site" dir={localeDirection(locale)}>
    <header className="topbar">
      <div className="container header-content">
        <Link href={root} className="logo-link" aria-label="SP-DECODE home"><Logo/></Link>
        <nav className="desktop-nav" aria-label="Main navigation">
          {nav.map((item)=> <Link key={item.label} href={item.href} className="nav-link">{item.label}</Link>)}
        </nav>
        <div className="header-actions">
          <details className="language-picker"><summary aria-label="Choose language"><Globe2 size={17}/><span>{languageCodes[locale]}</span></summary>
            <div className="lang-options">
              {locales.map((next)=><Link key={next} href={localePath(next,segment)} hrefLang={next} className={next===locale?"is-active":""} dir={localeDirection(next)}>{languageNames[next]}</Link>)}
            </div>
          </details>
          <a className="header-github" href={links.github} target="_blank" rel="noopener noreferrer" aria-label="SP-DECODE source code on GitHub"><Github size={19}/></a>
        </div>
      </div>
    </header>
    <main id="main">{children}</main>
    <footer className="footer"><div className="container">
      <div className="footer-top">
       <div><Logo/><p className="footer-description">{t.hero}</p></div>
       <div className="footer-links">
        <Link href={localePath(locale,"features")}>{t.featuresLabel}</Link>
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
      <Link href={links.stable}><Download size={20}/><span>{t.nav[2]}</span></Link>
      <Link href={localePath(locale,"support")}><Mail size={20}/><span>{t.nav[3]}</span></Link>
    </nav>
  </div>;
}

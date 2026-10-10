import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, ArrowUpRight, BadgeCheck, Blocks, Braces, CheckCheck, ClipboardCopy, CloudOff, CodeXml, Download, FileCode2, FileInput, FileStack, Github, Globe2, History, LockKeyhole, MessageCircle, ShieldCheck, Smartphone, Sparkles, TerminalSquare } from "lucide-react";
import { PhonePreview } from "@/components/PhonePreview";
import { copy } from "@/lib/content";
import { isLocale, links, localePath, type Locale } from "@/lib/i18n";
const icons=[FileInput,FileStack,Braces,ClipboardCopy,History,LockKeyhole,CloudOff,Globe2,CodeXml];
export default async function Landing({params}:{params:Promise<{locale:string}>}){
 const {locale:raw}=await params;
 if(!isLocale(raw))return null;
 const locale:Locale=raw;const t=copy[locale];
 const appData={"@context":"https://schema.org","@type":"SoftwareApplication",name:"SP-DECODE",operatingSystem:"Android 7.0+",applicationCategory:"UtilitiesApplication",softwareVersion:"1.0.4",downloadUrl:links.stable,codeRepository:links.github,author:{"@type":"Person",name:"Ghost Developer",url:links.developer},description:t.hero};
 return <>
 <script type="application/ld+json" dangerouslySetInnerHTML={{__html:JSON.stringify(appData).replace(/</g,"\\u003c")}}/>
 <section className="hero container">
   <div className="hero-copy">
    <div className="eyebrow"><span className="status-dot"/>{t.eyebrow}</div>
    <h1>{t.title}</h1><p className="hero-description">{t.hero}</p>
    <div className="hero-actions">
      <a className="button primary" href={links.stable} target="_blank" rel="noopener noreferrer"><Download size={18}/>{t.stableCta}<ArrowUpRight size={16}/></a>
      <a className="button secondary" href={links.github} target="_blank" rel="noopener noreferrer"><Github size={18}/>{t.sourceCta}</a>
    </div>
    <div className="hero-proof"><span><ShieldCheck size={15}/>{t.trusted}</span><span><CloudOff size={15}/>{t.device}</span></div>
    <p className="hero-caution">{t.experimental}</p>
   </div>
   <PhonePreview locale={locale}/>
 </section>
 <section className="section container" id="features">
  <span className="section-kicker">{t.sectionEyebrow}</span>
  <div className="section-heading"><div><h2>{t.sectionTitle}</h2><p>{t.sectionText}</p></div><Link className="text-link" href={localePath(locale,"features")}>{t.featuresLabel}<ArrowRight size={17}/></Link></div>
  <div className="feature-grid">{t.features.slice(0,3).map((f,i)=>{const Icon=icons[i];return <article className="feature-card" key={f.title}><div className="feature-icon"><Icon size={22}/></div><h3>{f.title}</h3><p>{f.description}</p></article>})}</div>
 </section>
 <section className="section container"><div className="trust-card"><div className="trust-icon"><Blocks size={25}/></div><div><h2>{t.techTitle}</h2><p>{t.techText}</p><div className="tech-tags">{t.techTags.map(x=><span key={x}>{x}</span>)}</div></div><a className="circle-link" href={links.github} target="_blank" rel="noopener noreferrer" aria-label="GitHub"><ArrowUpRight size={20}/></a></div></section>
 <section className="section container closing"><h2>{t.moreTitle}</h2><p>{t.moreText}</p><div className="closing-links">
   <Link href={localePath(locale,"features")}>{t.featuresLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"privacy")}>{t.privacyLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"terms")}>{t.termsLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"license")}>{t.licenseLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"support")}>{t.contactLabel}<ArrowUpRight size={16}/></Link>
 </div></section>
 </>;
}

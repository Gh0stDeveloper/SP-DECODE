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
 <section className="metrics-strip"><div className="container metrics">
  <div><strong>60</strong><span>{t.formats}</span></div>
  <div><strong>100%</strong><span>{t.device}</span></div>
  <div><strong>4</strong><span>{t.languages}</span></div>
 </div></section>
 <section className="section container" id="features">
  <span className="section-kicker">{t.sectionEyebrow}</span>
  <div className="section-heading"><div><h2>{t.sectionTitle}</h2><p>{t.sectionText}</p></div><Link className="text-link" href={localePath(locale,"features")}>{t.featuresLabel}<ArrowRight size={17}/></Link></div>
  <div className="feature-grid">{t.features.slice(0,6).map((f,i)=>{const Icon=icons[i];return <article className="feature-card" key={f.title}><div className="feature-icon"><Icon size={22}/></div><h3>{f.title}</h3><p>{f.description}</p></article>})}</div>
 </section>
 <section className="section process-wrap"><div className="container"><div className="center-title"><span className="section-kicker">SP-DECODE</span><h2>{t.flowTitle}</h2></div><div className="step-grid">{t.flow.map((step,i)=><div className="step" key={step.title}><span className="step-number">0{i+1}</span><h3>{step.title}</h3><p>{step.description}</p></div>)}</div></div></section>
 <section className="section container downloads" id="downloads"><div className="section-heading"><div><span className="section-kicker">GITHUB RELEASES</span><h2>{t.releaseTitle}</h2><p>{t.releaseText}</p></div></div>
  <div className="release-grid">
   <article className="release-card stable"><div className="release-badge"><BadgeCheck size={17}/>{t.stableLabel}</div><strong>SP-DECODE Android</strong><p>{t.stableDesc}</p><a className="button primary" href={links.stable} target="_blank" rel="noopener noreferrer"><Download size={17}/>{t.download}<ArrowUpRight size={17}/></a></article>
   <article className="release-card preview"><div className="release-badge"><Sparkles size={17}/>{t.previewLabel}</div><strong>SP-DECODE Android</strong><p>{t.previewDesc}</p><a className="button secondary" href={links.preview} target="_blank" rel="noopener noreferrer"><Download size={17}/>{t.download}<ArrowUpRight size={17}/></a></article>
  </div>
  <p className="release-disclaimer"><ShieldCheck size={17}/>{t.releaseNote}</p>
 </section>
 <section className="section container"><div className="trust-card"><div className="trust-icon"><Blocks size={25}/></div><div><h2>{t.techTitle}</h2><p>{t.techText}</p><div className="tech-tags">{t.techTags.map(x=><span key={x}>{x}</span>)}</div></div><a className="circle-link" href={links.github} target="_blank" rel="noopener noreferrer" aria-label="GitHub"><ArrowUpRight size={20}/></a></div></section>
 <section className="container bottom-panels">
  <div className="minor-panel"><span className="minor-icon"><ShieldCheck size={22}/></span><h3>{t.infoTitle}</h3><p>{t.infoText}</p><a className="text-link" href={links.parity} target="_blank" rel="noopener noreferrer">{t.report}<ArrowUpRight size={17}/></a></div>
  <div className="minor-panel"><span className="minor-icon"><MessageCircle size={22}/></span><h3>{t.botTitle}</h3><p>{t.botText}</p><a className="text-link" href={links.github} target="_blank" rel="noopener noreferrer">{t.botLink}<ArrowUpRight size={17}/></a></div>
 </section>
 <section className="section container closing"><h2>{t.moreTitle}</h2><p>{t.moreText}</p><div className="closing-links">
   <Link href={localePath(locale,"features")}>{t.featuresLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"privacy")}>{t.privacyLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"terms")}>{t.termsLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"license")}>{t.licenseLabel}<ArrowUpRight size={16}/></Link>
   <Link href={localePath(locale,"support")}>{t.contactLabel}<ArrowUpRight size={16}/></Link>
 </div></section>
 </>;
}

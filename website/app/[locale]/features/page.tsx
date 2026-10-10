import type { Metadata } from "next";
import { ArrowUpRight, CloudOff, FileCode2, Github, ShieldCheck } from "lucide-react";
import { copy } from "@/lib/content";
import { isLocale, links } from "@/lib/i18n";
export default async function FeaturesPage({params}:{params:Promise<{locale:string}>}){
 const {locale}=await params;if(!isLocale(locale))return null; const t=copy[locale];
 return <div className="container inner-page">
  <span className="section-kicker">SP-DECODE / ANDROID</span><h1>{t.sectionTitle}</h1><p className="inner-lead">{t.sectionText}</p>
  <div className="feature-grid expanded">{t.features.map((f,i)=><article className="feature-card" key={f.title}><span className="feature-count">{String(i+1).padStart(2,"0")}</span><div className="feature-icon"><FileCode2 size={20}/></div><h2>{f.title}</h2><p>{f.description}</p></article>)}</div>
  <div className="note-card"><ShieldCheck size={23}/><div><h2>{t.infoTitle}</h2><p>{t.infoText}</p><a href={links.parity} target="_blank" rel="noopener noreferrer" className="text-link">{t.report}<ArrowUpRight size={16}/></a></div></div>
  <div className="note-card"><CloudOff size={23}/><div><h2>{t.botTitle}</h2><p>{t.botText}</p><a href={links.github} target="_blank" rel="noopener noreferrer" className="text-link"><Github size={16}/>{t.botLink}</a></div></div>
 </div>;
}

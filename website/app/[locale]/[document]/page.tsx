import { notFound } from "next/navigation";
import type { Metadata } from "next";
import { ArrowUpRight, Github, Mail, ShieldCheck } from "lucide-react";
import { copy } from "@/lib/content";
import { isLocale, links, locales } from "@/lib/i18n";
type DocumentKey="privacy"|"terms"|"license"|"support";
const documents:DocumentKey[]=["privacy","terms","license","support"];
export function generateStaticParams(){return locales.flatMap(locale=>documents.map(document=>({locale,document})));}
export async function generateMetadata({params}:{params:Promise<{locale:string;document:string}>}):Promise<Metadata>{
 const {locale,document}=await params;if(!isLocale(locale)||!documents.includes(document as DocumentKey))return {};
 const page=copy[locale].pages[document as DocumentKey];return {title:page.title,description:page.summary,alternates:{canonical:`/${locale}/${document}`,languages:Object.fromEntries(locales.map(l=>[l,`/${l}/${document}`]))}};
}
export default async function DocumentPage({params}:{params:Promise<{locale:string;document:string}>}){
 const {locale,document}=await params;if(!isLocale(locale)||!documents.includes(document as DocumentKey))notFound();
 const t=copy[locale];const page=t.pages[document as DocumentKey];
 return <div className="container inner-page legal">
  <span className="section-kicker">SP-DECODE / {document.toUpperCase()}</span>
  <h1>{page.title}</h1><p className="inner-lead">{page.summary}</p>
  <p className="policy-updated">{t.legalNote}</p>
  <div className="legal-grid">{page.sections.map((section,i)=><section key={section.title} className="legal-section"><span className="legal-number">{String(i+1).padStart(2,"0")}</span><h2>{section.title}</h2><p>{section.description}</p></section>)}</div>
  <div className="legal-action"><ShieldCheck size={22}/><div><strong>{t.supportLabel}</strong><p>{t.moreText}</p><div className="legal-action-links"><a href={links.github} target="_blank" rel="noopener noreferrer"><Github size={16}/> GitHub <ArrowUpRight size={14}/></a><a href={links.dm} target="_blank" rel="noopener noreferrer"><Mail size={16}/> @Gh0stDeveloper <ArrowUpRight size={14}/></a></div></div></div>
 </div>;
}

import { Download, ShieldCheck, AlertCircle } from "lucide-react";
import { copy } from "@/lib/content";
import { isLocale, links } from "@/lib/i18n";
export default async function Downloads({params}:{params:Promise<{locale:string}>}){
 const {locale}=await params;if(!isLocale(locale))return null;const t=copy[locale];
 return <div className="container inner-page"><span className="section-kicker">GITHUB RELEASES</span><h1>{t.releaseTitle}</h1><p className="inner-lead">{t.releaseText}</p>
 <div className="release-grid"><article className="release-card stable"><div className="release-badge"><ShieldCheck size={17}/>{t.stableLabel}</div><strong>SP-DECODE Android</strong><p>{t.stableDesc}</p><a className="button primary" href={links.stable} target="_blank" rel="noopener noreferrer"><Download size={17}/>{t.download}</a></article>
 <article className="release-card preview"><div className="release-badge"><AlertCircle size={17}/>{t.previewLabel}</div><strong>SP-DECODE Android</strong><p>{t.previewDesc}</p><a className="button secondary" href={links.preview} target="_blank" rel="noopener noreferrer"><Download size={17}/>{t.download}</a></article></div><p className="release-disclaimer">{t.releaseNote}</p></div>;
}

import { ArrowUpRight, Check, ChevronRight, ClipboardList, FileCode2, FileUp, History, House, LayoutGrid, LockKeyhole, MoreHorizontal, Settings2, ShieldCheck } from "lucide-react";
import type { Locale } from "@/lib/i18n";
import { copy } from "@/lib/content";

export function PhonePreview({locale}: {locale:Locale}) {
 const t=copy[locale];
 return <figure className="phone-scene">
  <div className="orb orb-one"/><div className="orb orb-two"/>
  <div className="phone" dir={locale==="ar"?"rtl":"ltr"}>
   <div className="phone-hardware"><span>9:41</span><span className="signal" aria-hidden="true"><i/><i/><i/></span></div>
   <div className="phone-top"><div className="phone-logo"><span className="phone-symbol"><ShieldCheck size={17}/></span><span><b>SP-DECODE</b><small>{t.previewSubtitle}</small></span></div><Settings2 size={20} color="#8797AC"/></div>
   <div className="phone-content">
    <div className="phone-import"><div className="phone-upload-icon"><FileUp size={28}/></div><h3>{t.previewImport}</h3><p>{t.previewText}</p><div className="phone-cta">{t.previewImport}<ChevronRight size={16}/></div></div>
    <div className="phone-text-link"><ClipboardList size={15}/><span>{t.previewResult}</span><ArrowUpRight size={14}/></div>
    <div className="phone-section"><span>{t.previewRecent}</span><MoreHorizontal size={18}/></div>
    <div className="phone-file"><div className="phone-file-icon"><FileCode2 size={20}/></div><div><strong>{t.previewFile}</strong><small>JSON · HTTPS / SSH</small></div><span className="phone-verified"><Check size={14}/></span></div>
    <div className="phone-result"><div className="phone-result-title"><span><LockKeyhole size={13}/>{t.previewOffline}</span><ShieldCheck size={14}/></div><pre dir="ltr">{'{\n  "host": "example.invalid",\n  "port": 443,\n  "mode": "demo"\n}'}</pre></div>
   </div>
   <div className="phone-bottom"><House size={18}/><History size={18}/><LayoutGrid size={18}/><Settings2 size={18}/></div>
   <div className="home-indicator"/>
  </div>
  <figcaption className="phone-caption">{t.previewDemo}</figcaption>
 </figure>;
}

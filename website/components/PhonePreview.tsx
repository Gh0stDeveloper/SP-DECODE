import { Braces, FileUp, History, House, Settings2, Shield, SlidersHorizontal, CodeXml } from "lucide-react";
import type { Locale } from "@/lib/i18n";
import { copy } from "@/lib/content";
export function PhonePreview({locale}:{locale:Locale}){
 const t=copy[locale];
 return <figure className="phone-scene">
  <div className="phone" dir={locale==="ar"?"rtl":"ltr"}>
   <div className="phone-hardware"><span>4:44</span><span>4G ▮▮▮</span></div>
   <div className="phone-top"><div className="phone-logo"><span className="phone-symbol"><Shield size={22}/></span><span><b>SP-DECODE</b><small>{t.previewSubtitle}</small></span></div><SlidersHorizontal size={21}/></div>
   <div className="phone-actions"><div><FileUp size={16}/><span>Importar archivo</span></div><div><Braces size={16}/><span>Decodificar texto</span></div></div>
   <div className="phone-section"><strong>Resultado</strong><span>Experimental</span></div>
   <div className="phone-json"><div className="phone-json-heading"><Braces size={16}/><b>ejemplo.json</b></div><pre dir="ltr">{`// Ejemplo ilustrativo · datos ficticios
// Powered by Ghost Developer

{
  "BlockAll": true,
  "Username": "demo",
  "SSL": {
    "Sni": "example.invalid",
    "Host": ""
  },
  "HTTP": {
    "Payload": "GET / HTTP/1.1"
  }
}`}</pre></div>
   <div className="phone-bottom"><House size={18}/><History size={18}/><CodeXml size={18}/><Settings2 size={18}/></div>
  </div>
  <figcaption className="phone-caption">{t.previewDemo}</figcaption>
 </figure>;
}

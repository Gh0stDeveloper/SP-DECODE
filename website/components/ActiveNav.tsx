"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Download, House, LayoutGrid, Mail } from "lucide-react";
import { localePath, type Locale } from "@/lib/i18n";
const icons=[House,LayoutGrid,Download,Mail];
export function ActiveNav({locale,labels,mobile=false}:{locale:Locale;labels:[string,string,string,string];mobile?:boolean}){
 const pathname=usePathname();
 const paths=[localePath(locale),localePath(locale,"features"),localePath(locale,"downloads"),localePath(locale,"support")];
 return <nav className={mobile?"bottom-dock":"desktop-nav"} aria-label={mobile?"Mobile navigation":"Main navigation"}>
  {paths.map((href,i)=>{const Icon=icons[i];const active=pathname===href || (i===3 && ["privacy","terms","license"].some(s=>pathname===localePath(locale,s)));return <Link key={href} href={href} aria-current={active?"page":undefined} className={active?"nav-link active":"nav-link"}><Icon size={mobile?20:18}/><span>{labels[i]}</span></Link>})}
 </nav>;
}

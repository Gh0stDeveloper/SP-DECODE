import type { MetadataRoute } from "next";
import { locales, localePath, siteUrl } from "@/lib/i18n";
export default function sitemap():MetadataRoute.Sitemap {
 const pages=["","features","privacy","terms","license","support"];
 return pages.flatMap(p=>locales.map(l=>({url:siteUrl+localePath(l,p),changeFrequency:(p?"monthly":"weekly") as "monthly"|"weekly",priority:p?0.7:1})));
}

import type { Metadata, Viewport } from "next";
import "./globals.css";
export const metadata: Metadata = {
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL || "https://sp-decode.vercel.app"),
  title: {default:"SP-DECODE | Offline Android Decoder", template:"%s | SP-DECODE"},
  description: "Native offline Android decoder for VPN, proxy and tunnel configurations. Multilingual interface, signed APKs, original source and release transparency.",
  applicationName:"SP-DECODE",
  openGraph:{type:"website",siteName:"SP-DECODE",title:"SP-DECODE — Offline Android Decoder",description:"On-device file and text decoding, documented releases, source code and a separate Telegram bot."},
  twitter:{card:"summary_large_image"},
  robots:{index:true,follow:true},
};
export const viewport: Viewport = {themeColor:"#080C12",width:"device-width",initialScale:1};
export default function RootLayout({children}:{children:React.ReactNode}) {
 return <html lang="es" suppressHydrationWarning><body>{children}</body></html>;
}

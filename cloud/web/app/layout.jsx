export const metadata = {
  title: "SP-DECODE Cloud",
  description: "Infraestructura de SP-DECODE Cloud en preparación.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }) {
  return (
    <html lang="es">
      <body>{children}</body>
    </html>
  );
}

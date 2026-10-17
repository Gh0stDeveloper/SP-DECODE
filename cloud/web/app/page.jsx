import Link from "next/link";
const features=[
  {number:"01",title:"Descifrado remoto",text:"La app transmite el contenido cifrado por HTTPS. Los motores trabajan en servidores aislados y devuelven el resultado completo."},
  {number:"02",title:"Un solo punto de acceso",text:"Archivos, textos, importaciones HTTP Injector Cloud y catálogos NUR, bajo un contrato de API versionado."},
  {number:"03",title:"Protección de sesiones",text:"Integridad de la app, sesiones efímeras, límites de petición y un worker que no está expuesto públicamente."},
];
export default function Home(){
  return <main id="main">
    <section className="hero shell">
      <div className="hero-copy">
        <span className="eyebrow"><span className="pulse"/> Arquitectura Cloud · En preparación</span>
        <h1>SP-DECODE, ahora diseñado para <span className="gradient-text">funcionar online.</span></h1>
        <p className="lead">Una nueva infraestructura para procesar configuraciones cifradas en el servidor, sin instalar motores de descifrado dentro de la aplicación Android.</p>
        <div className="hero-actions"><Link className="button primary" href="/features">Explorar funciones <span aria-hidden="true">↗</span></Link>
          <Link className="button subtle" href="/docs">Cómo funciona</Link></div>
        <p className="hero-foot">El servicio todavía no está disponible públicamente. No hay descifrado web ni APK Cloud de producción.</p>
      </div>
      <div className="hero-display" aria-label="Diagrama conceptual del procesamiento seguro">
        <div className="mock-top"><span className="traffic"><i/><i/><i/></span><span>FLUJO DE PROCESAMIENTO</span><span>v1</span></div>
        <div className="flowbox">
          <div className="flow-node"><span className="flow-symbol">01</span><div><strong>Aplicación Android</strong><small>Archivo o texto cifrado</small></div><span className="status-dot"/></div>
          <div className="flow-line"><span>HTTPS · API protegida</span></div>
          <div className="flow-node active"><span className="flow-symbol">02</span><div><strong>SP-DECODE Cloud</strong><small>Motor privado en el servidor</small></div><span className="status-dot"/></div>
          <div className="flow-line"><span>Respuesta JSON completa</span></div>
          <div className="flow-node"><span className="flow-symbol">03</span><div><strong>Resultado en Android</strong><small>Misma interfaz y presentación</small></div><span className="status-dot"/></div>
        </div>
        <div className="mock-bottom"><span>COMPATIBILIDAD EN VALIDACIÓN</span><span>SERVER-SIDE</span></div>
      </div>
    </section>
    <section className="section shell">
      <div className="section-top"><div><span className="section-kicker">La plataforma</span>
        <h2>Menos código sensible en el dispositivo. Más control en el servidor.</h2></div>
        <p>Los motores no dependen de actualizaciones de APK para cada cambio del backend. Las revisiones de seguridad y de compatibilidad siguen siendo necesarias.</p></div>
      <div className="feature-grid">
        {features.map(f=><article className="feature-card" key={f.number}><div className="feature-index">{f.number}</div><h3>{f.title}</h3><p>{f.text}</p></article>)}
      </div>
    </section>
    <section className="section shell"><div className="stats-strip">
      <div><strong>240</strong><span>Rutas de archivo inventariadas</span></div>
      <div><strong>HTTPS</strong><span>Transporte previsto para Android</span></div>
      <div><strong>0</strong><span>Versiones de exportador certificadas a la fecha</span></div>
    </div><p className="smallnote">El inventario no equivale a compatibilidad garantizada con todas las versiones o archivos reales.</p></section>
    <section className="section shell"><div className="feature-band">
      <div><span className="section-kicker">Transparencia desde el inicio</span><h2>Estado, límites y privacidad, claramente documentados.</h2>
      <p>Conoce qué datos se envían, qué controles existen y qué verificaciones faltan antes de la publicación.</p></div>
      <div className="band-actions"><Link className="button primary" href="/privacy">Privacidad y datos</Link><Link className="button subtle" href="/status">Ver estado del proyecto</Link></div>
    </div></section>
  </main>;
}

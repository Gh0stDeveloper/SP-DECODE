import type { Locale } from "./i18n";

type Feature = { title: string; description: string };
type Copy = {
  nav: [string, string, string, string];
  subheading: string;
  eyebrow: string;
  title: string;
  hero: string;
  stableCta: string;
  sourceCta: string;
  experimental: string;
  trusted: string;
  device: string;
  formats: string;
  languages: string;
  previewTitle: string;
  previewSubtitle: string;
  previewImport: string;
  previewText: string;
  previewRecent: string;
  previewResult: string;
  previewFile: string;
  previewOffline: string;
  previewDemo: string;
  sectionEyebrow: string;
  sectionTitle: string;
  sectionText: string;
  features: Feature[];
  flowTitle: string;
  flow: Feature[];
  releaseTitle: string;
  releaseText: string;
  stableLabel: string;
  stableDesc: string;
  previewLabel: string;
  previewDesc: string;
  download: string;
  releaseNote: string;
  techTitle: string;
  techText: string;
  techTags: string[];
  infoTitle: string;
  infoText: string;
  botTitle: string;
  botText: string;
  botLink: string;
  moreTitle: string;
  moreText: string;
  privacyLabel: string;
  termsLabel: string;
  licenseLabel: string;
  supportLabel: string;
  featuresLabel: string;
  contactLabel: string;
  report: string;
  legalNote: string;
  footerNote: string;
  pages: {
    privacy: { title: string; summary: string; sections: Feature[] };
    terms: { title: string; summary: string; sections: Feature[] };
    license: { title: string; summary: string; sections: Feature[] };
    support: { title: string; summary: string; sections: Feature[] };
  };
};

const es: Copy = {
  nav: ["Inicio", "Funciones", "Descargas", "Soporte"],
  subheading: "Decodificador de configuraciones",
  eyebrow: "NATIVO PARA ANDROID · SIN CONEXIÓN",
  title: "Descifra tus configuraciones. Sin salir de tu dispositivo.",
  hero: "Importa archivos VPN, proxy y túneles, decodifica enlaces compatibles y consulta sus datos en una interfaz ordenada. Sin cuentas, sin servidores y sin enviar el archivo a una web.",
  stableCta: "Descargar APK estable", sourceCta: "Ver código fuente",
  experimental: "La compatibilidad varía según el formato y la versión exportadora.",
  trusted: "Firma de producción V1/V2/V3", device: "Procesamiento local", formats: "60 extensiones registradas", languages: "4 idiomas",
  previewTitle: "SP-DECODE", previewSubtitle: "Decodificador de configuraciones",
  previewImport: "Importar configuración", previewText: "Selecciona un archivo para analizarlo de forma local.",
  previewRecent: "Procesamiento sin conexión", previewResult: "Vista de resultado", previewFile: "ejemplo.hc",
  previewOffline: "Sin Internet · Sin cuenta", previewDemo: "Maqueta ilustrativa · no se procesan archivos aquí",
  sectionEyebrow: "CAPACIDADES", sectionTitle: "Todo lo esencial, en una sola aplicación",
  sectionText: "Diseñada alrededor de la privacidad, el control de archivos y una salida comprensible.",
  features: [
    {title:"Importación de archivos",description:"Selecciona configuraciones desde el explorador del sistema o compártelas directamente con la app."},
    {title:"Decodificación por lotes",description:"Procesa varios archivos y distingue de forma clara los resultados y los errores."},
    {title:"Textos y enlaces",description:"Pega protocolos compatibles como nm-ssh://, ar-ssh:// y Dark Tunnel con motores específicos."},
    {title:"Resultados completos",description:"Consulta estructuras JSON, campos anidados y valores sin truncamientos arbitrarios."},
    {title:"Copia y exportación",description:"Comparte únicamente cuando decidas copiar o exportar el contenido decodificado."},
    {title:"Historial protegido",description:"Consulta resultados conservados localmente mediante el almacenamiento protegido de Android."},
    {title:"Privacidad desde el diseño",description:"No requiere permiso de Internet, cuentas ni servicios remotos para descifrar archivos."},
    {title:"Interfaz multilingüe",description:"Español, inglés, portugués de Brasil y árabe con compatibilidad RTL."},
    {title:"Desarrollo verificable",description:"Código fuente, pruebas, registro de versiones y firma de APK accesibles en GitHub."}
  ],
  flowTitle:"Tres pasos, todo local",flow:[
    {title:"01 · Importa",description:"Selecciona un archivo o pega un enlace de texto compatible."},
    {title:"02 · Procesa",description:"La app identifica una ruta y ejecuta el motor local correspondiente."},
    {title:"03 · Consulta",description:"Revisa los datos, cópialos o expórtalos bajo tu control."}
  ],
  releaseTitle:"Descarga oficial", releaseText:"Distribuida desde GitHub Releases con archivos de integridad SHA-256 y verificación de firma.",
  stableLabel:"ESTABLE · v1.0.4",stableDesc:"Distribución aprobada por el responsable del producto.",previewLabel:"VISTA PREVIA · v1.0.5-rc.1",previewDesc:"Ajustes para Dark Tunnel y protocolos de texto; validación real adicional pendiente.",
  download:"Ver en GitHub",releaseNote:"La candidata 1.0.5 usa la firma permanente de producción, pero sigue sin aprobación para publicarse como estable. Las 60 rutas registradas no certifican todas las variantes reales.",
  techTitle:"Tecnología y proyecto abierto a revisión", techText:"Aplicación Android nativa en Kotlin y Jetpack Compose. El bot independiente de Telegram conserva motores Python, Node.js y PHP. El código está disponible públicamente; revisa las condiciones de licencia antes de reutilizarlo.",
  techTags:["Kotlin","Jetpack Compose","Android 7.0+","GitHub Actions","Python","Node.js","PHP","Vercel"],
  infoTitle:"Transparencia sobre compatibilidad",infoText:"La app registra 60 extensiones, pero las pruebas automáticas, incluidas las sintéticas, no demuestran que todos los exportadores reales funcionen. Consulta el reporte técnico y notifica incompatibilidades con datos anonimizados.",
  botTitle:"¿También usas Telegram?",botText:"El proyecto incluye un bot modular independiente, instalable en Termux o un VPS. A diferencia de la app Android, procesa archivos en el servidor donde lo ejecutas y se comunica mediante Telegram.",
  botLink:"Explorar el bot",
  moreTitle:"Conoce el proyecto completo",moreText:"Revisa funciones, políticas, código, documentación y canales oficiales.",
  privacyLabel:"Privacidad",termsLabel:"Términos",licenseLabel:"Licencia",supportLabel:"Soporte",featuresLabel:"Funciones",contactLabel:"Contacto",report:"Reportar un problema",legalNote:"Última revisión: 9 de octubre de 2026. Estas páginas informan sobre el proyecto y pueden requerir revisión jurídica antes de una distribución comercial.",footerNote:"Creado y mantenido por Ghost Developer.",
  pages:{
    privacy:{title:"Política de privacidad",summary:"La web es informativa; no decodifica ni recibe tus archivos. La aplicación Android procesa configuraciones en el dispositivo.",sections:[
      {title:"1. Qué procesa la aplicación Android",description:"La app trabaja localmente con archivos y enlaces elegidos por ti. No solicita cuenta ni permiso de Internet. Los resultados e historial se gestionan en el dispositivo mediante funciones de almacenamiento local; cuando copias, compartes o exportas, el contenido pasa al destino que elijas."},
      {title:"2. Qué procesa este sitio web",description:"Esta página no contiene un formulario de carga, un descifrador remoto ni inicio de sesión. No hemos incorporado analíticas de terceros, píxeles publicitarios ni cookies propias de seguimiento en el código del sitio."},
      {title:"3. Hosting y datos técnicos",description:"El sitio se aloja en Vercel. El proveedor puede procesar IP, cabeceras, registros técnicos y otros datos de acceso según sus propias políticas, por ejemplo para seguridad y operación. No controlamos las cookies o registros de enlaces externos."},
      {title:"4. Bot de Telegram: producto separado",description:"Si eliges utilizar el bot, los mensajes y archivos pasan por Telegram y por el servidor de quien lo aloja. Sus prácticas de gestión de datos dependen de Telegram y del operador del bot. No debes confundir esa modalidad con la app Android offline."},
      {title:"5. Conservación y control",description:"La web no guarda archivos de configuración proporcionados por el visitante, porque no permite enviarlos. En Android puedes gestionar resultados e historial localmente; consulta las opciones de eliminación de la app. No garantizamos poder borrar registros gestionados por servicios externos."},
      {title:"6. Contacto y actualizaciones",description:"Puedes plantear consultas sobre privacidad al responsable del proyecto en Telegram @Gh0stDeveloper. Los cambios importantes de esta política se reflejarán en el repositorio y en esta página."}
    ]},
    terms:{title:"Términos y condiciones",summary:"Condiciones generales de uso de la web, las descargas y el software SP-DECODE.",sections:[
      {title:"1. Uso autorizado",description:"Utiliza SP-DECODE solo para examinar archivos y configuraciones propios o aquellos que tengas autorización expresa para inspeccionar. No utilices el proyecto para acceder a sistemas ajenos ni vulnerar leyes o derechos de terceros."},
      {title:"2. Disponibilidad y compatibilidad",description:"Los formatos registrados, ejemplos de interfaz y pruebas automatizadas no representan una garantía de compatibilidad total. Algunas variantes de aplicaciones exportadoras pueden fallar. Las versiones preliminares no son equivalentes a una versión estable."},
      {title:"3. Descargas oficiales",description:"Las APK y sus reportes de SHA-256 y firma se distribuyen en GitHub Releases. Verifica origen e integridad antes de instalar. No redistribuyas compilaciones alteradas presentándolas como oficiales."},
      {title:"4. Información sensible",description:"Los resultados decodificados pueden incluir claves, contraseñas, servidores y datos privados. Eres responsable de decidir si los copias, exportas o compartes. Evita publicar ejemplos reales en Issues o grupos públicos."},
      {title:"5. Código, marca y licencias",description:"El código está disponible para consulta en GitHub, pero no existe actualmente una licencia general del proyecto que otorgue permisos amplios de copia, modificación o redistribución. Los componentes de terceros conservan sus licencias respectivas."},
      {title:"6. Cambios y contacto",description:"Podemos corregir funcionalidades, eliminar enlaces obsoletos y actualizar estas condiciones. Para dudas o permisos de reutilización contacta a Ghost Developer. Los derechos y garantías exigidos por las leyes aplicables no se ven limitados por esta descripción informativa."}
    ]},
    license:{title:"Licencias y atribuciones",summary:"Estado de licencia transparente, sin atribuir al proyecto permisos que no ha concedido.",sections:[
      {title:"Código fuente de SP-DECODE",description:"Al momento de esta publicación el repositorio Gh0stDeveloper/SP-DECODE no contiene una licencia general LICENSE. El código es visible públicamente, pero eso no significa que esté autorizado reutilizarlo o redistribuirlo bajo MIT, GPL, Apache u otra licencia de software libre. Solicita permisos al responsable."},
      {title:"Derechos del proyecto",description:"SP-DECODE y los materiales propios se atribuyen a Ghost Developer, sujeto a los derechos de terceros que puedan existir. La ausencia de una licencia expresa no modifica las excepciones que permita la ley aplicable."},
      {title:"Dependencias y marcas de terceros",description:"Next.js, React, Tailwind CSS, Lucide, Kotlin, Jetpack Compose, Python, Node.js, PHP y otras dependencias tienen sus propias licencias. Los nombres y marcas de aplicaciones compatibles pertenecen a sus respectivos titulares; mencionar compatibilidad no implica afiliación."},
      {title:"Código, permisos y contacto",description:"Revisa los archivos del repositorio y las licencias individuales de sus dependencias. Para solicitar permiso específico de uso o distribución contacta al desarrollador mediante los canales oficiales."}
    ]},
    support:{title:"Soporte y contacto",summary:"Ayuda con instalaciones, versiones y compatibilidad sin exponer configuraciones privadas.",sections:[
      {title:"Descarga y verificación",description:"Descarga la APK estable desde GitHub Releases. En cada publicación verifica SHA256SUMS.txt y SIGNATURE_VERIFICATION.txt. Para probar la versión candidata, utiliza la sección de prereleases conociendo sus limitaciones."},
      {title:"Problemas de descifrado",description:"Indica versión de SP-DECODE, versión exacta de la aplicación que exportó el archivo, extensión o esquema de texto, comportamiento esperado y resultado observado. Adjunta solo registros anonimizados o casos sintéticos."},
      {title:"No publiques datos privados",description:"Los archivos decodificados pueden contener credenciales y endpoints privados. No publiques muestras reales en Issues, chats públicos ni capturas sin censurar. Acuerda un canal privado con el mantenedor antes de compartir una muestra necesaria."},
      {title:"Contacto directo",description:"Desarrollador: @Gh0stDeveloper en Telegram. Noticias: @GhostDeve. Comunidad: @CodeBreakersHub. Código fuente e incidencias públicas: github.com/Gh0stDeveloper/SP-DECODE."}
    ]}
  }
};
const en: Copy = {
 ...es,
 nav:["Home","Features","Downloads","Support"], subheading:"Configuration decoder", eyebrow:"NATIVE ANDROID · FULLY OFFLINE",
 title:"Decode your configurations. Right on your device.",
 hero:"Import VPN, proxy and tunnel configurations, decode compatible links and inspect structured fields. No accounts, no servers and no file uploads to a website.",
 stableCta:"Download stable APK",sourceCta:"View source code",experimental:"Compatibility depends on the exporter and format version.",
 trusted:"Production signing V1/V2/V3",device:"On-device processing",formats:"60 registered suffixes",languages:"4 languages",
 previewImport:"Import configuration",previewText:"Select a file to decode it locally.",previewRecent:"Offline processing",previewResult:"Result preview",previewOffline:"No internet · No account",previewDemo:"Illustrative interface · this page does not decode files",
 sectionEyebrow:"CAPABILITIES",sectionTitle:"The essentials, in one native app",sectionText:"Built for privacy, file control and readable output.",
 features:[
  {title:"File import",description:"Open configurations with the system picker or share them from another Android app."},
  {title:"Batch decoding",description:"Process several files and distinguish successful results from failures."},
  {title:"Text and URI links",description:"Paste supported schemes including nm-ssh://, ar-ssh:// and Dark Tunnel with dedicated engines."},
  {title:"Complete results",description:"Explore JSON, nested fields and values without arbitrary truncation."},
  {title:"Copy and export",description:"Move decoded content outside the app only when you decide to copy or export."},
  {title:"Protected history",description:"Review decoded results stored locally using Android-protected storage."},
  {title:"Privacy by design",description:"No internet permission, account or remote service required for decoding."},
  {title:"Multilingual interface",description:"Spanish, English, Brazilian Portuguese and Arabic, including RTL layout."},
  {title:"Auditable development",description:"Review public source, tests, release history and APK signing records on GitHub."}
 ],
 flowTitle:"Three steps, entirely local",flow:[
 {title:"01 · Import",description:"Select a file or paste a supported configuration link."},
 {title:"02 · Decode",description:"The app matches the format and executes its local decoder."},
 {title:"03 · Inspect",description:"Review, copy or export the output under your control."}],
 releaseTitle:"Official download",releaseText:"Distributed through GitHub Releases, including SHA-256 integrity files and signing verification.",
 stableLabel:"STABLE · v1.0.4",stableDesc:"Distribution approved by the product owner.",previewLabel:"PREVIEW · v1.0.5-rc.1",previewDesc:"Dark Tunnel and text-protocol improvements; further real-export testing pending.",
 download:"Open on GitHub",releaseNote:"The v1.0.5 preview is permanently production-signed, but has not been approved as stable. Sixty registered routes do not certify every real-world exporter.",
 techTitle:"Technology and verifiable source",techText:"Native Android application built with Kotlin and Jetpack Compose. The separate Telegram bot retains Python, Node.js and PHP decoder engines. Source is publicly readable; check licensing before reusing it.",
 infoTitle:"Transparent compatibility",infoText:"The app registers 60 suffixes, but automated and synthetic tests do not prove that every exporting application variant works. Read the technical report and report sanitized reproducible cases.",
 botTitle:"Using Telegram too?",botText:"SP-DECODE also offers a separate modular Telegram bot for Termux or Linux VPS. Unlike the Android app, it handles files through the server where you host it and via Telegram.",
 botLink:"Explore Telegram bot",moreTitle:"Explore the whole project",moreText:"Features, policies, source, documentation and official support channels.",
 privacyLabel:"Privacy",termsLabel:"Terms",licenseLabel:"Licensing",supportLabel:"Support",featuresLabel:"Features",contactLabel:"Contact",report:"Report an issue",legalNote:"Last reviewed October 9, 2026. These pages describe the project; formal legal review may be needed before commercial distribution.",footerNote:"Created and maintained by Ghost Developer.",
 pages:{
 privacy:{title:"Privacy policy",summary:"This website is informational and never receives configuration files. The Android app processes files on-device.",sections:[
  {title:"1. Android app data",description:"The Android app processes files and links you choose locally. It does not require an account or Internet permission. Decoded results and history are managed on your device using local storage; when you copy, share or export, content goes to the destination you choose."},
  {title:"2. This website",description:"This website has no file upload, remote decoder or account system. We have not intentionally added third-party analytics, advertising pixels or first-party tracking cookies to its source."},
  {title:"3. Hosting and technical metadata",description:"Vercel hosts this website and may process IP addresses, headers and technical access logs for operation, security and abuse prevention in accordance with its policies. We do not control external websites' cookies or logging."},
  {title:"4. Separate Telegram bot",description:"If you use the Telegram bot, messages and files transit Telegram and your bot operator's server. Telegram's and the server operator's data handling policies apply; this differs from the offline Android application."},
  {title:"5. Retention and user control",description:"This website cannot retain configuration uploads because no such upload facility exists. On Android, use available in-app controls to manage local results and history. We cannot promise removal of independently retained external-provider logs."},
  {title:"6. Questions and updates",description:"Contact @Gh0stDeveloper on Telegram with privacy questions. Material changes to this policy will be reflected on this site and in the repository."}
 ]},
 terms:{title:"Terms and conditions",summary:"General terms governing the informational site, downloads and SP-DECODE software.",sections:[
  {title:"1. Authorized use",description:"Analyze only configurations you own or have explicit permission to inspect. Do not use SP-DECODE to access third-party systems without permission or infringe applicable law."},
  {title:"2. Availability and compatibility",description:"Registered formats, illustrated user interfaces and automated tests are not guarantees that every exporter variant will decode. Preview builds are not stable releases."},
  {title:"3. Official downloads",description:"APK downloads, checksums and signature reports are hosted on GitHub Releases. Verify origin and integrity before installation. Do not misrepresent modified third-party builds as official."},
  {title:"4. Sensitive data",description:"Decoded output may contain keys, passwords and private hosts. You decide whether to copy, export or share this content. Avoid posting real data in public reports."},
  {title:"5. Software rights",description:"The code is visible on GitHub but no project-wide license currently grants broad modification or redistribution permissions. Third-party components remain subject to their own licenses."},
  {title:"6. Changes and contact",description:"Features, links and terms may change. Contact Ghost Developer about permissions. Nothing in this informational notice is intended to exclude mandatory legal rights or remedies."}
 ]},
 license:{title:"Licensing and credits",summary:"A clear explanation of the project's current licensing status.",sections:[
  {title:"SP-DECODE source",description:"At publication the Gh0stDeveloper/SP-DECODE repository has no project-wide LICENSE file. Publicly readable source does not automatically give permission to reuse, modify or redistribute under MIT, GPL, Apache or any other open-source license. Request permission from the maintainer."},
  {title:"Attribution",description:"Original SP-DECODE material is attributed to Ghost Developer, subject to any third-party ownership rights. Absence of an express license does not override rights or exceptions under applicable law."},
  {title:"Third-party dependencies",description:"Next.js, React, Tailwind CSS, Lucide, Kotlin, Jetpack Compose, Python, Node.js, PHP and other packages each have their own licenses. Names and trademarks of supported exporters belong to their owners; compatibility references do not imply endorsement."},
  {title:"Permissions and contact",description:"Review the repository and individual dependency licenses. Contact the developer through official channels to request specific reuse or redistribution permissions."}
 ]},
 support:{title:"Support and contact",summary:"Get help without exposing private configuration data.",sections:[
  {title:"Downloads and verification",description:"Download stable APKs from GitHub Releases and verify SHA256SUMS.txt and SIGNATURE_VERIFICATION.txt. Preview versions are available separately with documented limitations."},
  {title:"Decoder failures",description:"Provide the SP-DECODE version, exact exporting app version, file suffix or text scheme, expected outcome and actual result. Submit sanitized logs or synthetic repro cases only."},
  {title:"Protect private information",description:"Decoded files can contain credentials and sensitive hosts. Never upload real samples to public issues or post unredacted screenshots. Contact the maintainer privately to coordinate a safe review."},
  {title:"Official channels",description:"Developer: Telegram @Gh0stDeveloper. Updates: @GhostDeve. Community: @CodeBreakersHub. Code and public issues: github.com/Gh0stDeveloper/SP-DECODE."}
 ]}
 }
};
const pt: Copy = {...es,
 nav:["Início","Recursos","Downloads","Suporte"],subheading:"Decodificador de configurações",eyebrow:"ANDROID NATIVO · OFFLINE",
 title:"Decodifique configurações. Diretamente no seu dispositivo.",
 hero:"Importe arquivos de VPN, proxy e túneis, decodifique links compatíveis e consulte os dados organizados. Sem conta, sem servidor e sem enviar seus arquivos à web.",
 stableCta:"Baixar APK estável",sourceCta:"Ver código-fonte",experimental:"A compatibilidade depende do formato e da versão do exportador.",
 trusted:"Assinatura V1/V2/V3",device:"Processamento local",formats:"60 extensões registradas",languages:"4 idiomas",
 previewImport:"Importar configuração",previewText:"Selecione um arquivo para análise local.",previewRecent:"Processamento offline",previewResult:"Prévia de resultado",previewOffline:"Sem Internet · Sem conta",previewDemo:"Interface ilustrativa · não decodifica arquivos aqui",
 sectionEyebrow:"RECURSOS",sectionTitle:"Tudo que importa, em um aplicativo",sectionText:"Privacidade, controle dos arquivos e resultados compreensíveis.",
 features:[
 {title:"Importação de arquivos",description:"Abra configurações pelo seletor do Android ou compartilhe arquivos de outro aplicativo."},
 {title:"Decodificação em lote",description:"Processe vários arquivos, com estados claros de sucesso e erro."},
 {title:"Textos e links",description:"Cole esquemas compatíveis como nm-ssh://, ar-ssh:// e Dark Tunnel, usando mecanismos específicos."},
 {title:"Resultados completos",description:"Veja JSON, campos aninhados e valores sem cortes arbitrários."},
 {title:"Copiar e exportar",description:"Compartilhe dados somente quando escolher copiar ou exportar."},
 {title:"Histórico protegido",description:"Consulte resultados armazenados localmente com os recursos de proteção do Android."},
 {title:"Privacidade por padrão",description:"Não exige permissão de Internet, conta ou serviço remoto para decodificar."},
 {title:"Interface multilíngue",description:"Espanhol, inglês, português brasileiro e árabe com layout RTL."},
 {title:"Desenvolvimento auditável",description:"Código, testes, versões e relatórios de assinatura disponíveis no GitHub."}],
 flowTitle:"Três passos, tudo local",flow:[
 {title:"01 · Importe",description:"Selecione um arquivo ou cole um link compatível."},
 {title:"02 · Decodifique",description:"O app identifica o formato e usa seu mecanismo local."},
 {title:"03 · Consulte",description:"Veja, copie ou exporte os dados sob seu controle."}],
 releaseTitle:"Download oficial",releaseText:"Distribuído pelo GitHub Releases com SHA-256 e relatório de assinatura.",
 stableLabel:"ESTÁVEL · v1.0.4",stableDesc:"Distribuição aprovada pelo responsável do projeto.",previewLabel:"PRÉVIA · v1.0.5-rc.1",previewDesc:"Melhorias Dark Tunnel e textos; testes reais adicionais pendentes.",
 download:"Abrir no GitHub",releaseNote:"A prévia v1.0.5 é assinada com a chave permanente, mas ainda não está aprovada como estável. As 60 rotas registradas não garantem todas as variantes.",
 techTitle:"Tecnologia e código verificável",techText:"Aplicativo Android em Kotlin e Jetpack Compose. O bot Telegram separado usa Python, Node.js e PHP. Código público para consulta; confira as condições de licença antes de reutilizar.",
 infoTitle:"Compatibilidade transparente",infoText:"60 extensões estão registradas, mas testes automatizados e sintéticos não garantem todas as variantes reais. Leia o relatório e envie casos anonimizados.",
 botTitle:"Também usa Telegram?",botText:"Há um bot modular separado para Termux ou VPS Linux. Diferente do app Android, os arquivos passam pelo servidor do operador e pelo Telegram.",
 botLink:"Explorar o bot",moreTitle:"Conheça o projeto",moreText:"Recursos, políticas, código, documentação e canais oficiais.",
 privacyLabel:"Privacidade",termsLabel:"Termos",licenseLabel:"Licença",supportLabel:"Suporte",featuresLabel:"Recursos",contactLabel:"Contato",report:"Relatar problema",legalNote:"Revisado em 9 de outubro de 2026. Textos informativos; revisão jurídica pode ser necessária.",footerNote:"Criado e mantido por Ghost Developer.",
 pages:{
 privacy:{title:"Política de privacidade",summary:"O site é informativo e não recebe configurações. O Android processa os dados localmente.",sections:[
 {title:"1. Dados no Android",description:"O app processa no dispositivo arquivos e links escolhidos por você. Não exige conta ou permissão de Internet. Resultados e histórico são geridos localmente. Ao copiar ou exportar, os dados chegam ao destino escolhido."},
 {title:"2. Este site",description:"Não há upload de arquivos, decodificador remoto ou login. O código não adiciona intencionalmente analytics de terceiros, anúncios ou cookies próprios de rastreamento."},
 {title:"3. Hospedagem",description:"A Vercel pode processar IP, cabeçalhos e logs técnicos para operação e segurança conforme suas políticas. Links externos podem aplicar políticas próprias."},
 {title:"4. Bot Telegram",description:"O bot é outro produto. Arquivos e mensagens passam pelo Telegram e pelo servidor operado por terceiros ou por você. As políticas do operador e do Telegram se aplicam."},
 {title:"5. Controle e retenção",description:"Como não recebe uploads, o site não armazena configurações enviadas por visitantes. No Android, use os controles disponíveis para gerenciar o histórico. Logs externos podem seguir outras regras."},
 {title:"6. Contato",description:"Perguntas podem ser encaminhadas a @Gh0stDeveloper no Telegram. Alterações importantes serão informadas aqui e no repositório."}]},
 terms:{title:"Termos e condições",summary:"Condições de uso do site, downloads e software SP-DECODE.",sections:[
 {title:"1. Uso permitido",description:"Analise apenas arquivos próprios ou com autorização expressa. Não use o aplicativo para acesso indevido ou violação de direitos."},
 {title:"2. Compatibilidade",description:"Formatos registrados e testes não garantem todas as variantes de exportação. Prévias não são versões estáveis."},
 {title:"3. Downloads oficiais",description:"As APKs e seus hashes e relatórios de assinatura são publicados no GitHub Releases. Verifique integridade e origem."},
 {title:"4. Informações sensíveis",description:"Resultados podem incluir senhas e servidores privados. Você decide o que copiar e compartilhar. Evite publicar dados reais."},
 {title:"5. Direitos e licenças",description:"Não existe licença geral no repositório concedendo ampla redistribuição. Componentes externos têm suas próprias licenças."},
 {title:"6. Mudanças",description:"Recursos e condições podem mudar. Contate Ghost Developer para permissões. Direitos legais obrigatórios permanecem aplicáveis."}]},
 license:{title:"Licenças e créditos",summary:"Estado atual de licença, sem prometer permissões não concedidas.",sections:[
 {title:"Código SP-DECODE",description:"O repositório Gh0stDeveloper/SP-DECODE não tem arquivo LICENSE geral. Código publicamente visível não equivale a autorização para copiar, modificar ou redistribuir sob MIT, GPL ou Apache. Solicite permissão."},
 {title:"Créditos",description:"Os materiais originais são atribuídos a Ghost Developer, respeitando possíveis direitos de terceiros."},
 {title:"Dependências",description:"Next.js, React, Tailwind CSS, Lucide, Kotlin, Compose, Python, Node.js e PHP têm licenças próprias. Marcas de aplicativos mencionados pertencem aos respectivos titulares."},
 {title:"Solicitar autorização",description:"Consulte o código e licenças individuais. Entre em contato com o desenvolvedor para licenças específicas."}]},
 support:{title:"Suporte e contato",summary:"Ajuda para instalação e compatibilidade, sem expor arquivos privados.",sections:[
 {title:"Download",description:"Baixe pelo GitHub Releases e confira SHA256SUMS.txt e SIGNATURE_VERIFICATION.txt."},
 {title:"Problemas de decodificação",description:"Informe versão do SP-DECODE, versão do exportador, extensão ou protocolo, comportamento esperado e observado, sem dados privados."},
 {title:"Privacidade",description:"Nunca publique configurações reais, chaves ou capturas sem censura. Combine com o mantenedor um canal seguro para amostras."},
 {title:"Canais",description:"Desenvolvedor @Gh0stDeveloper, canal @GhostDeve, comunidade @CodeBreakersHub e Issues no GitHub."}]}
 }
};
const ar: Copy = {...en,
 nav:["الرئيسية","المميزات","التنزيلات","الدعم"], subheading:"أداة فك ترميز الإعدادات",eyebrow:"أندرويد أصلي · دون اتصال",
 title:"افتح إعداداتك. محليًا على جهازك.",
 hero:"استورد ملفات إعدادات VPN والبروكسي والأنفاق، وافحص الروابط المدعومة والحقول المرتبة دون حساب أو خادم أو رفع الملفات إلى موقع ويب.",
 stableCta:"تنزيل APK المستقر",sourceCta:"عرض الشيفرة المصدرية",experimental:"يختلف التوافق باختلاف الصيغة وإصدار التطبيق المُصدّر.",
 trusted:"توقيع إنتاج V1/V2/V3",device:"معالجة محلية",formats:"60 امتدادًا مسجّلًا",languages:"4 لغات",
 previewImport:"استيراد إعداد",previewText:"اختر ملفًا لمعالجته على الجهاز.",previewRecent:"معالجة دون اتصال",previewResult:"معاينة النتيجة",previewOffline:"بدون إنترنت · بدون حساب",previewDemo:"واجهة توضيحية · لا تُعالج الملفات هنا",
 sectionEyebrow:"القدرات",sectionTitle:"الميزات الأساسية في تطبيق واحد",sectionText:"صُمم من أجل الخصوصية والتحكم والنتائج الواضحة.",
 features:[
 {title:"استيراد الملفات",description:"اختر الإعدادات عبر منتقي ملفات أندرويد أو شاركها مع التطبيق."},
 {title:"المعالجة المجمّعة",description:"عالج عدة ملفات مع التمييز بين النتائج الناجحة والأخطاء."},
 {title:"النصوص والروابط",description:"الصق روابط مدعومة مثل nm-ssh:// و ar-ssh:// و Dark Tunnel باستخدام محركات مخصصة."},
 {title:"نتائج كاملة",description:"استعرض JSON والحقول المتداخلة والقيم دون اقتطاع تعسفي."},
 {title:"النسخ والتصدير",description:"أخرج البيانات من التطبيق فقط عندما تختار نسخها أو تصديرها."},
 {title:"سجل محمي",description:"استعرض نتائج محفوظة محليًا باستخدام حماية تخزين أندرويد."},
 {title:"خصوصية افتراضية",description:"لا تحتاج عملية فك الترميز إلى إذن الإنترنت أو حساب أو خادم."},
 {title:"لغات متعددة",description:"الإسبانية والإنجليزية والبرتغالية البرازيلية والعربية مع اتجاه RTL."},
 {title:"تطوير قابل للمراجعة",description:"اطّلع على الشيفرة والاختبارات والإصدارات وتقارير التوقيع في GitHub."}],
 flowTitle:"ثلاث خطوات محلية",flow:[
 {title:"01 · الاستيراد",description:"اختر ملفًا أو الصق رابطًا مدعومًا."},
 {title:"02 · المعالجة",description:"يحدد التطبيق النوع ويشغل المحرك المحلي."},
 {title:"03 · المراجعة",description:"راجع البيانات أو انسخها أو صدّرها."}],
 releaseTitle:"التنزيل الرسمي",releaseText:"التوزيع عبر GitHub Releases مع ملفات SHA-256 وتقرير التوقيع.",
 stableLabel:"مستقر · v1.0.4",stableDesc:"توزيع معتمد من مالك المشروع.",previewLabel:"تجريبي · v1.0.5-rc.1",previewDesc:"تحسينات Dark Tunnel والنصوص؛ يلزم المزيد من الاختبارات الواقعية.",
 download:"فتح GitHub",releaseNote:"النسخة 1.0.5 التجريبية موقعة بمفتاح الإنتاج الدائم لكنها لم تُعتمد مستقرة. تسجيل 60 مسارًا لا يثبت توافق كل الإصدارات.",
 techTitle:"التقنيات والمصدر القابل للمراجعة",techText:"تطبيق أندرويد أصلي بـ Kotlin وJetpack Compose. يستخدم بوت Telegram المنفصل Python وNode.js وPHP. المصدر متاح للقراءة؛ راجع شروط الترخيص قبل إعادة استخدامه.",
 infoTitle:"وضوح بشأن التوافق",infoText:"هناك 60 امتدادًا مسجلًا، لكن الاختبارات الاصطناعية لا تضمن دعم جميع نسخ التصدير الواقعية. راجع التقرير وقدّم أمثلة منقحة.",
 botTitle:"هل تستخدم Telegram أيضًا؟",botText:"يتضمن المشروع بوت Telegram منفصلًا لـ Termux أو VPS. على خلاف تطبيق أندرويد، يعالج البوت الملفات عبر خادم المشغّل وTelegram.",
 botLink:"استكشف البوت",moreTitle:"تعرف على المشروع",moreText:"الميزات والسياسات والشيفرة والوثائق وقنوات الدعم.",
 privacyLabel:"الخصوصية",termsLabel:"الشروط",licenseLabel:"الترخيص",supportLabel:"الدعم",featuresLabel:"المميزات",contactLabel:"التواصل",report:"الإبلاغ عن مشكلة",legalNote:"آخر مراجعة: 9 أكتوبر 2026. هذه معلومات عن المشروع وقد تتطلب مراجعة قانونية قبل الاستخدام التجاري.",footerNote:"طُوّر ويُدار بواسطة Ghost Developer.",
 pages:{
 privacy:{title:"سياسة الخصوصية",summary:"هذا الموقع معلوماتي ولا يستقبل ملفات الإعدادات. يعالج تطبيق أندرويد الملفات محليًا.",sections:[
 {title:"1. بيانات التطبيق",description:"يعالج تطبيق أندرويد الملفات والروابط التي تختارها محليًا. لا يحتاج إلى حساب أو إذن إنترنت. تبقى النتائج والسجل على الجهاز؛ عند النسخ أو المشاركة ينتقل المحتوى إلى الوجهة التي تختارها."},
 {title:"2. بيانات الموقع",description:"لا يتضمن الموقع رفع ملفات أو أداة معالجة عن بُعد أو تسجيل دخول. لم نضف عمدًا تحليلات طرف ثالث أو إعلانات أو ملفات تعريف ارتباط للتتبع."},
 {title:"3. الاستضافة",description:"قد تعالج Vercel عناوين IP والترويسات وسجلات الوصول التقنية لتشغيل الموقع وحمايته وفق سياساتها. قد تطبق الروابط الخارجية سياسات خاصة."},
 {title:"4. بوت Telegram",description:"البوت منتج منفصل. تمر الرسائل والملفات عبر Telegram وخادم المشغل وتطبق سياسات كل منهما."},
 {title:"5. الاحتفاظ والتحكم",description:"لا يستقبل الموقع ملفات إعدادات للاحتفاظ بها. يمكن إدارة النتائج المحلية من التطبيق. لا يمكننا ضمان حذف السجلات لدى مزودي الخدمات الآخرين."},
 {title:"6. التواصل",description:"للأسئلة تواصل مع @Gh0stDeveloper عبر Telegram. سنحدّث هذه الصفحة عند إجراء تغييرات جوهرية."}]},
 terms:{title:"الشروط والأحكام",summary:"شروط استخدام الموقع والتنزيلات وبرنامج SP-DECODE.",sections:[
 {title:"1. الاستخدام المصرح",description:"حلّل فقط الملفات التي تملكها أو المصرّح لك بفحصها. لا تستخدم المشروع للوصول غير المصرح أو مخالفة القوانين."},
 {title:"2. التوافق",description:"لا يضمن تسجيل الصيغ أو نجاح الاختبارات دعم كل نسخ التصدير. الإصدارات التجريبية ليست مستقرة."},
 {title:"3. التنزيل",description:"تتوفر ملفات APK الرسمية وتقارير التوقيع وSHA-256 على GitHub Releases. تحقق من مصدرها وسلامتها."},
 {title:"4. البيانات الحساسة",description:"قد تتضمن النتائج كلمات مرور ومفاتيح وخوادم خاصة. أنت مسؤول عن مشاركة المحتوى المنسوخ أو المصدّر."},
 {title:"5. حقوق الشيفرة",description:"لا يوجد ترخيص عام للمشروع يسمح تلقائيًا بالنسخ والتعديل والتوزيع. للمكونات الخارجية تراخيصها الخاصة."},
 {title:"6. التغييرات",description:"قد تتغير الميزات والشروط. تواصل مع Ghost Developer للحصول على الأذونات دون المساس بالحقوق الإلزامية."}]},
 license:{title:"الترخيص والإسناد",summary:"الحالة الحالية لترخيص المشروع بشكل واضح.",sections:[
 {title:"شيفرة SP-DECODE",description:"لا يتضمن المستودع ملف LICENSE عامًا حاليًا. ظهور الشيفرة للعامة لا يمنح إذنًا تلقائيًا بإعادة استخدامها أو توزيعها بموجب MIT أو GPL أو Apache. اطلب الإذن من المطور."},
 {title:"الإسناد",description:"تُنسب المواد الأصلية إلى Ghost Developer مع احترام أي حقوق لأطراف أخرى."},
 {title:"اعتماديات خارجية",description:"تستخدم التقنيات مثل Next.js وReact وTailwind وLucide وKotlin وPython تراخيص مستقلة. أسماء التطبيقات والعلامات ملك لأصحابها."},
 {title:"الأذونات",description:"راجع المستودع وتراخيص المكونات، وتواصل مع المطور لطلب ترخيص محدد."}]},
 support:{title:"الدعم والتواصل",summary:"مساعدة في التنزيل والتوافق دون كشف إعدادات خاصة.",sections:[
 {title:"التنزيل والتحقق",description:"نزّل APK من GitHub Releases وتحقق من SHA256SUMS.txt وSIGNATURE_VERIFICATION.txt."},
 {title:"مشكلات الفك",description:"قدّم إصدار SP-DECODE وتطبيق التصدير والامتداد والخطوات والنتيجة المتوقعة دون أسرار."},
 {title:"حماية الخصوصية",description:"لا تنشر ملفات حقيقية أو مفاتيح أو صورًا غير منقحة في Issues. اتفق على قناة خاصة مع المطور."},
 {title:"القنوات",description:"المطور @Gh0stDeveloper، القناة @GhostDeve، المجتمع @CodeBreakersHub، والشيفرة على GitHub."}]}
 }
};
export const copy: Record<Locale, Copy> = { es, en, "pt-BR": pt, ar };

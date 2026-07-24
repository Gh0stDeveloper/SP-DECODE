const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { ArgumentParser } = require('argparse');

// Constantes y configuraciones
const DEFAULT_FILE_EXTENSION = '.tmt';

const KEY_LABELS = {
    "sshServer": "SSH Server",
    "sshPort": "SSH Port",
    "sshUser": "SSH User",
    "sshPass": "SSH Password",
    "sshPortLocal": "Local Port",
    "proxyPayload": "Proxy Payload",
    "sslHost": "SSL Host",
    "proxyRemotePort": "Remote Proxy",
    "proxyRemote": "Remote Proxy Port",
    "proxyuser": "Proxy User",
    "proxypass": "Proxy Password",
    "sslProtocol": "SSL Protocol",
    "sniHost": "SNI Host",
    "cUUID": "UUID",
    "dnspu": "PublicKey",
    "dnsnameserver": "DNS Name Server",
    "sshAllinOne": "SSH Field",
    "nameServer": "NameServer",
    "publickey": "PublicKey",
    "udpserver": "UDP Server",
    "dnsResolver": "Primary DNS",
    "udpResolver": "UDPGW",
    "up_mbps": "Upload Mbps",
    "down_mbps": "Download Mbps",
    "udpwindow": "QUIC Windows",
    "udpauth": "Authentication",
    "udpobfs": "Obfuscate",
    "sshPortaLocal": "Local Port",
    "v2rayprotocol": "V2ray protocol",
    "file.appVersionCode": "File App Version Code",
    "injectionmode": "Injection mode",
    "udpForward": "Udp Forward",
    "v2raytlsinsecure": "V2RAY tls insecure",
    "wakelock": "Wake lock",
    "speeddown": "Speed down",
    "blockroot": "Block root",
    "file.protect": "File protect",
    "speedup": "Speedup",
    "tunnelType": "Tunnel Type",
};

// Usando un objeto para almacenar múltiples contraseñas para '.ziv'
const PASSWORDS = {
    '.ziv': [Buffer.from('fubvx788b46v'), Buffer.from('SecurePart1SecurePart2SecurePart3SecurePart4SecurePart5')],
    '.tnl': [Buffer.from('B1m93p$$9pZcL9yBs0b$jJwtPM5VG@Vg')],
    '.pb': [Buffer.from('Cw1G6s0K8fJVKZmhSLZLw3L1R3ncNJ2e')],
    '.hqp': [Buffer.from('Ed')],
    '.hq': [Buffer.from('Ed')],
    '.bdi': [Buffer.from('@technore 2022')],
    '.NT': [Buffer.from('0x0')],
    '.pcx': [Buffer.from('cinbdf665$4')],
};

// Función para mostrar mensajes de error
function error(errorMsg = 'Corrupted/unsupported file.') {
    console.error(`\x1b[41m\x1b[30m X \x1b[0m ${errorMsg}`);
    process.exit(1);
}

// Configuración del parser de argumentos
const parser = new ArgumentParser();
parser.add_argument('file', { help: 'file to decrypt' });
parser.add_argument('--output', '-o', { help: 'file to output to' });
parser.add_argument('--stdout', '-O', { action: 'store_true', help: 'output to stdout', default: true });

const args = parser.parse_args();

const encryptedContents = fs.readFileSync(args.file);
const fileExt = path.extname(args.file);

if (!PASSWORDS[fileExt]) {
    console.warn(`Unknown file extension, defaulting to ${DEFAULT_FILE_EXTENSION}`);
}

const splitBase64Contents = encryptedContents.toString().split('.');
const splitContents = splitBase64Contents.map(part => Buffer.from(part, 'base64'));

// Intentar descifrar usando cada contraseña disponible para la extensión
let decryptedContents = null;

for (const password of PASSWORDS[fileExt]) {
    try {
        const decryptionKey = crypto.pbkdf2Sync(password, splitContents[0], 10000, 32, 'sha256');
        const decipher = crypto.createDecipheriv('aes-256-gcm', decryptionKey, splitContents[1]);

        const tag = splitContents[2].slice(-16); // El último bloque como tag
        const encryptedData = splitContents[2].slice(0, -16); // Los datos cifrados

        decryptedContents = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

        // Verificación de autenticidad
        decipher.setAuthTag(tag);
        decipher.final(); // Lanza error si el tag no coincide

        break; // Si se descifra correctamente, salir del bucle
    } catch (err) {
        continue; // Intentar con la siguiente contraseña
    }
}

if (!decryptedContents) {
    error('Failed to decrypt the file with available passwords.');
}

// Salida de datos descifrados
if (args.stdout) {
    const config = decryptedContents.toString('utf-8', 'ignore');
    let message = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.ziv)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n";
    const configDict = {};

    config.split('\n').forEach(line => {
        if (line.startsWith('<entry')) {
            line = line.replace('<entry key="', '').replace('</entry', '');
            const parts = line.split('">');
            if (parts.length > 1) {
                configDict[parts[0]] = parts[1].trim();
            } else {
                configDict[parts[0].trim()] = "";
            }
        }
    });

    for (const [key, label] of Object.entries(KEY_LABELS)) {
        if (configDict[key]) {
            const value = configDict[key].trim();
            if (value && value !== "0" && value !== "*******") {
                message += `│[۞] ${label}: ${value}\n`;
            }
        }
    }

    message += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @DecryptSP \n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @TEAM_CHICO_CP\n└───────────────\n";
    console.log(message);
}
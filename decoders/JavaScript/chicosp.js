#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const PROJECT_ROOT = path.resolve(__dirname, '../..');
const mainUtils = require(path.join(PROJECT_ROOT, 'lib/mainUtils'));
var configFile;
var languageFile;
var layoutFile;
var outputType = 0;
var showHelp = false;
var alreadyPrinted = false; // Bandera para controlar la impresión duplicada

// Leyendo todas las bibliotecas de decodificación
var libMethodsDirListArray = fs.readdirSync(path.join(PROJECT_ROOT, "lib/methods"));
var libMethodsArray = [];
for (let c = 0; c < libMethodsDirListArray.length; c++) {
    if (path.parse(libMethodsDirListArray[c]).ext == ".js") {
        libMethodsArray.push(require(path.join(PROJECT_ROOT, "lib/methods", libMethodsDirListArray[c])));
    }
}

// Leer el archivo de configuración
try {
    configFile = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "cfg/config.inc.json")));
} catch (error) {
    console.log("[ERROR] - Hubo un error al cargar el archivo de configuración en el módulo " + path.parse(__filename)["base"]);
    process.exit();
}

// Leer el archivo de idioma
try {
    languageFile = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "cfg/lang", configFile["language"] + ".lang.json")));
} catch (error) {
    console.log("[ERROR] - Hubo un error al cargar el archivo de idioma.");
    process.exit();
}

// Leer el archivo de diseño
try {
    layoutFile = JSON.parse(fs.readFileSync(path.join(PROJECT_ROOT, "cfg/layout", configFile["layout"] + ".layout.json")));
} catch (error) {
    console.log("[ERROR] - Hubo un error al cargar el archivo de diseño.");
    process.exit();
}

// Procesar los argumentos
for (let c = 0; c < process.argv.length; c++) {
    switch (process.argv[c]) {
        case "--keyFile":
        case "-k":
            console.log("[INFO] - La ruta de tu nuevo archivo de clave se guardó automáticamente en el archivo de configuración principal.");
            configFile["keyFile"] = process.argv[c + 1];
            break;
        case "--language":
        case "-l":
            console.log("[INFO] - Tu nueva preferencia de idioma se guardó automáticamente en el archivo de configuración principal.");
            configFile["language"] = process.argv[c + 1];
            break;
        case "--raw":
        case "-r":
            outputType = 1;
            break;
        case "--json":
        case "-j":
            outputType = 2;
            break;
        case "--help":
        case "-h":
            showHelp = true;
            break;
    }
}

if (showHelp) {
    var helpContent = [
        "Usage: node script.js [--args -a...]",
        "",
        "--keyFile, -k\t\tEspecificar una ruta exacta para un archivo de clave personalizado",
        "--language, -l\t\tConfigurar un idioma personalizado para la salida/resultados de la consola",
        "--raw, -r\t\tMostrar solo la salida RAW (sin ningún tipo de análisis)",
        "--json, -j\t\tMostrar solo la salida JSON",
        "--help, -h\t\tMostrar este texto de ayuda"
    ];
    for (let c = 0; c < helpContent.length; c++) {
        console.log(helpContent[c]);
    }
    process.exit();
}

// Función de ciclo
function loopFunction() {
    try {
        fs.writeFileSync(path.join(PROJECT_ROOT, "cfg/config.inc.json"), JSON.stringify(configFile, null, "\t"));
    } catch (error) {
        console.log("[ERROR] - Ocurrió un error al escribir el archivo de configuración.");
        process.exit();
    }
}

loopFunction(); // Actualizar con los últimos cambios desde cmd

// Iniciar el proceso de desencriptación
console.log();
if (!fs.existsSync(process.argv[process.argv.length - 1])) {
    console.log("[ERROR] - " + languageFile["invalidFile"]);
    process.exit();
}

var decryptionStage;
for (let c = 0; c < libMethodsArray.length; c++) {
    if (libMethodsArray[c] && libMethodsArray[c].metadata && libMethodsArray[c].metadata.schemeLength) {
        for (let d = 0; d < libMethodsArray[c].metadata["schemeLength"]; d++) {
            decryptionStage = libMethodsArray[c].decryptFile(fs.readFileSync(process.argv[process.argv.length - 1]), configFile, d);
            if (decryptionStage["error"] != 1) { break; }
        }
    }

    if (path.parse(process.argv[2]).ext != ".nm" & path.parse(process.argv[2]).ext != ".ehil" & path.parse(process.argv[2]).ext != ".hat" & path.parse(process.argv[2]).ext != ".ePro" & path.parse(process.argv[2]).ext != ".hc" & path.parse(process.argv[2]).ext != ".ehi" & path.parse(process.argv[2]).ext != ".npv2" & path.parse(process.argv[2]).ext != ".zxc" & path.parse(process.argv[2]).ext != ".sksplus") {
        return;
    }
    if (decryptionStage["error"] != 1) { break; }
}

if (decryptionStage["error"] == 1) {
    console.log("[ERROR] - " + languageFile["decryptionFailed"]);
    process.exit();
}

// Empezar a procesar la salida
switch (outputType) {
    case 1:
        console.log(decryptionStage["raw"]);
        break;
    case 2:
        console.log(decryptionStage["content"]);
        break;
    default:
        if (!alreadyPrinted) { // Evitar impresión doble
            console.log(mainUtils.jsonResponseParsing(decryptionStage["content"], languageFile, layoutFile));
            alreadyPrinted = true;
        }
        break;
}

process.exit();
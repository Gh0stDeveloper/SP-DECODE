const fs = require('fs');
const crypto = require('crypto');

// Definisi key
const key = Buffer.from('zbNkuNCGSLivpEuep3BcNA==', 'base64');

// Fungsi untuk melakukan dekripsi AES
function aesDecrypt(data, key) {
    const aesoutp2 = crypto.createDecipheriv("aes-128-ecb", key, null);
    let result = aesoutp2.update(data, "base64", "utf8");
    result += aesoutp2.final("utf-8");
    return result;
}

function xor(plaintext, key = '**rVg7EkL~c2`D[aNn') {
    const keyLength = key.length;
    let cipherAscii = '';
    for (let i = 0; i < plaintext.length; i++) {
        cipherAscii += String.fromCharCode(plaintext.charCodeAt(i) ^ key.charCodeAt(i % keyLength));
    }
    return cipherAscii;
}

// Fungsi untuk mengurai data yang telah di-dekripsi
function parseDecoded(data) {
    var xd, xdKeys;
    var uwu = {};
    try {
        xd = JSON.parse(data);
        xdKeys = Object.keys(xd);
    } catch(error) {}

    // Definisi objek untuk menyimpan informasi terdekripsi
    var decryptedInfo = "\n┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (.hat)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n";

    var connectionMode = [
        "Direct Connection",
        "Custom Payload (TCP)",
        "Custom Host Header (HTTP)",
        "Custom SNI (SSL/TLS)",
        "Imported Config"
    ];

    var connectionMode2 = [
        "SSH",
        "SSL + SSH"
    ];
    var nodeMappings = {
        'xx': 'Random Server, Any Location 🌍',
        'us': 'United States, New York 🇺🇸',
        'ca': 'Canada, Montréal 🇨🇦',
        'de': 'Germany, Frankfurt 🇩🇪',
        'uk': 'United Kingdom, London 🇬🇧',
        'nl': 'Netherlands, Amsterdam 🇳🇱',
        'fr': 'France, Paris 🇫🇷',
        'at': 'Vienne, Austria 🇦🇹',
        'au': 'Australia, Tasmania 🇦🇺',
        'br': 'Brazil, Sao-Paulo 🇧🇷',
        'sg': 'Singapore, Simpang 🇸🇬',
        'in': 'India, Bangalore 🇮🇳',
        'gb': 'Game | EU 🎮'
    };
    const layoutFile = fs.readFileSync("nodehat.json");
    const layout = JSON.parse(layoutFile);

    if (!!xd["configuration"]) {
        uwu["connectionMethod"] = connectionMode2[xd["configuration"]["connection_mode"]];
        uwu["usePayload"] = xd["configuration"]["using_http_headers"];
        uwu["payload"] = xd["configuration"]["http_headers"];
        uwu["aotServerGroup"] = xd["configuration"]["server_group_host"];
        uwu["enableHTTPProxy"] = xd["configuration"]["using_proxy"];
        uwu["aotUseHostAsProxy"] = xd["configuration"]["using_server_hosted_proxy"];
        uwu["proxyAddress"] = xd["configuration"]["proxy_host"];
        uwu["proxyPort"] = xd["configuration"]["proxy_port"];
        uwu["aotServerPort"] = xd["configuration"]["aotServerPort"];
        uwu["useSSL"] = xd["configuration"]["using_advssl"];
        uwu["sniValue"] = xd["configuration"]["adv_ssl_spoofhost"];
        uwu["serverPort"] = xd["configuration"]["adv_ssl_spoofport"];
        uwu["udpgwPort"] = xd["configuration"]["vpn_udpgw_port"];
        uwu["sshServer"] = xd["configuration"]["server_host"];
        uwu["sshUser"] = xd["configuration"]["server_username"];
        uwu["sshPassword"] = xd["configuration"]["server_password"];
    }

    if (!!xd["meta"]) {
        uwu["note1"] = xd["meta"]["meta_vendor_msg"];
    }

    if (!!xd["profile"]) {
        uwu["connectionMethod"] = connectionMode[xd["profile"]["connection_mode"]];
        uwu["payload"] = xd["profile"]["custom_payload"];
        uwu["hostHeader"] = xd["profile"]["custom_host"];
        uwu["sniValue"] = xd["profile"]["custom_sni"];
        uwu["aotRealmHost"] = xd["profile"]["use_realm_host"] ? xd["profile"]["realm_host"] : '';
        uwu["aotRealmHostValue"] = xd["profile"]["realm_host"];
        uwu["aotOverrideHost"] = xd["profile"]["override_primary_host"] ? xd["profile"]["primary_host"] : '';
        uwu["aotPrimaryHost"] = xd["profile"]["primary_host"];
        uwu["serverPort"] = xd["profile"]["server_port"] ? xd["profile"]["server_port"].toString() : '';
        uwu["aotNode"] = xd["profile"]["primary_node"];
        uwu["aotBaseTunnel"] = xd["profile"]["base_tunnel"];
    }

    if (!!xd["description"]) {
        uwu["note1"] = xd["description"];
    }

    if (!!xd["profilev4"]) {
        uwu["connectionMethod"] = connectionMode[xd["profilev4"]["connection_mode"]];
        uwu["payload"] = xd["profilev4"]["custom_payload"];
        uwu["hostHeader"] = xd["profilev4"]["custom_host"];
        uwu["sniValue"] = xd["profilev4"]["custom_sni"];
        uwu["aotRealmHost"] = xd["profilev4"]["use_realm_host"] ? xd["profilev4"]["realm_host"] : '';
        uwu["aotRealmHostValue"] = xd["profilev4"]["realm_host"];
        uwu["aotOverrideHost"] = xd["profilev4"]["override_primary_host"] ? xd["profilev4"]["primary_host"] : '';
        uwu["aotPrimaryHost"] = xd["profilev4"]["primary_host"];
        uwu["serverPort"] = xd["profilev4"]["server_port"] ? xd["profilev4"]["server_port"].toString() : '';
        uwu["aotNode"] = xd["profilev4"]["primary_node"];
        uwu["aotBaseTunnel"] = xd["profilev4"]["base_tunnel"];
    }

    if (!!xd["descriptionv4"]) {
        uwu["note1"] = xd["descriptionv4"];
    }

    if (!!xd["profilev5"]) {
        uwu["connectionMethod"] = xor(Buffer.from(xd["profilev5"]["connection_mode"], 'base64').toString());
        uwu["payload"] = xor(Buffer.from(xd["profilev5"]["custom_payload"], 'base64').toString());
        uwu["hostHeader"] = xor(Buffer.from(xd["profilev5"]["custom_host"], 'base64').toString());
        uwu["sniValue"] = xor(Buffer.from(xd["profilev5"]["custom_sni"], 'base64').toString());
        uwu["customresolver"] = xd["profilev5"]["custom_resolver"];
        uwu["dnsprimaryhost"] = xd["profilev5"]["dns_primary_host"];
        uwu["aotRealmHost"] = xd["profilev5"]["use_realm_host"] ? xd["profilev5"]["realm_host"] : '';
        uwu["aotRealmHostValue"] = xd["profilev5"]["realm_host"];
        uwu["aotOverrideHost"] = xd["profilev5"]["override_primary_host"] ? xd["profilev5"]["primary_host"] : '';
        uwu["aotPrimaryHost"] = xd["profilev5"]["primary_host"];
        uwu["serverPort"] = xd["profilev5"]["server_port"] ? xd["profilev5"]["server_port"].toString() : '';
        uwu["aotNode"] = xd["profilev5"]["primary_node"];
        uwu["aotBaseTunnel"] = xd["profilev5"]["base_tunnel"];
    }

    if (!!xd["descriptionv5"]) {
        uwu["note1"] = xd["descriptionv5"];
    }

    if (!!xd["protextras"]) {
        try { uwu["antiSniff"] = xd["protextras"]["anti_sniff"].toString() } catch(e) {};
        try { uwu["mobileData"] = xd["protextras"]["mobile_data"].toString() } catch(e) {};
        try { uwu["blockRoot"] = xd["protextras"]["block_root"].toString() } catch(e) {};
        try { uwu["passwordProtected"] = xd["protextras"]["password"].toString() } catch(e) {};
        try { uwu["cryptedPasswordValueMD5"] = xd["protextras"]["password_value"].toString() } catch(e) {};
        try { uwu["hwidEnabled"] = xd["protextras"]["id_lock"].toString() } catch(e) {};
        try { uwu["cryptedHwidValueMD5"] = xd["protextras"]["id_lock_value"].toString() } catch(e) {};
        try { uwu["enableExpire"] = xd["protextras"]["expiry"].toString() } catch(e) {};
        try { uwu["expireDate"] = new Date(xd["protextras"]["expiry_value"]).toUTCString() } catch(e) {};
    }
    
    if (!!uwu["aotNode"] && nodeMappings[uwu["aotNode"]]) {
        uwu["aotNode"] = nodeMappings[uwu["aotNode"]];
    }
    
    // Menyusun informasi terdekripsi sesuai dengan format yang diinginkan
    Object.keys(layout).forEach(key => {
        if (xd[key]) {
            uwu[key] = xd[key];
        }
    });

    // Menambahkan akhir konten
    
    Object.entries(uwu).forEach(([key, value]) => {
        decryptedInfo += `│[۞] ${layout[key]}${value}\n`;
    });

    // Mengembalikan informasi terdekripsi
    return decryptedInfo;
}

function decryptStage(data) {
    var complete = false;
    var response = {};
    response["content"] = '';    

    // Tahap dekripsi
    try {
        const decryptedData = aesDecrypt(data, key);
        if (decryptedData.indexOf("{\"") !== -1) {
            complete = true;
            response["content"] = parseDecoded(decryptedData);
        }
    } catch (error) {
        console.error(error);
    }
     
    response["content"] += "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n";

    return response;
}

const args = process.argv.slice(2);

// Pastikan argumen yang diberikan sesuai
if (args.length !== 1) {
    console.log('Penggunaan: node hat.js <nama_file_input>');
    process.exit(1);
}

// Baca file input dari argumen baris perintah
const inputFile = args[0];

// Baca file input
fs.readFile(inputFile, 'utf8', (err, data) => {
    if (err) {
        console.error(`Terjadi kesalahan saat membaca file: ${err}`);
        return;
    }
    
    // Lakukan dekripsi tahap
    const decryptedData = decryptStage(data);

    // Output hasil dekripsi
    console.log(decryptedData.content);
});

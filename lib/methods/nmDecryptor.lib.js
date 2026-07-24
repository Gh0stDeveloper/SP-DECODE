const metadata = {
    "title":"nmDecryptor",
    "author":"HACK_K, Abdoxfox",
    "version":1,
    "schemeLength":4
}
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
module.exports.metadata = metadata;
function aesDecrypt(data, key) {
    //aes but with raw data
    //data = receives b64 data
    //key = buffered sha1 value
    const aesoutp2 = crypto.createDecipheriv("aes-128-ecb", key, null);
    var result = aesoutp2.update(data, "base64", "utf8");
    result += aesoutp2.final("utf-8");
    return result;
}
function parseDecoded(data) {
    //made with tears
    /*
    * ok so, there's a high chance that profile and profilev4 sand so one are from different versions of Art Of Tunnel apps
    * whatever, i'm going to see if i can do black magic with this theory
    */
    var xd, xdKeys;
    var ex = {};
    try {
        xd = JSON.parse(data);
        xdKeys = Object.keys(xd);
    } catch(error) {}
    var connectionMode = [
        "Direct Connection", //probably unused
        "Custom Payload (TCP)",
        "Custom Host Header (HTTP)",
        "Custom SNI (SSL/TLS)",
        "Imported Config" //probably unused
    ];
    var connectionMode2 = [
        "SSH",
        "SSL + SSH"
    ]
    var haNodes = [
        //remind me to fill this one
    ];
    console.log(xd)
    console.log("\r\n")
    console.log("Decrypted By => LEGEND ✓\r\n")
    return 0;
}
function decryptStage(filecontent, configFile) {
    //reeeeeeeeeeeeeeeeeeeeeeeee
    var keyFile;
    var complete = false;
    var response = {};
    response["content"] = "";
    response["raw"] = "";
    response["error"] = 0;
    try {
        keyFile = JSON.parse(fs.readFileSync(configFile["keyFile"]).toString())["nm"];
    } catch(error) {
        response["error"] = 1;
        return response;
    }
    //decrypting stage
    for(let c = 0; c < keyFile.length; c++) {
        key = Buffer.from(keyFile[c], "base64");
        try {
            response["content"] = aesDecrypt(filecontent.toString(), key);
            if(response["content"].indexOf("{\"") == -1) {
                throw "err"; 
            }
            complete = true;
        } catch(error) {}
    }
    if(complete) {
        response["raw"] = response["content"];
        response["content"] = parseDecoded(response["content"]);
        //return;
        return response;
    } else {
        //response["content"] = parseDecoded(response["content"]); //please comment this one once finished
        response["error"] = 1;
        return response;
    }
}
module.exports.decryptFile = function(file, configFile, type) {
    // This function acts like a "hub" between the decoding methods, less fashioned that the other solution, but hopefully can work.
    var defaultApiError = {};
    defaultApiError["content"] = "";
    defaultApiError["raw"] = "";
    defaultApiError["error"] = 1;
    switch(type) {
        case 0:
            return decryptStage(file, configFile);
        default:
            return defaultApiError;
    }
}

const fs = require('fs');
const path = require('path');
var configFile;
try {
    configFile = JSON.parse(fs.readFileSync(__dirname + "/../cfg/config.inc.json"));
} catch(error) {
    console.log("[ERROR] - There was an error while loading config file at module " + path.parse(__filename)["base"]);
    process.exit();
}
module.exports.jsonResponseParsing = function(jsonText, languageObject, layoutObject) {
    let jsonObject;
    let jsonProperties;
    let response = layoutObject["header"];
    try {
        jsonObject = JSON.parse(jsonText);
        jsonProperties = Object.keys(jsonObject);
    } catch(error) {
        console.log("[ERROR] - There was an error while parsing JSON text at module " + path.parse(__filename)["base"]);
    }
    for(let c = 0; c < jsonProperties.length; c++) {
        if(languageObject["_" + jsonProperties[c]]) {
            if(jsonObject[jsonProperties[c]].length >= 1) {
                response += layoutObject["propertyIndicator"] + " " + languageObject["_" + jsonProperties[c]] + "" + jsonObject[jsonProperties[c]] + "\r\n";
            }
        }
    }
 //   response += layoutObject["footer"];
    return response;
}
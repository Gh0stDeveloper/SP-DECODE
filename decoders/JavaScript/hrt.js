// DEVELOPED BY: @Gh0stDeveloper
// DATE: January 2025
// PROGRAM: Created with pride in Mexico (Country Flag) 
// DESCRIPTION: This script showcases the dedication and expertise of its developer.

const crypto = require('crypto');
const fs = require('fs');

function generateKey() {
    const password = "Radz_11_2021";
    return crypto.createHash('sha256').update(password).digest();
}

function aesDecrypt(base64EncodedCiphertext) {
    try {
        const ciphertext = Buffer.from(base64EncodedCiphertext, 'base64');
        const key = generateKey();
        const iv = Buffer.alloc(16, 0);
        const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);

        let decrypted = decipher.update(ciphertext, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        console.error("Decryption error:", error.message);
        return null;
    }
}

function decodeBase64InJson(jsonObj) {
    for (const [key, value] of Object.entries(jsonObj)) {
        if (typeof value === 'string') {
            try {
                const decodedValue = Buffer.from(value, 'base64').toString('utf8');
                if (decodedValue) {
                    jsonObj[key] = decodedValue;
                }
            } catch (error) {
                // Silently ignore errors
            }
        } else if (typeof value === 'object' && value !== null) {
            decodeBase64InJson(value);
        }
    }
    return jsonObj;
}

function main(args) {
    if (args.length !== 3) {
        console.error("Usage: node script.js file.jez");
        process.exit(1);
    }

    const filePath = args[2];

    try {
        if (!fs.existsSync(filePath)) {
            throw new Error(`File ${filePath} not found.`);
        }

        const base64EncodedCiphertext = fs.readFileSync(filePath, 'utf8').trim();
        const plaintext = aesDecrypt(base64EncodedCiphertext);

        if (plaintext) {
            try {
                const jsonData = JSON.parse(plaintext);

                decodeBase64InJson(jsonData);

                const filteredData = {};
                for (const [key, value] of Object.entries(jsonData)) {
                    filteredData[`│[۞] ${key}`] = ` : ${typeof value === 'object' ? JSON.stringify(value) : value}`;
                }

                let formattedResult = "\n┌───────────────\n";
                formattedResult += "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (hrt)\n";
                formattedResult += "│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n";
                formattedResult += "├───────────────\n";

                for (const [key, value] of Object.entries(filteredData)) {
                    formattedResult += `${key}${value}\n`;
                }

                formattedResult += "├───────────────\n";
                formattedResult += "│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n";
                formattedResult += "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n";
                formattedResult += "└───────────────\n";

                console.log(formattedResult);
            } catch (error) {
                console.error("Error:", error.message);
            }
        } else {
            console.error("Decryption failed.");
        }
    } catch (error) {
        console.error("Error:", error.message);
    }
}

if (require.main === module) {
    main(process.argv);
}
const fs = require(`fs`);

function xor(b64text, key = '**rVg7EkL~c2`D[aNn') {
    var plaintext = Buffer.from(b64text, `base64`).toString()
    var keyLength = key.length;
    var cipherAscii = '';

    for (var i = 0; i < plaintext.length; i++) {
        var left = plaintext.charCodeAt(i)
        var right = key.charCodeAt(i % keyLength);
        console.log("left: ", left, "right: ", right);
        // process.stdout.write((left ^ right).toString() + "\n");
        cipherAscii += String.fromCharCode(left ^ right);
    }
    // process.exit();

    return cipherAscii;
}

const profileInfo = {
    customPayload: "bW8mdkjwn7G08Keks/Cit67wkbeq8KyUo/Clh4jwpra58Je3u/Cot6HwkKeS8KengvCit7DwnqGR6qu3eykaOnoFQ3hWbCkNETYMQRR+OQAiD0RJFzcDWDdFPw4GVwQ9Ng44B0YEETkKGSgTYwwGVgk2PgI6VBIaKToBagYEIhAGURQtNA90TklGHSUCbCYZIBg+ak0CNBM5D1hOFzJKcSpRLh8PUw4nPgAqAVgEASYCUiESIREVWwxqOA4jQEdSXSQCUywZKR0XCFh0AA0oM2lFHCICWTFGABsNVRQsYUF3VxMTS29eDnxL8KGBj+qrkPCRtJ/wrJeW8KWHhE7wl7WS8KG3kPCkpqTwrIei8K6XuPClpqXwpZeK8KunsvChoZ/qqpkgMTkJWSAIOBcMXFpk8KSxkOqrvfCmtZXwl7e/8Ki3rRfwrIST8K6XuPClpqHwpZeN8Kunp/Cut7nwl7ak8KG3hfCrsIbqq7YwIBg+aQwiBg=="
};

const base64CustomPayload = profileInfo.customPayload;
const result = xor(base64CustomPayload);

console.log(result);
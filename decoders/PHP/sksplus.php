<?php
// DEVELOPED BY: @Gh0stDeveloper
// DATE: January 2025
// PROGRAM: Created with pride in Mexico (Country Flag) 
// DESCRIPTION: This script showcases the dedication and expertise of its developer.
 
function decrypt_data($key, $iv, $ciphertext) {
    $decrypted = openssl_decrypt(
        $ciphertext,
        'aes-256-cbc',
        $key,
        OPENSSL_RAW_DATA,
        $iv
    );

    if ($decrypted === false) {
        throw new Exception("Error durante el descifrado");
    }

    return $decrypted;
}

function read_json_file($file_path) {
    if (!file_exists($file_path)) {
        throw new Exception("El archivo no existe: $file_path");
    }

    $json_data = file_get_contents($file_path);
    $data = json_decode($json_data, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Error al decodificar JSON: " . json_last_error_msg());
    }

    return $data;
}

function format_output($data) {
    $formatted = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (sksplus)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────\n";

    foreach ($data as $key => $value) {
        if (is_array($value)) {
            $value = implode(", ", $value);
        }
        $formatted .= "│[۞] $key : $value\n";
    }

    $formatted .= "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n└───────────────\n";
    return $formatted;
}

try {
    if ($argc !== 2) {
        throw new Exception("Uso: php decode.php <ruta_del_archivo>");
    }

    $file_path = $argv[1];

    $key = hex2bin("6237376365303534616164623839653963313064633430656265393735323631");

    $data = read_json_file($file_path);
    $iv = array_map(fn($x) => $x < 0 ? $x + 256 : $x, $data['payload']['iv']);
    $iv = implode(array_map("chr", $iv));

    $encoded = array_map(fn($x) => $x < 0 ? $x + 256 : $x, $data['payload']['encoded']);
    $ciphertext = implode(array_map("chr", $encoded));

    $decrypted_data = decrypt_data($key, $iv, $ciphertext);

    $json_data = json_decode($decrypted_data, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception("Error al decodificar los datos descifrados: " . json_last_error_msg());
    }

    $formatted_output = format_output($json_data);
    echo $formatted_output . PHP_EOL;

} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . PHP_EOL;
    exit(1);
}
?>
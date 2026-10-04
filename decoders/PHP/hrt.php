<?php

function generate_key() {
    $password = "Radz_11_2021";
    return hash("sha256", $password, true);
}

function aes_decrypt($base64_encoded_ciphertext) {
    try {
        $ciphertext = base64_decode($base64_encoded_ciphertext);
        $key = generate_key();
        $iv = str_repeat("\0", 16);
        $decrypted_data = openssl_decrypt($ciphertext, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
        
        if ($decrypted_data === false) {
            throw new Exception("Error during decryption");
        }
        
        return $decrypted_data;
    } catch (Exception $e) {
        echo "Decryption error: " . $e->getMessage() . PHP_EOL;
        return null;
    }
}

function decode_base64_in_json(&$json_obj) {
    foreach ($json_obj as $key => $value) {
        if (is_string($value)) {
            try {
                $decoded_value = base64_decode($value, true);
                if ($decoded_value !== false) {
                    $json_obj[$key] = $decoded_value;
                }
            } catch (Exception $e) {
            }
        } elseif (is_array($value)) {
            decode_base64_in_json($json_obj[$key]);
        }
    }
    return $json_obj;
}

function main($argc, $argv) {
    if ($argc != 2) {
        echo "Usage: php script.php file.jez" . PHP_EOL;
        exit(1);
    }

    $file_path = $argv[1];

    try {
        if (!file_exists($file_path)) {
            throw new Exception("File $file_path not found.");
        }

        $base64_encoded_ciphertext = trim(file_get_contents($file_path));
        $plaintext = aes_decrypt($base64_encoded_ciphertext);

        if ($plaintext) {
            try {
                $json_data = json_decode($plaintext, true);

                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new Exception("JSON parsing error: " . json_last_error_msg());
                }

                decode_base64_in_json($json_data);

                $filtered_data = [];
                foreach ($json_data as $key => $value) {
                    $filtered_data["│[۞] $key"] = " : " . (is_array($value) ? json_encode($value) : (string)$value);
                }
                
                $formatted_result = "\n┌───────────────\n";
                $formatted_result .= "│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (hrt)\n";
                $formatted_result .= "│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n";
                $formatted_result .= "├───────────────\n";

                foreach ($filtered_data as $key => $value) {
                    $formatted_result .= $key . $value . PHP_EOL;
                }

                $formatted_result .= "├───────────────\n";
                $formatted_result .= "│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub\n";
                $formatted_result .= "│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeve\n";
                $formatted_result .= "└───────────────\n";

                echo $formatted_result;

            } catch (Exception $e) {
                echo "Error: " . $e->getMessage() . PHP_EOL;
            }
        } else {
            echo "Decryption failed." . PHP_EOL;
        }
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . PHP_EOL;
    }
}

if (php_sapi_name() === 'cli') {
    main($argc, $argv);
}
?>
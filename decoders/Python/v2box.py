import telebot
import base64
from urllib.parse import urlparse, parse_qs


API_TOKEN = 'No quiero actualizar mis tokens xD'
bot = telebot.TeleBot(API_TOKEN)
bot.remove_webhook()


@bot.message_handler(func=lambda message: message.text.startswith("v2box://"))
def decode_v2box(message):
    try:
        encoded_part = message.text.split("locked=")[1]

        decoded_part = base64.b64decode(encoded_part).decode('utf-8')

        parsed_url = urlparse(decoded_part)
        params = parse_qs(parsed_url.query)

        Y = "┌───────────────\n│𝗦𝗣 - 𝗗𝗘𝗖𝗢𝗗𝗘 (v2box)\n│𝗗𝗘𝗩𝗘𝗟𝗢𝗣𝗘𝗥 : https://bit.ly/3TOrZEu\n├───────────────"
        X = ""
        for key, value in params.items():
            X += f"│[۞] {key}: {', '.join(value)}\n"
        Z = "├───────────────\n│[۞] 𝗚𝗥𝗢𝗨𝗣 : @CodeBreakersHub \n│[۞] 𝗖𝗛𝗔𝗡𝗡𝗘𝗟 : @GhostDeveloperSpy\n└───────────────\n"

        response = f"{Y}\n{X}{Z}"
        bot.reply_to(message, response)

    except Exception as e:
        bot.reply_to(message, f"Error al decodificar: {str(e)}")

print("Bot ejecutándose...")
bot.infinity_polling()

# Android — Telegram clipboard format and transient Home results

**Scope:** UI and clipboard only. No VPN decryption algorithm, imported file, network permission, or encrypted history record is modified.

## Copy vs export

The **Copy → JSON** option now copies a complete Telegram-oriented text message:
- Plain, human-readable comments above the code fence, matching the result card's attribution: decoded by SP-DECODE, original decoding date and Powered by Ghost Developer
- Additional attribution to `@AES224` and `@Gh0stDeveloper`
- A blank line, then `\`\`\`json` on its own line, **complete, unmasked, pretty, typed JSON**, and a closing `\`\`\`` code fence
- The JSON payload uses the same normalization as the full Home result preview (`ResultJsonDisplay.render`), including nested objects, arrays, numbers, nulls and multiline HTTP payload strings.

The **Copy → Original decoder text** option puts the same plain-text credits before the unmodified original decoder response. **Copy → Structured** keeps the existing built-in attribution. Clipboard operations can expose credentials: the existing privacy warning remains; Android 13+ marks the clipboard sensitive.

**Export → JSON** is **not** changed into Markdown: a .json file remains valid, machine-readable JSON with no extra comments or fences. **Export → Original** remains byte-equivalent to the stored decoder text. The encrypted history is not rewritten.

Note: literal triple-backtick notation is designed for Telegram Markdown-capable clients/bots. Whether a manually pasted message is rendered as a code block depends on the receiving Telegram client and formatting mode.

## Clear displayed result vs clear encrypted history

- A new dedicated `DeleteOutline` icon sits beside the Home result heading. Its accessible label is localized in English, Spanish, pt-BR and Arabic.
- Clicking it clears the **currently displayed Home result** and credential reveal/notification state. It does not call history deletion, reset retention, or remove favorites.
- On a cold app launch, Home starts with no selected result; the activity stops automatically restoring the previous `selectedId` from DataStore. The encrypted history is loaded normally and can still be opened from History/Recent.
- During a normal Activity recreation (e.g. rotation), the existing `DecodeSessionViewModel` retains the on-screen result; backgrounding to share in Telegram **does not** forcibly erase the Home result.
- The older `current_result_id` value may exist in DataStore for existing installs, but it is no longer used for cold-start result restoration. Clear action removes the obsolete pointer.

## Verification

`TelegramResultCopyInstrumentedTest` tests the JSON fence, credit placement, user-visible JSON parity, valid JSON file export, preservation of the original decoder text, and that Home clear does not delete saved history. Existing imported-result, EHI and NPVS signed-fixture API35 parity tests continue running in the main validation workflow.

## Ads and security boundary

No ad SDK, tracking or `INTERNET` permission is introduced in this UI patch. Any proposed advertising model needs separate product and privacy review, explicit approval and updated privacy disclosures; third-party ad SDKs would break the current strict offline/no-network security contract. Keystore-backed encrypted history and the permanent APK signing identity remain unchanged.

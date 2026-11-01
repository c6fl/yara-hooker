# Yara

Module that hooks Roblox's YARA scanner (`RBX::Scanner::Scan` and `RBX::Scanner::EncodeRulesets`)
and then logs every memory scans and include its arguments such as status, if it was a violation or not and which rules matched.

## Why two hooks only instead of 10 different offsets through 50 functions like real roblox hackers

`Scan` only exposes the final obfuscated result, and the real rule IDs only exist.... unobfuscated right before something called `EncodeRulesets` encrypts them, meaning that our module hooks both and sends the data back together per scan.

## Use

Inject this into RobloxPlayerBeta, log file `yara_scan_log.txt` will appear.

## Very useful info

- I use of hardcoded RVAs for current `version-5a21b87bbc2641cf` build on purpose, will stop working on next update.
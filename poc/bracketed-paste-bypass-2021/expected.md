# Expected behaviour: bracketed-paste-bypass-2021

## Class

bracketed-paste-bypass -- CVE-2021-31701 CVE-2021-37326 CVE-2021-40147

## What the payload does

Pasted content that embeds the end-bracketed-paste sequence (CSI 201 ~) tricks the terminal into ending paste mode early, so the rest of the paste is treated as typed input and runs. A secure terminal sanitizes paste to ASCII and strips the escape, so the guard cannot be broken.

## Verification (paste-autoexec)

Real-effect oracle: the payload is fed through the REAL GUI paste path
(insertFromMimeData) and the bytes written to the child are spied. The embedded
end-paste escape makes the paste risky, so secure-terminal holds it for review; a
hit = a submit (CR) reaches the child with no review interposed. (The retired
paste-bypass mode only checked whether an ESC survived sanitize_paste -- a proxy
this class passed while a vulnerable terminal still auto-ran the payload.)

## Reference

https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters

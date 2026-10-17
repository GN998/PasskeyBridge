# Passkey Bridge

A lightweight FIDO2 cross-device authentication (caBLE v2 / Hybrid Transport) bridge for Android 14+ (API 34). Operating without Google Play Services (GMS), it intercepts `fido:/` QR code intents and forwards PC WebAuthn requests over BLE and encrypted WebSocket tunnels to Android's native `CredentialManager` API.

## Core Features

* **URI Parsing**: Intercepts and decodes `fido:/` URIs (GMS Base34 and CBOR decoding).
* **Hybrid Transport (caBLE v2)**: Implements `0xFFF9` BLE proximity advertising, `Noise_KNpsk0` encrypted handshakes, and CTAP 2.3 tunnel domain derivation (supports build-time injection and runtime custom Tunnel IDs: `256 - 65535`).
* **CTAP2 Bridging**: Features a zero-dependency CBOR codec supporting `GetInfo`, `MakeCredential`, and `GetAssertion` commands, forwarding the PC `origin` and `clientDataHash` to Android `CredentialManager`.

## Requirements

1. **System & Permissions**: Android 14+, with Bluetooth enabled and `BLUETOOTH_ADVERTISE` / `BLUETOOTH_CONNECT` permissions granted.
2. **Credential Provider Trust**: Must be authorized via the **local trust mechanism** built into your credential manager (e.g., Bitwarden, Authnkey) to allow privileged `origin` forwarding (unauthorized calls return `0x27` Operation Denied).
3. **QR Scanning**: No built-in camera; use the system camera or a third-party scanner to scan the PC FIDO QR code and trigger the app via system `Intent`.


### License & Acknowledgments

This project is licensed under the [GNU General Public License v3.0 (GPLv3)](LICENSE).

**Acknowledgments:**

* **[microG GmsCore](https://github.com/microg/GmsCore/)**: Portions of the implementation logic and protocol structures were inspired by and refactored from microG GmsCore ([Apache License 2.0](https://github.com/microg/GmsCore/blob/master/LICENSE)).
* **[FIDO Alliance](https://fidoalliance.org/)**: For the open CTAP 2.3 and WebAuthn specifications.
* **[Bitwarden](https://github.com/bitwarden/android)**: For open-source Android `CredentialManager` integration and local app trust support.
* **[Cloudflare](https://www.cloudflare.com/)**: For edge network and WebSocket tunnel relay infrastructure.
* **[Linux.do](https://linux.do/)**
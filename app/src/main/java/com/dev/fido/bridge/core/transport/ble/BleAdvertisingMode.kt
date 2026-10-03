package com.dev.fido.bridge.core.transport.ble

/**
 * Represent caBLE v2 Bluetooth Low Energy (BLE) advertising modes and payload specifications.
 *
 * CTAP 2.3 §11.5 defines two distinct BLE advertisement structures depending on the transaction type:
 * 1. Ad-hoc (QR-initiated): Transmits a 20-byte EID containing a 16-byte encrypted timestamp/routing seed
 *    and a 4-byte HMAC tag derived from the QR secret.
 * 2. State-assisted (Linked Connection): Transmits a 15-byte payload (e.g., random nonce or short EID)
 *    to allow previously paired client platforms to identify nearby authenticators with minimal BLE overhead.
 */
sealed class BleAdvertisingMode {

    /**
     * Raw binary payload to be broadcast inside the FIDO BLE Service Data field (UUID 0xFFF9).
     */
    abstract val rawPayload: ByteArray

    /**
     * Expected payload length in bytes according to CTAP 2.3 specifications.
     */
    abstract val expectedLength: Int

    /**
     * Validate that the advertising payload matches protocol length constraints.
     *
     * @throws IllegalArgumentException If payload size deviates from CTAP 2.3 requirements.
     */
    fun validate() {
        require(rawPayload.size == expectedLength) {
            "Invalid BLE advertising payload size for ${javaClass.simpleName}: " +
                "expected $expectedLength bytes, got ${rawPayload.size} bytes."
        }
    }

    /**
     * Ad-hoc BLE advertising mode for QR-initiated initial transactions.
     *
     * @property rawPayload 20-byte Encrypted Identifier (EID) constructed per CTAP 2.3 §11.5.1.
     */
    data class AdHoc(override val rawPayload: ByteArray) : BleAdvertisingMode() {
        override val expectedLength: Int = 20

        init {
            validate()
        }
    }

    /**
     * State-assisted BLE advertising mode for paired, zero-interaction transactions.
     *
     * @property rawPayload 15-byte truncated EID or random nonce constructed per CTAP 2.3 §11.5.2.
     */
    data class StateAssisted(override val rawPayload: ByteArray) : BleAdvertisingMode() {
        override val expectedLength: Int = 15

        init {
            validate()
        }
    }
}

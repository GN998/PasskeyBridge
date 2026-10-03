package com.dev.fido.bridge.core.transport.websocket

import com.dev.fido.bridge.core.security.CryptoUtils
import com.dev.fido.bridge.core.security.DomainDerivation

/**
 * Encapsulate caBLE v2 WebSocket tunnel connection target endpoints and headers.
 *
 * CTAP 2.3 §11.5 defines two distinct WebSocket connection endpoints:
 * 1. New Tunnel (`/cable/new/<tunnel_id>`): Used for ad-hoc QR code flows where the domain is derived
 *    from a 16-bit domain ID and the tunnel ID is ephemeral.
 * 2. Contact Tunnel (`/cable/contact/<contact_id>`): Used for state-assisted flows where the authenticator
 *    reconnects using a persistent contact ID and sends an optional client payload header.
 */
sealed class CableTunnelEndpoint {

    /**
     * Construct the full WebSocket connection URL (e.g., `wss://domain/cable/...`).
     */
    abstract fun buildUrl(): String

    /**
     * Construct required HTTP headers for the WebSocket handshake request.
     */
    abstract fun buildHeaders(): Map<String, String>

    /**
     * QR-initiated connection endpoint targeting a dynamically derived tunnel server domain.
     *
     * @property domainId 16-bit domain identifier parsed from QR data.
     * @property ephemeralTunnelId 16-byte random or derived tunnel routing ID.
     */
    data class NewTunnel(
        val domainId: Int,
        val ephemeralTunnelId: ByteArray
    ) : CableTunnelEndpoint() {

        override fun buildUrl(): String {
            val domain = DomainDerivation.deriveDomainForTunnelId(domainId)
            val tunnelIdHex = ephemeralTunnelId.joinToString("") { "%02x".format(it) }
            return "wss://$domain/cable/new/$tunnelIdHex"
        }

        override fun buildHeaders(): Map<String, String> {
            return mapOf(
                "Sec-WebSocket-Protocol" to "fido.cable"
            )
        }
    }

    /**
     * State-assisted connection endpoint targeting a known paired domain and contact identifier.
     *
     * @property domain Target tunnel server domain saved during initial pairing (e.g., `cable.auth.com`).
     * @property contactId Persistent routing contact identifier assigned by the tunnel server.
     * @property clientPayload Optional client payload header bytes (`X-caBLE-Client-Payload`).
     */
    data class ContactTunnel(
        val domain: String,
        val contactId: ByteArray,
        val clientPayload: ByteArray = ByteArray(0)
    ) : CableTunnelEndpoint() {

        override fun buildUrl(): String {
            val contactIdBase64Url = CryptoUtils.encodeBase64UrlNoPadding(contactId)
            return "wss://$domain/cable/contact/$contactIdBase64Url"
        }

        override fun buildHeaders(): Map<String, String> {
            val headers = mutableMapOf(
                "Sec-WebSocket-Protocol" to "fido.cable"
            )
            if (clientPayload.isNotEmpty()) {
                val payloadHex = clientPayload.joinToString("") { "%02x".format(it) }
                headers["X-caBLE-Client-Payload"] = payloadHex
            }
            return headers
        }
    }
}

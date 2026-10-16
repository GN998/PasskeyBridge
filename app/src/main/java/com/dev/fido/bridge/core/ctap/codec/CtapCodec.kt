package com.dev.fido.bridge.core.ctap.codec

import android.util.Log
import com.dev.fido.bridge.core.ctap.AuthenticatorInfo
import com.dev.fido.bridge.core.ctap.model.CredentialDescriptor
import com.dev.fido.bridge.core.ctap.model.Ctap2Request
import com.dev.fido.bridge.core.ctap.model.Ctap2Response
import com.dev.fido.bridge.core.ctap.model.CtapStatus
import java.io.ByteArrayOutputStream

/**
 * Custom exception representing CTAP codec errors with standard protocol status codes.
 */
class CtapCodecException(
    val statusCode: Byte,
    message: String,
    cause: Throwable? = null
) : IllegalArgumentException(message, cause)

/**
 * Map CTAP2 boolean "uv" option flag to WebAuthn userVerification requirement string.
 */
fun Boolean?.toWebAuthnUv(): String = when (this) {
    true -> "required"
    false -> "discouraged"
    null -> "preferred"
}

object CtapCodec {

    // Standard COSE algorithm identifiers supported by Android CredentialManager providers (ES256, EdDSA, RS256, ES384, ES512, PS256)
    private val SUPPORTED_COSE_ALGORITHMS = setOf(-7L, -8L, -257L, -35L, -36L, -37L)

    fun decodeRequest(rawPayload: ByteArray): Ctap2Request {
        if (rawPayload.isEmpty()) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CTAP payload")
        }
        val commandByte = rawPayload[0]
        val cborBytes = if (rawPayload.size > 1) rawPayload.copyOfRange(1, rawPayload.size) else ByteArray(0)

        // Centralize CBOR decoding error handling to avoid duplicating catch blocks across command parsers
        return try {
            when (commandByte) {
                0x04.toByte() -> {
                    if (cborBytes.isNotEmpty()) {
                        throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "GetInfo command must not contain parameters")
                    }
                    Ctap2Request.GetInfo
                }
                0x01.toByte() -> decodeMakeCredential(cborBytes)
                0x02.toByte() -> decodeGetAssertion(cborBytes)
                else -> throw CtapCodecException(
                    CtapStatus.ERR_INVALID_COMMAND,
                    "Unsupported command byte: 0x${"%02X".format(commandByte)}"
                )
            }
        } catch (e: CtapCodecException) {
            throw e
        } catch (e: Exception) {
            Log.e("CtapCodec", "CTAP request decode error (command: 0x${"%02X".format(commandByte)})", e)
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid CTAP CBOR payload", e)
        }
    }

    /**
     * Extract and cast mandatory CBOR map fields while distinguishing missing keys (0x14) from type mismatches (0x11) per CTAP 2.3 §6.
     */
    internal inline fun <reified T> Map<*, *>.requireField(
        key: Any,
        name: String,
        missingStatus: Byte = CtapStatus.ERR_MISSING_PARAMETER
    ): T {
        val value = this[key]
            ?: throw CtapCodecException(missingStatus, "Missing required parameter: $name")
        return value as? T
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for parameter: $name")
    }

    private fun decodeMakeCredential(cborBytes: ByteArray): Ctap2Request.MakeCredential {
        val map = SimpleCbor.read(cborBytes) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "MakeCredential request must be a CBOR map")

        val clientDataHash = map.requireField<ByteArray>(1L, "clientDataHash")

        val rp = map.requireField<Map<*, *>>(2L, "rp")
        val rpId = rp.requireField<String>("id", "rp.id", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        val rpName = rp["name"]?.let {
            it as? String ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for rp.name")
        } ?: ""

        val user = map.requireField<Map<*, *>>(3L, "user")
        val userId = user.requireField<ByteArray>("id", "user.id", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
        val userName = user["name"]?.let {
            it as? String ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for user.name")
        } ?: ""
        val userDisplayName = user["displayName"]?.let {
            it as? String ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "Unexpected CBOR type for user.displayName")
        } ?: ""

        val pubKeyCredParamsRaw = map.requireField<List<*>>(4L, "pubKeyCredParams")

        // Validate every pubKeyCredParams element and ensure at least one supported public-key algorithm is present per CTAP 2.3 §6.1.2 Step 3
        val pubKeyCredParams = pubKeyCredParamsRaw.map { item ->
            val paramMap = item as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "pubKeyCredParams element must be a map")
            val type = paramMap.requireField<String>("type", "pubKeyCredParams.type", CtapStatus.ERR_INVALID_CBOR)
            // Enforce CBOR integer type for COSEAlgorithmIdentifier per CTAP 2.3 §6.1
            val alg = paramMap.requireField<Long>("alg", "pubKeyCredParams.alg", CtapStatus.ERR_INVALID_CBOR)

            mapOf(
                "type" to type,
                "alg" to alg
            )
        }
        if (pubKeyCredParams.none { it["type"] == "public-key" && it["alg"] in SUPPORTED_COSE_ALGORITHMS }) {
            throw CtapCodecException(CtapStatus.ERR_UNSUPPORTED_ALGORITHM, "No supported public-key algorithm in pubKeyCredParams")
        }

        // Extract excludeList (key 5) to prevent duplicate credential registration on the authenticator
        val excludeList = parseDescriptorList(map[5L], "excludeList")

        // Extract and strictly type-check options (key 7) such as resident key (rk) and user verification (uv) requirements per CTAP 2.3 §6.1.2
        val options = parseOptionsMap(map[7L], "MakeCredential.options")

        // Reject explicit "up" option in MakeCredential since FIDO_2_0 authenticators must return CTAP2_ERR_INVALID_OPTION if "up" is present, and "up"=false is invalid across all versions per CTAP 2.3 §6.1
        if (options != null && options.containsKey("up")) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_OPTION, "Option 'up' is not valid in MakeCredential")
        }

        return Ctap2Request.MakeCredential(
            clientDataHash = clientDataHash,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            pubKeyCredParams = pubKeyCredParams,
            excludeList = excludeList,
            options = options
        )
    }

    private fun decodeGetAssertion(cborBytes: ByteArray): Ctap2Request.GetAssertion {
        val map = SimpleCbor.read(cborBytes) as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "GetAssertion request must be a CBOR map")

        val rpId = map.requireField<String>(1L, "rpId")
        val clientDataHash = map.requireField<ByteArray>(2L, "clientDataHash")

        val allowList = parseDescriptorList(map[3L], "allowList")

        // Validate CTAP2 options (key 5) per CTAP 2.3 §6.2.2 Step 4
        val options = parseOptionsMap(map[5L], "GetAssertion.options")
        if (options != null && options.containsKey("rk")) {
            // Reject prohibited "rk" option in GetAssertion per CTAP 2.3 §6.2.2 Step 4.4
            throw CtapCodecException(CtapStatus.ERR_UNSUPPORTED_OPTION, "Option 'rk' is not supported in GetAssertion")
        }
        val uvFlag = options?.get("uv")
        // Default "up" to true when absent per CTAP 2.3 §6.2.2 Step 4.5
        val upFlag = options?.get("up") ?: true

        return Ctap2Request.GetAssertion(
            rpId = rpId,
            clientDataHash = clientDataHash,
            allowList = allowList,
            userVerification = uvFlag.toWebAuthnUv(),
            userPresence = upFlag
        )
    }

    /**
     * Validate and extract the CTAP2 options map (Map<String, Boolean>), throwing ERR_CBOR_UNEXPECTED_TYPE on non-map or non-boolean values per CTAP 2.3 §6 & §8.
     */
    private fun parseOptionsMap(rawOptions: Any?, fieldName: String): Map<String, Boolean>? {
        if (rawOptions == null) return null
        val optionsMap = rawOptions as? Map<*, *>
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName must be a CBOR map")
        return optionsMap.entries.associate { (k, v) ->
            val keyStr = k as? String
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName key must be a text string")
            val valBool = v as? Boolean
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName['$keyStr'] value must be a boolean")
            keyStr to valBool
        }
    }

    /**
     * Parse CBOR array of PublicKeyCredentialDescriptor maps shared by MakeCredential and GetAssertion.
     */
    private fun parseDescriptorList(rawList: Any?, fieldName: String): List<CredentialDescriptor>? {
        if (rawList == null) return null
        val list = rawList as? List<*>
            ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName must be a CBOR array")
        return list.map { item ->
            val descMap = item as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName element must be a map")
            val type = descMap.requireField<String>("type", "$fieldName.type", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            val id = descMap.requireField<ByteArray>("id", "$fieldName.id", CtapStatus.ERR_CBOR_UNEXPECTED_TYPE)
            CredentialDescriptor(type = type, id = id)
        }
    }

    fun encodeResponse(response: Ctap2Response): ByteArray {
        return when (response) {
            is Ctap2Response.ErrorResponse -> byteArrayOf(response.errorCode)
            is Ctap2Response.GetInfoResponse -> {
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(AuthenticatorInfo.toCborMap(response))
            }
            is Ctap2Response.MakeCredentialResponse -> {
                val map = mapOf(
                    1L to response.fmt,
                    2L to response.authData,
                    3L to response.attStmt
                )
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(map)
            }
            is Ctap2Response.GetAssertionResponse -> {
                val map = mutableMapOf<Long, Any>(
                    2L to response.authenticatorData,
                    3L to response.signature
                )
                if (response.credentialId.isNotEmpty()) {
                    map[1L] = mapOf("id" to response.credentialId, "type" to "public-key")
                }
                response.userHandle?.let { map[4L] = mapOf("id" to it) }
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(map)
            }
        }
    }

    // A lightweight, dependency-free CBOR encoder/decoder optimized for FIDO structures
    object SimpleCbor {
        fun read(bytes: ByteArray): Any? {
            if (bytes.isEmpty()) {
                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CBOR byte stream")
            }
            var pos = 0
            fun readByte(): Int {
                if (pos >= bytes.size) throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unexpected end of CBOR stream")
                return bytes[pos++].toInt() and 0xFF
            }
            fun readBytes(len: Int): ByteArray {
                if (len < 0 || pos + len > bytes.size) {
                    throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid CBOR byte string length: $len")
                }
                val res = bytes.copyOfRange(pos, pos + len)
                pos += len
                return res
            }
            fun readItem(depth: Int): Any? {
                // Enforce CTAP 2.3 §8 maximum CBOR nesting depth of 4 levels for maps/arrays
                if (depth > 4) {
                    throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR nesting depth exceeds CTAP2 limit of 4")
                }
                val b = readByte()
                val majorType = b shr 5
                val info = b and 0x1F

                // Decode unsigned argument and enforce CTAP 2.3 §8 canonical minimal-length integer encoding
                val value: Long = when {
                    info < 24 -> info.toLong()
                    info == 24 -> {
                        val v = readByte().toLong()
                        if (majorType != 7 && v < 24L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 1-byte CBOR integer encoding")
                        }
                        v
                    }
                    info == 25 -> {
                        val v = ((readByte() shl 8) or readByte()).toLong()
                        if (majorType != 7 && v < 0x100L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 2-byte CBOR integer encoding")
                        }
                        v
                    }
                    info == 26 -> {
                        val i = (readByte() shl 24) or (readByte() shl 16) or (readByte() shl 8) or readByte()
                        val v = i.toLong() and 0xFFFFFFFFL
                        if (majorType != 7 && v < 0x10000L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 4-byte CBOR integer encoding")
                        }
                        v
                    }
                    info == 27 -> {
                        val v = (readByte().toLong() shl 56) or
                            (readByte().toLong() shl 48) or
                            (readByte().toLong() shl 40) or
                            (readByte().toLong() shl 32) or
                            (readByte().toLong() shl 24) or
                            (readByte().toLong() shl 16) or
                            (readByte().toLong() shl 8) or
                            readByte().toLong()
                        if (majorType != 7 && v in 0L until 0x100000000L) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Non-canonical 8-byte CBOR integer encoding")
                        }
                        v
                    }
                    // Reject indefinite-length items (info == 31) and reserved additional info (28..30) per CTAP 2.3 §8
                    else -> throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unsupported or indefinite-length CBOR info: $info")
                }

                return when (majorType) {
                    0 -> value
                    1 -> -1L - value
                    2 -> {
                        if (value < 0L || value > Int.MAX_VALUE) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR byte string length overflow")
                        }
                        readBytes(value.toInt())
                    }
                    3 -> {
                        if (value < 0L || value > Int.MAX_VALUE) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR text string length overflow")
                        }
                        String(readBytes(value.toInt()), Charsets.UTF_8)
                    }
                    4 -> {
                        if (value < 0L || value > Int.MAX_VALUE) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR array length overflow")
                        }
                        val list = mutableListOf<Any?>()
                        for (i in 0 until value.toInt()) list.add(readItem(depth + 1))
                        list
                    }
                    5 -> {
                        if (value < 0L || value > Int.MAX_VALUE) {
                            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "CBOR map length overflow")
                        }
                        val map = linkedMapOf<Any?, Any?>()
                        for (i in 0 until value.toInt()) {
                            val k = readItem(depth + 1)
                            // Reject duplicate map keys per CTAP 2.3 §8 canonical CBOR decoding rules
                            if (map.containsKey(k)) {
                                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Duplicate CBOR map key: $k")
                            }
                            map[k] = readItem(depth + 1)
                        }
                        map
                    }
                    7 -> {
                        when (info) {
                            20 -> false
                            21 -> true
                            22 -> null
                            else -> throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unsupported CBOR simple value or float: $info")
                        }
                    }
                    else -> throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Unsupported CBOR major type: $majorType")
                }
            }
            val root = readItem(0)
            // Reject trailing unconsumed bytes to guarantee strict single-item CBOR framing per CTAP 2.3 §8
            if (pos != bytes.size) {
                throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Trailing bytes after root CBOR item: ${bytes.size - pos}")
            }
            return root
        }

        fun write(value: Any?): ByteArray {
            // Use ByteArrayOutputStream to avoid O(N^2) array allocations during serialization
            val out = ByteArrayOutputStream()
            fun writeMajor(major: Int, v: Long) {
                val type = major shl 5
                when {
                    v < 24 -> out.write(type or v.toInt())
                    v < 0x100 -> {
                        out.write(type or 24)
                        out.write(v.toInt())
                    }
                    v < 0x10000 -> {
                        out.write(type or 25)
                        out.write((v shr 8).toInt())
                        out.write(v.toInt())
                    }
                    v < 0x100000000L -> {
                        out.write(type or 26)
                        out.write((v shr 24).toInt())
                        out.write((v shr 16).toInt())
                        out.write((v shr 8).toInt())
                        out.write(v.toInt())
                    }
                    else -> {
                        out.write(type or 27)
                        out.write((v shr 56).toInt())
                        out.write((v shr 48).toInt())
                        out.write((v shr 40).toInt())
                        out.write((v shr 32).toInt())
                        out.write((v shr 24).toInt())
                        out.write((v shr 16).toInt())
                        out.write((v shr 8).toInt())
                        out.write(v.toInt())
                    }
                }
            }
            fun writeItem(v: Any?) {
                when (v) {
                    null -> out.write(0xF6)
                    is Int -> if (v >= 0) writeMajor(0, v.toLong()) else writeMajor(1, -1L - v.toLong())
                    is Long -> if (v >= 0) writeMajor(0, v) else writeMajor(1, -1L - v)
                    is ByteArray -> { writeMajor(2, v.size.toLong()); out.write(v) }
                    is String -> { val b = v.toByteArray(Charsets.UTF_8); writeMajor(3, b.size.toLong()); out.write(b) }
                    is List<*> -> { writeMajor(4, v.size.toLong()); v.forEach { writeItem(it) } }
                    is Map<*, *> -> {
                        writeMajor(5, v.size.toLong())
                        // Sort map keys canonically per CTAP2 specification (length first, then lexicographical byte order)
                        val sortedEntries = v.entries.map { (k, vl) ->
                            write(k) to vl
                        }.sortedWith { a, b ->
                            val k1Bytes = a.first
                            val k2Bytes = b.first
                            if (k1Bytes.size != k2Bytes.size) {
                                k1Bytes.size.compareTo(k2Bytes.size)
                            } else {
                                var cmp = 0
                                for (i in k1Bytes.indices) {
                                    val b1 = k1Bytes[i].toInt() and 0xFF
                                    val b2 = k2Bytes[i].toInt() and 0xFF
                                    if (b1 != b2) {
                                        cmp = b1.compareTo(b2)
                                        break
                                    }
                                }
                                cmp
                            }
                        }
                        sortedEntries.forEach { (kBytes, vl) ->
                            out.write(kBytes)
                            writeItem(vl)
                        }
                    }
                    is Boolean -> out.write(if (v) 0xF5 else 0xF4)
                }
            }
            writeItem(value)
            return out.toByteArray()
        }
    }
}
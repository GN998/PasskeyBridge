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

    fun decodeRequest(rawPayload: ByteArray): Ctap2Request {
        if (rawPayload.isEmpty()) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CTAP payload")
        }
        val commandByte = rawPayload[0]
        val cborBytes = if (rawPayload.size > 1) rawPayload.copyOfRange(1, rawPayload.size) else ByteArray(0)

        // Validate command code explicitly and throw CtapCodecException with ERR_INVALID_COMMAND (0x01)
        return when (commandByte) {
            0x04.toByte() -> Ctap2Request.GetInfo
            0x01.toByte() -> decodeMakeCredential(cborBytes)
            0x02.toByte() -> decodeGetAssertion(cborBytes)
            else -> throw CtapCodecException(
                CtapStatus.ERR_INVALID_COMMAND,
                "Unsupported command byte: 0x${"%02X".format(commandByte)}"
            )
        }
    }

    private fun decodeMakeCredential(cborBytes: ByteArray): Ctap2Request.MakeCredential {
        return try {
            val map = SimpleCbor.read(cborBytes) as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "MakeCredential request must be a CBOR map")

            val clientDataHash = map[1L] as? ByteArray
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing clientDataHash (key 1)")

            val rp = map[2L] as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing rp entity (key 2)")
            val rpId = rp["id"] as? String
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing rp.id")
            val rpName = rp["name"] as? String ?: ""

            val user = map[3L] as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing user entity (key 3)")
            val userId = user["id"] as? ByteArray
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing user.id")
            val userName = user["name"] as? String ?: ""
            val userDisplayName = user["displayName"] as? String ?: ""

            val pubKeyCredParamsRaw = map[4L] as? List<*> ?: emptyList<Any>()

            // Validate required fields 'type' and 'alg' without non-null assertions
            val pubKeyCredParams = pubKeyCredParamsRaw.map { item ->
                val paramMap = item as? Map<*, *>
                    ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "pubKeyCredParams element must be a map")
                val type = paramMap["type"] as? String
                    ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing required member 'type' in pubKeyCredParams")
                val alg = paramMap["alg"]
                    ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing required member 'alg' in pubKeyCredParams")

                mapOf(
                    "type" to type,
                    "alg" to alg
                )
            }

            // Extract excludeList (key 5) to prevent duplicate credential registration on the authenticator
            val excludeList = parseDescriptorList(map[5L], "excludeList")

            // Extract options (key 7) such as resident key (rk) and user verification (uv) requirements
            val optionsRaw = map[7L] as? Map<*, *>
            val options = optionsRaw?.entries?.mapNotNull { (k, v) ->
                val keyStr = k as? String
                val valBool = v as? Boolean
                if (keyStr != null && valBool != null) keyStr to valBool else null
            }?.toMap()

            Ctap2Request.MakeCredential(
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
        } catch (e: CtapCodecException) {
            throw e
        } catch (e: Exception) {
            Log.e("CtapCodec", "MakeCredential decode error", e)
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid MakeCredential CBOR payload", e)
        }
    }

    private fun decodeGetAssertion(cborBytes: ByteArray): Ctap2Request.GetAssertion {
        return try {
            val map = SimpleCbor.read(cborBytes) as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "GetAssertion request must be a CBOR map")

            val rpId = map[1L] as? String
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing rpId (key 1)")
            val clientDataHash = map[2L] as? ByteArray
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing clientDataHash (key 2)")

            val allowList = parseDescriptorList(map[3L], "allowList")

            // Map CTAP2 options (key 5) uv flag to WebAuthn userVerification requirement
            val optionsRaw = map[5L] as? Map<*, *>
            val uvFlag = optionsRaw?.get("uv") as? Boolean

            Ctap2Request.GetAssertion(
                rpId = rpId,
                clientDataHash = clientDataHash,
                allowList = allowList,
                userVerification = uvFlag.toWebAuthnUv()
            )
        } catch (e: CtapCodecException) {
            throw e
        } catch (e: Exception) {
            Log.e("CtapCodec", "GetAssertion decode error", e)
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid GetAssertion CBOR payload", e)
        }
    }

    /**
     * Parse CBOR array of PublicKeyCredentialDescriptor maps shared by MakeCredential and GetAssertion.
     */
    private fun parseDescriptorList(rawList: Any?, fieldName: String): List<CredentialDescriptor>? {
        val list = rawList as? List<*> ?: return null
        return list.map { item ->
            val descMap = item as? Map<*, *>
                ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "$fieldName element must be a map")
            val type = descMap["type"] as? String ?: "public-key"
            val id = descMap["id"] as? ByteArray
                ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing id in $fieldName descriptor")
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
            var pos = 0
            fun readByte(): Int {
                if (pos >= bytes.size) throw IndexOutOfBoundsException()
                return bytes[pos++].toInt() and 0xFF
            }
            fun readBytes(len: Int): ByteArray {
                if (len < 0 || pos + len > bytes.size) throw IndexOutOfBoundsException()
                val res = bytes.copyOfRange(pos, pos + len)
                pos += len
                return res
            }
            fun readItem(): Any? {
                if (pos >= bytes.size) return null
                val b = readByte()
                val majorType = b shr 5
                val info = b and 0x1F

                // Decode 64-bit integers (info == 27) properly to prevent silent data corruption on large values
                val value: Long = when {
                    info < 24 -> info.toLong()
                    info == 24 -> readByte().toLong()
                    info == 25 -> ((readByte() shl 8) or readByte()).toLong()
                    info == 26 -> {
                        val i = (readByte() shl 24) or (readByte() shl 16) or (readByte() shl 8) or readByte()
                        i.toLong() and 0xFFFFFFFFL
                    }
                    info == 27 -> {
                        (readByte().toLong() shl 56) or
                        (readByte().toLong() shl 48) or
                        (readByte().toLong() shl 40) or
                        (readByte().toLong() shl 32) or
                        (readByte().toLong() shl 24) or
                        (readByte().toLong() shl 16) or
                        (readByte().toLong() shl 8) or
                        readByte().toLong()
                    }
                    else -> return null
                }

                return when (majorType) {
                    0 -> value
                    1 -> -1L - value
                    2 -> readBytes(value.toInt())
                    3 -> String(readBytes(value.toInt()), Charsets.UTF_8)
                    4 -> {
                        val list = mutableListOf<Any?>()
                        for (i in 0 until value) list.add(readItem())
                        list
                    }
                    5 -> {
                        val map = linkedMapOf<Any?, Any?>()
                        for (i in 0 until value) map[readItem()] = readItem()
                        map
                    }
                    7 -> {
                        when (info) {
                            20 -> false
                            21 -> true
                            else -> null
                        }
                    }
                    else -> null
                }
            }
            return readItem()
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
package com.yourcompany.passkeybridge.core.ctap.codec

import android.util.Log
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import com.yourcompany.passkeybridge.core.ctap.model.CtapStatus
import com.yourcompany.passkeybridge.core.ctap.model.CredentialDescriptor

/**
 * Custom exception representing CTAP codec errors with standard protocol status codes.
 */
class CtapCodecException(
    val statusCode: Byte,
    message: String,
    cause: Throwable? = null
) : IllegalArgumentException(message, cause)

object CtapCodec {

    fun decodeRequest(rawPayload: ByteArray): Ctap2Request {
        if (rawPayload.isEmpty()) {
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Empty CTAP payload")
        }
        val commandByte = rawPayload[0]
        val cborBytes = if (rawPayload.size > 1) rawPayload.copyOfRange(1, rawPayload.size) else ByteArray(0)

        // Fix for Bug 5: Validate command code explicitly and throw CtapCodecException with ERR_INVALID_COMMAND (0x01)
        return when (commandByte) {
            0x04.toByte() -> Ctap2Request.GetInfo()
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

            // Fix for Bug 6: Safely validate required fields 'type' and 'alg' without non-null assertions (!!) or unsafe casts
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

            Ctap2Request.MakeCredential(
                clientDataHash = clientDataHash,
                rpId = rpId,
                rpName = rpName,
                userId = userId,
                userName = userName,
                userDisplayName = userDisplayName,
                pubKeyCredParams = pubKeyCredParams
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

            val allowListRaw = map[3L] as? List<*>
            val allowList = allowListRaw?.map { item ->
                val descMap = item as? Map<*, *>
                    ?: throw CtapCodecException(CtapStatus.ERR_CBOR_UNEXPECTED_TYPE, "allowList element must be a map")
                val type = descMap["type"] as? String ?: "public-key"
                val id = descMap["id"] as? ByteArray
                    ?: throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Missing id in allowList descriptor")
                CredentialDescriptor(type = type, id = id)
            }

            Ctap2Request.GetAssertion(
                rpId = rpId,
                clientDataHash = clientDataHash,
                allowList = allowList
            )
        } catch (e: CtapCodecException) {
            throw e
        } catch (e: Exception) {
            Log.e("CtapCodec", "GetAssertion decode error", e)
            throw CtapCodecException(CtapStatus.ERR_INVALID_CBOR, "Invalid GetAssertion CBOR payload", e)
        }
    }

    fun encodeResponse(response: Ctap2Response): ByteArray {
        return when (response) {
            is Ctap2Response.ErrorResponse -> byteArrayOf(response.errorCode)
            is Ctap2Response.GetInfoResponse -> {
                val map = mapOf(
                    1L to response.versions,
                    2L to response.extensions,
                    3L to response.aaguid,
                    4L to response.options,
                    5L to response.maxMsgSize.toLong(),
                    6L to response.pinUvAuthProtocols.map { it.toLong() }
                )
                byteArrayOf(CtapStatus.SUCCESS) + SimpleCbor.write(map)
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
                val res = bytes.copyOfRange(pos, pos + len)
                pos += len
                return res
            }
            fun readItem(): Any? {
                if (pos >= bytes.size) return null
                val b = readByte()
                val majorType = b shr 5
                val info = b and 0x1F
                var value = info.toLong()
                
                if (info == 24) value = readByte().toLong()
                else if (info == 25) value = ((readByte() shl 8) or readByte()).toLong()
                else if (info == 26) {
                    val i = (readByte() shl 24) or (readByte() shl 16) or (readByte() shl 8) or readByte()
                    value = i.toLong() and 0xFFFFFFFFL
                } else if (info == 27) {
                    pos += 8 // Not fully supported, skipped
                    return null
                }
                
                return when (majorType) {
                    0 -> value
                    1 -> -1L - value
                    2 -> readBytes(value.toInt())
                    3 -> String(readBytes(value.toInt()))
                    4 -> {
                        val list = mutableListOf<Any?>()
                        for (i in 0 until value) list.add(readItem())
                        list
                    }
                    5 -> {
                        val map = mutableMapOf<Any?, Any?>()
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
            var bytes = ByteArray(0)
            fun writeMajor(major: Int, v: Long) {
                val type = major shl 5
                if (v < 24) bytes += (type or v.toInt()).toByte()
                else if (v < 256) { bytes += (type or 24).toByte(); bytes += v.toByte() }
                else if (v < 65536) { bytes += (type or 25).toByte(); bytes += (v shr 8).toByte(); bytes += v.toByte() }
                else { bytes += (type or 26).toByte(); bytes += (v shr 24).toByte(); bytes += (v shr 16).toByte(); bytes += (v shr 8).toByte(); bytes += v.toByte() }
            }
            fun writeItem(v: Any?) {
                when (v) {
                    is Int -> if (v >= 0) writeMajor(0, v.toLong()) else writeMajor(1, (-v - 1).toLong())
                    is Long -> if (v >= 0) writeMajor(0, v) else writeMajor(1, (-v - 1))
                    is ByteArray -> { writeMajor(2, v.size.toLong()); bytes += v }
                    is String -> { val b = v.toByteArray(); writeMajor(3, b.size.toLong()); bytes += b }
                    is List<*> -> { writeMajor(4, v.size.toLong()); v.forEach { writeItem(it) } }
                    is Map<*, *> -> {
                        writeMajor(5, v.size.toLong())
                        val sortedEntries = v.entries.map { (k, vl) ->
                            Pair(k, write(k)) to vl
                        }.sortedWith { a, b ->
                            val k1Bytes = a.first.second
                            val k2Bytes = b.first.second
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
                        sortedEntries.forEach { (keyPair, vl) ->
                            writeItem(keyPair.first)
                            writeItem(vl)
                        }
                    }
                    is Boolean -> bytes += if (v) 0xF5.toByte() else 0xF4.toByte()
                }
            }
            writeItem(value)
            return bytes
        }
    }
}

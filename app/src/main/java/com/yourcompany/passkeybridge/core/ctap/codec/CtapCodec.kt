package com.yourcompany.passkeybridge.core.ctap.codec

import android.util.Log
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Request
import com.yourcompany.passkeybridge.core.ctap.model.Ctap2Response
import com.yourcompany.passkeybridge.core.ctap.model.CtapStatus
import com.yourcompany.passkeybridge.core.ctap.model.CredentialDescriptor

object CtapCodec {

    fun decodeRequest(rawPayload: ByteArray): Ctap2Request {
        if (rawPayload.isEmpty()) throw IllegalArgumentException("Empty CTAP payload")
        val commandByte = rawPayload[0]
        val cborBytes = if (rawPayload.size > 1) rawPayload.copyOfRange(1, rawPayload.size) else ByteArray(0)

        return try {
            when (commandByte) {
                0x04.toByte() -> Ctap2Request.GetInfo()
                0x01.toByte() -> {
                    val map = SimpleCbor.read(cborBytes) as Map<*, *>
                    val rp = map[2L] as Map<*, *>
                    val user = map[3L] as Map<*, *>
                    val pubKeyCredParamsRaw = map[4L] as? List<Map<*, *>> ?: emptyList()
                    
                    val pubKeyCredParams = pubKeyCredParamsRaw.map {
                        mapOf(
                            "type" to (it["type"] as String),
                            "alg" to it["alg"]!!
                        )
                    }

                    Ctap2Request.MakeCredential(
                        clientDataHash = map[1L] as ByteArray,
                        rpId = rp["id"] as String,
                        rpName = rp["name"] as? String ?: "",
                        userId = user["id"] as ByteArray,
                        userName = user["name"] as? String ?: "",
                        userDisplayName = user["displayName"] as? String ?: "",
                        pubKeyCredParams = pubKeyCredParams
                    )
                }
                0x02.toByte() -> {
                    val map = SimpleCbor.read(cborBytes) as Map<*, *>
                    val allowListRaw = map[3L] as? List<Map<*, *>>
                    
                    val allowList = allowListRaw?.map {
                        CredentialDescriptor(
                            type = it["type"] as String,
                            id = it["id"] as ByteArray
                        )
                    }
                    
                    Ctap2Request.GetAssertion(
                        rpId = map[1L] as String,
                        clientDataHash = map[2L] as ByteArray,
                        allowList = allowList
                    )
                }
                else -> throw IllegalArgumentException("Unsupported command byte: $commandByte")
            }
        } catch (e: Exception) {
            Log.e("CtapCodec", "CBOR Decode Error", e)
            throw IllegalArgumentException("Invalid CBOR payload")
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
                // FIDO requires integer keys for the response map: 1: fmt, 2: authData, 3: attStmt
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
                response.userHandle?.let { map[6L] = it }
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
                    is Map<*, *> -> { writeMajor(5, v.size.toLong()); v.forEach { (k, vl) -> writeItem(k); writeItem(vl) } }
                    is Boolean -> bytes += if (v) 0xF5.toByte() else 0xF4.toByte()
                }
            }
            writeItem(value)
            return bytes
        }
    }
}
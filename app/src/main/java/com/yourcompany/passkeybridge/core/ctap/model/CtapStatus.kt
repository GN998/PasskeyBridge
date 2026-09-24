package com.yourcompany.passkeybridge.core.ctap.model

object CtapStatus {
    const val SUCCESS: Byte = 0x00
    const val ERR_INVALID_COMMAND: Byte = 0x01
    const val ERR_INVALID_PARAMETER: Byte = 0x02
    const val ERR_CREDENTIAL_EXCLUDED: Byte = 0x19
    const val ERR_NO_CREDENTIALS: Byte = 0x2E
    const val ERR_UNSUPPORTED_ALGORITHM: Byte = 0x26
    const val ERR_OPERATION_DENIED: Byte = 0x27
    const val ERR_INVALID_CBOR: Byte = 0x11
}
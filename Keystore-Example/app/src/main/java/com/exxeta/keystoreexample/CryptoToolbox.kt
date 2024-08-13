package com.exxeta.keystoreexample

interface CryptoToolbox {
    fun getValueFor(key: String, doubleEncryption: Boolean = true): String?

    fun setValueFor(
        key: String,
        value: String,
        doubleEncryption: Boolean = true,
    )

    fun deleteValueFor(key: String)
}

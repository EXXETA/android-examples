package com.exxeta.keystoreexample

class EncryptionException(
    override val message: String,
    override val cause: Throwable,
) : RuntimeException()

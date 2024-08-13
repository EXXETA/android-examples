package com.exxeta.keystoreexample

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource

class CryptoToolboxImpl(context: Context) : CryptoToolbox {

    private val sharedPreferences: SharedPreferences =
        EncryptedSharedPreferences.create(
            ENCRYPTED_SHARED_PREFS_FILENAME,
            ENCRYPTED_SHARED_PREFS,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

    // MARK: - Public

    @Throws(EncryptionException::class)
    override fun getValueFor(key: String, doubleEncryption: Boolean): String? {
        val encryptedValue =
            sharedPreferences.getString(key, null) ?: return null
        return if (doubleEncryption) {
            decryptWithDefaultKey(encryptedValue)
        } else {
            encryptedValue
        }
    }

    @Throws(EncryptionException::class)
    override fun setValueFor(
        key: String,
        value: String,
        doubleEncryption: Boolean,
    ) {
        val encryptedValue = if (doubleEncryption) {
            encryptWithDefaultKey(value)
        } else {
            value
        }

        sharedPreferences.edit().apply {
            putString(key, encryptedValue)
            apply()
        }
    }

    override fun deleteValueFor(key: String) {
        sharedPreferences.edit().apply {
            remove(key)
            apply()
        }
    }

    // MARK: - Private

    @Throws(EncryptionException::class)
    private fun decryptWithDefaultKey(value: String): String {
        try {
            val keystore = getKeyStore()
            val keyEntry = getKeyEntry(keyStore = keystore)
            val privateKey = getPrivateKey(keyStoreEntry = keyEntry)

            val decode: ByteArray = Base64.decode(value, 2)
            val instance = Cipher.getInstance(CIPHER)
            instance.init(
                Cipher.DECRYPT_MODE,
                privateKey,
                OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT
                )
            )
            return String(instance.doFinal(decode), StandardCharsets.UTF_8)
        } catch (e: Throwable) {
            throw EncryptionException(
                message = "Could not decrypt value",
                cause = e
            )
        }
    }

    @Throws(EncryptionException::class)
    private fun encryptWithDefaultKey(value: String): String {
        try {
            val keystore = getKeyStore()
            val keyEntry = getKeyEntry(keyStore = keystore)
            val publicKey = getPublicKey(keyStoreEntry = keyEntry)

            val instance = Cipher.getInstance(CIPHER)
            instance.init(
                Cipher.ENCRYPT_MODE,
                publicKey,
                OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA1,
                    PSource.PSpecified.DEFAULT
                )
            )
            return Base64.encodeToString(
                instance.doFinal(
                    value.encodeToByteArray()
                ),
                2
            )
        } catch (e: Throwable) {
            throw EncryptionException(
                message = "Could not encrypt value",
                cause = e
            )
        }
    }

    @Throws(EncryptionException::class)
    private fun getKeyStore(): KeyStore {
        try {
            val keyStore =
                KeyStore.getInstance(KEYSTORE_PROVIDER_NAME)
            keyStore.load(null)

            if (!keyStore.containsAlias(KEY)) {
                // generate
                val keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    KEYSTORE_PROVIDER_NAME
                )
                val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                    KEY,
                    KeyProperties.PURPOSE_SIGN or
                            KeyProperties.PURPOSE_ENCRYPT or
                            KeyProperties.PURPOSE_DECRYPT or
                            KeyProperties.PURPOSE_VERIFY
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                    .build()
                keyPairGenerator.initialize(keyGenParameterSpec)
                keyPairGenerator.generateKeyPair()
            }
            return keyStore
        } catch (e: Throwable) {
            throw EncryptionException(
                message = "Keystore could not provide key",
                cause = e
            )
        }
    }

    @Throws(EncryptionException::class)
    private fun getKeyEntry(keyStore: KeyStore): KeyStore.PrivateKeyEntry {
        try {
            val privateKeyEntry = keyStore.getEntry(
                KEY,
                null
            ) as KeyStore.PrivateKeyEntry

            return privateKeyEntry
        } catch (e: Throwable) {
            throw EncryptionException(
                message = "Keystore has no private key",
                cause = e
            )
        }
    }

    private fun getPublicKey(keyStoreEntry: KeyStore.PrivateKeyEntry): PublicKey {
        return keyStoreEntry.certificate.publicKey
    }

    private fun getPrivateKey(keyStoreEntry: KeyStore.PrivateKeyEntry): PrivateKey {
        return keyStoreEntry.privateKey
    }

    private companion object {
        private const val KEY = "private_key"
        private const val KEYSTORE_PROVIDER_NAME = "AndroidKeyStore"
        private const val CIPHER = "RSA/ECB/OAEPPadding"
        private const val ENCRYPTED_SHARED_PREFS = "ENCRYPTED_SHARED_PREFS"
        private const val ENCRYPTED_SHARED_PREFS_FILENAME = "shared_prefs"
    }
}

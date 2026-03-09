package com.example.opaque_demo.crypto

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Client-side HPKE (RFC 9180) mutual authentication in mode_auth.
 *
 * Implements DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM
 * to match the server's auth.rs implementation exactly.
 *
 * Handshake from client perspective:
 * 1. Client sends auth_init { clientId }
 * 2. Server sends auth_challenge { enc, ciphertext, serverKid }
 *    - Client performs AuthDecap(client_sk, server_pk) to decrypt the nonce
 * 3. Client sends auth_response { enc, ciphertext }
 *    - Client performs AuthEncap(client_sk, server_pk) to encrypt nonce||"ack"
 * 4. Server sends auth_ok
 */
class HpkeClient(
    private val clientKeyPair: KeyPair,
    private val serverPublicKey: ECPublicKey
) {
    companion object {
        // HPKE suite identifiers
        // DHKEM(P-256, HKDF-SHA256) = 0x0010
        private val SUITE_ID_KEM = byteArrayOf(
            'K'.code.toByte(), 'E'.code.toByte(), 'M'.code.toByte(),
            0x00, 0x10
        )

        // HPKE suite: KEM=0x0010 KDF=0x0001 AEAD=0x0001
        private val SUITE_ID_HPKE = byteArrayOf(
            'H'.code.toByte(), 'P'.code.toByte(), 'K'.code.toByte(), 'E'.code.toByte(),
            0x00, 0x10, 0x00, 0x01, 0x00, 0x01
        )

        private const val MODE_AUTH: Byte = 0x02

        private val HPKE_V1 = "HPKE-v1".toByteArray()
    }

    /**
     * Handle the server's auth_challenge: decrypt the nonce, compute
     * HMAC-SHA256(key=nonce, msg=salt), then encrypt the HMAC as the response.
     *
     * @param encB64 base64url-encoded encapsulated key from auth_challenge
     * @param ciphertextB64 base64url-encoded ciphertext from auth_challenge
     * @param saltB64 base64url-encoded salt from auth_challenge (sent in the clear)
     * @return Pair of (enc, ciphertext) both base64url-encoded for auth_response
     */
    fun handleChallenge(encB64: String, ciphertextB64: String, saltB64: String): Pair<String, String> {
        val encBytes = b64Decode(encB64)
        val ciphertextBytes = b64Decode(ciphertextB64)
        val saltBytes = b64Decode(saltB64)

        // Step 2 (receiving): AuthDecap to decrypt the server's challenge nonce
        // The server was the sender (server_sk), we are the recipient (client_sk)
        // enc came from the server's ephemeral key
        val decapKey = authDecap(
            enc = encBytes,
            recipientSk = clientKeyPair.private as ECPrivateKey,
            recipientPk = clientKeyPair.public as ECPublicKey,
            senderPk = serverPublicKey
        )

        // Decrypt the nonce
        val nonce = aeadOpen(decapKey, ciphertextBytes, "r2ps-auth-challenge".toByteArray())

        // Compute response: HMAC-SHA256(key=nonce, msg=salt)
        // This proves we decrypted the nonce and received the salt
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(nonce, "HmacSHA256"))
        val responsePayload = mac.doFinal(saltBytes)

        // Step 3 (sending): AuthEncap to encrypt the HMAC response
        // We are the sender (client_sk), server is the recipient (server_pk)
        val (responseEnc, encapKey) = authEncap(
            senderSk = clientKeyPair.private as ECPrivateKey,
            senderPk = clientKeyPair.public as ECPublicKey,
            recipientPk = serverPublicKey
        )

        // Encrypt the HMAC response
        val responseCiphertext = aeadSeal(encapKey, responsePayload, "r2ps-auth-response".toByteArray())

        return Pair(b64Encode(responseEnc), b64Encode(responseCiphertext))
    }

    // ─── HPKE AuthEncap (RFC 9180, mode_auth) ───

    /**
     * Generate ephemeral key, compute shared secret with both the recipient's
     * public key and the sender's static private key.
     *
     * @return Pair of (enc, aes128Key) where enc is the serialized ephemeral public key
     */
    private fun authEncap(
        senderSk: ECPrivateKey,
        senderPk: ECPublicKey,
        recipientPk: ECPublicKey
    ): Pair<ByteArray, ByteArray> {
        // Generate ephemeral key pair
        val ephKpg = KeyPairGenerator.getInstance("EC")
        ephKpg.initialize(ECGenParameterSpec("secp256r1"))
        val ephKeyPair = ephKpg.generateKeyPair()
        val ephSk = ephKeyPair.private as ECPrivateKey
        val ephPk = ephKeyPair.public as ECPublicKey

        // enc = uncompressed SEC1 encoding of ephemeral public key
        val enc = encodeUncompressed(ephPk)

        // DH1 = DH(eph_sk, recipient_pk) — ephemeral ECDH, extract x-coordinate
        val dh1X = ecdhXCoordinate(ephSk, recipientPk)

        // DH2 = DH(sender_sk, recipient_pk) — static-static ECDH for auth, extract x-coordinate
        val dh2X = ecdhXCoordinate(senderSk, recipientPk)

        // kem_context = enc || recipient_pk || sender_pk (all uncompressed)
        val recipientPkBytes = encodeUncompressed(recipientPk)
        val senderPkBytes = encodeUncompressed(senderPk)
        val kemContext = enc + recipientPkBytes + senderPkBytes

        // dh_concat = dh1_x || dh2_x
        val dhConcat = dh1X + dh2X

        // shared_secret = ExtractAndExpand(dh_concat, kem_context)
        val sharedSecret = extractAndExpandKem(dhConcat, kemContext)

        // key = KeySchedule(shared_secret)
        val key = keySchedule(sharedSecret)

        return Pair(enc, key)
    }

    // ─── HPKE AuthDecap (RFC 9180, mode_auth) ───

    /**
     * Compute shared secret from received enc, recipient's SK, and sender's PK.
     */
    private fun authDecap(
        enc: ByteArray,
        recipientSk: ECPrivateKey,
        recipientPk: ECPublicKey,
        senderPk: ECPublicKey
    ): ByteArray {
        // Recover ephemeral public key from enc (uncompressed SEC1)
        val ephPk = decodeUncompressed(enc)

        // DH1 = DH(recipient_sk, eph_pk) — extract x-coordinate
        val dh1X = ecdhXCoordinate(recipientSk, ephPk)

        // DH2 = DH(recipient_sk, sender_pk) — static-static for auth, extract x-coordinate
        val dh2X = ecdhXCoordinate(recipientSk, senderPk)

        // kem_context = enc || recipient_pk || sender_pk (all uncompressed)
        val recipientPkBytes = encodeUncompressed(recipientPk)
        val senderPkBytes = encodeUncompressed(senderPk)
        val kemContext = enc + recipientPkBytes + senderPkBytes

        // dh_concat = dh1_x || dh2_x
        val dhConcat = dh1X + dh2X

        // shared_secret = ExtractAndExpand(dh_concat, kem_context)
        val sharedSecret = extractAndExpandKem(dhConcat, kemContext)

        // key = KeySchedule(shared_secret)
        return keySchedule(sharedSecret)
    }

    // ─── KEM ExtractAndExpand (RFC 9180 Section 4.1) ───

    private fun extractAndExpandKem(dh: ByteArray, kemContext: ByteArray): ByteArray {
        // LabeledExtract("", "shared_secret", dh)
        // labeled_ikm = "HPKE-v1" || suite_id_kem || "shared_secret" || dh
        val labeledIkm = HPKE_V1 + SUITE_ID_KEM + "shared_secret".toByteArray() + dh

        // Extract: PRK = HKDF-Extract(salt=empty, ikm=labeled_ikm)
        val prk = hkdfExtract(ByteArray(0), labeledIkm)

        // LabeledExpand(prk, "shared_secret", kem_context, 32)
        // info = I2OSP(32, 2) || "HPKE-v1" || suite_id_kem || "shared_secret" || kem_context
        val expandInfo = i2osp(32, 2) + HPKE_V1 + SUITE_ID_KEM +
                "shared_secret".toByteArray() + kemContext

        return hkdfExpand(prk, expandInfo, 32)
    }

    // ─── HPKE Key Schedule ───

    private fun keySchedule(sharedSecret: ByteArray): ByteArray {
        // PSK input defaults (mode_auth, no PSK)
        val pskIdHash = labeledExtractHpke("psk_id_hash".toByteArray(), ByteArray(0), ByteArray(0))
        val infoHash = labeledExtractHpke("info_hash".toByteArray(), ByteArray(0), ByteArray(0))

        // ks_context = mode || psk_id_hash || info_hash
        val ksContext = byteArrayOf(MODE_AUTH) + pskIdHash + infoHash

        // secret = LabeledExtract(shared_secret, "secret", default_psk="")
        val secretIkm = HPKE_V1 + SUITE_ID_HPKE + "secret".toByteArray()
        val secret = hkdfExtract(sharedSecret, secretIkm)

        // key = LabeledExpand(secret, "key", ks_context, Nk=16)
        val keyInfo = i2osp(16, 2) + HPKE_V1 + SUITE_ID_HPKE +
                "key".toByteArray() + ksContext

        return hkdfExpand(secret, keyInfo, 16)
    }

    /**
     * LabeledExtract for the HPKE suite.
     * Matches the server's labeled_extract_hpke function which does:
     *   HKDF-Extract(salt, "HPKE-v1" || SUITE_ID_HPKE || label || ikm)
     *   then HKDF-Expand(prk, "", 32)
     */
    private fun labeledExtractHpke(label: ByteArray, salt: ByteArray, ikm: ByteArray): ByteArray {
        val labeledIkm = HPKE_V1 + SUITE_ID_HPKE + label + ikm

        val effectiveSalt = if (salt.isEmpty()) null else salt
        val prk = hkdfExtract(effectiveSalt, labeledIkm)

        // The server does hk.expand(&[], &mut out) with 32 bytes output.
        // This expands with empty info to get 32 bytes.
        return hkdfExpand(prk, ByteArray(0), 32)
    }

    // ─── AEAD (AES-128-GCM) ───

    private fun aeadSeal(key: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        // Zero nonce (12 bytes), matching the server's fixed nonce
        val gcmSpec = GCMParameterSpec(128, ByteArray(12))
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun aeadOpen(key: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val keySpec = SecretKeySpec(key, "AES")
        val gcmSpec = GCMParameterSpec(128, ByteArray(12))
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)
        cipher.updateAAD(aad)
        return cipher.doFinal(ciphertext)
    }

    // ─── HKDF Primitives ───

    /**
     * HKDF-Extract(salt, ikm) using HMAC-SHA256.
     * If salt is null, uses a zero-filled key of hash length (32 bytes).
     */
    private fun hkdfExtract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val effectiveSalt = if (salt == null || salt.isEmpty()) ByteArray(32) else salt
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(effectiveSalt, "HmacSHA256"))
        return mac.doFinal(ikm)
    }

    /**
     * HKDF-Expand(prk, info, length) using HMAC-SHA256.
     */
    private fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(prk, "HmacSHA256"))

        val n = (length + 31) / 32 // ceil(length / HashLen)
        val output = ByteArrayOutputStream()
        var t = ByteArray(0) // T(0) = empty

        for (i in 1..n) {
            mac.reset()
            mac.update(t)
            mac.update(info)
            mac.update(i.toByte())
            t = mac.doFinal()
            output.write(t)
        }

        return output.toByteArray().copyOfRange(0, length)
    }

    // ─── EC Utilities ───

    /**
     * Perform ECDH and return the x-coordinate of the shared point (32 bytes).
     * This matches what the Rust p256 library returns as the raw shared secret.
     */
    private fun ecdhXCoordinate(privateKey: ECPrivateKey, publicKey: ECPublicKey): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(privateKey)
        keyAgreement.doPhase(publicKey, true)
        val sharedSecret = keyAgreement.generateSecret()
        // Java's ECDH already returns just the x-coordinate (32 bytes for P-256)
        return sharedSecret
    }

    /**
     * Encode an EC public key as uncompressed SEC1 format (0x04 || x || y, 65 bytes).
     */
    private fun encodeUncompressed(key: ECPublicKey): ByteArray {
        val x = key.w.affineX.toByteArray().padOrTrimTo32()
        val y = key.w.affineY.toByteArray().padOrTrimTo32()
        return byteArrayOf(0x04) + x + y
    }

    /**
     * Decode an uncompressed SEC1 encoded EC public key (0x04 || x || y).
     */
    private fun decodeUncompressed(data: ByteArray): ECPublicKey {
        require(data.size == 65 && data[0] == 0x04.toByte()) {
            "Expected 65-byte uncompressed SEC1 point (0x04 || x || y)"
        }
        val x = data.copyOfRange(1, 33)
        val y = data.copyOfRange(33, 65)

        val xBigInt = java.math.BigInteger(1, x)
        val yBigInt = java.math.BigInteger(1, y)

        val ecPoint = java.security.spec.ECPoint(xBigInt, yBigInt)

        // Get the P-256 curve parameters from our existing key
        val params = (clientKeyPair.public as ECPublicKey).params
        val pubKeySpec = java.security.spec.ECPublicKeySpec(ecPoint, params)
        val keyFactory = java.security.KeyFactory.getInstance("EC")
        return keyFactory.generatePublic(pubKeySpec) as ECPublicKey
    }

    // ─── Helpers ───

    /**
     * Pad to 32 bytes (left-pad with zeros) or trim leading zeros to get exactly 32 bytes.
     * BigInteger.toByteArray() may return 33 bytes (sign bit) or fewer than 32.
     */
    private fun ByteArray.padOrTrimTo32(): ByteArray {
        return when {
            size == 32 -> this
            size > 32 -> copyOfRange(size - 32, size) // trim leading sign byte(s)
            else -> ByteArray(32 - size) + this // left-pad with zeros
        }
    }

    /** I2OSP(n, w): Integer to Octet String Primitive */
    private fun i2osp(n: Int, w: Int): ByteArray {
        val result = ByteArray(w)
        var value = n
        for (i in w - 1 downTo 0) {
            result[i] = (value and 0xFF).toByte()
            value = value shr 8
        }
        return result
    }
}

/** Base64url encode (no padding). */
fun b64Encode(data: ByteArray): String {
    return Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}

/** Base64url decode (no padding). */
fun b64Decode(data: String): ByteArray {
    return Base64.decode(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
}

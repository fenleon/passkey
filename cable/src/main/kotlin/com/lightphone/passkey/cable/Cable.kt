package com.lightphone.passkey.cable

import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * caBLE v2 protocol primitives, byte-for-byte per Chromium
 * (`device/fido/cable/`): Derive, the Noise handshake (KNpsk0 / NKpsk0 / NK),
 * the EID advert construction, and the post-handshake Crypter.
 */

// --- key derivation (Chromium cablev2::Derive / DerivedValueType) ---

enum class DerivedValueType(val value: Int) {
    EID_KEY(1),
    TUNNEL_ID(2),
    PSK(3),
    PAIRED_SECRET(4),
    IDENTITY_KEY_SEED(5),
    PER_CONTACT_ID_SECRET(6),
}

fun derive(secret: ByteArray, nonce: ByteArray, type: DerivedValueType, outLen: Int): ByteArray =
    Hkdf.sha256(secret, nonce, byteArrayOf(type.value.toByte(), 0, 0, 0), outLen)

// --- Noise symmetric state (Chromium noise.cc) ---

class Noise constructor(protocolName: String) {
    private var ck: ByteArray
    private var h: ByteArray
    private var key = ByteArray(32)
    private var nonce = 0

    init {
        // ck = h = protocol name (Chromium zero-fills then copy_prefix).
        ck = protocolName.toByteArray(Charsets.UTF_8)
        h = ck.copyOf()
    }

    companion object {
        const val KN = "Noise_KNpsk0_P256_AESGCM_SHA256"
        const val NK = "Noise_NKpsk0_P256_AESGCM_SHA256"
        const val NK_NO_PSK = "Noise_NK_P256_AESGCM_SHA256"
    }

    fun mixHash(data: ByteArray) {
        h = sha256(h + data)
    }

    fun mixHashPoint(point: ECPoint) = mixHash(point.toX962())

    fun mixKey(ikm: ByteArray) {
        val (newCk, k) = Hkdf.noise2(ck, ikm)
        ck = newCk
        initializeKey(k)
    }

    fun mixKeyAndHash(ikm: ByteArray) {
        val out = Hkdf.sha256(ikm, ck, ByteArray(0), 96)
        ck = out.copyOfRange(0, 32)
        mixHash(out.copyOfRange(32, 64))
        initializeKey(out.copyOfRange(64, 96))
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, noiseNonce()))
        cipher.updateAAD(h)
        val ct = cipher.doFinal(plaintext)
        mixHash(ct)
        return ct
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray? {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val plaintext = try {
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, noiseNonce()))
            cipher.updateAAD(h)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            return null
        }
        mixHash(ciphertext)
        return plaintext
    }

    fun trafficKeys(): Pair<ByteArray, ByteArray> = Hkdf.noise2(ck, ByteArray(0))

    fun handshakeHash(): ByteArray = h.copyOf()

    private fun initializeKey(k: ByteArray) {
        key = k.copyOf()
        nonce = 0
    }

    /** 12-byte nonce: 4-byte big-endian counter ‖ 8 zero bytes (noise.cc). */
    private fun noiseNonce(): ByteArray {
        val n = ByteArray(12)
        n[0] = (nonce ushr 24).toByte()
        n[1] = (nonce ushr 16).toByte()
        n[2] = (nonce ushr 8).toByte()
        n[3] = nonce.toByte()
        nonce++
        return n
    }

    private fun sha256(data: ByteArray) =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)
}

// --- EID advert (Chromium v2_handshake.cc eid::*) ---

object Eid {
    const val EID_LEN = 16 // 0x00 ‖ 10B nonce ‖ 3B routing ‖ 2B BE domain
    const val ADVERT_LEN = 20 // AES block ‖ 4B HMAC
    const val NONCE_LEN = 10
    const val ROUTING_LEN = 3
    const val KEY_LEN = 64 // 32B AES ‖ 32B HMAC
    const val NUM_ASSIGNED_DOMAINS = 2 // "cable.ua5v.com", "cable.auth.com"

    class Components(val nonce: ByteArray, val routingId: ByteArray, val tunnelServerDomain: Int) {
        init {
            require(nonce.size == NONCE_LEN)
            require(routingId.size == ROUTING_LEN)
        }
    }

    fun fromComponents(c: Components): ByteArray {
        val eid = ByteArray(EID_LEN)
        c.nonce.copyInto(eid, 1)
        c.routingId.copyInto(eid, 11)
        eid[14] = (c.tunnelServerDomain ushr 8).toByte()
        eid[15] = c.tunnelServerDomain.toByte()
        return eid
    }

    fun toComponents(eid: ByteArray): Components {
        require(eid.size == EID_LEN && eid[0] == 0.toByte()) { "invalid EID" }
        return Components(
            eid.copyOfRange(1, 11),
            eid.copyOfRange(11, 14),
            ((eid[14].toInt() and 0xff) shl 8) or (eid[15].toInt() and 0xff),
        )
    }

    fun encrypt(eid: ByteArray, key: ByteArray): ByteArray {
        require(eid.size == EID_LEN && key.size == KEY_LEN)
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key.copyOfRange(0, 32), "AES"))
        val ct = cipher.doFinal(eid)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.copyOfRange(32, 64), "HmacSHA256"))
        return ct + mac.doFinal(ct).copyOfRange(0, 4)
    }

    fun decrypt(advert: ByteArray, key: ByteArray): ByteArray? {
        if (advert.size != ADVERT_LEN || key.size != KEY_LEN) return null
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key.copyOfRange(32, 64), "HmacSHA256"))
        val tag = mac.doFinal(advert.copyOfRange(0, 16))
        if (!tag.copyOfRange(0, 4).contentEquals(advert.copyOfRange(16, 20))) return null
        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key.copyOfRange(0, 32), "AES"))
        val eid = cipher.doFinal(advert.copyOfRange(0, 16))
        if (eid[0] != 0.toByte()) return null
        val domain = ((eid[14].toInt() and 0xff) shl 8) or (eid[15].toInt() and 0xff)
        // Assigned domains 0..NUM-1 and hashed domains 256..64K are valid;
        // 2..255 are unknown/assigned-but-unknown and rejected (ToKnownDomainID).
        if (domain !in 0 until NUM_ASSIGNED_DOMAINS && domain < 256) return null
        return eid
    }
}

// --- post-handshake Crypter (Chromium cablev2::Crypter) ---

class Crypter(readKey: ByteArray, writeKey: ByteArray) {
    private val readKey = readKey.copyOf()
    private val writeKey = writeKey.copyOf()
    private var readSeq = 0
    private var writeSeq = 0

    fun encrypt(message: ByteArray): ByteArray {
        require(writeSeq <= MAX_SEQ) { "caBLE sequence exhausted" }
        // Pad the message length to a multiple of 32: msg ++ zeros ++ [count].
        val paddedLen = (message.size + 1 + 31) / 32 * 32
        val numZeros = paddedLen - message.size - 1
        val padded = ByteArray(paddedLen)
        message.copyInto(padded)
        padded[paddedLen - 1] = numZeros.toByte()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(writeKey, "AES"),
            GCMParameterSpec(128, crypterNonce(writeSeq)),
        )
        writeSeq++
        return cipher.doFinal(padded)
    }

    fun decrypt(ciphertext: ByteArray): ByteArray? {
        if (readSeq > MAX_SEQ) return null
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val padded = try {
            cipher.init(
                Cipher.DECRYPT_MODE,
                SecretKeySpec(readKey, "AES"),
                GCMParameterSpec(128, crypterNonce(readSeq)),
            )
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            return null
        }
        if (padded.isEmpty()) return null
        val padLen = padded[padded.size - 1].toInt() and 0xff
        if (padLen + 1 > padded.size) return null
        readSeq++
        return padded.copyOfRange(0, padded.size - padLen - 1)
    }

    /** 12-byte nonce: 8 zero bytes ‖ 4-byte big-endian counter (Crypter::ConstructNonce). */
    private fun crypterNonce(counter: Int): ByteArray =
        ByteArray(8) + byteArrayOf(
            (counter ushr 24).toByte(),
            (counter ushr 16).toByte(),
            (counter ushr 8).toByte(),
            counter.toByte(),
        )

    companion object {
        const val MAX_SEQ = (1 shl 24) - 1
    }
}

// --- handshake (Chromium HandshakeInitiator / RespondToHandshake) ---

class HandshakeResult(val crypter: Crypter, val handshakeHash: ByteArray)

private const val P256_X962 = Ec.X962_LEN
private const val EMPTY_CIPHERTEXT = 16 // AES-256-GCM tag on empty plaintext
private const val RESPONSE_SIZE = P256_X962 + EMPTY_CIPHERTEXT

/**
 * Desktop/initiator side. Constructed with exactly one of [peerIdentity]
 * (paired: the phone's static public key) or [identitySeed] (QR flow: this
 * desktop's own QR seed). [psk] null only for no-PSK handshakes.
 */
class HandshakeInitiator(
    private val psk: ByteArray?,
    private val peerIdentity: ByteArray?,
    identitySeed: ByteArray?,
) {
    private val localIdentity: Pair<java.math.BigInteger, ECPoint>? = identitySeed?.let { Ec.keyFromSeed(it) }
    private val peerIdentityPoint: ECPoint? = peerIdentity?.let { it.toEcPoint() }
    private val noise: Noise
    private var ephemeral: KeyPair? = null

    init {
        require((peerIdentity != null) xor (localIdentity != null)) { "need peer identity or seed" }
        noise = when {
            psk == null -> Noise(Noise.NK_NO_PSK).also {
                it.mixHash(byteArrayOf(0))
                it.mixHash(peerIdentity!!)
            }
            peerIdentityPoint != null -> Noise(Noise.NK).also {
                it.mixHash(byteArrayOf(0))
                it.mixHash(peerIdentity!!)
                it.mixKeyAndHash(psk!!)
            }
            else -> Noise(Noise.KN).also {
                it.mixHash(byteArrayOf(1))
                it.mixHash(localIdentity!!.second.toX962())
                it.mixKeyAndHash(psk!!)
            }
        }
    }

    fun buildInitialMessage(): ByteArray {
        ephemeral = Ec.generateKeyPair()
        val ephPub = (ephemeral!!.public as ECPublicKey).w.toX962()
        noise.mixHash(ephPub)
        noise.mixKey(ephPub)
        if (peerIdentityPoint != null) {
            noise.mixKey(Ec.ecdh(ephemeral!!.private, peerIdentityPoint))
        }
        return ephPub + noise.encryptAndHash(ByteArray(0))
    }

    fun processResponse(response: ByteArray): HandshakeResult? {
        if (response.size != RESPONSE_SIZE) return null
        val peerPointBytes = response.copyOfRange(0, P256_X962)
        val ciphertext = response.copyOfRange(P256_X962, RESPONSE_SIZE)
        val peerPoint = try {
            peerPointBytes.toEcPoint()
        } catch (e: Exception) {
            return null
        }
        noise.mixHash(peerPointBytes)
        noise.mixKey(peerPointBytes)
        noise.mixKey(Ec.ecdh(ephemeral!!.private, peerPoint))
        if (localIdentity != null) {
            noise.mixKey(Ec.ecdh(Ec.ecPrivateKey(localIdentity.first), peerPoint))
        }
        val plaintext = noise.decryptAndHash(ciphertext) ?: return null
        if (plaintext.isNotEmpty()) return null
        val (first, second) = noise.trafficKeys()
        return HandshakeResult(Crypter(second, first), noise.handshakeHash())
    }
}

/**
 * Phone/responder side. Exactly one of [identity] (paired: the phone's
 * identity keypair) or [peerIdentity] (QR flow: the desktop's public key from
 * the scanned QR) must be non-null. Returns the (crypter + handshake hash)
 * and the response bytes, or null on failure.
 */
fun respondToHandshake(
    psk: ByteArray?,
    identity: KeyPair?,
    peerIdentity: ByteArray?,
    inMessage: ByteArray,
): Pair<HandshakeResult, ByteArray>? {
    require((peerIdentity != null) xor (identity != null)) { "need identity or peer identity" }
    if (inMessage.size < P256_X962) return null
    val peerPointBytes = inMessage.copyOfRange(0, P256_X962)
    val ciphertext = inMessage.copyOfRange(P256_X962, inMessage.size)
    val peerPoint = try {
        peerPointBytes.toEcPoint()
    } catch (e: Exception) {
        return null
    }

    val noise = when {
        psk == null -> Noise(Noise.NK_NO_PSK).also {
            it.mixHash(byteArrayOf(0))
            it.mixHashPoint((identity!!.public as ECPublicKey).w)
        }
        identity != null -> Noise(Noise.NK).also {
            it.mixHash(byteArrayOf(0))
            it.mixHashPoint((identity.public as ECPublicKey).w)
            it.mixKeyAndHash(psk)
        }
        else -> Noise(Noise.KN).also {
            it.mixHash(byteArrayOf(1))
            it.mixHash(peerIdentity!!)
            it.mixKeyAndHash(psk!!)
        }
    }
    noise.mixHash(peerPointBytes)
    noise.mixKey(peerPointBytes)
    if (identity != null) {
        noise.mixKey(Ec.ecdh(identity.private, peerPoint))
    }
    val plaintext = noise.decryptAndHash(ciphertext) ?: return null
    if (plaintext.isNotEmpty()) return null

    val ephemeral = Ec.generateKeyPair()
    val ephPub = (ephemeral.public as ECPublicKey).w.toX962()
    noise.mixHash(ephPub)
    noise.mixKey(ephPub)
    noise.mixKey(Ec.ecdh(ephemeral.private, peerPoint))
    if (peerIdentity != null) {
        noise.mixKey(Ec.ecdh(ephemeral.private, peerIdentity.toEcPoint()))
    }
    val myCiphertext = noise.encryptAndHash(ByteArray(0))
    val response = ephPub + myCiphertext

    val (first, second) = noise.trafficKeys()
    return HandshakeResult(Crypter(first, second), noise.handshakeHash()) to response
}

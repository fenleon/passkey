package com.lightphone.passkey.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * CredentialCodec round-trip + migration: legacy rows (pre-manager, no
 * timestamp fields) must decode with 0 timestamps and re-save with the new
 * fields, and a full round-trip must preserve every field. Pure JVM — the
 * Keystore-backed store's delete is covered end-to-end on the emulator.
 */
class CredentialCodecTest {

    private val alice = Credential(
        credentialId = byteArrayOf(1, 2, 3),
        rpId = "example.com",
        userName = "alice",
        userHandle = byteArrayOf(9, 8),
        uvBound = true,
        signCount = 4,
        createdAt = 1_700_000_000_000,
        lastUsedAt = 1_700_000_100_000,
    )

    @Test
    fun roundTrip_preservesEveryField() {
        val decoded = CredentialCodec.decode(CredentialCodec.encode(listOf(alice))).single()
        assertTrue(decoded.credentialId.contentEquals(alice.credentialId))
        assertTrue(decoded.userHandle.contentEquals(alice.userHandle))
        assertEquals(alice.rpId, decoded.rpId)
        assertEquals(alice.userName, decoded.userName)
        assertEquals(alice.uvBound, decoded.uvBound)
        assertEquals(alice.signCount, decoded.signCount)
        assertEquals(alice.createdAt, decoded.createdAt)
        assertEquals(alice.lastUsedAt, decoded.lastUsedAt)
    }

    @Test
    fun legacyRow_decodesWithZeroTimestamps() {
        // Pre-manager rows carry no createdAt/lastUsedAt fields.
        val json = """[{"credentialId":"QUJD","rpId":"old.com","userName":"legacy","userHandle":"REVG","uvBound":false,"signCount":3}]"""

        val c = CredentialCodec.decode(json).single()
        assertEquals("old.com", c.rpId)
        assertEquals(3L, c.signCount)
        assertEquals(0L, c.createdAt)
        assertEquals(0L, c.lastUsedAt)
    }

    @Test
    fun legacyRow_reEncodesWithTimestampFields() {
        // A later store mutation re-saves the migrated row; the new fields
        // must survive the round-trip (0 = unknown/never used, not absent).
        val legacy = CredentialCodec.decode(
            """[{"credentialId":"QUJD","rpId":"old.com","userName":"legacy","userHandle":"REVG","uvBound":false,"signCount":3}]"""
        ).single()

        val migrated = CredentialCodec.decode(CredentialCodec.encode(listOf(legacy))).single()
        assertEquals(0L, migrated.createdAt)
        assertEquals(0L, migrated.lastUsedAt)
        assertEquals(3L, migrated.signCount)
    }

    @Test
    fun deleteFilter_keepsSiblingRows() {
        // The store's delete is `save(creds.filterNot { id matches })` — the
        // same filter, exercised over the codec, must drop only the target.
        val b = alice.copy(credentialId = byteArrayOf(7, 8), rpId = "example.org", userName = "bob")
        val target = alice.credentialId

        val remaining = CredentialCodec.decode(CredentialCodec.encode(listOf(alice, b)))
            .filterNot { it.credentialId.contentEquals(target) }

        assertEquals(listOf("bob"), remaining.map { it.userName })
        assertEquals(listOf("example.org"), remaining.map { it.rpId })
    }

    @Test
    fun deleteFilter_unknownId_isNoop() {
        val remaining = CredentialCodec.decode(CredentialCodec.encode(listOf(alice)))
            .filterNot { it.credentialId.contentEquals(ByteArray(32)) }
        assertEquals(1, remaining.size)
        assertNull(remaining.firstOrNull { it.credentialId.contentEquals(ByteArray(32)) })
    }
}

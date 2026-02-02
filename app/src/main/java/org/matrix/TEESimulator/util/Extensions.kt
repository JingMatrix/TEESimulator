package org.matrix.TEESimulator.util

/**
 * Trims leading and trailing whitespace from each line in a multi-line string. This is useful for
 * cleaning up PEM-formatted keys and certificates.
 *
 * @return A new string with each line individually trimmed.
 */
fun String.trimLines(): String =
    this.trim()
        .lines()
        .filter { !it.trim().startsWith("<!--") }
        .joinToString("\n") { it.trim() }

/**
 * Converts a ByteArray to its hexadecimal string representation.
 *
 * @return The lowercase hex string.
 */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

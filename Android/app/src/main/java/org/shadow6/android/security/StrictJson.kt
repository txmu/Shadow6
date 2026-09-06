package org.shadow6.android.security

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.text.Normalizer

/** Small bounded JSON data parser, with no Android JSONObject coercion/leniency. */
object StrictJson {
    const val MAX_BYTES = 1_048_576
    private const val MAX_INTEGER = 9_007_199_254_740_991L

    fun decode(bytes: ByteArray, portable: Boolean = true): Any? {
        require(bytes.isNotEmpty() && bytes.size <= MAX_BYTES) { "JSON is empty or oversized" }
        val source = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
        return parse(source, portable)
    }

    fun parse(source: String, portable: Boolean = true): Any? {
        require(source.length <= MAX_BYTES && source.toByteArray(Charsets.UTF_8).size <= MAX_BYTES)
        return Parser(source, portable).read()
    }

    fun objectValue(value: Any?): Map<String, Any?> {
        require(value is Map<*, *> && value.keys.all { it is String }) { "Expected JSON object" }
        @Suppress("UNCHECKED_CAST")
        return value as Map<String, Any?>
    }

    fun text(value: Any?, limit: Int = 65_536, nfc: Boolean = true): String {
        require(value is String && value.length <= limit && '\u0000' !in value) { "Expected bounded JSON string" }
        var position = 0
        while (position < value.length) {
            val char = value[position++]
            if (char.isHighSurrogate()) {
                require(position < value.length && value[position++].isLowSurrogate()) { "Invalid Unicode" }
            } else require(!char.isLowSurrogate()) { "Invalid Unicode" }
        }
        require(!nfc || Normalizer.isNormalized(value, Normalizer.Form.NFC)) { "JSON text must be NFC" }
        return value
    }

    /** Matches Python json.dumps(sort_keys=True, ensure_ascii=True, separators=...). */
    fun canonical(value: Any?): String = when (value) {
        null -> "null"
        is Boolean -> value.toString()
        is Long -> { require(value in -MAX_INTEGER..MAX_INTEGER); value.toString() }
        is String -> quote(text(value))
        is List<*> -> value.joinToString(",", "[", "]") { canonical(it) }
        is Map<*, *> -> objectValue(value).toSortedMap().entries.joinToString(",", "{", "}") {
            quote(text(it.key)) + ":" + canonical(it.value)
        }
        else -> error("Non-portable JSON value")
    }

    private fun quote(value: String): String = buildString {
        append('"')
        value.forEach { char ->
            append(when (char) {
                '"' -> "\\\""; '\\' -> "\\\\"; '\b' -> "\\b"; '\u000c' -> "\\f"
                '\n' -> "\\n"; '\r' -> "\\r"; '\t' -> "\\t"
                else -> if (char.code < 32 || char.code > 126) "\\u" + char.code.toString(16).padStart(4, '0') else char.toString()
            })
        }
        append('"')
    }

    private class Parser(val source: String, val portable: Boolean) {
        var at = 0
        var nodes = 0
        fun read(): Any? {
            val value = value(0)
            whitespace()
            require(at == source.length) { "Trailing JSON input" }
            return value
        }
        fun whitespace() { while (at < source.length && source[at] in " \r\n\t") at++ }
        fun take(char: Char): Boolean {
            whitespace()
            return (at < source.length && source[at] == char).also { if (it) at++ }
        }
        fun value(depth: Int): Any? {
            require(depth <= 16 && ++nodes <= 32_768) { "JSON nesting or collection limit exceeded" }
            whitespace()
            require(at < source.length) { "Incomplete JSON" }
            return when (source[at]) {
                '{' -> {
                    at++
                    val result = linkedMapOf<String, Any?>()
                    if (!take('}')) {
                        do {
                            whitespace()
                            val key = string()
                            require(!result.containsKey(key) && take(':')) { "Duplicate field or missing colon" }
                            result[key] = value(depth + 1)
                        } while (take(','))
                        require(take('}')) { "Missing closing brace" }
                    }
                    result
                }
                '[' -> {
                    at++
                    val result = mutableListOf<Any?>()
                    if (!take(']')) {
                        do { result.add(value(depth + 1)) } while (take(','))
                        require(take(']')) { "Missing closing bracket" }
                    }
                    result
                }
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> number()
            }
        }
        fun literal(token: String, result: Any?): Any? {
            require(source.startsWith(token, at)) { "Invalid JSON literal" }
            at += token.length
            return result
        }
        fun string(): String {
            require(at < source.length && source[at++] == '"') { "Expected quoted string" }
            val result = StringBuilder()
            while (at < source.length) {
                val char = source[at++]
                if (char == '"') return text(result.toString(), nfc = portable)
                require(char.code >= 32 && result.length < 65_536) { "Invalid or oversized JSON string" }
                if (char != '\\') result.append(char) else {
                    require(at < source.length)
                    result.append(when (val escape = source[at++]) {
                        '"', '\\', '/' -> escape
                        'b' -> '\b'; 'f' -> '\u000c'; 'n' -> '\n'; 'r' -> '\r'; 't' -> '\t'
                        'u' -> {
                            require(at + 4 <= source.length)
                            val code = source.substring(at, at + 4)
                            require(code.all { it in "0123456789abcdefABCDEF" })
                            at += 4
                            code.toInt(16).toChar()
                        }
                        else -> error("Invalid JSON escape")
                    })
                }
            }
            error("Unterminated JSON string")
        }
        fun number(): Number {
            val start = at
            while (at < source.length && source[at] !in " \r\n\t,]}") {
                at++
                require(at - start <= 128) { "Oversized JSON number" }
            }
            val token = source.substring(start, at)
            require(Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?").matches(token)) { "Invalid JSON number" }
            if (token.none { it in ".eE" }) {
                val integer = token.toLongOrNull()
                require(integer != null && integer in -MAX_INTEGER..MAX_INTEGER) { "Non-portable integer" }
                return integer
            }
            require(!portable) { "Floats are not allowed in signed JSON" }
            return token.toDouble().also { require(it.isFinite()) }
        }
    }
}

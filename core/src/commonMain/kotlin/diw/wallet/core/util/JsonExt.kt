package diw.wallet.core.util

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

/** Lenient JSON instance shared by protocol code. Unknown keys are always tolerated. */
val DiwJson: Json = Json {
    ignoreUnknownKeys = true
    explicitNulls = false
    encodeDefaults = false
}

/** Thrown when a protocol message violates its specification. Messages are meant for logs and diagnostics. */
open class ProtocolException(
    val code: String,
    message: String,
    cause: Throwable? = null
) : Exception(message, cause)

fun JsonObject.str(name: String): String? =
    (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content

fun JsonObject.reqStr(name: String, code: String = "invalid_request"): String =
    str(name) ?: throw ProtocolException(code, "Missing or non-string '$name'")

fun JsonObject.obj(name: String): JsonObject? = this[name] as? JsonObject

fun JsonObject.reqObj(name: String, code: String = "invalid_request"): JsonObject =
    obj(name) ?: throw ProtocolException(code, "Missing or non-object '$name'")

fun JsonObject.arr(name: String): JsonArray? = this[name] as? JsonArray

fun JsonObject.long(name: String): Long? = (this[name] as? JsonPrimitive)?.longOrNull

fun JsonObject.int(name: String): Int? = (this[name] as? JsonPrimitive)?.intOrNull

fun JsonObject.bool(name: String): Boolean? = (this[name] as? JsonPrimitive)?.booleanOrNull

fun JsonObject.strList(name: String): List<String> = when (val e = this[name]) {
    is JsonArray -> e.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
    is JsonPrimitive -> if (e.isString) listOf(e.content) else emptyList()
    else -> emptyList()
}

fun JsonElement?.isNullOrJsonNull(): Boolean = this == null || this is JsonNull

fun parseJsonObject(text: String, code: String = "invalid_request"): JsonObject = try {
    DiwJson.parseToJsonElement(text) as? JsonObject
        ?: throw ProtocolException(code, "JSON value is not an object")
} catch (e: ProtocolException) {
    throw e
} catch (e: Exception) {
    throw ProtocolException(code, "Malformed JSON: ${e.message}", e)
}

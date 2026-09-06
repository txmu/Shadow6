package org.shadow6.android.i18n
import org.shadow6.android.security.StrictJson
import java.util.Locale
/** Stable extension point for bounded, already signature-verified third-party language bundles. */
class TranslationRegistry(private val fallback: Map<String,String>) {
    fun parse(json: String): Map<String, String> {
        val root = StrictJson.objectValue(StrictJson.parse(json))
        require(root.size <= 4096)
        return root.mapValues { (key, value) ->
            require(key.length <= 256 && key.matches(Regex("^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)+$")))
            StrictJson.text(value, 4096)
        }
    }
    fun text(key:String, locale:Locale, bundles:Map<String,Map<String,String>>):String = bundles[locale.toLanguageTag()]?.get(key) ?: bundles[locale.language]?.get(key) ?: fallback[key] ?: key
}

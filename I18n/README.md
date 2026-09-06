# Shadow6 i18n contribution contract

CLIs and third-party components may add strict UTF-8 JSON bundles named with a
BCP-47 language tag such as `en.json` or `zh-CN.json`. Keys are stable,
namespaced identifiers (`component.section.message`); values are bounded
Unicode strings and use Python-style named placeholders. English is the
fallback. A contribution must keep placeholder names identical in every
locale, include tests, and must not place secrets in translations.

Plugins receive a top-level `locale` request field and return their effective
locale. Android uses normal `values[-locale]/strings.xml` resources for bundled
UI and `TranslationRegistry` for signed third-party message bundles. Unknown or
invalid locales fall back to English rather than changing security behavior.

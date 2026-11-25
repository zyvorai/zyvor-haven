-- Per-realm branding of the sign-in pages and emails, and per-realm, per-language
-- email wording. A realm without a row has the built-in look and wording (the
-- behaviour before this migration). Nothing here is a secret.
CREATE TABLE IF NOT EXISTS realm_branding (
    realm             text PRIMARY KEY REFERENCES realms(name) ON DELETE CASCADE,
    display_name      text NOT NULL DEFAULT '',
    accent_color      text NOT NULL DEFAULT '',
    accent_color_dark text NOT NULL DEFAULT '',
    logo_light        text NOT NULL DEFAULT '',
    logo_dark         text NOT NULL DEFAULT '',
    support_url       text NOT NULL DEFAULT '',
    privacy_url       text NOT NULL DEFAULT '',
    terms_url         text NOT NULL DEFAULT '',
    default_locale    text NOT NULL DEFAULT '',
    updated_at        timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS realm_email_templates (
    realm      text NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    kind       text NOT NULL,
    locale     text NOT NULL,
    subject    text NOT NULL,
    body_text  text NOT NULL,
    body_html  text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (realm, kind, locale)
);

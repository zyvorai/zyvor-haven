# Branding, email templates and languages

Each realm of haven-idp can have its own name, accent colour, logo and footer links on the sign-in pages, its own
wording for the emails it sends, and a default language. The pages and emails exist in **English, German and
Hindi**. Everything here is optional: a realm that sets nothing looks and reads exactly as before.

!!! warning "Translation quality"
    The German and Hindi texts are **machine-generated** (written by an AI model) and have **not been reviewed by a
    native speaker**. Treat them as a draft: have someone who reads the language check them before real users do,
    especially the security warnings on the approval pages. English is the source text. Corrections go in
    `internal/idp/i18n/catalog_de.go` and `catalog_hi.go`.

## Branding

Set with the Admin API; the whole record is replaced on each `PUT`.

```bash
curl -X PUT "$IDP/admin/v1/realms/acme/branding" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{
    "displayName": "Acme Cloud",
    "accentColor": "#0a6644",
    "accentColorDark": "#66ddaa",
    "logoLight": "<svg viewBox=\"0 0 120 32\"><rect width=\"32\" height=\"32\" rx=\"8\" fill=\"#0a6644\"/></svg>",
    "supportUrl": "https://help.acme.example/",
    "privacyUrl": "https://acme.example/privacy",
    "termsUrl": "https://acme.example/terms",
    "defaultLocale": "de"
  }'
```

| Field | Rule |
|---|---|
| `displayName` | replaces the realm's display name on pages and in emails; at most 64 characters, one line, no invisible formatting characters, no `://`, `@`, `<` or `>` |
| `accentColor` | `#rrggbb`; links and button fills in light mode. Must reach a contrast of **4.5:1 against the white card**, otherwise `400` |
| `accentColorDark` | optional, `#rrggbb`, 4.5:1 against the dark card (`#1d1d1f`). Left empty, a lighter shade of the accent is derived (`effectiveAccentColorDark` in the response) |
| `logoLight`, `logoDark` | inline SVG source, see below; `logoDark` is optional and needs `logoLight` |
| `supportUrl`, `privacyUrl`, `termsUrl` | absolute `https` URLs, printable ASCII, no user name or password |
| `defaultLocale` | `en`, `de`, `hi` or empty |

One colour cannot be readable on both a white and a near-black background (it would need to be darker than one
limit and lighter than another), which is why dark mode has its own value. Button labels are white or black,
whichever reads better, and hover and pressed shades move away from the label colour, so they are never less
readable than the accent.

The logo takes the place of the page's illustration. The links appear at the foot of the card.

### Logos: why a strict SVG subset

Logos are **SVG only, a small subset, rebuilt by the server**. PNG is not accepted.

* The pages are served with `Content-Security-Policy: default-src 'none'; style-src 'nonce-…'`. Showing an image
  file, from this server or as a `data:` URI, would need a new `img-src` permission. An `<svg>` element that is part
  of the document needs **none**, so branding does not change the policy at all.
* Sanitising SVG is risky when the idea is to delete the bad parts of somebody's file. haven-idp does not do that.
  It parses the upload and **writes a new document** from a closed vocabulary. Anything outside it rejects the
  whole upload.

| Allowed | |
|---|---|
| elements | `svg` (root, `viewBox` required), `g`, `path`, `rect`, `circle`, `ellipse`, `line`, `polyline`, `polygon` |
| geometry | `d`, `points`, `x`, `y`, `width`, `height`, `rx`, `ry`, `cx`, `cy`, `r`, `x1`, `y1`, `x2`, `y2` |
| presentation | `fill`, `stroke` (`none`, `currentColor`, `#rgb`, `#rrggbb`), `stroke-width`, `stroke-linecap`, `stroke-linejoin`, `stroke-miterlimit`, `fill-rule`, `clip-rule`, `opacity`, `fill-opacity`, `stroke-opacity`, `transform` |
| limits | 16 KiB, 200 elements, 8 levels |

Refused, among others: scripts, event handlers, `style` and `class`, `id`, gradients and anything else that uses
`url(#…)`, links, `use`, `image`, `foreignObject`, animation, text, other namespaces, DOCTYPE, entities and
processing instructions. Comments are dropped. If your drawing program writes `style="fill:…"`, export with
presentation attributes (for example "SVG 1.1, styling: presentation attributes") and convert text to outlines.

The server stores the rebuilt form and **validates it again** each time a page is rendered.

## Email templates

A realm can replace the wording of any email, per language. Where it has none for a language, the built-in wording
in **that language** is used (a custom English template is not shown to a German reader).

| `kind` | Variables | Link |
|---|---|---|
| `verify_email` | `realm`, `username`, `link`, `hours` | required |
| `reset_password` | `realm`, `username`, `link`, `hours` | required |
| `change_email` (to the new address) | `realm`, `username`, `link`, `hours` | required |
| `password_changed` | `realm`, `username`, `when`, `via` | never |
| `email_change_requested` (to the old address) | `realm`, `username`, `new_email` (masked), `when` | never |
| `email_changed` (to the old address) | `realm`, `username`, `new_email` (masked), `when` | never |
| `ciba_approval` | `realm`, `username`, `link`, `client`, `binding`, `scope`, `resources`, `minutes` | required |

A template has a `subject`, a `text` body and an optional `html` body. SMTP stays **one per deployment**
([email-and-password-reset.md](email-and-password-reset.md)).

```json
{
  "subject": "{{realm}}: Passwort zurücksetzen",
  "text": "Hallo {{username}},\n\nöffnen Sie diesen Link (gültig {{hours}} Std.):\n\n{{link}}\n",
  "html": "<p>Hallo {{username}},</p><p><a href=\"{{link}}\">Neues Passwort wählen</a></p>"
}
```

### What is checked at upload (and again before sending)

* **No template execution.** The only syntax is `{{name}}`. It is replaced once; a value that looks like a
  placeholder stays as typed. There are no conditionals, loops, functions or fields, and a template can only name
  the variables of its kind, so nothing else (settings, secrets, tokens, other users) is reachable.
* **Links only to our own URLs.** The only link is `{{link}}`, which the server fills. The literal text may not
  contain anything a mail program would turn into a link or address: `://`, `//host`, `www.`, `name.tld`,
  IP addresses, `mailto:`, `tel:`, `@`. Variables count as words, so `evil.{{realm}}` is refused. Entities,
  full-width letters, ideographic full stops and zero-width joiners are folded before the check. `{{link}}` must
  stand alone, separated by white space or a tag.
* **HTML is formatting only:** `html`, `head`, `body`, `title`, `meta charset`, headings, paragraphs, lists,
  tables, `a`, `span`, `div`, `strong`, `em`, `b`, `i`, `u`, `s`, `small`, `code`, `pre`, `blockquote`, `br`, `hr`.
  No images, scripts, `style` elements, forms, frames, comments or event handlers. `href` must be exactly
  `{{link}}`. `style` attributes take plain colours, sizes, spacing and fonts (no functions such as `url()`).
* Values are HTML-escaped in the HTML body. Control and bidirectional-override characters are refused.
* Limits: subject 200 characters, text 16 KiB, HTML 64 KiB.

The address check is deliberately blunt. "z. B." is fine; a sentence with a missing space after a full stop
("Hello.Bye") is refused. If a stored template ever fails validation, or cannot be loaded, the built-in wording is
sent instead and a warning is logged: a broken template never stops a password reset.

Limits of the check: values such as `{{username}}`, `{{client}}` and `{{binding}}` are filled in as they are, and a
user or application could choose a value that a mail program shows as a link (the built-in wording has the same
property). `{{binding}}` is always quoted.

### Preview and test send

* `POST …/email-templates/{kind}/{locale}/preview` returns `{source, subject, text, html}` filled with made-up data.
  With a `{subject, text, html}` body it previews that draft; without one, the stored template, else the built-in
  wording (`source` is `draft`, `custom` or `builtin`). The sample link points at this server and is not a token.
* `POST …/email-templates/{kind}/{locale}/test-send` (same optional body) mails that sample, subject prefixed
  `[Test]`, **to the address of the administrator making the call**. The request cannot name a recipient. It needs
  an administrator *user* token (a user holding `haven-admin`) whose account has an email address; service accounts
  get `409`. Limit: 10 per administrator per hour. `409` when SMTP is not configured.

## Languages

For each page the first of these that names a language we have wins:

1. `ui_locales` (OIDC, space separated, in order of preference), also from a pushed or signed authorization request;
2. the browser's `Accept-Language`, by quality value;
3. the realm's `defaultLocale`;
4. English.

Only the primary subtag matters (`de-AT` is `de`). The page carries `<html lang="…">`; discovery lists
`ui_locales_supported`. `ui_locales` is carried on the links, form targets and sign-in redirects between pages. It
is not carried in emailed links, in the redirect that returns from the sign-in step of the device and approval
flows, or into "Continue with …" beyond the authorization request itself; there the browser's language applies.

Emails sent because of what someone just did in a browser (sign-in, forgot password, reset, email change) use the
language chosen for that request; emails sent from the Admin API and CIBA approval emails use the realm's default.
There is no stored per-user language.

Layout is ready for right-to-left languages (logical CSS properties, `dir="rtl"` for `ar`, `fa`, `he`, `ur`, isolated
user-chosen names, codes and keys kept left-to-right). No right-to-left catalogue ships.

Not translated: OAuth/OIDC protocol errors (`error_description`), Admin API messages, logs, dates (ISO format, UTC),
scope names, and text that comes from configuration (realm, client and provider names).

## Adding or changing a page

The English text is the key. Missing translations show English.

```go
type myView struct {
    Nonce string
    Name  string
    L     Loc // 1. a field L
}

var myTmpl = template.Must(template.New("my").Parse(withTheme(`<!doctype html>
<html<!--loc-->><head>...<title>{{.L.T "My page"}}</title>
<!--theme--></head><body><main>
<!--hero:lock-->
<h1>{{.L.T "Hello %s" .Name}}</h1>
<p>{{.L.H "Signed in as %s." (.L.B .Name)}}</p>
</main></body></html>`)))

// in the handler, before WriteHeader:
l := p.loc(w)
```

1. Start the template with `<html<!--loc-->>` and pass it through `withTheme`. That adds `lang`/`dir`, the accent
   colours inside the one nonce'd stylesheet, the logo in place of the illustration, and the footer.
2. Give the data a field `L Loc` and set it with `p.loc(w)`.
3. Write every fixed text as `{{$.L.T "…"}}` (or `{{$.L.H "… %s …" ($.L.B x)}}` when part is bold or code).
   Messages passed from Go to `simplePage`, `errorPage`, `stepPage` and `mfaPage` are translated automatically;
   compose ones with parameters yourself: `p.loc(w).T("… %s …", name)`.
4. Add the German and Hindi lines to the catalogues.
5. Add the template to `localizedPages()` and the file to `localizedFiles` in
   `internal/idp/oidc/i18n_complete_test.go`. The tests then fail on any text left outside the catalogue.

A step page rendered through `stepPage` or `mfaPage` is already branded; only steps 3 to 5 apply. A page that skips
all of this still works: English, unbranded.

## Security properties

* The Content-Security-Policy is unchanged by branding. No `img-src`, no external resources.
* Colours are parsed to numbers and the CSS is formatted from those numbers; typed text never enters a stylesheet.
* Logos are rebuilt from a closed vocabulary; links must be `https`; all stored values are validated again at render
  time, so a tampered database row is ignored rather than shown.
* Languages come from a fixed list; request values are never echoed into the page.
* Email templates cannot execute anything or link elsewhere; test sends go only to the caller.
* Changes need the Admin API's authentication and are audited (`ADMIN_UPDATE|DELETE "branding …"`,
  `"email-template <kind>/<locale>"`, `ADMIN_ACTION "email-template-test …"`; content is never logged).
* A store without `core.BrandingStore` answers `501` on these routes and shows the built-in look. If branding cannot
  be loaded, pages are shown unbranded.

## Storage

PostgreSQL migration `0026_branding.sql` (`realm_branding`, `realm_email_templates`, removed with the realm).
Included in `haven-idp dev --persist` snapshots.

## Not yet

* Review of the German and Hindi text by native speakers; further languages; a per-user language.
* The [account console](account-console.md) is branded but not translated (the links to it are).
* PNG or other bitmap logos, SVG gradients or text, a favicon, background images, custom fonts or CSS.
* The authenticator-app (TOTP) issuer name and the passkey relying-party name still use the realm's own names.
* Only the accent colour is configurable; the hero gradient and background are not.
* Branding and templates are not part of config as code (`plan`/`apply`), the realm export or the console UI, and are
  not gated by Haven Guard.
* No plural rules beyond the two fixed sentences about link lifetime; minutes use "minute(s)".

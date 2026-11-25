// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"regexp"
	"strings"
)

// themeMarker is where a page template wants the shared theme. withTheme
// replaces it with the one nonce'd <style> block; a template without it fails
// at start-up (template.Must), so no page can ship with its own look.
const themeMarker = "<!--theme-->"

// themeCSS is the single stylesheet of every server-rendered page: a calm,
// typographic, single-column look in light and dark with a frosted card over a
// slowly drifting gradient mesh. System fonts only, no external resources, no
// images, nothing but CSS (transform/opacity animations, off under
// prefers-reduced-motion). Pages style bare elements plus a few classes (.sub,
// .err, .ok, .warn, .code, .row, .deny, .secondary, .fed, .wide, .item, .hero);
// keep new pages to those.
const themeCSS = `
:root{color-scheme:light dark;--bg:#fff;--card:#fff;--glass:rgba(255,255,255,.74);--edge:rgba(0,0,0,.08);--surface:#f5f5f7;--field:#fff;--text:#1d1d1f;--muted:#6e6e73;--line:#d2d2d7;--link:#0066cc;--accent:#0071e3;--accent-h:#0077ed;--accent-a:#006edb;--err:#e30000;--ok:#1d7a3a;--ring:rgba(0,113,227,.25);--t1:#1d1d1f;--t2:#4b3fd1;--g1:#0a84ff;--g2:#5e5ce6;--g3:#bf5af2;--shadow:0 1px 2px rgba(0,0,0,.04),0 8px 24px rgba(0,0,0,.06),0 24px 64px rgba(60,60,140,.10);--m1:rgba(0,113,227,.16);--m2:rgba(94,92,230,.14);--m3:rgba(191,90,242,.11);--m4:rgba(50,200,190,.12)}
@media (prefers-color-scheme:dark){:root{--bg:#000;--card:#1d1d1f;--glass:rgba(29,29,31,.72);--edge:rgba(255,255,255,.1);--surface:#2a2a2d;--field:rgba(0,0,0,.5);--text:#f5f5f7;--muted:#86868b;--line:#424245;--link:#2997ff;--err:#ff453a;--ok:#30d158;--ring:rgba(41,151,255,.35);--t1:#f5f5f7;--t2:#9db8ff;--shadow:0 1px 2px rgba(0,0,0,.4),0 12px 32px rgba(0,0,0,.5),0 32px 80px rgba(20,20,80,.35);--m1:rgba(10,132,255,.34);--m2:rgba(94,92,230,.32);--m3:rgba(191,90,242,.22);--m4:rgba(50,200,190,.16)}}
*,*::before,*::after{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;min-height:100vh;background:var(--bg);color:var(--text);font:17px/1.47 -apple-system,BlinkMacSystemFont,"SF Pro Text","SF Pro Display","Helvetica Neue",Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;letter-spacing:-.022em;overflow-x:hidden}
body::before{content:"";position:fixed;inset:-25%;z-index:-1;pointer-events:none;background:radial-gradient(40% 40% at 22% 24%,var(--m1),transparent 70%),radial-gradient(38% 42% at 80% 18%,var(--m2),transparent 70%),radial-gradient(44% 40% at 70% 82%,var(--m3),transparent 70%),radial-gradient(34% 34% at 14% 80%,var(--m4),transparent 70%);animation:drift 32s ease-in-out infinite alternate;will-change:transform}
@keyframes drift{from{transform:translate3d(-2%,-1%,0) rotate(0deg) scale(1)}to{transform:translate3d(2%,2%,0) rotate(6deg) scale(1.08)}}
[hidden]{display:none!important}
main{width:min(440px,calc(100% - 24px));margin:max(20px,8vh) auto 48px;padding:40px 32px 36px;background:var(--card);border:1px solid var(--edge);border-radius:28px;box-shadow:var(--shadow);animation:rise .25s ease-out backwards}
@supports ((-webkit-backdrop-filter:blur(1px)) or (backdrop-filter:blur(1px))){main{background:var(--glass);-webkit-backdrop-filter:blur(28px) saturate(170%);backdrop-filter:blur(28px) saturate(170%)}}
main.wide{width:min(600px,calc(100% - 24px))}
@keyframes rise{from{opacity:0;transform:translateY(8px)}}
.hero{display:block;width:72px;height:72px;margin:0 auto 20px;overflow:visible;filter:drop-shadow(0 8px 18px rgba(94,92,230,.35))}
.hero .tile{fill:url(#hg)}
.hero .hs1{stop-color:var(--g1)}.hero .hs2{stop-color:var(--g2)}.hero .hs3{stop-color:var(--g3)}
.hero .gl{fill:none;stroke:#fff;stroke-width:2.5;stroke-linecap:round;stroke-linejoin:round}
.hero .gf{fill:#fff;stroke:none}
.hero .shine{fill:#fff;opacity:.16}
.hero .draw{stroke-dasharray:90;stroke-dashoffset:0;animation:draw .8s .2s ease-out backwards}
@keyframes draw{from{stroke-dashoffset:90}}
h1{margin:0 0 12px;font-size:clamp(1.75rem,1.3rem + 1.8vw,2.25rem);line-height:1.12;font-weight:600;letter-spacing:-.025em;text-align:center;overflow-wrap:anywhere;color:var(--text)}
@supports ((-webkit-background-clip:text) or (background-clip:text)){h1{background:linear-gradient(115deg,var(--t1) 35%,var(--t2) 100%);-webkit-background-clip:text;background-clip:text;-webkit-text-fill-color:transparent}}
h1+.sub{text-align:center}
h2{font-size:1.3rem;line-height:1.2;font-weight:600;letter-spacing:-.02em;margin:40px 0 12px}
p{margin:0 0 16px;overflow-wrap:anywhere}
strong{font-weight:600}
.sub{color:var(--muted);font-size:.9rem;line-height:1.45;letter-spacing:-.016em}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
a:focus-visible,button:focus-visible{outline:none;box-shadow:0 0 0 4px var(--ring)}
label{display:block;margin:20px 0 6px;font-size:.88rem;color:var(--muted);letter-spacing:-.01em}
input{display:block;width:100%;height:48px;padding:0 16px;font:inherit;color:var(--text);background:var(--field);border:1px solid var(--line);border-radius:12px;letter-spacing:-.01em;transition:border-color .15s,box-shadow .15s;-webkit-appearance:none;appearance:none}
input::placeholder{color:var(--muted);opacity:.8}
input:hover{border-color:var(--muted)}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 4px var(--ring)}
input[type=hidden]{display:none}
input[name=code],input[name=user_code]{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:1.3rem;letter-spacing:.18em;text-align:center}
input[name=user_code]{text-transform:uppercase}
button{position:relative;display:block;width:100%;min-height:48px;margin-top:24px;padding:0 20px;font:inherit;font-weight:400;letter-spacing:-.01em;color:#fff;background:var(--accent);border:1px solid transparent;border-radius:12px;cursor:pointer;transition:background-color .15s,border-color .15s,box-shadow .15s,transform .12s}
button:hover{background:var(--accent-h)}
button:active{background:var(--accent-a);transform:scale(.985)}
button:disabled,button[aria-busy=true]{cursor:progress;color:transparent;opacity:.85}
button:disabled::after,button[aria-busy=true]::after{content:"";position:absolute;top:50%;left:50%;width:20px;height:20px;margin:-10px 0 0 -10px;border:2px solid rgba(255,255,255,.4);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
button+button{margin-top:12px}
button.deny,button.secondary,#pkform button,button[value=deny],form.row button,div.row>button+button{color:var(--link);background:transparent;border-color:var(--line)}
button.deny:hover,button.secondary:hover,#pkform button:hover,button[value=deny]:hover,form.row button:hover{background:var(--surface)}
button.deny:active,button.secondary:active,#pkform button:active,button[value=deny]:active,form.row button:active{background:var(--line)}
button.deny:disabled::after,button.secondary:disabled::after,#pkform button:disabled::after{border-color:var(--line);border-top-color:var(--link)}
a.fed{display:flex;align-items:center;justify-content:center;min-height:48px;margin-top:12px;padding:0 20px;color:var(--link);border:1px solid var(--line);border-radius:12px;transition:background-color .15s}
a.fed:hover{background:var(--surface);text-decoration:none}
form+form{margin-top:32px}
form~p.sub{margin:20px 0 0;text-align:center}
.err{color:var(--err);font-size:.92rem;line-height:1.45;margin:12px 0}
h1+.err,h1+.sub+.err{text-align:center}
.ok{color:var(--ok);font-size:.92rem;margin:12px 0}
.warn{margin:24px 0;padding:14px 16px;background:var(--surface);border:1px solid var(--line);border-radius:14px;font-size:.9rem;line-height:1.45}
div.row{display:flex;gap:12px;align-items:stretch}
div.row>form{flex:1;min-width:0;margin-top:0}
div.row>form button{margin-top:0}
div.row>input{flex:1;min-width:0}
div.row>button{flex:0 0 auto;width:auto;margin-top:0}
form.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
form.row+form.row{margin-top:8px}
form.row input{flex:1 1 12rem;width:auto;min-width:0}
form.row button{flex:0 0 auto;width:auto;margin-top:0}
ul{list-style:none;margin:0 0 16px;padding:0;border-top:1px solid var(--line)}
li{padding:12px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.item{padding:16px 0;border-top:1px solid var(--line)}
.item p{margin:0 0 12px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.88em;letter-spacing:0}
code{padding:1px 6px;background:var(--surface);border-radius:6px;word-break:break-all}
pre{margin:16px 0;padding:16px;background:var(--surface);border-radius:14px;font-size:1.1rem;line-height:1.9;letter-spacing:.12em;text-align:center;white-space:pre-wrap;overflow-wrap:anywhere}
.code{margin:16px 0;padding:18px 12px;font:600 1.75rem/1.2 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;letter-spacing:.2em;text-align:center;background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow-wrap:anywhere}
blockquote{margin:12px 0;padding:4px 0 4px 16px;border-left:3px solid var(--line);color:var(--muted);overflow-wrap:anywhere}
dl{margin:16px 0;font-size:.9rem}
dt{color:var(--muted);margin-top:12px;font-size:.82rem}
dd{margin:2px 0 0;overflow-wrap:anywhere}
@media (max-width:480px){main{padding:32px 20px 28px;border-radius:24px;margin-top:12px}}
@media (prefers-reduced-motion:reduce){*,*::before,*::after{transition:none!important;animation:none!important}}
@media (forced-colors:active){body::before{display:none}main{background:Canvas;border:1px solid CanvasText;box-shadow:none;-webkit-backdrop-filter:none;backdrop-filter:none}h1{background:none;-webkit-text-fill-color:CanvasText;color:CanvasText}.hero{filter:none;forced-color-adjust:none}.hero .tile{fill:Canvas;stroke:CanvasText}.hero .gl{stroke:CanvasText}.hero .gf{fill:CanvasText}.hero .shine{display:none}button{background:ButtonFace;color:ButtonText;border-color:ButtonText}input{border-color:CanvasText}a{color:LinkText}}
`

// themeStyle is the full nonce'd style element injected into every page.
const themeStyle = `<style nonce="{{.Nonce}}">` + themeCSS + consoleCSS + `</style>`

// heroGlyphs are the illustrations, drawn on a 64x64 tile in one style
// (rounded 2.5 strokes, white glyph on a gradient tile with a soft glow). They
// are static markup, aria-hidden, and use classes from themeCSS only.
var heroGlyphs = map[string]string{ // #nosec G101 -- SVG path data, no credentials
	"lock":         `<rect class="gl" x="19" y="29" width="26" height="19" rx="6"/><path class="gl" d="M24 29v-5a8 8 0 0 1 16 0v5"/><circle class="gf" cx="32" cy="37.5" r="2.6"/><path class="gl" d="M32 40v4"/>`,
	"fingerprint":  `<path class="gl" d="M18 32c1-9 7-15 14-15s13 6 14 15"/><path class="gl" d="M22 41c0-8 4-14 10-14s10 6 10 14"/><path class="gl" d="M27 46c0-6 2-10 5-10s5 4 5 8"/><path class="gl" d="M32 47v-8"/>`,
	"shield-code":  `<path class="gl" d="M32 15l14 5v10c0 9-6 15-14 19-8-4-14-10-14-19V20z"/><circle class="gf" cx="25" cy="31" r="1.8"/><circle class="gf" cx="32" cy="31" r="1.8"/><circle class="gf" cx="39" cy="31" r="1.8"/>`,
	"shield-check": `<path class="gl" d="M32 15l14 5v10c0 9-6 15-14 19-8-4-14-10-14-19V20z"/><path class="gl" d="M25.5 32l4.5 4.5 8.5-9"/>`,
	"envelope":     `<rect class="gl" x="15" y="21" width="34" height="23" rx="6"/><path class="gl" d="M18 25l14 11 14-11"/>`,
	"door":         `<path class="gl" d="M27 18h-7a2 2 0 0 0-2 2v24a2 2 0 0 0 2 2h7"/><path class="gl" d="M31 32h18M43 26l6 6-6 6"/>`,
	"devices":      `<rect class="gl" x="13" y="21" width="28" height="19" rx="3.5"/><path class="gl" d="M10 46h34"/><rect class="gl" x="44" y="29" width="9" height="17" rx="2.5"/>`,
	"person":       `<circle class="gl" cx="32" cy="25" r="8"/><path class="gl" d="M18 47c1-9 7-13 14-13s13 4 14 13"/>`,
	"bell":         `<path class="gl" d="M32 17a9 9 0 0 0-9 9v7l-3 5h24l-3-5v-7a9 9 0 0 0-9-9z"/><path class="gl" d="M28 44a4 4 0 0 0 8 0"/>`,
	"compass":      `<circle class="gl" cx="32" cy="32" r="14"/><path class="gl" d="M38.5 25.5l-3.5 9-9 3.5 3.5-9z"/>`,
	"check":        `<circle class="gl draw" cx="32" cy="32" r="14"/><path class="gl draw" d="M25.5 32.5l5 5 9-10"/>`,
}

var heroMarkerRE = regexp.MustCompile(`<!--hero:([a-z-]+)-->`)

// heroSVG renders the named illustration; it panics on an unknown name (only
// reachable from package-level template initialisers).
func heroSVG(name string) string {
	g, ok := heroGlyphs[name]
	if !ok {
		panic("oidc: unknown hero " + name)
	}
	return `<svg class="hero" viewBox="0 0 64 64" aria-hidden="true" focusable="false"><defs><linearGradient id="hg" x1="0" y1="0" x2="1" y2="1"><stop class="hs1" offset="0"/><stop class="hs2" offset=".6"/><stop class="hs3" offset="1"/></linearGradient></defs>` +
		`<rect class="tile" x="2" y="2" width="60" height="60" rx="17"/><path class="shine" d="M19 2h26a17 17 0 0 1 17 17v2C46 24 22 22 2 14v-2A10 10 0 0 1 12 2z"/>` + g + `</svg>`
}

// heroForBody picks the illustration of a step page from its (static) body.
func heroForBody(body string) string {
	switch {
	case strings.Contains(body, `data-pk=`):
		return "fingerprint"
	case strings.Contains(body, "consent_decision"), strings.Contains(body, "grant_id"):
		return "shield-check"
	case strings.Contains(body, `name="email"`), strings.Contains(body, "new email address"):
		return "envelope"
	case strings.Contains(body, "mfa_token"), strings.Contains(body, `name="code"`), strings.Contains(body, "recovery codes"):
		return "shield-code"
	}
	return "lock"
}

// withTheme injects the shared theme at themeMarker and expands every
// <!--hero:name--> marker. It panics when the theme marker is missing (called
// from package-level template.Must initialisers).
func withTheme(src string) string {
	if !strings.Contains(src, themeMarker) {
		panic("oidc: page template lacks " + themeMarker)
	}
	src = strings.Replace(src, themeMarker, themeStyle, 1)
	return heroMarkerRE.ReplaceAllStringFunc(src, func(m string) string {
		return heroSVG(heroMarkerRE.FindStringSubmatch(m)[1])
	})
}

// consoleCSS styles the account console (account_ui.go): a sidebar beside the
// content on wide screens, a wrapping segmented menu above it on narrow ones
// (down to 320px). Every selector is scoped to main.console.
const consoleCSS = `
main.console{width:min(960px,calc(100% - 24px));display:grid;grid-template-columns:minmax(0,1fr);gap:20px;margin-top:max(16px,4vh);padding:24px;align-content:start}
.console .who{display:flex;align-items:center;gap:14px;min-width:0}
.console .who .hero{width:48px;height:48px;flex:0 0 auto;margin:0}
.console .who p{margin:0;min-width:0;line-height:1.3}
.console .who strong,.console .who span{display:block;overflow-wrap:anywhere}
.console .seg{display:flex;flex-wrap:wrap;gap:4px;align-self:start;padding:4px;background:var(--surface);border-radius:14px}
.console .seg a{flex:1 1 auto;min-height:40px;display:flex;align-items:center;justify-content:center;padding:0 12px;font-size:.88rem;color:var(--text);border-radius:10px}
.console .seg a:hover{background:var(--card);text-decoration:none}
.console .seg a[aria-current=page],.console .seg a[aria-current=page]:hover{background:var(--accent);color:#fff;font-weight:600}
.console .seg a.out{color:var(--link)}
.console .content{min-width:0}
.console h1{text-align:left;font-size:1.6rem;margin-bottom:12px}
.console h1+.sub,.console h1+.err{text-align:left}
.console h2{margin:28px 0 8px}
.console h3{margin:0 0 8px;font-size:1.02rem;font-weight:600;overflow-wrap:anywhere}
.console .panel{margin:0 0 12px;padding:16px;background:var(--card);border:1px solid var(--line);border-radius:16px}
.console .panel h2{margin:0 0 8px;font-size:1.1rem}
.console .panel>:last-child{margin-bottom:0}
.console .panel dl{margin:0}
.console .panel dl dt:first-child{margin-top:0}
.console .panel ul{margin-bottom:12px}
.console .confirm{border-color:var(--accent)}
.console form+form{margin-top:12px}
.console form~p.sub{text-align:left}
.console form>label:first-of-type{margin-top:0}
.console .panel button{margin-top:12px}
.console a.fed{margin-top:8px;text-align:center}
.console .meta{display:block;margin:0 0 8px;color:var(--muted);font-size:.85rem;line-height:1.55;overflow-wrap:anywhere}
.console .meta strong{color:var(--text)}
.console li.meta{margin:0;padding:8px 0}
.console li .meta{margin-bottom:0}
.console li form{margin-top:4px}
.console .ua{font-size:.75rem}
.console .badge{display:inline-block;padding:1px 9px;font-size:.72rem;font-weight:600;line-height:1.7;color:var(--ok);border:1px solid currentColor;border-radius:999px;vertical-align:middle;white-space:nowrap}
.console .badge.off{color:var(--muted)}
.console .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px}
.console .stat{display:block;padding:14px 16px;color:var(--text);background:var(--card);border:1px solid var(--line);border-radius:16px}
.console .stat:hover{border-color:var(--accent);text-decoration:none}
.console .stat strong{display:block;font-size:1.6rem;line-height:1.2}
.console .stat span{color:var(--muted);font-size:.85rem}
.console .events li strong{display:block;font-size:.92rem}
.console .events li .meta{margin:0}
.console .events strong.err{margin:0}
@media (min-width:760px){main.console{grid-template-columns:200px minmax(0,1fr);grid-template-rows:auto 1fr;grid-template-areas:"who content" "menu content";column-gap:28px;padding:32px}.console .who{grid-area:who}.console .seg{grid-area:menu;flex-direction:column;flex-wrap:nowrap}.console .seg a{flex:0 0 auto;justify-content:flex-start}.console .content{grid-area:content}}
@media (max-width:480px){main.console{padding:20px 14px;gap:16px}.console .seg a{padding:0 8px}}
@media (forced-colors:active){.console .seg a[aria-current=page]{text-decoration:underline;forced-color-adjust:none;background:Highlight;color:HighlightText}.console .panel,.console .stat{border-color:CanvasText}}
`

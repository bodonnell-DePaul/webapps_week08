/**
 * sanitize-har.mjs — remove credentials from a HAR without destroying its shape.
 * ---------------------------------------------------------------------------
 * CSC 436 Week 8, HW7 §5. Zero dependencies.
 *
 *   node sanitize-har.mjs raw-evidence/authorize.har evidence/03-authorize.har
 *
 * READ THIS BEFORE YOU RUN IT. You are responsible for what it misses.
 *
 * A HAR from an OAuth flow hides credentials in FIVE places, and a sanitizer
 * that walks only one of them is worse than none because it produces false
 * confidence:
 *
 *   1. `request.url`                  — ?code=…&state=…  (the whole redirect)
 *   2. `request.queryString[]`        — the same values, parsed out
 *   3. `request.headers[]` / `response.headers[]`
 *                                     — Authorization, Cookie, Set-Cookie, Location
 *   4. `request.cookies[]` / `response.cookies[]`
 *   5. `request.postData.text` / `.params[]` and `response.content.text`
 *                                     — the token response lives here
 *
 * Redaction preserves SHAPE — `<REDACTED:access_token 1043 chars>` — because the
 * shape is often the evidence. A blacked-out rectangle proves nothing.
 *
 * It cannot know about a secret it has never seen a name for. After running it,
 * run `scan-evidence.mjs` against the list of actual values you handled.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const [, , inPath, outPath] = process.argv;
if (!inPath || !outPath) {
    console.error('usage: node sanitize-har.mjs <in.har> <out.har>');
    process.exit(2);
}

/** Parameter names whose values are always credentials. */
const SECRET_PARAM = /^(code|access_token|id_token|refresh_token|code_verifier|client_secret|client_assertion|assertion|token|session_state|device_code)$/i;
/** Header names whose values are always credentials. */
const SECRET_HEADER = /^(authorization|cookie|set-cookie|proxy-authorization|x-api-key)$/i;

let redactions = 0;
const mark = (label, value) => {
    redactions++;
    return `<REDACTED:${label} ${String(value ?? '').length} chars>`;
};

/** Rewrite a URL's query string in place, keeping every parameter name. */
function sanitizeUrl(u) {
    try {
        const absolute = /^[a-z][a-z\d+.-]*:/i.test(u);
        const url = new URL(u, 'http://redaction.invalid');
        let touched = false;
        for (const k of [...url.searchParams.keys()]) {
            if (SECRET_PARAM.test(k)) {
                url.searchParams.set(k, mark(k, url.searchParams.get(k)));
                touched = true;
            }
        }
        // Fragments carry implicit-flow tokens. Drop the whole thing.
        if (url.hash && /access_token|id_token|code=/.test(url.hash)) {
            url.hash = `#<REDACTED:fragment ${url.hash.length} chars>`;
            touched = true;
        }
        return touched ? (absolute ? url.toString() : `${url.pathname}${url.search}${url.hash}`) : u;
    } catch {
        return u;
    }
}

/** Rewrite any `name=value` or `"name":"value"` pair inside a text body. */
function sanitizeText(text) {
    if (typeof text !== 'string' || !text) return text;
    return text
        // JSON:  "access_token": "…"
        .replace(
            /("(?:code|access_token|id_token|refresh_token|code_verifier|client_secret|client_assertion|assertion|token|session_state|device_code)"\s*:\s*")((?:\\.|[^"\\])*)(")/gi,
            (_, a, v, z) => a + mark('json', v) + z,
        )
        // form-encoded:  code_verifier=…
        .replace(
            /\b(code|access_token|id_token|refresh_token|code_verifier|client_secret|client_assertion|assertion|token|session_state|device_code)=([^&\s<]*)/gi,
            (_, k, v) => `${k}=${mark(k, v)}`,
        )
        // anything JWT-shaped that survived the above
        .replace(
            /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
            m => mark('jwt', m),
        );
}

const har = JSON.parse(readFileSync(inPath, 'utf8'));

for (const entry of har?.log?.entries ?? []) {
    const req = entry.request ?? {};
    const res = entry.response ?? {};

    if (req.url) req.url = sanitizeUrl(req.url);

    for (const q of req.queryString ?? []) {
        if (SECRET_PARAM.test(q.name)) q.value = mark(q.name, q.value);
    }

    for (const list of [req.headers ?? [], res.headers ?? []]) {
        for (const h of list) {
            if (SECRET_HEADER.test(h.name)) h.value = mark(h.name, h.value);
            else if (/^location$/i.test(h.name)) h.value = sanitizeUrl(h.value);
        }
    }

    for (const list of [req.cookies ?? [], res.cookies ?? []]) {
        for (const c of list) c.value = mark(`cookie:${c.name}`, c.value);
    }

    if (req.postData) {
        if (req.postData.text) req.postData.text = sanitizeText(req.postData.text);
        for (const p of req.postData.params ?? []) {
            if (SECRET_PARAM.test(p.name)) p.value = mark(p.name, p.value);
        }
    }

    if (res.content?.text) {
        if (res.content.encoding === 'base64') {
            res.content.text = sanitizeText(Buffer.from(res.content.text, 'base64').toString('utf8'));
            delete res.content.encoding;
        } else res.content.text = sanitizeText(res.content.text);
    }
    if (res.redirectURL) res.redirectURL = sanitizeUrl(res.redirectURL);
}

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, JSON.stringify(har, null, 2));

console.log(`
wrote      ${outPath}
entries    ${har?.log?.entries?.length ?? 0}
redactions ${redactions}

This handled the credentials it knows the NAMES of. It cannot know about
provider-specific parameters. Now run:

  node scan-evidence.mjs <evidence-dir> --secrets-from raw-evidence/known-values.txt
`);

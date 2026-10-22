// Renders writeups/src/<slug>.md into writeups/<slug>/index.html and
// rebuilds writeups/index.html. Run: npm install && npm run build
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Marked } from "marked";
import markedKatex from "marked-katex-extension";
import hljs from "highlight.js";

const here = dirname(fileURLToPath(import.meta.url));
const site = join(here, "..", "..");
const out = join(site, "writeups");
const events = JSON.parse(readFileSync(join(here, "events.json"), "utf8"));

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const plain = (s) =>
  s
    .replace(/\*\*\[[^\]]*\]\*\*/g, "")
    .replace(/[*_`]/g, "")
    .replace(/\s+/g, " ")
    .trim();

const slugify = (s) =>
  plain(s)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "") || "section";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
const fmtDate = (iso) => {
  const [y, m, d] = iso.split("-").map(Number);
  return `${d} ${MONTHS[m - 1]} ${y}`;
};

// HackMD-isms: ```python= (line numbers), and $$a$$$$b$$ runs on one line.
function normalize(md) {
  return md
    .replace(/\r\n/g, "\n")
    .replace(/^(\s*```+\s*[\w+-]*)=\S*\s*$/gm, "$1")
    .replace(/^(\s*```+)\s+(\w+)\s*$/gm, "$1$2")
    // multi-line $$ … $$ (matrices) must stand alone as a block
    .replace(/^\$\$([^$]*\n[^$]*?)\$\$[ \t]*/gm, (_, tex) => `$$\n${tex.trim()}\n$$\n\n`)
    .replace(/^[ \t]*((?:\$\$[^$\n]+\$\$)+)[ \t]*$/gm, (line) =>
      line
        .trim()
        .match(/\$\$[^$]+\$\$/g)
        .map((m) => `\n$$\n${m.slice(2, -2).trim()}\n$$\n`)
        .join("\n"),
    );
}

function render(md) {
  const headings = [];
  const used = new Map();
  const marked = new Marked();
  marked.use(markedKatex({ throwOnError: false, nonStandard: true, strict: false }));
  marked.use({
    gfm: true,
    renderer: {
      heading({ tokens, depth, text }) {
        const html = this.parser.parseInline(tokens);
        let id = slugify(text);
        const n = used.get(id) || 0;
        used.set(id, n + 1);
        if (n) id = `${id}-${n}`;
        if (depth === 2 || depth === 3) headings.push({ depth, id, text: plain(text) });
        return `<h${depth} id="${id}"><a class="anchor" href="#${id}" aria-hidden="true">#</a>${html}</h${depth}>\n`;
      },
      image({ href, text }) {
        return `<img src="${esc(href)}" alt="${esc(text || "screenshot")}" loading="lazy" decoding="async" />`;
      },
      code({ text, lang }) {
        const language = (lang || "").split(/\s/)[0];
        const valid = hljs.getLanguage(language) ? language : "plaintext";
        const body = hljs.highlight(text, { language: valid }).value;
        return `<figure class="code"><figcaption><span>${esc(language || "text")}</span><button type="button" class="copy" aria-label="Copy code">copy</button></figcaption><pre><code class="hljs language-${valid}">${body}</code></pre></figure>\n`;
      },
    },
  });
  const html = marked.parse(md);
  return { html, headings };
}

const head = (title, description, path) => `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="color-scheme" content="dark" />
    <meta name="theme-color" content="#050b18" />
    <title>${esc(title)}</title>
    <meta name="description" content="${esc(description)}" />
    <meta property="og:title" content="${esc(title)}" />
    <meta property="og:description" content="${esc(description)}" />
    <meta property="og:type" content="article" />
    <meta property="og:url" content="https://wondping0.github.io/${path}" />
    <meta property="og:image" content="https://wondping0.github.io/assets/avatar.jpg" />
    <link rel="canonical" href="https://wondping0.github.io/${path}" />
    <link rel="icon" href="/assets/favicon.png" type="image/png" />
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Space+Grotesk:wght@500;700&display=swap" />
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/katex@0.16.47/dist/katex.min.css" />
    <link rel="stylesheet" href="/styles.css" />
    <link rel="stylesheet" href="/writeups/writeups.css" />
    <script src="/writeups/writeups.js" defer></script>
  </head>
  <body>
    <a class="skip-link" href="#main">Skip to content</a>
    <div class="backdrop" aria-hidden="true"></div>
    <header class="header">
      <div class="wrap header-inner">
        <a class="brand" href="/" aria-label="wondping0 home">
          <img src="/assets/avatar.webp" width="40" height="40" alt="" />
          <span>wondping0<span class="brand-dot">_</span></span>
        </a>
        <nav class="nav" aria-label="Main navigation">
          <a href="/#projects">Projects</a>
          <a href="/#research">Research</a>
          <a href="/writeups/" aria-current="${path.startsWith("writeups") ? "page" : "false"}">Writeups</a>
          <a href="/#contact">Contact</a>
        </nav>
        <a class="header-source" href="https://hackmd.io/@wondPing">HackMD <span aria-hidden="true">↗</span></a>
      </div>
    </header>
`;

const foot = `    <footer class="footer">
      <div class="wrap footer-inner">
        <span>© ${new Date().getFullYear()} Muhammad Faturrohman</span>
        <span class="footer-mono">&lt;/&gt; add some code to this world</span>
      </div>
    </footer>
  </body>
</html>
`;

const built = [];
for (const ev of events) {
  const raw = readFileSync(join(out, "src", `${ev.slug}.md`), "utf8");
  const md = normalize(raw).replace(/^#\s+.*\n/, ""); // the page supplies its own H1
  const { html, headings } = render(md);
  const hasH3 = headings.some((h) => h.depth === 3);
  const challenges = headings.filter((h) => h.depth === (hasH3 ? 3 : 2));
  built.push({ ...ev, challenges });

  const toc = headings
    .map((h) => `<li class="toc-${h.depth}"><a href="#${h.id}">${esc(h.text)}</a></li>`)
    .join("\n            ");
  const page = `${head(`${ev.title} — wondping0 writeup`, ev.summary, `writeups/${ev.slug}/`)}
    <main id="main" class="wrap writeup">
      <div class="writeup-head">
        <a class="back" href="/writeups/"><span aria-hidden="true">←</span> All writeups</a>
        <p class="kicker">${esc(ev.event.toUpperCase())} <span class="sep">/</span> ${esc(fmtDate(ev.date))}</p>
        <h1>${esc(ev.title)}</h1>
        <p class="section-sub">${esc(ev.summary)}</p>
        <div class="tags">${ev.tags.map((t) => `<span>${esc(t)}</span>`).join("")}<span>${challenges.length} challenges</span></div>
        <a class="project-link" href="https://hackmd.io/@wondPing/${ev.hackmd}">Original on HackMD <span aria-hidden="true">↗</span></a>
      </div>
      <div class="writeup-grid">
        <nav class="toc" aria-label="On this page">
          <p class="toc-title">ON THIS PAGE</p>
          <ol>
            ${toc}
          </ol>
        </nav>
        <article class="prose">
${html}
        </article>
      </div>
    </main>
${foot}`;
  mkdirSync(join(out, ev.slug), { recursive: true });
  writeFileSync(join(out, ev.slug, "index.html"), page);
  console.log(`writeups/${ev.slug}/  ${challenges.length} challenges`);
}

built.sort((a, b) => b.date.localeCompare(a.date));
const total = built.reduce((n, e) => n + e.challenges.length, 0);
const cards = built
  .map(
    (ev) => `        <li class="reveal">
          <a class="wu-card" href="/writeups/${ev.slug}/">
            <span class="wu-date">${esc(fmtDate(ev.date))}</span>
            <span class="wu-body">
              <span class="wu-event">${esc(ev.event)}</span>
              <span class="wu-title">${esc(ev.title)}</span>
              <span class="wu-chals">${ev.challenges.map((c) => `<span>${esc(c.text)}</span>`).join("")}</span>
            </span>
            <span class="wu-count"><strong>${ev.challenges.length}</strong> solves <span aria-hidden="true">→</span></span>
          </a>
        </li>`,
  )
  .join("\n");
const index = `${head("Writeups — wondping0", "CTF writeups by wondping0, mostly cryptography: HackToday, COMPFEST, TCP1P, National Cyber Week and ASEAN Cyber Shield.", "writeups/")}
    <main id="main" class="wrap writeups-index">
      <div class="section-head">
        <p class="kicker">WRITEUPS <span class="sep">/</span> ${built.length} EVENT${built.length === 1 ? "" : "S"} <span class="sep">/</span> ${total} CHALLENGES</p>
        <h1>How the flags fell</h1>
        <p class="section-sub">Competition writeups, mostly cryptography. Mirrored from <a href="https://hackmd.io/@wondPing">HackMD</a>, with the full solvers.</p>
      </div>
      <ol class="wu-list">
${cards}
      </ol>
    </main>
${foot}`;
writeFileSync(join(out, "index.html"), index);
writeFileSync(
  join(out, "writeups.json"),
  JSON.stringify(
    built.map(({ slug, title, event, date, challenges }) => ({ slug, title, event, date, challenges: challenges.length })),
    null,
    2,
  ) + "\n",
);
console.log(`writeups/index.html  ${built.length} events, ${total} challenges`);

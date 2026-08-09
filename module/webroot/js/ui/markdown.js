// Minimal, dependency-free Markdown -> DOM, used for the "What's new" release-notes body.
//
// It builds real nodes through el() and never touches innerHTML, so a release body — text we do not
// control, fetched from GitHub — can style but never inject markup. It covers what release notes
// actually use: ATX headings, paragraphs, unordered lists, GitHub pipe tables, and inline **bold**,
// `code`, and [text](url). Anything it does not recognise falls through as plain text, so a body
// always renders (just less prettily) rather than breaking the page.

import { el } from "./dom.js";

// Only http(s) links become anchors; anything else (javascript:, data:, …) keeps its label as text.
const SAFE_URL = /^https?:\/\//i;
const TABLE_SEP = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/;
const isHeading = (s) => /^#{1,6}\s+/.test(s);
const isList = (s) => /^\s*[-*+]\s+/.test(s);
const splitRow = (s) => s.replace(/^\s*\|/, "").replace(/\|\s*$/, "").split("|").map((c) => c.trim());

// Parse one line's inline spans into text / <strong> / <code> / <a> nodes.
function inline(text) {
  const out = [];
  let buf = "";
  const flush = () => {
    if (buf) out.push(document.createTextNode(buf));
    buf = "";
  };
  for (let i = 0; i < text.length; ) {
    const c = text[i];
    if (c === "`") {
      const end = text.indexOf("`", i + 1);
      if (end > i) {
        flush();
        out.push(el("code", { class: "md-code", text: text.slice(i + 1, end) }));
        i = end + 1;
        continue;
      }
    }
    if (c === "*" && text[i + 1] === "*") {
      const end = text.indexOf("**", i + 2);
      if (end > i + 1) {
        flush();
        out.push(el("strong", {}, inline(text.slice(i + 2, end))));
        i = end + 2;
        continue;
      }
    }
    // *italic* — single asterisk, opening not followed by a space (so "a * b" is left alone).
    if (c === "*" && text[i + 1] !== "*" && text[i + 1] !== " ") {
      const end = text.indexOf("*", i + 1);
      if (end > i) {
        flush();
        out.push(el("em", {}, inline(text.slice(i + 1, end))));
        i = end + 1;
        continue;
      }
    }
    if (c === "[") {
      const close = text.indexOf("]", i + 1);
      if (close > i && text[close + 1] === "(") {
        const paren = text.indexOf(")", close + 2);
        if (paren > close) {
          const label = text.slice(i + 1, close);
          const url = text.slice(close + 2, paren).trim();
          flush();
          if (SAFE_URL.test(url)) {
            out.push(el("a", { class: "linklike", href: url, target: "_blank", rel: "noreferrer" }, inline(label)));
          } else {
            for (const n of inline(label)) out.push(n);
          }
          i = paren + 1;
          continue;
        }
      }
    }
    buf += c;
    i++;
  }
  flush();
  return out;
}

function tableNode(header, rows) {
  const head = el("tr", {}, header.map((h) => el("th", {}, inline(h))));
  const body = rows.map((r) => el("tr", {}, header.map((_, ci) => el("td", {}, inline(r[ci] || "")))));
  return el("div", { class: "md-table-wrap" }, [
    el("table", { class: "md-table" }, [el("thead", {}, head), el("tbody", {}, body)]),
  ]);
}

// Render Markdown source into an array of block-level nodes.
export function renderMarkdown(src) {
  const lines = String(src || "").replace(/\r\n?/g, "\n").split("\n");
  const blocks = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (!line.trim()) {
      i++;
      continue;
    }

    const h = /^(#{1,6})\s+(.*)$/.exec(line);
    if (h) {
      const level = Math.min(h[1].length, 3);
      blocks.push(el("div", { class: "md-h md-h" + level }, inline(h[2].trim())));
      i++;
      continue;
    }

    // A pipe table: a header row followed by a |---|---| separator.
    if (line.includes("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1])) {
      const header = splitRow(line);
      i += 2;
      const rows = [];
      while (i < lines.length && lines[i].trim() && lines[i].includes("|")) {
        rows.push(splitRow(lines[i]));
        i++;
      }
      blocks.push(tableNode(header, rows));
      continue;
    }

    if (isList(line)) {
      const items = [];
      while (i < lines.length && isList(lines[i])) {
        let item = lines[i].replace(/^\s*[-*+]\s+/, "");
        i++;
        // Fold a soft-wrapped continuation of the same item (a non-blank line that is not itself a
        // new block) onto it, so a wrapped bullet is one <li>.
        while (i < lines.length && lines[i].trim() && !isList(lines[i]) && !isHeading(lines[i]) && !lines[i].includes("|")) {
          item += " " + lines[i].trim();
          i++;
        }
        items.push(el("li", {}, inline(item)));
      }
      blocks.push(el("ul", { class: "md-list" }, items));
      continue;
    }

    // Paragraph: fold soft-wrapped lines with spaces (GitHub-style) until a blank line or a new block.
    const para = [line];
    i++;
    while (
      i < lines.length && lines[i].trim() && !isHeading(lines[i]) && !isList(lines[i]) &&
      !(lines[i].includes("|") && i + 1 < lines.length && TABLE_SEP.test(lines[i + 1]))
    ) {
      para.push(lines[i]);
      i++;
    }
    blocks.push(el("p", { class: "md-p" }, inline(para.join(" "))));
  }
  return blocks;
}

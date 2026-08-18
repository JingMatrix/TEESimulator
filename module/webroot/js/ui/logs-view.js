// The Logs panel: a scrollback pane of recent logcat lines under a sticky header with
// the title and a Filter / Pause / Save toolbar, plus two floating buttons pinned to the
// pane that jump it to the top or the bottom. Filters (min level, a set of
// selected tags, and a message substring) live in the controller and are applied here;
// the filter controls themselves open in a bottom sheet built by renderLogFilters. Pure
// DOM — it renders from controller state and calls back through `actions`. Lines are
// colored by level and the pane stays pinned to the bottom unless the user has scrolled
// up or paused. Log text is textContent (never innerHTML), so a crafted log line can't
// inject markup.

import { el, clear } from "./dom.js";
import { t } from "../i18n.js";

const LEVEL_CLASS = { V: "lv-v", D: "lv-d", I: "lv-i", W: "lv-w", E: "lv-e", F: "lv-f" };
const LEVEL_RANK = { V: 0, D: 1, I: 2, W: 3, E: 4, F: 5 };
const MAX_SHOWN = 1000;

const seqOf = (ln) => (typeof ln.seq === "number" ? ln.seq : null);

// A line passes the filter when it is at or above the minimum level, its tag is in the
// selected-tag set (or the set is empty, meaning "all tags"), and its text contains the
// case-insensitive message needle. An empty set / empty needle match everything. Tag is
// an EXACT match against the selected chips; message is a substring.
function selectedTagsOf(filter) {
  return filter.tags instanceof Set ? filter.tags : new Set(filter.tags || []);
}

function makePredicate(filter) {
  const minRank = LEVEL_RANK[filter.minLevel] || 0;
  const tags = selectedTagsOf(filter);
  const text = (filter.text || "").toLowerCase();
  return (ln) => {
    if ((LEVEL_RANK[ln.level] || 0) < minRank) return false;
    if (tags.size && !tags.has(String(ln.tag || ""))) return false;
    if (text && !String(ln.text || "").toLowerCase().includes(text)) return false;
    return true;
  };
}

// The pane tracks this key; a change forces one full append-render rebuild. It folds in
// min level, the selected tags (sorted so order is irrelevant), and the message needle.
const filterKeyOf = (f) =>
  (f.minLevel || "V") + "|" + [...selectedTagsOf(f)].sort().join(",") + "|" + (f.text || "");

export function renderLogs(mount, state, actions) {
  let shell = mount.querySelector(".logs");
  const firstBuild = !shell;
  if (!shell) {
    clear(mount);
    shell = el("div", { class: "logs" }, [
      el("div", { class: "panel-head logs-head" }, [
        el("h1", { class: "panel-title", text: t("log_title") }),
        el("div", { class: "logs-tools" }, [
          el("button", { class: "btn small ghost", "data-act": "filter", type: "button" }, t("log_filter")),
          el("button", { class: "btn small ghost", "data-act": "pause", type: "button" }, t("log_pause")),
          el("button", { class: "btn small ghost", "data-act": "save", type: "button" }, t("log_save")),
        ]),
      ]),
      el("span", { class: "logs-msg", "data-role": "msg" }, ""),
      el("pre", { class: "logs-pane", tabindex: "0" }),
      el("div", { class: "logs-fabs" }, [
        el("button", { class: "logs-fab", type: "button", "data-scroll": "top", "aria-label": t("log_scroll_top") }, [
          el("span", { class: "fab-chevron up", "aria-hidden": "true" }),
        ]),
        el("button", { class: "logs-fab", type: "button", "data-scroll": "bottom", "aria-label": "Scroll to bottom" }, [
          el("span", { class: "fab-chevron down", "aria-hidden": "true" }),
        ]),
      ]),
    ]);
    shell.querySelector('[data-act="filter"]').addEventListener("click", () => actions.openFilters());
    shell.querySelector('[data-act="pause"]').addEventListener("click", () => actions.togglePause());
    shell.querySelector('[data-act="save"]').addEventListener("click", () => actions.openSaveSheet());

    // Two floating buttons that jump the log pane to the top or the bottom.
    const paneEl = shell.querySelector(".logs-pane");
    shell.querySelector('[data-scroll="top"]').addEventListener("click", () =>
      paneEl.scrollTo({ top: 0, behavior: "smooth" }));
    shell.querySelector('[data-scroll="bottom"]').addEventListener("click", () =>
      paneEl.scrollTo({ top: paneEl.scrollHeight, behavior: "smooth" }));
    mount.append(shell);
  }

  const filter = state.filter || {};
  const filterBtn = shell.querySelector('[data-act="filter"]');
  filterBtn.classList.toggle("active", !!state.filterActive);
  filterBtn.textContent = state.filterActive ? t("log_filter_active") : t("log_filter");

  const pauseBtn = shell.querySelector('[data-act="pause"]');
  pauseBtn.textContent = state.paused ? t("log_resume") : t("log_pause");
  pauseBtn.classList.toggle("active", state.paused);

  const msg = shell.querySelector('[data-role="msg"]');
  msg.textContent = state.reachable ? "" : t("log_daemon_unreachable") + (state.error ? " — " + state.error : "");
  msg.classList.toggle("off", !state.reachable);
  msg.hidden = state.reachable;

  // Append-only render, filter-aware. Each 1.5 s poll typically brings a handful of new
  // lines; we append just the newcomers that pass the filter rather than rebuilding. A
  // change in the filter (tracked as a key on the pane node) forces one full rebuild.
  const pane = shell.querySelector(".logs-pane");
  const atBottom = pane.scrollHeight - pane.scrollTop - pane.clientHeight < 40;
  const pred = makePredicate(filter);
  const fkey = filterKeyOf(filter);
  const maxSeq = state.lines.length ? seqOf(state.lines[state.lines.length - 1]) : null;

  // Empty buffer (nothing fetched yet): drop rendered lines and forget cursors.
  if (state.lines.length === 0) {
    if (pane.firstChild) clear(pane);
    pane._lastSeq = undefined;
    pane._filterKey = fkey;
    return;
  }

  const needsRebuild = firstBuild || pane._filterKey !== fkey || pane._lastSeq == null;
  let fresh;
  if (needsRebuild) {
    clear(pane);
    const matched = state.lines.filter(pred);
    fresh = matched.length > MAX_SHOWN ? matched.slice(-MAX_SHOWN) : matched;
    pane._filterKey = fkey;
  } else {
    const last = pane._lastSeq;
    fresh = state.lines.filter((ln) => { const s = seqOf(ln); return s != null && s > last; }).filter(pred);
  }
  // Advance the cursor to the newest RAW seq we've seen (filtered or not), so the next
  // poll's append picks up exactly the lines that arrived since.
  if (maxSeq != null) pane._lastSeq = maxSeq;

  if (fresh.length === 0 && !needsRebuild) return;
  for (const ln of fresh) {
    pane.append(el("div", { class: "logline " + (LEVEL_CLASS[ln.level] || "lv-i") }, ln.text));
  }
  while (pane.childElementCount > MAX_SHOWN) pane.removeChild(pane.firstElementChild);

  if (!state.paused && atBottom) pane.scrollTop = pane.scrollHeight;
}

// ---- filter sheet -------------------------------------------------------
// renderLogFilters(state, actions) -> HTMLElement   (content for the filter sheet)
//   state   = { filter:{ minLevel, tags:Set<string>, text }, tags:[seen tags] }
//   actions = { setLevel(v), toggleTag(t), setText(v), reset(), close() }
export function renderLogFilters(state, actions) {
  const { filter = {}, tags = [] } = state;
  const selected = selectedTagsOf(filter);
  const levels = ["V", "D", "I", "W", "E"];
  const seg = el("div", { class: "segmented", role: "group", "aria-label": "Minimum level" },
    levels.map((lv) => el("button", {
      type: "button", class: "seg" + (lv === (filter.minLevel || "V") ? " on" : ""),
      "aria-pressed": lv === (filter.minLevel || "V") ? "true" : "false",
      text: lv === "V" ? t("log_level_all") : lv, onclick: () => actions.setLevel(lv),
    })));

  // Tag chips: one per distinct tag seen in the buffer. Toggling a chip selects or
  // deselects that tag; an empty selection means "all tags". Each toggle rebuilds the
  // sheet so the selected state repaints — focus is on a button, so no caret is lost.
  const tagChips = tags.length
    ? el("div", { class: "chips" }, tags.map((t) => {
        const on = selected.has(t);
        return el("button", {
          type: "button", class: "chip clickable" + (on ? " selected" : ""),
          "aria-pressed": on ? "true" : "false", text: t,
          onclick: () => actions.toggleTag(t),
        });
      }))
    : el("span", { class: "muted small", text: t("log_no_tags") });

  // Uncontrolled input: keystrokes update the controller's filter and re-render the
  // pane behind the sheet, but do NOT rebuild the sheet, so the caret stays put.
  const textInput = el("input", {
    class: "input", type: "text", value: filter.text || "", placeholder: "substring in the message",
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
    oninput: (e) => actions.setText(e.target.value),
  });

  return el("div", {}, [
    el("div", { class: "sheet-head" }, [
      el("h2", { text: t("log_filter_title") }),
      el("button", { class: "iconbtn", type: "button", "aria-label": t("btn_close"), onclick: () => actions.close() }, [
        el("span", { class: "x-mark", "aria-hidden": "true" }),
      ]),
    ]),
    el("div", { class: "field" }, [el("span", { class: "field-label", text: t("log_min_level") }), seg]),
    el("div", { class: "field" }, [el("span", { class: "field-label", text: t("log_tags") }), tagChips]),
    el("div", { class: "field" }, [el("span", { class: "field-label", text: t("log_message_contains") }), textInput]),
    el("button", { class: "btn ghost block sheet-submit", type: "button", text: t("log_reset_filters"), onclick: () => actions.reset() }),
  ]);
}

// ---- save sheet ---------------------------------------------------------
// renderSaveSheet(state, actions) -> HTMLElement   (content for the save sheet)
//   state   = { dir, name }
//   actions = { save(dir, name), close() }
// The daemon (root) writes the file, so the folder can be anywhere it can reach. The two
// inputs are uncontrolled: their live values are read only when Save is clicked, so typing
// never rebuilds the sheet. The Save click is the gesture that fires the POST.
export function renderSaveSheet(state, actions) {
  const { dir = "", name = "" } = state;
  const dirInput = el("input", {
    class: "input", type: "text", value: dir, placeholder: "/sdcard/Download",
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
  });
  const nameInput = el("input", {
    class: "input", type: "text", value: name, placeholder: "teesim-logs.log",
    autocapitalize: "off", autocorrect: "off", spellcheck: "false",
  });
  return el("div", {}, [
    el("div", { class: "sheet-head" }, [
      el("h2", { text: t("log_save_title") }),
      el("button", { class: "iconbtn", type: "button", "aria-label": t("btn_close"), onclick: () => actions.close() }, [
        el("span", { class: "x-mark", "aria-hidden": "true" }),
      ]),
    ]),
    el("div", { class: "field" }, [el("span", { class: "field-label", text: t("log_folder") }), dirInput]),
    el("div", { class: "field" }, [el("span", { class: "field-label", text: t("log_filename") }), nameInput]),
    el("button", {
      class: "btn primary block sheet-submit", type: "button", text: t("btn_save"),
      onclick: () => actions.save(dirInput.value, nameInput.value),
    }),
  ]);
}

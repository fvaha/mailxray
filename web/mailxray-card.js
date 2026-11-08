/*!
 * mailxray-card.js — reference renderer for a mailxray report.
 *
 * Drop-in for any webmail: no framework, no eval, no innerHTML. Everything is
 * built with DOM nodes and textContent, so an attachment called
 * `<img src=x onerror=...>.zip` renders as text and nothing else.
 *
 *   const card = MailxrayCard.render(report, {
 *     entryUrl: (member) => `/entry?path=${encodeURIComponent(member)}`,
 *     onOpen: (member) => openMyViewer(member),
 *   });
 *   container.append(card);
 *
 * `report` is the JSON from POST /inspect (or GET /report/{hash}).
 * Entry URLs must live on an origin you isolate from your mail UI.
 */
(function (global) {
  "use strict";

  const PREVIEWABLE = new Set(["image", "pdf", "text", "audio", "video"]);

  const el = (tag, className, text) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  };

  function badge(verdict) {
    const b = el("span", "mx-badge mx-badge--" + verdict, verdict);
    return b;
  }

  function reasons(list) {
    if (!Array.isArray(list) || list.length === 0) return null;
    const wrap = el("ul", "mx-reasons");
    for (const r of list) {
      const li = el("li", "mx-reason mx-reason--" + (r.severity || "info"));
      li.append(el("code", "mx-code", r.code), document.createTextNode(" — " + (r.detail || "")));
      wrap.append(li);
    }
    return wrap;
  }

  function entryRow(entry, options) {
    const row = el("tr", "mx-row mx-row--" + entry.verdict);

    const nameCell = el("td", "mx-name");
    nameCell.append(el("span", "mx-file", entry.name));
    if (entry.class) nameCell.append(el("span", "mx-class", entry.class));
    row.append(nameCell);

    row.append(el("td", "mx-num", formatSize(entry.size)));
    row.append(el("td", "mx-num", entry.ratio ? "×" + Math.round(entry.ratio) : ""));

    const verdictCell = el("td", "mx-verdict");
    verdictCell.append(badge(entry.verdict));
    row.append(verdictCell);

    const actionCell = el("td", "mx-action");
    if (options.entryUrl && PREVIEWABLE.has(entry.class)) {
      const open = el("a", "mx-open", "open");
      open.href = options.entryUrl(entry.name);
      open.rel = "noopener noreferrer";
      open.target = "_blank";
      if (options.onOpen) {
        open.addEventListener("click", (ev) => {
          ev.preventDefault();
          options.onOpen(entry.name, entry);
        });
      }
      actionCell.append(open);
    }
    row.append(actionCell);
    return row;
  }

  function formatSize(bytes) {
    if (typeof bytes !== "number") return "";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / 1024 / 1024).toFixed(1) + " MB";
  }

  function archiveSection(details, options) {
    const section = el("div", "mx-archive");
    const head = el("div", "mx-archive-head");
    head.append(
      el("span", "mx-format", details.format || "archive"),
      el("span", "mx-count", (details.entries || []).length + " entries")
    );
    if (details.encrypted) head.append(el("span", "mx-flag", "encrypted"));
    if (details.truncated) head.append(el("span", "mx-flag", "listing truncated"));
    if (details.depth) head.append(el("span", "mx-flag", "nested ×" + details.depth));
    section.append(head);

    if (!details.listed) {
      section.append(el("p", "mx-note", "This container was recognised but not opened."));
      return section;
    }

    const table = el("table", "mx-tree");
    const thead = el("thead");
    const hr = el("tr");
    for (const label of ["member", "size", "ratio", "verdict", ""]) {
      hr.append(el("th", null, label));
    }
    thead.append(hr);
    table.append(thead);

    const tbody = el("tbody");
    for (const entry of details.entries || []) {
      tbody.append(entryRow(entry, options));
    }
    table.append(tbody);
    section.append(table);
    return section;
  }

  function facts(details) {
    const rows = [];
    const add = (label, value) => {
      if (value !== undefined && value !== null && value !== "" && value !== false) {
        rows.push([label, String(value)]);
      }
    };
    if (details.kind === "pdf") {
      add("pages", details.pages);
      if (details.javascript && details.javascript.length) {
        add("javascript", details.javascript.length + " action(s)");
      }
      if (details.embedded_files) add("embedded files", details.embedded_files);
      if (details.launch) add("launch", "yes");
      if (details.open_action) add("runs on open", "yes");
      if (details.submit_form) add("submit form", "yes");
      if (details.xfa) add("xfa form", "yes");
      if (details.links && details.links.length) {
        add("links", details.links.length + " (" + (details.hosts || []).join(", ") + ")");
      }
    } else if (details.kind === "ooxml") {
      add("format", details.format);
      add("macros", details.macros ? "yes" : "no");
      if (details.external_rels && details.external_rels.length) {
        add("external references", details.external_rels.join(", "));
      }
      if (details.embedded_objects) add("embedded objects", details.embedded_objects);
    } else if (details.kind === "ole") {
      add("vba", details.has_vba ? "yes" : "no");
      add("embedded objects", details.has_embedded ? "yes" : "no");
    }
    if (rows.length === 0) return null;

    const dl = el("dl", "mx-facts");
    for (const [label, value] of rows) {
      dl.append(el("dt", null, label), el("dd", null, value));
    }
    return dl;
  }

  function render(report, options) {
    options = options || {};
    const card = el("article", "mx-card mx-card--" + report.verdict);

    const header = el("header", "mx-head");
    header.append(el("h3", "mx-title", report.name || report.real_type || "attachment"));
    header.append(badge(report.verdict));
    card.append(header);

    const meta = el("div", "mx-meta");
    meta.append(
      el("span", null, report.real_type),
      el("span", null, formatSize(report.size)),
      el("span", "mx-hash", report.sha256 ? report.sha256.slice(0, 16) + "…" : "")
    );
    if (report.type_mismatch) {
      meta.append(el("span", "mx-flag mx-flag--warn", "type mismatch"));
    }
    card.append(meta);

    const r = reasons(report.reasons);
    if (r) card.append(r);

    const details = report.details || {};
    const f = facts(details);
    if (f) card.append(f);

    if (details.kind === "archive") {
      card.append(archiveSection(details, options));
    }

    return card;
  }

  global.MailxrayCard = { render: render, formatSize: formatSize };
})(window);

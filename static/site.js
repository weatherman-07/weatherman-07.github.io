(function () {
  var root = document.documentElement;
  var base = document.body.getAttribute("data-base") || "";
  var calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- Intro title card (home): mark as seen for this session, allow skipping
  var intro = document.getElementById("intro");
  if (intro && root.classList.contains("intro-on")) {
    try { sessionStorage.setItem("intro", "1"); } catch (e) {}
    var skip = function () { root.classList.remove("intro-on"); root.classList.add("intro-off"); };
    intro.addEventListener("click", skip);
    document.addEventListener("keydown", skip, { once: true });
    setTimeout(skip, 2000);
  }

  // ---- Copy buttons on code blocks
  document.querySelectorAll(".codehilite").forEach(function (block) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn";
    btn.textContent = "copy";
    btn.addEventListener("click", function () {
      var pre = block.querySelector("pre");
      if (!pre || !navigator.clipboard) return;
      navigator.clipboard.writeText(pre.innerText).then(function () {
        btn.textContent = "copied";
        setTimeout(function () { btn.textContent = "copy"; }, 1500);
      });
    });
    block.appendChild(btn);
  });

  // ---- Graded background video. Every page is a separate document, so the browser would restart the clip on each
  // click. Instead each page remembers where the video was (per tab) and the next page carries on from there, as if
  // it had kept playing, even through blog pages that have no video. Skipped for reduced motion / data saver.
  var vid = document.getElementById("bg-video");
  if (vid) {
    var VKEY = "bgvideo", saver = navigator.connection && navigator.connection.saveData;
    var saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(VKEY)); } catch (e) {}
    if (saved && (typeof saved.t !== "number" || typeof saved.at !== "number")) saved = null;

    var remember = function () {
      if (vid.readyState < 1 || !isFinite(vid.currentTime)) return;
      try { sessionStorage.setItem(VKEY, JSON.stringify({ t: vid.currentTime, at: Date.now() })); } catch (e) {}
    };
    var resume = function () {                                    // jump to where it would be by now
      if (!saved || !(vid.duration > 0)) return;
      var t = (saved.t + Math.max(0, Date.now() - saved.at) / 1000) % vid.duration;
      try { vid.currentTime = t; } catch (e) {}
    };
    var startVideo = function () {
      if (saved && !calm && !saver) {                             // continuing: no poster flash, no fade
        vid.removeAttribute("poster");
        vid.classList.add("instant");
        vid.addEventListener("loadedmetadata", resume, { once: true });
      }
      vid.classList.add("on");                                    // the poster frame fades in either way
      if (calm || saver) return;
      var p = vid.play();
      if (p && p.catch) p.catch(function () {});
    };
    if (saved || document.readyState === "complete") startVideo(); else window.addEventListener("load", startVideo);

    vid.addEventListener("timeupdate", remember);
    window.addEventListener("pagehide", remember);
    document.addEventListener("visibilitychange", function () {
      if (calm || saver) return;
      if (document.hidden) { remember(); vid.pause(); }
      else { var q = vid.play(); if (q && q.catch) q.catch(function () {}); }
    });
  }

  // ---- ASCII art background: pick a random baked picture/gif and draw it as text
  var bg = document.getElementById("ascii-bg");
  if (bg && bg.getContext) {
    var bctx = bg.getContext("2d"), art = null, frame = 0, timer = null, cw = 0.6;
    var bdpr = Math.min(window.devicePixelRatio || 1, 2);
    var bcolor = function () { return getComputedStyle(root).getPropertyValue("--accent").trim() || "#ffd60a"; };

    var paint = function () {
      if (!art) return;
      var vw = window.innerWidth * bdpr, vh = window.innerHeight * bdpr;
      if (bg.width !== vw || bg.height !== vh) { bg.width = vw; bg.height = vh; }
      var W = vw / vh > art.aspect ? vw : vh * art.aspect;    // cover the viewport, centre-crop
      var H = W / art.aspect;
      var size = W / (art.cols * cw), step = H / art.rows;
      bctx.clearRect(0, 0, vw, vh);
      bctx.font = size + "px ui-monospace, Consolas, Menlo, monospace";
      bctx.textBaseline = "top";
      bctx.fillStyle = bcolor();
      var rows = art.frames[frame % art.frames.length].split("\n"), ox = (vw - W) / 2, oy = (vh - H) / 2;
      for (var i = 0; i < rows.length; i++) { if (rows[i]) bctx.fillText(rows[i], ox, oy + i * step); }
    };
    var measure = function () {
      bctx.font = "100px ui-monospace, Consolas, Menlo, monospace";
      cw = bctx.measureText("M").width / 100 || 0.6;
    };
    var play = function () {
      clearTimeout(timer);
      if (!art || art.frames.length < 2 || calm || document.hidden) return;
      timer = setTimeout(function () { frame++; paint(); play(); }, 1000 / (art.fps || 8));
    };

    fetch(base + "/assets/ascii/index.json").then(function (r) { return r.json(); }).then(function (list) {
      if (!list.length) return;
      var last = null; try { last = sessionStorage.getItem("lastbg"); } catch (e) {}
      var pool = list.filter(function (x) { return x.id !== last; });
      var want = new URLSearchParams(location.search).get("bg");      // ?bg=<id> pins one picture
      var pinned = list.filter(function (x) { return x.id === want; })[0];
      var pick = pinned || (pool.length ? pool : list)[Math.floor(Math.random() * (pool.length || list.length))];
      try { sessionStorage.setItem("lastbg", pick.id); } catch (e) {}
      return fetch(base + "/assets/ascii/" + pick.file).then(function (r) { return r.json(); });
    }).then(function (data) {
      if (!data) return;
      art = data; measure(); paint(); bg.classList.add("on"); play();
    }).catch(function () {});

    window.addEventListener("resize", paint);
    document.addEventListener("visibilitychange", play);
  }

  // ---- Blogs: full-text search + tag filter (state lives in the URL: ?q=...&tag=a,b)
  var input = document.getElementById("post-filter");
  if (input) {
    var rows = Array.prototype.slice.call(document.querySelectorAll("#post-list .row"));
    var chips = Array.prototype.slice.call(document.querySelectorAll(".tagbar .chip[data-tag]"));
    var clear = document.getElementById("clear-filters");
    var empty = document.getElementById("no-results");
    var count = document.getElementById("result-count");
    var bodies = {};                                              // slug -> lowercased full text
    var active = {};                                              // tag slug -> true

    var params = new URLSearchParams(location.search);
    input.value = params.get("q") || "";
    (params.get("tag") || "").split(",").filter(Boolean).forEach(function (t) { active[t] = true; });

    function apply() {
      var terms = input.value.toLowerCase().split(/\s+/).filter(Boolean);
      var tags = Object.keys(active);
      var shown = 0;
      rows.forEach(function (row) {
        var rowTags = (row.getAttribute("data-tags") || "").split(" ");
        var hay = (row.getAttribute("data-search") || "") + " " + (bodies[row.getAttribute("data-slug")] || "");
        var okTags = tags.every(function (t) { return rowTags.indexOf(t) !== -1; });
        var okText = terms.every(function (t) { return hay.indexOf(t) !== -1; });
        row.hidden = !(okTags && okText);
        if (!row.hidden) shown++;
      });
      chips.forEach(function (c) { c.setAttribute("aria-pressed", active[c.getAttribute("data-tag")] ? "true" : "false"); });
      if (clear) clear.hidden = !(tags.length || terms.length);
      if (empty) empty.hidden = shown !== 0;
      if (count) count.textContent = (tags.length || terms.length) ? shown + " of " + rows.length + " blogs" : rows.length + " blogs";
      var q = new URLSearchParams();
      if (input.value.trim()) q.set("q", input.value.trim());
      if (tags.length) q.set("tag", tags.join(","));
      try { history.replaceState(null, "", location.pathname + (q.toString() ? "?" + q.toString() : "") + location.hash); } catch (e) {}
    }

    input.addEventListener("input", apply);
    chips.forEach(function (c) {
      c.addEventListener("click", function () {
        var t = c.getAttribute("data-tag");
        if (active[t]) delete active[t]; else active[t] = true;
        apply();
      });
    });
    if (clear) clear.addEventListener("click", function () { input.value = ""; active = {}; apply(); input.focus(); });
    apply();

    // Full-text index loads in the background; title/tag search works immediately.
    fetch(base + "/search.json").then(function (r) { return r.json(); }).then(function (idx) {
      Object.keys(idx).forEach(function (slug) { bodies[slug] = idx[slug].toLowerCase(); });
      apply();
    }).catch(function () {});

    if (location.hash === "#search") input.focus();
  }

  // ---- Vim-style keys: j/k scroll, g/G top/bottom, "/" jumps to search
  document.addEventListener("keydown", function (e) {
    var t = e.target, tag = t && t.tagName;
    if (tag === "INPUT" || tag === "TEXTAREA" || (t && t.isContentEditable)) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    var step = Math.round(window.innerHeight * 0.3);
    if (e.key === "j") window.scrollBy({ top: step });
    else if (e.key === "k") window.scrollBy({ top: -step });
    else if (e.key === "g") window.scrollTo({ top: 0 });
    else if (e.key === "G") window.scrollTo({ top: document.body.scrollHeight });
    else if (e.key === "/") { e.preventDefault(); if (input) input.focus(); else location.href = base + "/blogs/#search"; }
  });
})();

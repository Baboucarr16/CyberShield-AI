/* CyberShield AI — progressive enhancement only. No backend dependency. */
(function () {
  "use strict";

  var themeToggle = document.querySelector("[data-theme-toggle]");
  var themeLabel = document.querySelector("[data-theme-label]");
  function setTheme(theme, persist) {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    var target = theme === "dark" ? "light" : "dark";
    var label = target === "light" ? "Light" : "Dark";
    if (themeLabel) themeLabel.textContent = label;
    if (themeToggle) {
      themeToggle.setAttribute("aria-label", "Switch to " + target + " theme");
      themeToggle.setAttribute("title", "Switch to " + target + " theme");
    }
    if (persist) {
      try { localStorage.setItem("cybershield.theme", theme); }
      catch (e) { /* Theme still applies for this page when storage is unavailable. */ }
    }
  }
  var initialTheme = document.documentElement.dataset.theme === "light" ? "light" : "dark";
  setTheme(initialTheme, false);
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      setTheme(document.documentElement.dataset.theme === "light" ? "dark" : "light", true);
    });
  }

  // Mobile nav
  var toggle = document.querySelector(".nav-toggle");
  var menu = document.getElementById("nav-menu");
  if (toggle && menu) {
    toggle.addEventListener("click", function () {
      var open = menu.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    menu.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        menu.classList.remove("open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  // Lightweight URL validation + loading state for every scan form
  function looksLikeUrl(v) {
    v = v.trim();
    if (!v || /\s/.test(v) || v.length < 4) return false;
    if (/^https?:\/\//i.test(v)) return v.split("://")[1].indexOf(".") > 0;
    return v.indexOf(".") > 0 && v.indexOf(" ") < 0;
  }

  document.querySelectorAll("[data-scan-form]").forEach(function (form) {
    var input = form.querySelector('input[name="url"]');
    var btn = form.querySelector("[data-scan-btn]");
    var label = form.querySelector("[data-btn-label]");
    var err = form.querySelector("[data-form-error]");
    var status = form.querySelector("[data-scan-status]");
    if (!input) return;

    form.addEventListener("submit", function (e) {
      var v = input.value.trim();
      if (!looksLikeUrl(v)) {
        e.preventDefault();
        if (err) err.hidden = false;
        input.focus();
        input.setAttribute("aria-invalid", "true");
        return;
      }
      if (err) err.hidden = true;
      input.removeAttribute("aria-invalid");
      // Auto-prepend scheme so the backend feature extractor sees protocol
      if (!/^https?:\/\//i.test(v)) input.value = "https://" + v;
      if (btn) {
        btn.disabled = true;
        btn.setAttribute("aria-busy", "true");
      }
      if (label) label.textContent = "Analyzing…";
      else if (btn) btn.textContent = "Analyzing…";
      if (status) status.hidden = false;
    });

    input.addEventListener("input", function () {
      if (err) err.hidden = true;
      input.removeAttribute("aria-invalid");
    });
  });

  // Example-fill helper on scanner page
  document.querySelectorAll("[data-fill-example]").forEach(function (b) {
    b.addEventListener("click", function () {
      var input = document.getElementById("scan-url");
      if (input) {
        input.value = "http://free-paypal-bonus-login.example.com";
        input.focus();
      }
    });
  });

  // Session-local scan history (dashboard + scanner result capture)
  var KEY = "cybershield.scans.v1";
  function read() {
    try { return JSON.parse(localStorage.getItem(KEY) || "[]"); }
    catch (e) { return []; }
  }
  function write(rows) {
    try { localStorage.setItem(KEY, JSON.stringify(rows.slice(0, 20))); }
    catch (e) { /* private mode — ignore */ }
  }

  var resultEl = document.querySelector("[data-result]");
  if (resultEl) {
    var rows = read();
    rows.unshift({
      url: resultEl.getAttribute("data-url") || "",
      prediction: resultEl.getAttribute("data-prediction") || "",
      score: parseInt(resultEl.getAttribute("data-score") || "0", 10),
      at: new Date().toISOString()
    });
    // de-dupe consecutive identical scans (compare URLs only; timestamps always differ)
    rows = rows.filter(function (r, i) {
      return i === 0 || r.url !== rows[i - 1].url;
    });
    write(rows);
  }

  function renderDashboard() {
    var list = document.querySelector("[data-history-list]");
    if (!list) return;
    var rows = read();
    var total = rows.length;
    var phish = rows.filter(function (r) { return r.prediction === "PHISHING"; }).length;
    var safe = total - phish;
    var set = function (sel, v) {
      var el = document.querySelector(sel);
      if (el) el.textContent = String(v);
    };
    set("[data-stat-total]", total);
    set("[data-stat-safe]", safe);
    set("[data-stat-phish]", phish);
    var rate = document.querySelector("[data-stat-rate]");
    var fill = document.querySelector("[data-rate-fill]");
    if (rate) rate.textContent = total ? Math.round((phish / total) * 100) + "% flagged" : "—";
    if (fill) fill.style.width = total ? Math.round((phish / total) * 100) + "%" : "0%";

    var empty = document.querySelector("[data-history-empty]");
    list.innerHTML = "";
    if (!rows.length) {
      list.hidden = true;
      if (empty) empty.hidden = false;
      return;
    }
    if (empty) empty.hidden = true;
    list.hidden = false;
    rows.slice(0, 10).forEach(function (r) {
      var li = document.createElement("li");
      var badge = document.createElement("span");
      badge.className = "badge " + (r.prediction === "PHISHING" ? "badge-danger" : "badge-safe");
      badge.textContent = r.prediction === "PHISHING" ? "Phishing" : "Safe";
      var url = document.createElement("span");
      url.className = "h-url";
      url.textContent = r.url;
      url.title = r.url;
      var score = document.createElement("span");
      score.className = "muted small";
      score.textContent = r.score + "/10";
      li.appendChild(badge);
      li.appendChild(url);
      li.appendChild(score);
      list.appendChild(li);
    });
  }
  renderDashboard();

  var clearBtn = document.querySelector("[data-clear-history]");
  if (clearBtn) {
    clearBtn.addEventListener("click", function () {
      write([]);
      renderDashboard();
    });
  }

  // Animate risk bars into view
  var fills = document.querySelectorAll("[data-risk-fill]");
  if ("IntersectionObserver" in window && fills.length) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (en.isIntersecting) {
          en.target.style.width = en.target.style.width || "0%";
          io.unobserve(en.target);
        }
      });
    });
    fills.forEach(function (f) { io.observe(f); });
  }
})();

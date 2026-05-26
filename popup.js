// ── Tabs ──
document.querySelectorAll(".tab").forEach(function(tab) {
  tab.onclick = function() {
    document.querySelectorAll(".tab").forEach(function(t) { t.classList.remove("active"); });
    document.querySelectorAll(".panel").forEach(function(p) { p.classList.remove("active"); });
    tab.classList.add("active");
    document.getElementById("panel-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "dashboard") loadDashboard();
    if (tab.dataset.tab === "about") loadAbout();
    if (tab.dataset.tab === "settings") loadSettings();
    if (tab.dataset.tab === "history") loadHistory();
  };
});

function timeAgo(ts) {
  if (!ts) return "Never";
  var diff = Date.now() - ts;
  var s = Math.floor(diff / 1000);
  if (s < 60) return "Just now";
  var m = Math.floor(s / 60);
  if (m < 60) return m + "m ago";
  var h = Math.floor(m / 60);
  if (h < 24) return h + "h ago";
  return Math.floor(h / 24) + "d ago";
}
function escHtml(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

// ── Dashboard ──
function loadDashboard() {
  chrome.runtime.sendMessage({ type: "get-stats" }, function(s) {
    if (!s) return;
    document.getElementById("n-threats").textContent = s.threatCount;
    document.getElementById("n-extensions").textContent = s.totalExtensions;
    document.getElementById("n-feed").textContent = s.feedCount.toLocaleString();
    document.getElementById("n-custom").textContent = s.customCount;
    document.getElementById("d-fetch").textContent = timeAgo(s.lastFetch);
    document.getElementById("d-scan").textContent = timeAgo(s.lastScan);

    var statEl = document.getElementById("stat-threats");
    var alertBar = document.getElementById("alert-bar");
    var hStatus = document.getElementById("h-status");
    var viewBtn = document.getElementById("btn-view-threats");

    if (s.threatCount > 0) {
      statEl.classList.add("highlight");
      alertBar.classList.add("show");
      document.getElementById("ab-text").textContent = s.threatCount + " malicious extension" + (s.threatCount !== 1 ? "s" : "") + " detected!";
      hStatus.classList.add("danger");
      viewBtn.style.display = "block";
    } else {
      statEl.classList.remove("highlight");
      alertBar.classList.remove("show");
      hStatus.classList.remove("danger");
      viewBtn.style.display = "none";
    }
  });
}

document.getElementById("btn-scan").onclick = function() {
  this.innerHTML = "\u23f3 Scanning...";
  var btn = this;
  chrome.runtime.sendMessage({ type: "scan-now" }, function() {
    btn.innerHTML = "\ud83d\udd04 Scan Now";
    loadDashboard();
  });
};
document.getElementById("btn-force-feed").onclick = function() {
  this.innerHTML = "\u23f3 Updating feed...";
  this.disabled = true;
  var btn = this;
  chrome.runtime.sendMessage({ type: "force-update-feed" }, function(resp) {
    btn.disabled = false;
    if (resp && resp.ok) {
      btn.innerHTML = "\u2705 Feed updated! (" + resp.count + " IDs)";
      setTimeout(function() { btn.innerHTML = "\ud83d\udce1 Force Feed Update"; }, 3000);
    } else {
      btn.innerHTML = "\u274c Update failed";
      setTimeout(function() { btn.innerHTML = "\ud83d\udce1 Force Feed Update"; }, 3000);
    }
    loadDashboard();
  });
};
document.getElementById("btn-view-threats").onclick = function() {
  chrome.tabs.create({ url: chrome.runtime.getURL("warning.html") });
};

// ── About ──
function loadAbout() {
  chrome.runtime.sendMessage({ type: "get-policy" }, function(p) {
    var el = document.getElementById("about-managed-info");
    if (p && p.isManaged) {
      var lines = [];
      if (p.orgName) lines.push("<strong>Organization:</strong> " + escHtml(p.orgName));
      lines.push("<strong>Feeds:</strong> " + p.feedUrls.length + " source(s)");
      lines.push("<strong>Admin blocklist:</strong> " + p.adminBlocklist.length + " IDs");
      lines.push("<strong>Admin whitelist:</strong> " + p.adminWhitelist.length + " IDs");
      lines.push("<strong>Settings locked:</strong> " + (p.lockSettings ? "Yes" : "No"));
      if (p.orgMessage) lines.push("<strong>IT message:</strong> " + escHtml(p.orgMessage));
      el.innerHTML = '<div class="managed-detail"><div class="feat"><div class="fi">\ud83c\udfe2</div><div class="ft">' + lines.join("<br>") + '</div></div></div>';
    } else {
      el.innerHTML = "";
    }
  });
}

// ── Settings ──
function loadSettings() {
  chrome.runtime.sendMessage({ type: "get-settings" }, function(s) {
    if (!s) return;
    document.getElementById("opt-autodisable").checked = s.autoDisable;
    var lockNotice = document.getElementById("lock-notice");
    var lockIcon = document.getElementById("lock-icon");

    if (s.lockSettings) {
      lockNotice.classList.add("show");
      lockIcon.style.display = "inline";
      document.getElementById("lock-org").textContent = s.orgName || "your admin";
      // Disable all user controls
      document.getElementById("opt-autodisable").disabled = true;
      document.getElementById("custom-ids").disabled = true;
      document.getElementById("btn-save-custom").disabled = true;
      document.getElementById("whitelist-ids").disabled = true;
      document.getElementById("btn-save-whitelist").disabled = true;
    } else {
      lockNotice.classList.remove("show");
      lockIcon.style.display = "none";
      document.getElementById("opt-autodisable").disabled = false;
      document.getElementById("custom-ids").disabled = false;
      document.getElementById("btn-save-custom").disabled = false;
      document.getElementById("whitelist-ids").disabled = false;
      document.getElementById("btn-save-whitelist").disabled = false;
    }

    // Show feed URLs
    if (s.feedUrls && s.feedUrls.length > 0) {
      chrome.runtime.sendMessage({ type: "get-user-feeds" }, function(userFeeds) {
        userFeeds = userFeeds || [];
        var userSet = {};
        userFeeds.forEach(function(u) { userSet[u] = true; });
        document.getElementById("feed-list").innerHTML = s.feedUrls.map(function(u) {
          var isUser = !!userSet[u];
          return '<div class="feed-url">' +
            '<div class="fu-text">' + escHtml(u) + '</div>' +
            (isUser
              ? '<button class="fu-remove" data-feed="' + escHtml(u) + '" title="Remove">\u2715</button>'
              : '<span class="fu-default">default</span>') +
          '</div>';
        }).join("");
      });
    }
  });

  chrome.runtime.sendMessage({ type: "get-custom-blocklist" }, function(ids) {
    ids = ids || [];
    document.getElementById("custom-ids").value = ids.join("\n");
    document.getElementById("custom-badge").textContent = ids.length;
  });
  chrome.runtime.sendMessage({ type: "get-whitelist" }, function(ids) {
    ids = ids || [];
    document.getElementById("whitelist-ids").value = ids.join("\n");
    document.getElementById("white-badge").textContent = ids.length;
  });
}

document.getElementById("opt-autodisable").onchange = function() {
  chrome.runtime.sendMessage({ type: "set-settings", settings: { autoDisable: this.checked } }, function(r) {
    if (r && !r.ok) alert(r.error);
  });
};

// Feed management
document.getElementById("btn-add-feed").onclick = function() {
  var input = document.getElementById("new-feed-url");
  var url = input.value.trim();
  if (!url) return;
  try { new URL(url); } catch (e) {
    document.getElementById("feed-result").textContent = "\u274c Invalid URL";
    return;
  }
  if (!url.startsWith("https://") && !url.startsWith("http://")) {
    document.getElementById("feed-result").textContent = "\u274c URL must start with http:// or https://";
    return;
  }
  chrome.runtime.sendMessage({ type: "get-user-feeds" }, function(feeds) {
    feeds = feeds || [];
    if (feeds.indexOf(url) !== -1) {
      document.getElementById("feed-result").textContent = "\u26a0\ufe0f Feed already added";
      return;
    }
    feeds.push(url);
    chrome.runtime.sendMessage({ type: "set-user-feeds", urls: feeds }, function() {
      input.value = "";
      document.getElementById("feed-result").textContent = "\u2705 Feed added and synced";
      loadSettings();
      loadDashboard();
    });
  });
};

document.getElementById("new-feed-url").onkeydown = function(e) {
  if (e.key === "Enter") document.getElementById("btn-add-feed").click();
};

document.addEventListener("click", function(e) {
  if (e.target.classList.contains("fu-remove")) {
    var url = e.target.getAttribute("data-feed");
    chrome.runtime.sendMessage({ type: "get-user-feeds" }, function(feeds) {
      feeds = (feeds || []).filter(function(u) { return u !== url; });
      chrome.runtime.sendMessage({ type: "set-user-feeds", urls: feeds }, function() {
        document.getElementById("feed-result").textContent = "\u2705 Feed removed";
        loadSettings();
        loadDashboard();
      });
    });
  }
});

// Test
document.getElementById("btn-test").onclick = function() {
  document.getElementById("test-result").textContent = "Running test...";
  chrome.runtime.sendMessage({ type: "run-test" }, function(resp) {
    if (resp && resp.ok) {
      document.getElementById("test-result").textContent = "\u2705 Test triggered: \"" + resp.tested + "\"";
      document.getElementById("btn-clear-test").style.display = "block";
    } else {
      document.getElementById("test-result").textContent = "\u274c " + (resp ? resp.error : "Failed");
    }
  });
};
document.getElementById("btn-clear-test").onclick = function() {
  chrome.runtime.sendMessage({ type: "clear-test" }, function() {
    document.getElementById("test-result").textContent = "Test cleared.";
    document.getElementById("btn-clear-test").style.display = "none";
    loadDashboard();
  });
};

// Custom blocklist
function parseIds(raw) {
  return raw.split(/[\n,\s]+/).map(function(s) { return s.trim(); }).filter(function(s) { return /^[a-z]{32}$/.test(s); });
}
function countInvalid(raw) {
  return raw.split(/[\n,\s]+/).map(function(s) { return s.trim(); }).filter(function(s) { return s.length > 0 && !/^[a-z]{32}$/.test(s); }).length;
}

document.getElementById("btn-save-custom").onclick = function() {
  var raw = document.getElementById("custom-ids").value;
  var ids = parseIds(raw); var bad = countInvalid(raw);
  chrome.runtime.sendMessage({ type: "set-custom-blocklist", ids: ids }, function() {
    var msg = "\u2705 Saved " + ids.length + " ID(s)";
    if (bad > 0) msg += " (" + bad + " invalid skipped)";
    document.getElementById("custom-result").textContent = msg;
    document.getElementById("custom-badge").textContent = ids.length;
    loadDashboard();
  });
};
document.getElementById("btn-export-custom").onclick = function() {
  chrome.runtime.sendMessage({ type: "get-custom-blocklist" }, function(ids) {
    var blob = new Blob([(ids || []).join("\n")], { type: "text/plain" });
    var a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = "extsentry-custom-blocklist.txt"; a.click();
  });
};
document.getElementById("btn-import-custom").onclick = function() { document.getElementById("import-file").click(); };
document.getElementById("import-file").onchange = function(e) {
  var file = e.target.files[0]; if (!file) return;
  var reader = new FileReader();
  reader.onload = function(ev) {
    var existing = document.getElementById("custom-ids").value;
    document.getElementById("custom-ids").value = existing ? existing + "\n" + ev.target.result : ev.target.result;
    document.getElementById("custom-result").textContent = "Imported. Click Save to apply.";
  };
  reader.readAsText(file); e.target.value = "";
};

document.getElementById("btn-save-whitelist").onclick = function() {
  var ids = parseIds(document.getElementById("whitelist-ids").value);
  chrome.runtime.sendMessage({ type: "set-whitelist", ids: ids }, function() {
    document.getElementById("white-result").textContent = "\u2705 Saved " + ids.length + " ID(s)";
    document.getElementById("white-badge").textContent = ids.length;
    loadDashboard();
  });
};

// ── History ──
function loadHistory() {
  chrome.runtime.sendMessage({ type: "get-stats" }, function(s) {
    var el = document.getElementById("history-list");
    if (!s || !s.history || s.history.length === 0) {
      el.innerHTML = '<div class="empty">\ud83c\udf89 No threats have been detected yet.</div>';
      return;
    }
    el.innerHTML = s.history.map(function(h) {
      var date = new Date(h.timestamp);
      var dateStr = date.toLocaleDateString() + " " + date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      var entries = h.threats.map(function(t) {
        return '<div class="hi-entry"><span class="hi-name">' + escHtml(t.name) + '</span><span class="hi-id">' + t.id + '</span></div>';
      }).join("");
      return '<div class="history-item"><div class="hi-left">' + entries + '</div><div class="hi-date">' + dateStr + '</div></div>';
    }).join("");
  });
}

loadDashboard();

function esc(s) { var d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

function render(threats) {
  var el = document.getElementById("threats");
  var summary = document.getElementById("summary");

  if (!threats || threats.length === 0) {
    summary.innerHTML = "";
    el.innerHTML = '<div class="all-clear"><div class="ac-icon">\u2705</div><h2>All Clear</h2><p>No malicious extensions detected. You\'re safe!</p></div>';
    return;
  }

  var real = threats.filter(function(t) { return !t.isTest; });
  var tests = threats.filter(function(t) { return t.isTest; });
  var enabled = real.filter(function(t) { return t.enabled; });

  summary.innerHTML =
    '<div class="summary-card danger"><div class="sc-num">' + real.length + '</div><div class="sc-lbl">Threat' + (real.length !== 1 ? 's' : '') + '</div></div>' +
    '<div class="summary-card' + (enabled.length > 0 ? ' danger' : '') + '"><div class="sc-num">' + enabled.length + '</div><div class="sc-lbl">Active</div></div>' +
    (tests.length > 0 ? '<div class="summary-card"><div class="sc-num">' + tests.length + '</div><div class="sc-lbl">Test</div></div>' : '');

  el.innerHTML = threats.map(function(t) {
    var iconHtml = t.iconUrl
      ? '<img src="' + esc(t.iconUrl) + '" onerror="this.parentNode.innerHTML=\'🧩\'">'
      : '--';

    var statusClass = t.enabled ? "enabled" : "disabled";
    var statusText = t.enabled ? "Active" : "Disabled";

    var permsHtml = "";
    var allPerms = (t.permissions || []).concat(t.hostPermissions || []);
    if (allPerms.length > 0) {
      var tags = allPerms.slice(0, 12).map(function(p) {
        var isHost = p.indexOf("://") !== -1 || p.indexOf("<all_urls>") !== -1;
        return '<span class="perm-tag' + (isHost ? ' host' : '') + '">' + esc(p) + '</span>';
      }).join("");
      if (allPerms.length > 12) tags += '<span class="perm-tag">+' + (allPerms.length - 12) + ' more</span>';
      permsHtml = '<div class="perms"><div class="perms-title">Permissions requested</div><div class="perm-tags">' + tags + '</div></div>';
    }

    var explainText, buttons;
    if (t.isTest) {
      explainText = 'This is a <strong>simulated test warning</strong>. This extension was temporarily flagged to verify the warning system. It is <strong>not actually malicious</strong>. Dismiss safely.';
      buttons = '<button class="btn btn-dismiss" data-action="dismiss">Dismiss test</button>';
    } else {
      explainText = 'This extension has been identified as <strong>malicious</strong> by the ExtSentry threat intelligence feed. It may be <strong>stealing your data</strong>, injecting ads, hijacking searches, tracking your browsing activity, or performing other harmful actions. <strong>Remove it immediately.</strong>';

      var disableBtn = t.enabled
        ? '<button class="btn btn-disable" data-action="disable" data-id="' + t.id + '">Disable</button>'
        : '';

      buttons =
        '<button class="btn btn-uninstall" data-action="uninstall" data-id="' + t.id + '">Uninstall now</button>' +
        disableBtn +
        '<button class="btn btn-whitelist" data-action="whitelist" data-id="' + t.id + '" title="Mark as safe (false positive)">Trust</button>';
    }

    // Nag banner if disabled but still installed
    var nagHtml = "";
    if (!t.isTest && !t.enabled) {
      nagHtml = '<div class="nag-banner">' +
        '<strong>Still installed.</strong> This extension is disabled but remains on your browser. ' +
        'It could re-enable itself or be re-enabled accidentally. ' +
        '<strong>Uninstall it completely</strong> to eliminate the risk. ' +
        'When you click "Uninstall Now", Chrome will show a confirmation dialog - please click "Remove" to finish.' +
        '</div>';
    }

    return '<div class="threat' + (t.isTest ? ' test' : (t.enabled ? ' has-danger' : '')) + '">' +
      (t.isTest ? '<div class="test-badge">Test - Simulated Warning</div>' : '') +
      '<div class="threat-top">' +
        '<div class="threat-icon">' + iconHtml + '</div>' +
        '<div>' +
          '<div class="threat-name">' + esc(t.name) + '</div>' +
          '<div class="threat-meta">v' + esc(t.version) + ' - ' + esc(t.installType) + '</div>' +
          '<div class="threat-id">' + t.id + '</div>' +
        '</div>' +
      '</div>' +
      '<div class="threat-status ' + statusClass + '"><span class="status-dot"></span>' + statusText + '</div>' +
      nagHtml +
      '<div class="threat-explain">' + explainText + '</div>' +
      permsHtml +
      '<div class="threat-actions">' + buttons + '</div>' +
      '<div class="action-feedback" data-feedback="' + t.id + '"></div>' +
    '</div>';
  }).join("");
}

function load() {
  chrome.runtime.sendMessage({ type: "get-threats" }, render);
  // Show org message if enterprise-managed
  chrome.runtime.sendMessage({ type: "get-policy" }, function(p) {
    if (p && p.isManaged) {
      var bar = document.getElementById("org-bar");
      if (bar) {
        var parts = [];
        if (p.orgName) parts.push("Managed by <strong>" + esc(p.orgName) + "</strong>");
        if (p.orgMessage) parts.push(esc(p.orgMessage));
        if (parts.length > 0) {
          bar.innerHTML = '<div class="org-icon"></div><div>' + parts.join(" - ") + '</div>';
          bar.style.display = "flex";
        }
      }
    }
  });
}

document.getElementById("threats").addEventListener("click", function(e) {
  var btn = e.target.closest("[data-action]");
  if (!btn) return;
  var action = btn.getAttribute("data-action");
  var id = btn.getAttribute("data-id");

  if (action === "uninstall") {
    btn.textContent = "\u23f3 Waiting for confirmation...";
    btn.disabled = true;
    chrome.runtime.sendMessage({ type: "uninstall-ext", id: id }, function(resp) {
      if (resp && resp.cancelled) {
        // User dismissed the Chrome dialog without removing
        var fb = document.querySelector('[data-feedback="' + id + '"]');
        if (fb) {
          fb.innerHTML =
            '<div class="cancel-warning">' +
            '<strong>Uninstall was cancelled.</strong> The malicious extension is still on your browser. ' +
            'Please click "Uninstall now" again and confirm by clicking <strong>"Remove"</strong> in the Chrome dialog. ' +
            'Keeping this extension installed puts your data at risk.' +
            '</div>';
        }
        btn.textContent = "Uninstall now - please confirm";
        btn.disabled = false;
      } else {
        load();
      }
    });
  } else if (action === "disable") {
    chrome.runtime.sendMessage({ type: "disable-ext", id: id }, load);
  } else if (action === "whitelist") {
    chrome.runtime.sendMessage({ type: "whitelist-ext", id: id }, load);
  } else if (action === "dismiss") {
    chrome.runtime.sendMessage({ type: "clear-test" }, load);
  }
});

// Manual removal instructions fallback
function showManualInstructions(id) {
  var el = document.querySelector('[data-feedback="' + id + '"]');
  if (el) {
    el.innerHTML =
      '<div class="manual-steps">' +
      '<strong>Manual removal:</strong>' +
      '<ol>' +
      '<li>Open a new tab and go to <code>chrome://extensions</code></li>' +
      '<li>Find the extension listed above</li>' +
      '<li>Click the <strong>"Remove"</strong> button</li>' +
      '<li>Confirm the removal in the dialog</li>' +
      '</ol></div>';
  }
}

load();

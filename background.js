const DEFAULT_FEED = "https://raw.githubusercontent.com/ExtSentry/ExtSentry.github.io/refs/heads/main/feeds/ioc_malicious_extension_ids.txt";
const DEFAULT_CHECK_MINUTES = 30;
const DEFAULT_WARN_MINUTES = 5;
const DEFAULT_ADBLOCK_ENABLED = false;
const DEFAULT_ADBLOCK_RULES = [
  "doubleclick.net",
  "googlesyndication.com",
  "googleadservices.com",
  "adservice.google.com",
  "amazon-adsystem.com",
  "adroll.com",
  "adsafeprotected.com",
  "adnxs.com",
  "taboola.com",
  "outbrain.com"
];
const ADBLOCK_RULE_IDS = DEFAULT_ADBLOCK_RULES.map(function(_, i) { return i + 1; });

// ── Managed Policy ──
// Reads admin-pushed config from chrome.storage.managed (GPO / MDM / JSON policy)
async function getManagedPolicy() {
  try {
    const m = await chrome.storage.managed.get(null);
    return {
      feedUrls: m.feed_urls || null,
      adminBlocklist: m.custom_blocklist || [],
      adminWhitelist: m.whitelist || [],
      autoDisable: m.auto_disable,               // undefined = not set by admin
      checkInterval: m.check_interval_minutes,
      warnInterval: m.warn_interval_minutes,
      lockSettings: m.lock_settings || false,
      orgName: m.org_name || null,
      orgMessage: m.org_message || null,
      adblockEnabled: m.adblock_enabled,
      adblockRules: m.adblock_rules || [],
      isManaged: true
    };
  } catch (e) {
    // No managed storage = not enterprise-managed
    return { feedUrls: null, adminBlocklist: [], adminWhitelist: [], isManaged: false, lockSettings: false };
  }
}

// Merges admin policy with user-local settings. Admin wins when lockSettings is true.
async function getEffectiveConfig() {
  const policy = await getManagedPolicy();
  const local = await chrome.storage.local.get(["autoDisable", "checkInterval", "warnInterval", "customBlocklist", "whitelist", "userFeedUrls"]);

  const locked = policy.lockSettings;
  const baseFeedUrls = policy.feedUrls || [DEFAULT_FEED];
  const userFeeds = locked ? [] : (local.userFeedUrls || []);

  return {
    feedUrls: [...baseFeedUrls, ...userFeeds],
    autoDisable: (policy.autoDisable !== undefined) ? policy.autoDisable : (local.autoDisable !== undefined ? local.autoDisable : true),
    adBlockEnabled: (policy.adblockEnabled !== undefined) ? policy.adblockEnabled : (local.adBlockEnabled !== undefined ? local.adBlockEnabled : DEFAULT_ADBLOCK_ENABLED),
    checkInterval: policy.checkInterval || local.checkInterval || DEFAULT_CHECK_MINUTES,
    warnInterval: policy.warnInterval || local.warnInterval || DEFAULT_WARN_MINUTES,
    // Admin lists always apply; user lists only if not locked
    adminBlocklist: policy.adminBlocklist,
    userBlocklist: locked ? [] : (local.customBlocklist || []),
    adminWhitelist: policy.adminWhitelist,
    userWhitelist: locked ? [] : (local.whitelist || []),
    adminAdblockRules: policy.adblockRules || [],
    userAdblockRules: locked ? [] : (local.userAdblockRules || []),
    lockSettings: locked,
    orgName: policy.orgName,
    orgMessage: policy.orgMessage,
    isManaged: policy.isManaged
  };
}

// ── Feed ──
async function fetchBlocklist() {
  const config = await getEffectiveConfig();
  let allIds = [];

  for (const url of config.feedUrls) {
    try {
      console.log("[ExtSentry] Fetching feed:", url);
      const storeKey = "feed_" + btoa(url).slice(0, 20);
      const stored = await chrome.storage.local.get([storeKey + "_etag", storeKey + "_lm"]);
      const headers = {};
      if (stored[storeKey + "_etag"]) headers["If-None-Match"] = stored[storeKey + "_etag"];
      if (stored[storeKey + "_lm"]) headers["If-Modified-Since"] = stored[storeKey + "_lm"];

      const resp = await fetch(url, { headers });
      console.log("[ExtSentry] Feed", url, "→", resp.status);

      if (resp.status === 304) {
        // Use cached version
        const cached = await chrome.storage.local.get(storeKey);
        if (cached[storeKey]) allIds = allIds.concat(cached[storeKey]);
        continue;
      }
      if (!resp.ok) continue;

      const text = await resp.text();
      const ids = text.split("\n").map(l => l.trim()).filter(l => l.length > 0);

      const save = {};
      save[storeKey] = ids;
      save[storeKey + "_etag"] = resp.headers.get("etag") || "";
      save[storeKey + "_lm"] = resp.headers.get("last-modified") || "";
      await chrome.storage.local.set(save);

      allIds = allIds.concat(ids);
    } catch (e) {
      console.error("[ExtSentry] Feed error:", url, e);
      // Try to use cached version on error
      const storeKey = "feed_" + btoa(url).slice(0, 20);
      const cached = await chrome.storage.local.get(storeKey);
      if (cached[storeKey]) allIds = allIds.concat(cached[storeKey]);
    }
  }

  // Deduplicate
  const unique = [...new Set(allIds)];
  const prev = (await chrome.storage.local.get("blocklist")).blocklist || [];
  await chrome.storage.local.set({
    blocklist: unique,
    lastFetch: Date.now(),
    feedDelta: unique.length - prev.length
  });
  console.log("[ExtSentry] Blocklist updated:", unique.length, "IDs from", config.feedUrls.length, "feed(s)");
  return true;
}

async function getFullBlocklist() {
  const config = await getEffectiveConfig();
  const { blocklist = [] } = await chrome.storage.local.get("blocklist");

  const whiteSet = new Set([...config.adminWhitelist, ...config.userWhitelist]);
  const combined = [...blocklist, ...config.adminBlocklist, ...config.userBlocklist].filter(id => !whiteSet.has(id));
  return new Set(combined);
}

function normalizeAdblockPattern(pattern) {
  if (!pattern) return null;
  var input = pattern.trim();
  if (!input) return null;
  if (input.startsWith("||") || input.startsWith("http://") || input.startsWith("https://") || input.includes("*") || input.includes("^")) {
    return input;
  }
  if (/^[^\/]+\.[^\/]+$/.test(input)) {
    return "||" + input + "^";
  }
  return input;
}

function createAdblockDnrRules(ruleStrings) {
  var rules = [];
  ruleStrings.forEach(function(rule, index) {
    if (index >= ADBLOCK_RULE_IDS.length) return;
    var filter = normalizeAdblockPattern(rule);
    if (!filter) return;
    rules.push({
      id: ADBLOCK_RULE_IDS[index],
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: filter,
        resourceTypes: ["main_frame", "sub_frame", "script", "image", "xmlhttprequest", "object", "font", "stylesheet", "media", "ping"]
      }
    });
  });
  return rules;
}

async function getFullAdblockRules() {
  const config = await getEffectiveConfig();
  const rules = [...DEFAULT_ADBLOCK_RULES, ...config.adminAdblockRules, ...config.userAdblockRules];
  return [...new Set(rules.map(function(r) { return typeof r === "string" ? r.trim() : ""; }).filter(function(r) { return r.length > 0; }))];
}

async function applyAdblockRules() {
  if (!chrome.declarativeNetRequest) return;
  var config = await getEffectiveConfig();
  var removeIds = ADBLOCK_RULE_IDS;
  if (!config.adBlockEnabled) {
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds });
    return;
  }
  var rules = createAdblockDnrRules(await getFullAdblockRules());
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeIds, addRules: rules });
}

// ── Scanning ──
async function scanExtensions(testId = null) {
  const blockSet = await getFullBlocklist();
  if (testId) blockSet.add(testId);
  const installed = await chrome.management.getAll();
  const self = chrome.runtime.id;
  console.log("[ExtSentry] Scanning", installed.length - 1, "extensions against", blockSet.size, "blocked IDs");

  const threats = installed
    .filter(ext => ext.id !== self && blockSet.has(ext.id))
    .map(ext => ({
      id: ext.id, name: ext.name, enabled: ext.enabled, isTest: ext.id === testId,
      description: ext.description || "", version: ext.version || "",
      permissions: ext.permissions || [], hostPermissions: ext.hostPermissions || [],
      iconUrl: ext.icons && ext.icons.length ? ext.icons[ext.icons.length - 1].url : "",
      installType: ext.installType || "unknown"
    }));

  await chrome.storage.local.set({ threats, lastScan: Date.now() });
  console.log("[ExtSentry] Scan complete:", threats.length, "threats found" + (threats.length > 0 ? " → " + threats.map(t => t.name).join(", ") : ""));

  if (threats.filter(t => !t.isTest).length > 0) await logThreats(threats.filter(t => !t.isTest));

  const config = await getEffectiveConfig();
  if (config.autoDisable) {
    for (const t of threats) {
      if (t.enabled && !t.isTest) {
        try { await chrome.management.setEnabled(t.id, false); } catch (e) {}
      }
    }
  }

  updateBadge(threats);
  if (threats.length > 0) showWarning(threats);
  return threats;
}

async function logThreats(threats) {
  const { threatHistory = [] } = await chrome.storage.local.get("threatHistory");
  threatHistory.unshift({ timestamp: Date.now(), threats: threats.map(t => ({ id: t.id, name: t.name })) });
  if (threatHistory.length > 100) threatHistory.length = 100;
  await chrome.storage.local.set({ threatHistory });
}

function updateBadge(threats) {
  const real = (threats || []).filter(t => !t.isTest);
  if (real.length > 0) {
    chrome.action.setBadgeText({ text: String(real.length) });
    chrome.action.setBadgeBackgroundColor({ color: "#e63946" });
  } else {
    chrome.action.setBadgeText({ text: "" });
  }
}

function showWarning(threats) {
  const names = threats.map(t => t.name).slice(0, 3).join(", ");
  const more = threats.length > 3 ? " and " + (threats.length - 3) + " more" : "";
  chrome.notifications.create("extsentry-warning", {
    type: "basic", iconUrl: "icon128.png",
    title: "\u26a0\ufe0f Malicious Extension Detected!",
    message: "Found " + threats.length + " dangerous extension(s): " + names + more,
    priority: 2, requireInteraction: true
  });
  chrome.tabs.create({ url: chrome.runtime.getURL("warning.html") });
}

// ── Alarms ──
async function setupAlarms() {
  const config = await getEffectiveConfig();
  chrome.alarms.create("check-feed", { periodInMinutes: config.checkInterval });
  chrome.alarms.create("re-warn", { periodInMinutes: config.warnInterval });
}

chrome.notifications.onClicked.addListener(function(id) {
  if (id === "extsentry-warning") chrome.tabs.create({ url: chrome.runtime.getURL("warning.html") });
});

chrome.alarms.onAlarm.addListener(async function(alarm) {
  if (alarm.name === "check-feed") { await fetchBlocklist(); await scanExtensions(); }
  if (alarm.name === "re-warn") {
    const { threats = [] } = await chrome.storage.local.get("threats");
    const real = threats.filter(t => !t.isTest);
    if (real.length > 0) showWarning(real);
  }
});

chrome.runtime.onInstalled.addListener(async function() {
  await fetchBlocklist(); await scanExtensions(); await setupAlarms(); await applyAdblockRules();
});
chrome.runtime.onStartup.addListener(async function() {
  await fetchBlocklist(); await scanExtensions(); await setupAlarms(); await applyAdblockRules();
});
chrome.management.onInstalled.addListener(async function() { await scanExtensions(); });
chrome.management.onUninstalled.addListener(async function() { await scanExtensions(); });

// Re-apply alarms if managed policy changes
chrome.storage.onChanged.addListener(function(changes, area) {
  if (area === "managed") {
    console.log("[ExtSentry] Managed policy changed, re-applying config");
    setupAlarms();
    fetchBlocklist().then(function() { scanExtensions(); });
  }
});

// ── Messages ──
chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
  var handlers = {
    "get-threats": async function() {
      return (await chrome.storage.local.get("threats")).threats || [];
    },
    "uninstall-ext": async function() {
      return new Promise(function(resolve) {
        chrome.management.uninstall(msg.id, { showConfirmDialog: true }, function() {
          var cancelled = !!chrome.runtime.lastError;
          scanExtensions().then(function() { resolve({ ok: !cancelled, cancelled: cancelled }); });
        });
      });
    },
    "disable-ext": async function() {
      await new Promise(function(r) { chrome.management.setEnabled(msg.id, false, r); });
      await scanExtensions();
      return { ok: true };
    },
    "run-test": async function() {
      var installed = await chrome.management.getAll();
      var self = chrome.runtime.id;
      var candidates = installed.filter(function(e) { return e.id !== self && e.type === "extension"; });
      if (candidates.length === 0) return { ok: false, error: "No other extensions to test with." };
      var pick = candidates[Math.floor(Math.random() * candidates.length)];
      await scanExtensions(pick.id);
      return { ok: true, tested: pick.name, testedId: pick.id };
    },
    "clear-test": async function() {
      var d = await chrome.storage.local.get("threats");
      var real = (d.threats || []).filter(function(t) { return !t.isTest; });
      await chrome.storage.local.set({ threats: real });
      updateBadge(real);
      return { ok: true };
    },
    "scan-now": async function() {
      await fetchBlocklist(); var t = await scanExtensions();
      return { ok: true, threats: t };
    },
    "force-update-feed": async function() {
      // Clear all cached etags/last-modified to force a fresh download
      var all = await chrome.storage.local.get(null);
      var keysToRemove = Object.keys(all).filter(function(k) {
        return k.startsWith("feed_") && (k.endsWith("_etag") || k.endsWith("_lm"));
      });
      if (keysToRemove.length > 0) await chrome.storage.local.remove(keysToRemove);
      console.log("[ExtSentry] Force update: cleared", keysToRemove.length, "cached headers");
      await fetchBlocklist();
      var t = await scanExtensions();
      var d = await chrome.storage.local.get("blocklist");
      return { ok: true, count: (d.blocklist || []).length, threats: t };
    },
    "get-custom-blocklist": async function() {
      return (await chrome.storage.local.get("customBlocklist")).customBlocklist || [];
    },
    "set-custom-blocklist": async function() {
      await chrome.storage.local.set({ customBlocklist: msg.ids }); await scanExtensions();
      return { ok: true };
    },
    "get-whitelist": async function() {
      return (await chrome.storage.local.get("whitelist")).whitelist || [];
    },
    "set-whitelist": async function() {
      await chrome.storage.local.set({ whitelist: msg.ids }); await scanExtensions();
      return { ok: true };
    },
    "whitelist-ext": async function() {
      var d = await chrome.storage.local.get("whitelist");
      var wl = d.whitelist || [];
      if (wl.indexOf(msg.id) === -1) wl.push(msg.id);
      await chrome.storage.local.set({ whitelist: wl }); await scanExtensions();
      return { ok: true };
    },
    "get-user-feeds": async function() {
      return (await chrome.storage.local.get("userFeedUrls")).userFeedUrls || [];
    },
    "set-user-feeds": async function() {
      await chrome.storage.local.set({ userFeedUrls: msg.urls });
      await fetchBlocklist();
      await scanExtensions();
      return { ok: true };
    },
    "get-adblock-settings": async function() {
      var config = await getEffectiveConfig();
      return {
        adBlockEnabled: config.adBlockEnabled,
        adblockRules: await getFullAdblockRules(),
        lockSettings: config.lockSettings,
        isManaged: config.isManaged
      };
    },
    "set-adblock-settings": async function() {
      var config = await getEffectiveConfig();
      if (config.lockSettings) return { ok: false, error: "Settings locked by admin policy." };
      await chrome.storage.local.set({ adBlockEnabled: msg.enabled });
      await applyAdblockRules();
      return { ok: true };
    },
    "get-adblock-rules": async function() {
      return (await chrome.storage.local.get("userAdblockRules")).userAdblockRules || [];
    },
    "set-adblock-rules": async function() {
      var config = await getEffectiveConfig();
      if (config.lockSettings) return { ok: false, error: "Settings locked by admin policy." };
      await chrome.storage.local.set({ userAdblockRules: msg.rules });
      await applyAdblockRules();
      return { ok: true };
    },
    "get-settings": async function() {
      var config = await getEffectiveConfig();
      return {
        autoDisable: config.autoDisable,
        warnInterval: config.warnInterval,
        checkInterval: config.checkInterval,
        lockSettings: config.lockSettings,
        isManaged: config.isManaged,
        orgName: config.orgName,
        orgMessage: config.orgMessage,
        feedUrls: config.feedUrls
      };
    },
    "set-settings": async function() {
      var config = await getEffectiveConfig();
      if (config.lockSettings) return { ok: false, error: "Settings locked by admin policy." };
      await chrome.storage.local.set(msg.settings);
      await setupAlarms();
      return { ok: true };
    },
    "get-stats": async function() {
      var d = await chrome.storage.local.get(null);
      var config = await getEffectiveConfig();
      var installed = await chrome.management.getAll();
      return {
        feedCount: (d.blocklist || []).length,
        customCount: (d.customBlocklist || []).length + config.adminBlocklist.length,
        whitelistCount: (d.whitelist || []).length + config.adminWhitelist.length,
        threatCount: (d.threats || []).filter(function(t) { return !t.isTest; }).length,
        totalExtensions: installed.length - 1,
        historyCount: (d.threatHistory || []).length,
        lastFetch: d.lastFetch, lastScan: d.lastScan,
        feedDelta: d.feedDelta || 0,
        history: (d.threatHistory || []).slice(0, 20),
        isManaged: config.isManaged,
        orgName: config.orgName,
        feedUrls: config.feedUrls
      };
    },
    "get-policy": async function() {
      return await getEffectiveConfig();
    }
  };
  if (handlers[msg.type]) { handlers[msg.type]().then(sendResponse); return true; }
});

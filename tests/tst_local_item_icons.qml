import QtQuick
import QtQuick.Controls
import "../components"
import "../components/IconPolicy.js" as IconPolicy

// Vault items are drawn with local, type-based glyphs only. No component may
// request a website icon from a remote icon service.
Item {
  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  VaultItemList { id: list }
  ItemInspector { id: insp }

  property var loginItem: ({
    name: "GitHub",
    type_name: "login",
    login: { username: "octocat", uris: [{ uri: "https://github.com" }] },
    sub_title: "octocat"
  })
  property var cardItem: ({ name: "Bank Card", type_name: "card" })
  property var identityItem: ({ name: "Passport", type_name: "identity" })
  property var noteItem: ({ name: "Secret Recipe", type_name: "note", sub_title: "Secure Note" })

  function readSource(path) {
    var xhr = new XMLHttpRequest()
    xhr.open("GET", path, false)
    xhr.send()
    return xhr.responseText
  }

  readonly property var sourceFiles: [
    "../OmarchyBitwarden.qml",
    "../components/IconPolicy.js",
    "../components/ItemInspector.qml",
    "../components/VaultItemList.qml",
    "../components/EmptyInspector.qml",
    "../components/SettingsModal.qml"
  ]

  Component.onCompleted: {
    console.log("Running Local Item Icon Tests...")

    // A. Server classification and origin matching (used by the mTLS settings)
    check(IconPolicy.isOfficialServer("https://vault.bitwarden.com") === true, "vault.bitwarden.com is official")
    check(IconPolicy.isOfficialServer("https://vault.bitwarden.eu") === true, "vault.bitwarden.eu is official")
    check(IconPolicy.isOfficialServer("https://api.bitwarden.com") === true, "api.bitwarden.com is official")
    check(IconPolicy.isOfficialServer("") === true, "empty server_url defaults to official")
    check(IconPolicy.isOfficialServer("https://vaultwarden.example.com") === false, "vaultwarden.example.com is self-hosted")
    check(IconPolicy.isOfficialServer("http://192.168.1.50:8080") === false, "lan IP is self-hosted")
    check(IconPolicy.isOfficialServer("https://vault.corp.internal/api/") === false, "corp.internal is self-hosted")
    check(IconPolicy.extractOrigin("https://vault.example.com:8443/api/") === "https://vault.example.com:8443", "extractOrigin parses origin with port and path")
    check(IconPolicy.extractOrigin("http://127.0.0.1:8080") === "http://127.0.0.1:8080", "extractOrigin parses http IP and port")
    check(IconPolicy.extractOrigin("vault.bitwarden.com") === "https://vault.bitwarden.com", "extractOrigin adds https scheme if missing")
    check(IconPolicy.isSameOrigin("https://vault.corp.com:8443", "https://vault.corp.com:8443/api") === true, "isSameOrigin true for same origin different path")
    check(IconPolicy.isSameOrigin("https://vault.corp.com:8443", "https://vault.corp.com:9443") === false, "isSameOrigin false for different port")
    check(IconPolicy.isSameOrigin("https://vault.corp.com", "https://other.corp.com") === false, "isSameOrigin false for different domain")
    check(IconPolicy.isSameOrigin("https://vault.corp.com", "https://vault.bitwarden.com") === false, "isSameOrigin false for cloud vs custom")

    // B. The remote icon URL builders are gone
    check(typeof IconPolicy.resolveIconUrl === "undefined", "IconPolicy no longer builds remote icon URLs")
    check(typeof IconPolicy.getIconBaseUrl === "undefined", "IconPolicy no longer resolves an icon service")
    check(typeof IconPolicy.resolve === "undefined", "IconPolicy no longer resolves an icon setting")

    // C. Components expose no website icon state and draw type-based glyphs
    var comps = [{ n: "VaultItemList", c: list }, { n: "ItemInspector", c: insp }]
    for (var i = 0; i < comps.length; i++) {
      var c = comps[i].c
      check(c.showWebsiteIcons === undefined, comps[i].n + ": has no showWebsiteIcons property")
      check(typeof c.getFaviconUrl === "undefined", comps[i].n + ": has no getFaviconUrl function")
      check(c.getItemIcon(loginItem) === "", comps[i].n + ": login uses the key glyph")
      check(c.getItemIcon(cardItem) === "", comps[i].n + ": card uses the card glyph")
      check(c.getItemIcon(identityItem) === "", comps[i].n + ": identity uses the identity glyph")
      check(c.getItemIcon(noteItem) === "", comps[i].n + ": note uses the note glyph")
    }

    // D. No source loads an image from the network or names an icon service
    for (var f = 0; f < sourceFiles.length; f++) {
      var src = readSource(Qt.resolvedUrl(sourceFiles[f]))
      check(src.length > 0, sourceFiles[f] + ": source is readable")
      check(!/icons\.bitwarden\.net|\/icon\.png|favicon/i.test(src), sourceFiles[f] + ": names no icon service")
      check(!/Image\s*\{[^}]*source:[^\n]*https?:/.test(src), sourceFiles[f] + ": has no Image with a remote source")
    }

    console.log("ALL LOCAL ITEM ICON TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}

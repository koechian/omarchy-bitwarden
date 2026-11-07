import QtQuick
import "lib"
import "../components/UriPolicy.js" as UriPolicy

// Qt.openUrlExternally may receive http:// and https:// URLs only; every
// other scheme is displayed and copyable but never opened.
Item {
  id: testRunner

  readonly property var openable: [
    ["https://github.com/login", "https://github.com/login"],
    ["HTTP://Example.com/a?b=c#d", "HTTP://Example.com/a?b=c#d"],
    ["  https://example.com/path  ", "https://example.com/path"],
    ["github.com/login", "https://github.com/login"],
    ["192.168.1.10:8080/admin", "https://192.168.1.10:8080/admin"],
    ["localhost:8080", "https://localhost:8080"],
    ["localhost:8080/admin?x=1", "https://localhost:8080/admin?x=1"],
    ["github.com:443/x", "https://github.com:443/x"],
    ["nas.local:5000#dashboard", "https://nas.local:5000#dashboard"],
    ["Vault.Example.COM:8443", "https://Vault.Example.COM:8443"],
    // A scheme with a numeric value reads as host:port and can only ever
    // open as https; no scheme handler is invoked.
    ["mailto:25", "https://mailto:25"],
    ["steam:12/run", "https://steam:12/run"]
  ]

  readonly property var refused: [
    "file:///etc/passwd",
    "smb://nas/share",
    "ssh://host",
    "ftp://example.com/file",
    "javascript:alert(1)",
    "data:text/html,<script>x</script>",
    "androidapp://com.example",
    "steam://run/1",
    "mailto:someone@example.com",
    "tel:5551234567",
    "localhost:0",
    "localhost:65536",
    "localhost:8080x",
    "host:port",
    "file:///localhost:8080",
    "javascript:alert(1)//localhost:80",
    "https://exa mple.com",
    "https://example.com/\u0000",
    "https://",
    "",
    null
  ]

  Component.onCompleted: {
    console.log("Running URI allowlist tests...")
    openable.forEach(function(entry) {
      Assert.check(UriPolicy.openableUrl(entry[0]) === entry[1], "opens " + JSON.stringify(entry[0]) + " as " + entry[1] + " (got " + UriPolicy.openableUrl(entry[0]) + ")")
    })
    refused.forEach(function(uri) {
      Assert.check(UriPolicy.openableUrl(uri) === "" && !UriPolicy.isOpenable(uri), "refuses to open " + JSON.stringify(uri))
    })

    var entries = UriPolicy.itemUris({ login: { uris: [
      { uri: "file:///home/user/doc.pdf" },
      { uri: "https://example.com/a" },
      { uri: "https://example.com/a" },
      "https://example.com/b",
      { uri: "   " },
      { uri: null }
    ] } })
    Assert.check(entries.length === 3, "URIs are trimmed, empty ones dropped and duplicates removed (" + entries.length + ")")
    Assert.check(entries[0].uri === "https://example.com/a" && entries[0].isOpenable, "openable URIs come first and keep their full value")
    Assert.check(entries[2].uri === "file:///home/user/doc.pdf" && !entries[2].isOpenable && entries[2].openUrl === "", "file:// is listed but not openable")
    Assert.check(UriPolicy.firstOpenableUrl({ login: { uris: [{ uri: "smb://nas" }] } }) === "", "no openable URL for an item with only smb://")
    Assert.check(UriPolicy.itemUris(null).length === 0, "an item without login has no URIs")

    var source = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml")) + readSource(Qt.resolvedUrl("../components/ItemInspector.qml"))
    var calls = source.match(/Qt\.openUrlExternally\(/g) || []
    Assert.check(calls.length === 1, "exactly one Qt.openUrlExternally call site (" + calls.length + ")")
    Assert.check(/var url = UriPolicy\.openableUrl\(uri\)[\s\S]{0,200}Qt\.openUrlExternally\(url\)/.test(source), "the only call site opens the allowlisted URL")
    Qt.exit(Assert.exitCode())
  }

  function readSource(path) {
    var request = new XMLHttpRequest()
    request.open("GET", path, false)
    request.send()
    return request.responseText || ""
  }
}

import QtQuick
import "lib"
import "../components" as Components

// A held key repeats. Every secret copy or reveal is a budgeted release
// (more than 30 within 60 s hard-locks the vault), so the chords that
// release a secret act on the first press only. SearchHeader is driven
// directly; OmarchyBitwarden.qml needs the Quickshell runtime and is checked
// at the source level.
Item {
  id: testRunner
  width: 600
  height: 200

  property int totpRequests: 0
  property int usernameRequests: 0

  Components.SearchHeader {
    id: searchHeader
    width: 600
    onCopyTotpRequested: testRunner.totpRequests++
    onCopyUsernameRequested: testRunner.usernameRequests++
  }

  function keyEvent(key, isAutoRepeat) {
    return { key: key, text: "", modifiers: Qt.ControlModifier, isAutoRepeat: isAutoRepeat }
  }

  function readSource(path) {
    var request = new XMLHttpRequest()
    request.open("GET", path, false)
    request.send()
    return request.responseText || ""
  }

  function functionBody(source, name) {
    var start = source.indexOf("function " + name + "(")
    if (start === -1) return ""
    var open = source.indexOf("{", start)
    var depth = 0
    for (var i = open; i < source.length; i++) {
      if (source[i] === "{") depth++
      else if (source[i] === "}" && --depth === 0) return source.substring(open, i + 1)
    }
    return ""
  }

  function shortcutBlock(source, sequenceText) {
    var start = source.indexOf(sequenceText)
    return start === -1 ? "" : source.substring(start, source.indexOf("}", start))
  }

  function testSearchHeader() {
    Assert.check(searchHeader.handleControlShortcut(keyEvent(Qt.Key_Return, false)), "Ctrl+Enter in the search field is handled")
    Assert.check(totpRequests === 1, "Ctrl+Enter requests one TOTP copy")
    Assert.check(searchHeader.handleControlShortcut(keyEvent(Qt.Key_Return, true)), "a repeated Ctrl+Enter is still accepted")
    Assert.check(searchHeader.handleControlShortcut(keyEvent(Qt.Key_Enter, true)), "a repeated keypad Ctrl+Enter is still accepted")
    Assert.check(totpRequests === 1, "repeats of a held Ctrl+Enter request no further TOTP copy")
    searchHeader.handleControlShortcut(keyEvent(Qt.Key_U, false))
    searchHeader.handleControlShortcut(keyEvent(Qt.Key_U, true))
    Assert.check(usernameRequests === 1, "a held Ctrl+U copies the username once")
    Assert.check(!searchHeader.handleControlShortcut(keyEvent(Qt.Key_Z, false)), "an unbound chord is left to the overlay")
  }

  function testEscapeOrder() {
    searchHeader.searchQuery = "github"
    Assert.check(searchHeader.handleEscapeKey() && searchHeader.searchField.text === "", "Esc clears the query first")
    Assert.check(!searchHeader.handleEscapeKey(), "Esc with nothing to clear is left to the overlay")
  }

  function testRootSource() {
    var root = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    Assert.check(root.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")
    var primary = functionBody(root, "handlePrimaryKey")
    Assert.check(/if \(event\.isAutoRepeat\) return true/.test(primary), "a held Enter or Ctrl+Enter copies once")
    Assert.check(/ControlModifier\) root\.copyItemTotp/.test(primary), "Ctrl+Enter in the overlay copies the TOTP code, not the password")
    Assert.check(/if \(!event\.isAutoRepeat\) root\.toggleItemRevealed\(\)/.test(functionBody(root, "handleOverlayKey")), "a held Ctrl+T reveals once")
    Assert.check(/autoRepeat: false/.test(shortcutBlock(root, 'sequences: ["Ctrl+Return", "Ctrl+Enter"]')), "the Ctrl+Enter shortcut does not repeat")
    Assert.check(/autoRepeat: false/.test(shortcutBlock(root, 'sequence: "Ctrl+T"')), "the Ctrl+T shortcut does not repeat")
    Assert.check(/if \(!event\.isAutoRepeat\) entry\[1\]\(\)/.test(functionBody(root, "handleControlKey")), "a held Ctrl chord in the overlay (Ctrl+O included) acts once")
    Assert.check(/autoRepeat: false/.test(shortcutBlock(root, 'sequence: "Ctrl+O"')), "the Ctrl+O shortcut does not repeat, so a held chord opens one browser tab")
  }

  Component.onCompleted: {
    console.log("Running release key repetition tests...")
    testSearchHeader()
    testEscapeOrder()
    testRootSource()
    Qt.exit(Assert.exitCode())
  }
}

import QtQuick
import "lib"
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// Source checks on OmarchyBitwarden.qml, which needs the Quickshell runtime
// and cannot be instantiated here: the overlay reads no plaintext secret
// field, releases nothing on selection, copies secrets only through
// `vault copy-field`, drops revealed values when hidden or locked, and returns
// to the unlock view on release_limit_exceeded.
Item {
  id: testRunner

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

  Component.onCompleted: {
    console.log("Running secret release wiring checks...")
    var root = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    Assert.check(root.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")

    var plaintextReads = [/\.login\.password\b/, /\.login\.totp\b/, /\.login\.password_history\b/, /item\.notes\b/,
      /\.card\.number\b/, /\.card\.code\b/, /\.identity\.ssn\b/, /passportNumber/, /licenseNumber/, /search_text/, /currentTotp/]
    plaintextReads.forEach(function(pattern) {
      Assert.check(!pattern.test(root), "overlay reads no plaintext field matching " + pattern)
    })
    Assert.check(root.indexOf('"totp", item.id') === -1 && root.indexOf('"totp"]') === -1, "overlay never runs `omawarden totp` on selection")

    var selection = functionBody(root, "handleSelectedItemChanged")
    Assert.check(selection.length > 0 && !/reveal|copy|totp/i.test(selection), "selection change releases nothing")

    var activeBinding = (root.match(/SecretReleaseController \{[\s\S]*?\n  \}/) || [""])[0]
    Assert.check(/active: root\.opened && [^\n]*"unlocked"[^\n]*effectiveView === "search"/.test(activeBinding), "release controller is active only while shown and unlocked")
    Assert.check(/itemId: root\.selectedItem/.test(activeBinding), "release controller follows the selected item")

    var refusal = functionBody(root, "handleReleaseRefusal")
    Assert.check(/errorLocksVault\(errorCode\)/.test(refusal) && /markVaultLocked\(\)/.test(refusal), "release_limit_exceeded and vault_locked return to the unlock view")
    var locked = functionBody(root, "markVaultLocked")
    Assert.check(/clearSensitiveState\(\)/.test(locked) && /status: "locked"/.test(locked), "locking drops vault state and keeps the session")
    Assert.check(/secretRelease\.reset\(\)/.test(functionBody(root, "clearSensitiveState")), "clearing sensitive state drops revealed values")
    Assert.check(/secretRelease\.reset\(\)/.test(functionBody(root, "resetTransientState")) && /resetTransientState\(\)/.test(functionBody(root, "close")), "hiding the overlay drops revealed values")

    var copySecret = functionBody(root, "copySecretField")
    Assert.check(/secretRelease\.copyField\(field/.test(copySecret) && !/copyToClipboard/.test(copySecret), "secret copies go through copy-field only")
    Assert.check(/isAutoRepeat/.test(functionBody(root, "handlePrimaryKey")), "a held Enter key copies once")
    Assert.check(/onStreamFinished: secretRelease\.handleCommandOutput\(text\)/.test(root), "release output goes to the controller and is not logged")
    Assert.check(/onCommandStopRequested: function\(forceful\) \{ root\.stopSecretFieldProcess\(forceful\) \}/.test(root), "a timed-out release asks the overlay to stop its process")
    var stopBody = functionBody(root, "stopSecretFieldProcess")
    Assert.check(/secretFieldProc\.running = false/.test(stopBody) && /secretFieldProc\.signal\(root\.forcefulStopSignal\)/.test(stopBody), "the release process is stopped, then killed if it does not exit")

    var copyArgv = SecretFieldCatalog.copyArguments("omawarden", "id-1", SecretFieldCatalog.NOTES, 30)
    Assert.check(copyArgv.indexOf("copy-field") !== -1, "notes copy uses copy-field, which always sets the sensitive hint (contracts.md 3.4)")
    Assert.check(SecretFieldCatalog.revealArguments("omawarden", "-x", "notes")[3] === "--id=-x", "an id that starts with '-' cannot be read as an option")
    Assert.check(SecretFieldCatalog.copyArguments("omawarden", "id-1", "notes", 0).length === 5, "out-of-range clear-after is omitted")
    Qt.exit(Assert.exitCode())
  }
}

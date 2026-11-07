import QtQuick
import Quickshell.Io
import qs.Commons
import qs.Commons as Commons
import qs.Ui
import "components" as Components
import "components/QuickAccessModel.js" as QuickAccessModel
import "components/SecretFieldCatalog.js" as SecretFieldCatalog

// Bar entry for Omarchy Bitwarden. A left click opens a dropdown under the
// icon (the quick access panel): search the vault's logins and copy a
// username, password or verification code, or unlock the vault with the
// master password. A right click opens the full vault window.
//
// The dropdown talks to the running omawarden daemon only. It lists redacted
// items, so it never holds a secret: passwords and codes are written to the
// clipboard by the daemon (`vault copy-field`), and the dropdown closes after
// each copy so the value can be pasted at once.
Panel {
  id: root
  moduleName: "icyleaf.bitwarden"
  ipcTarget: "icyleaf.bitwarden.quickaccess"

  readonly property string overlayIdentifier: "icyleaf.bitwarden"
  readonly property string enginePath: "omawarden"
  readonly property string lockGlyph: "󰌾"
  readonly property string copiedGlyph: "󰄬"
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family

  property string view: QuickAccessModel.VIEW_LOADING
  property var vaultItems: []
  property bool busy: false
  property string errorText: ""
  property string confirmationText: ""
  property bool showCopied: false

  readonly property QtObject strings: Commons.Translations {
    directory: Qt.resolvedUrl("i18n")
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  // Closing clears the master password field at once; the rest of what the
  // dropdown shows (query, details page, messages) is kept until the card
  // has faded out, so the exit shows the dropdown as it was instead of a
  // card that changes size and content in its first frame.
  onOpenedChanged: opened ? refresh() : forgetSecretInput()

  // --- full window ---------------------------------------------------------

  function openOverlay() {
    root.close()
    var shell = root.bar ? root.bar.shell : null
    if (!shell) return
    if (typeof shell.summon === "function") shell.summon(root.overlayIdentifier, "{}")
    else if (typeof shell.toggle === "function") shell.toggle(root.overlayIdentifier, "{}")
  }

  // --- vault state ---------------------------------------------------------

  // Every opening asks the daemon again, so a vault locked elsewhere (the
  // full window, auto-lock, suspend) is never shown as unlocked.
  function refresh() {
    root.errorText = ""
    if (root.vaultItems.length === 0) root.view = QuickAccessModel.VIEW_LOADING
    statusCommand.run(["auth", "status"], "")
  }

  function forgetSecretInput() {
    if (panel.loadedContent) panel.loadedContent.clearSecretInput()
  }

  function forgetInput() {
    root.errorText = ""
    root.confirmationText = ""
    if (panel.loadedContent) panel.loadedContent.reset()
  }

  function applyStatus(reply, exitStatus) {
    root.view = QuickAccessModel.viewForAuthStatus(reply)
    if (root.view === QuickAccessModel.VIEW_UNLOCKED) listCommand.run(["vault", "list"], "")
    else root.vaultItems = []
  }

  function applyListing(reply) {
    var listing = QuickAccessModel.redactedListing(reply)
    if (listing) {
      root.vaultItems = listing
      return
    }
    root.vaultItems = []
    var envelope = QuickAccessModel.parseJson(reply)
    if (Array.isArray(envelope)) {
      root.errorText = root.strings.t("quickAccess.engineNotRedacting", "The installed omawarden engine sent secrets with the vault list, so the list was discarded. Install omawarden 0.12.0 or later.")
    } else if (envelope && SecretFieldCatalog.errorLocksVault(envelope.error_code)) {
      root.view = QuickAccessModel.VIEW_LOCKED
    } else {
      root.errorText = root.strings.t("quickAccess.listFailed", "The vault list could not be read.")
    }
  }

  function markLocked() {
    root.vaultItems = []
    root.view = QuickAccessModel.VIEW_LOCKED
  }

  // A command the engine never answered (it could not be started, or hangs).
  function applyTimeout(command) {
    root.busy = false
    if (command === statusCommand) root.view = QuickAccessModel.VIEW_ENGINE_UNAVAILABLE
    else root.errorText = root.strings.t("quickAccess.engineTimeout", "The omawarden engine did not answer.")
  }

  // --- unlock and lock -----------------------------------------------------

  // The master password goes to stdin, never to argv.
  function unlock(password) {
    if (root.busy || !password) return
    root.busy = true
    root.errorText = ""
    unlockCommand.run(["auth", "unlock"], password)
  }

  function applyUnlockReply(reply) {
    root.busy = false
    var envelope = QuickAccessModel.parseJson(reply)
    if (envelope && envelope.ok === true) {
      root.refresh()
      return
    }
    root.errorText = (envelope && envelope.error) ? String(envelope.error) : root.strings.t("quickAccess.unlockFailed", "Unlock failed.")
  }

  function lockVault() {
    if (root.busy) return
    root.markLocked()
    lockCommand.run(["auth", "lock"], "")
  }

  // --- copies --------------------------------------------------------------

  // Secrets are copied by the daemon: argv holds only the item id and the
  // field identifiers, and the reply carries no value. The username is a
  // public field of the redacted item and goes to the clipboard on stdin.
  // A quick copy from the list closes the dropdown so the value can be
  // pasted at once; a copy from the details page keeps it open.
  property bool closeAfterCopy: true
  property string pendingCopyKind: ""

  function beginCopy(kind, closeAfter) {
    root.busy = true
    root.errorText = ""
    root.confirmationText = ""
    root.pendingCopyKind = kind
    root.closeAfterCopy = closeAfter
  }

  function copy(item, kind, closeAfter) {
    if (root.busy || !QuickAccessModel.canCopy(item, kind)) return
    root.beginCopy(kind, closeAfter)
    if (kind === QuickAccessModel.COPY_USERNAME) {
      usernameCopyCommand.run(["copy", "--stdin"], JSON.stringify({ text: QuickAccessModel.usernameOf(item) }))
      return
    }
    var argv = SecretFieldCatalog.copyArguments(root.enginePath, item.id, QuickAccessModel.secretField(kind), 0)
    secretCopyCommand.run(argv.slice(1), "")
  }

  // Stages the password and then the verification code: the daemon serves
  // the clipboard itself and swaps in the code after the first paste.
  function copySequence(item) {
    if (root.busy || !QuickAccessModel.canCopySequence(item)) return
    root.beginCopy(QuickAccessModel.COPY_SEQUENCE, true)
    sequenceCommand.run(QuickAccessModel.sequenceArguments(item.id), "")
  }

  function confirmCopy(clearAfterSeconds) {
    root.busy = false
    root.showCopied = true
    copiedTimer.restart()
    if (root.closeAfterCopy) {
      root.close()
      return
    }
    root.confirmationText = QuickAccessModel.copyConfirmation(root.pendingCopyKind, clearAfterSeconds)
  }

  function rejectCopy(result) {
    root.busy = false
    // An engine older than 0.13.0 has no `vault copy-sequence` and answers
    // with a usage error and no envelope.
    if (root.pendingCopyKind === QuickAccessModel.COPY_SEQUENCE && !result.errorCode) {
      root.errorText = root.strings.t("quickAccess.sequenceUnsupported", "The paste sequence needs omawarden 0.13.0 or later. Rebuild the engine (see the README).")
      return
    }
    var key = SecretFieldCatalog.errorMessageKey(result.errorCode)
    root.errorText = key ? root.strings.t(key, result.error) : (result.error || root.strings.t("quickAccess.copyFailed", "The value could not be copied."))
    if (SecretFieldCatalog.errorLocksVault(result.errorCode)) root.markLocked()
  }

  function applySecretCopyReply(reply, exitStatus) {
    var result = SecretFieldCatalog.parseReleaseResponse(reply, exitStatus)
    if (result.ok) root.confirmCopy(result.clearAfterSeconds)
    else root.rejectCopy(result)
  }

  function applyUsernameCopyExit(exitStatus) {
    if (exitStatus === 0) {
      root.confirmCopy(0)
      return
    }
    root.busy = false
    root.errorText = root.strings.t("quickAccess.copyFailed", "The value could not be copied.")
  }

  Timer {
    id: copiedTimer
    interval: 1500
    onTriggered: root.showCopied = false
  }

  // The glyph swap (lock to check mark and back) settles in rather than
  // flipping, so the confirmation reads as intended after the dropdown has
  // closed. Subtle, because copies happen many times a day.
  onShowCopiedChanged: glyphSettle.restart()

  ParallelAnimation {
    id: glyphSettle
    NumberAnimation {
      target: button
      property: "scale"
      from: 0.9
      to: 1
      duration: Style.duration(120)
      easing.type: Easing.Bezier
      easing.bezierCurve: Style.easeOut
    }
    NumberAnimation {
      target: button
      property: "opacity"
      from: 0.5
      to: 1
      duration: Style.duration(120)
      easing.type: Easing.Bezier
      easing.bezierCurve: Style.easeOut
    }
  }

  // --- engine commands -----------------------------------------------------

  // One omawarden invocation. Quickshell reports the end of stdout and the
  // exit of the process in either order, so `completed` is emitted once both
  // have arrived; a command that does not complete within `timeoutMs` emits
  // `timedOut` instead. `stdinLine` (a master password, or the username to
  // copy) is written once on start and then cleared.
  component EngineCommand: Process {
    id: engineCommand
    property string stdinLine: ""
    property string reply: ""
    property bool replyReceived: false
    property bool exitReceived: false
    property int exitStatus: -1
    property int timeoutMs: 10000
    signal completed(string reply, int exitStatus)
    signal timedOut()

    function run(argv, line) {
      engineCommand.running = false
      engineCommand.reply = ""
      engineCommand.replyReceived = false
      engineCommand.exitReceived = false
      engineCommand.exitStatus = -1
      engineCommand.stdinLine = line || ""
      engineCommand.command = [root.enginePath].concat(argv)
      engineCommand.running = true
      watchdog.restart()
    }

    function completeWhenReady() {
      if (!engineCommand.replyReceived || !engineCommand.exitReceived) return
      watchdog.stop()
      var text = engineCommand.reply
      engineCommand.reply = ""
      engineCommand.completed(text, engineCommand.exitStatus)
    }

    stdinEnabled: true
    onStarted: {
      engineCommand.write(engineCommand.stdinLine + "\n")
      engineCommand.stdinLine = ""
    }
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        engineCommand.reply = text
        engineCommand.replyReceived = true
        engineCommand.completeWhenReady()
      }
    }
    onExited: function(code) {
      engineCommand.exitStatus = code
      engineCommand.exitReceived = true
      engineCommand.completeWhenReady()
    }

    property Timer watchdog: Timer {
      interval: engineCommand.timeoutMs
      onTriggered: {
        engineCommand.stdinLine = ""
        engineCommand.running = false
        engineCommand.timedOut()
      }
    }
  }

  EngineCommand {
    id: statusCommand
    timeoutMs: 5000
    onCompleted: function(reply, exitStatus) { root.applyStatus(reply, exitStatus) }
    onTimedOut: root.applyTimeout(statusCommand)
  }

  EngineCommand {
    id: listCommand
    onCompleted: function(reply, exitStatus) { root.applyListing(reply) }
    onTimedOut: root.applyTimeout(listCommand)
  }

  EngineCommand {
    id: unlockCommand
    timeoutMs: 60000
    onCompleted: function(reply, exitStatus) { root.applyUnlockReply(reply) }
    onTimedOut: root.applyTimeout(unlockCommand)
  }

  EngineCommand {
    id: lockCommand
  }

  EngineCommand {
    id: secretCopyCommand
    onCompleted: function(reply, exitStatus) { root.applySecretCopyReply(reply, exitStatus) }
    onTimedOut: root.applyTimeout(secretCopyCommand)
  }

  EngineCommand {
    id: sequenceCommand
    onCompleted: function(reply, exitStatus) { root.applySecretCopyReply(reply, exitStatus) }
    onTimedOut: root.applyTimeout(sequenceCommand)
  }

  EngineCommand {
    id: usernameCopyCommand
    onCompleted: function(reply, exitStatus) { root.applyUsernameCopyExit(exitStatus) }
    onTimedOut: root.applyTimeout(usernameCopyCommand)
  }

  // --- bar icon and dropdown -----------------------------------------------

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: root.showCopied ? root.copiedGlyph : root.lockGlyph
    tooltipText: "Bitwarden"
    onPressed: function(mouseButton) {
      if (mouseButton === Qt.RightButton) root.openOverlay()
      else if (mouseButton === Qt.LeftButton) root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: panel.loadedContent
    contentWidth: panel.fittedContentWidth(380)
    contentHeight: panel.fittedContentHeight(panel.loadedContentHeight, 560)
    // `visible` stays true through the fade-out and drops when it ends.
    onVisibleChanged: if (!visible && !root.opened) root.forgetInput()

    content: Components.QuickAccessView {
      anchors.fill: parent
      view: root.view
      vaultItems: root.vaultItems
      busy: root.busy
      errorText: root.errorText
      confirmationText: root.confirmationText
      fontFamily: root.fontFamily
      onCopyRequested: function(item, kind, closeAfter) { root.copy(item, kind, closeAfter) }
      onSequenceRequested: function(item) { root.copySequence(item) }
      onUnlockRequested: function(password) { root.unlock(password) }
      onOpenOverlayRequested: root.openOverlay()
      onLockRequested: root.lockVault()
      onRetryRequested: root.refresh()
      onCloseRequested: root.close()
    }
  }
}

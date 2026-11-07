import QtQuick
import "lib"
import "../components" as Components
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// SecretReleaseController against a recording command runner: nothing is
// released without an explicit action, argv carries only the item id and the
// field identifier, revealed values are dropped on selection change, reveal
// toggle off, deactivation (overlay hidden, lock, logout) and timeout, a
// revealed TOTP refreshes at most once per period and stops when deselected
// or inactive, and refusals map to the contract's error codes.
Item {
  id: testRunner
  width: 200
  height: 100

  readonly property string loginId: "login-1"
  readonly property string otherId: "login-2"
  readonly property string password: "Correct-Horse-Battery-1"

  property var commands: []
  property var copies: []
  property var refusals: []
  property int historyConcealments: 0

  Components.SecretReleaseController {
    id: controller
    helperPath: "/usr/bin/omawarden"
    active: true
    itemId: testRunner.loginId
    clipboardClearSeconds: 30
    revealDurationMs: 400
    totpRevealDurationMs: 3000
    totpCountdownIntervalMs: 50
    repeatedCopyIntervalMs: 300
    onCommandRequested: function(argv) { testRunner.commands = testRunner.commands.concat([argv]) }
    onCopyConfirmed: function(label, seconds) { testRunner.copies = testRunner.copies.concat([{ label: label, seconds: seconds }]) }
    onReleaseRefused: function(code, message) { testRunner.refusals = testRunner.refusals.concat([{ code: code, message: message }]) }
    onPasswordHistoryConcealed: testRunner.historyConcealments++
  }

  function lastCommand() {
    return commands.length > 0 ? commands[commands.length - 1] : []
  }

  function reply(payload, exitCode) {
    controller.handleCommandOutput(JSON.stringify(payload))
    controller.handleCommandExit(exitCode === undefined ? 0 : exitCode)
  }

  function revealReply(id, field, value) {
    reply({ ok: true, id: id, field: field, value: value })
  }

  function totpReply(id, code, secondsRemaining) {
    reply({ ok: true, id: id, field: SecretFieldCatalog.LOGIN_TOTP, value: code, seconds_remaining: secondsRemaining, period: 30 })
  }

  function argvContains(argv, text) {
    return argv.some(function(argument) { return String(argument).indexOf(text) !== -1 })
  }

  function resetState() {
    controller.active = false
    controller.active = true
    controller.itemId = loginId
    commands = []
    copies = []
    refusals = []
    historyConcealments = 0
  }

  // ---- Steps ----

  function testNoReleaseWithoutAction() {
    controller.itemId = otherId
    controller.itemId = loginId
    Assert.check(commands.length === 0, "selecting items issues no command")
    controller.active = false
    controller.active = true
    Assert.check(commands.length === 0, "activating issues no command")
  }

  function testRevealArgumentsAndStorage() {
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    Assert.check(commands.length === 1, "reveal issues one command")
    var argv = lastCommand()
    Assert.check(JSON.stringify(argv) === JSON.stringify(["/usr/bin/omawarden", "vault", "reveal", "--id=login-1", "--field=login.password"]), "reveal argv carries only the id and the field: " + JSON.stringify(argv))
    Assert.check(controller.isPending(SecretFieldCatalog.LOGIN_PASSWORD), "field is pending until the reply arrives")
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    Assert.check(commands.length === 1, "a second reveal of a pending field is not sent")
    revealReply(loginId, SecretFieldCatalog.LOGIN_PASSWORD, password)
    Assert.check(controller.revealedValue(SecretFieldCatalog.LOGIN_PASSWORD) === password, "revealed value stored")
    Assert.check(!controller.busy, "controller idle after reply")
  }

  function testRevealToggleOffClears() {
    controller.toggleReveal(SecretFieldCatalog.LOGIN_PASSWORD)
    Assert.check(!controller.isRevealed(SecretFieldCatalog.LOGIN_PASSWORD), "toggle off drops the revealed value")
    Assert.check(Object.keys(controller.revealedValues).length === 0, "no revealed values remain after toggle off")
  }

  function testSelectionChangeClearsAndIgnoresStaleReply() {
    controller.reveal(SecretFieldCatalog.NOTES)
    revealReply(loginId, SecretFieldCatalog.NOTES, "private notes")
    Assert.check(controller.isRevealed(SecretFieldCatalog.NOTES), "notes revealed")
    controller.itemId = otherId
    Assert.check(Object.keys(controller.revealedValues).length === 0, "selection change drops revealed values")

    controller.itemId = loginId
    controller.reveal(SecretFieldCatalog.CARD_CODE)
    controller.itemId = otherId
    revealReply(loginId, SecretFieldCatalog.CARD_CODE, "123")
    Assert.check(!controller.isRevealed(SecretFieldCatalog.CARD_CODE), "a reply that arrives after a selection change is discarded")
    controller.itemId = loginId
  }

  // A failure that arrives after a selection change belongs to the previous
  // item: it must not cancel the new item's pending reveal of the same field
  // or show its error over the new item. A failure that locked the vault is
  // still reported.
  function testStaleFailureIgnored() {
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    controller.itemId = otherId
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    Assert.check(controller.isPending(SecretFieldCatalog.LOGIN_PASSWORD), "the new item's reveal is pending behind the previous item's")
    refusals = []
    reply({ ok: false, error: "engine text", error_code: "item_not_found" }, 1)
    Assert.check(refusals.length === 0, "a stale failure of the previous item shows no error")
    Assert.check(controller.isPending(SecretFieldCatalog.LOGIN_PASSWORD), "a stale failure does not cancel the new item's pending reveal")
    Assert.check(argvContains(lastCommand(), "--id=" + otherId), "the new item's reveal is dispatched next")
    revealReply(otherId, SecretFieldCatalog.LOGIN_PASSWORD, "other-password")
    Assert.check(controller.revealedValue(SecretFieldCatalog.LOGIN_PASSWORD) === "other-password", "the new item's reveal completes")

    controller.itemId = loginId
    controller.reveal(SecretFieldCatalog.NOTES)
    controller.itemId = otherId
    reply({ ok: false, error: "engine text", error_code: "vault_locked" }, 1)
    Assert.check(refusals.length === 1 && refusals[0].code === "vault_locked", "a stale failure that reports a locked vault is still reported")
    controller.itemId = loginId
  }

  function testDeactivationClears() {
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    revealReply(loginId, SecretFieldCatalog.LOGIN_PASSWORD, password)
    controller.reveal(SecretFieldCatalog.NOTES)
    Assert.check(controller.busy, "notes reveal in flight")
    controller.active = false
    Assert.check(Object.keys(controller.revealedValues).length === 0, "deactivation (hide, lock, logout) drops revealed values")
    Assert.check(Object.keys(controller.requestedFields).length === 0, "deactivation drops pending reveals")
    revealReply(loginId, SecretFieldCatalog.NOTES, "late notes")
    Assert.check(!controller.isRevealed(SecretFieldCatalog.NOTES), "a reply after deactivation is discarded")
    var before = commands.length
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    controller.copyField(SecretFieldCatalog.LOGIN_PASSWORD, "password")
    Assert.check(commands.length === before, "an inactive controller releases nothing")
    controller.active = true
  }

  function testCopyArgumentsAndRepeatGuard() {
    controller.copyField(SecretFieldCatalog.NOTES, "notes")
    var argv = lastCommand()
    Assert.check(JSON.stringify(argv) === JSON.stringify(["/usr/bin/omawarden", "vault", "copy-field", "--id=login-1", "--field=notes", "--clear-after=30"]), "copy argv: " + JSON.stringify(argv))
    Assert.check(!argvContains(argv, password), "copy argv carries no secret")
    reply({ ok: true, id: loginId, field: "notes", copied: true, clear_after_seconds: 30 })
    Assert.check(copies.length === 1 && copies[0].label === "notes" && copies[0].seconds === 30, "copy confirmed with the clear-after seconds")
    Assert.check(Object.keys(controller.revealedValues).length === 0, "copy reveals nothing")
    var before = commands.length
    controller.copyField(SecretFieldCatalog.NOTES, "notes")
    Assert.check(commands.length === before, "a repeated copy within the repeat interval is ignored")
  }

  function testExitBeforeOutputOrdering() {
    controller.reveal(SecretFieldCatalog.CARD_NUMBER)
    controller.handleCommandExit(0)
    Assert.check(controller.busy, "exit alone does not complete the request")
    controller.handleCommandOutput(JSON.stringify({ ok: true, id: loginId, field: SecretFieldCatalog.CARD_NUMBER, value: "4111111111111111" }))
    Assert.check(controller.revealedValue(SecretFieldCatalog.CARD_NUMBER) === "4111111111111111", "exit then output completes the reveal")
  }

  function testReleaseLimitExceeded() {
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    reply({ ok: false, error: "Too many secrets were requested (more than 30 within 60 seconds). The vault has been locked.", error_code: "release_limit_exceeded" }, 1)
    Assert.check(refusals.length === 1 && refusals[0].code === "release_limit_exceeded", "release_limit_exceeded reported with its code")
    Assert.check(refusals[0].message.indexOf("locked as a precaution") !== -1, "release_limit_exceeded explains the precautionary lock: " + refusals[0].message)
    Assert.check(SecretFieldCatalog.errorLocksVault(refusals[0].code), "release_limit_exceeded returns the overlay to the unlock view")
    Assert.check(!controller.isPending(SecretFieldCatalog.LOGIN_PASSWORD), "refused reveal is no longer pending")
  }

  function testErrorMessages() {
    var cases = [
      ["vault_locked", "vault is locked", true],
      ["item_not_found", "no longer in the vault", false],
      ["field_empty", "no value for that field", false],
      ["unknown_field", "does not support this field", false],
      ["clipboard_failed", "wl-clipboard", false]
    ]
    cases.forEach(function(entry) {
      refusals = []
      controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
      reply({ ok: false, error: "engine text", error_code: entry[0] }, 1)
      Assert.check(refusals.length === 1 && refusals[0].message.indexOf(entry[1]) !== -1, entry[0] + " has a specific message: " + (refusals[0] ? refusals[0].message : "none"))
      Assert.check(SecretFieldCatalog.errorLocksVault(entry[0]) === entry[2], entry[0] + (entry[2] ? " returns to the unlock view" : " keeps the vault view"))
    })
    refusals = []
    controller.reveal(SecretFieldCatalog.IDENTITY_SSN)
    reply({ ok: false, error: "An engine message without a code" }, 1)
    Assert.check(refusals.length === 1 && refusals[0].message === "An engine message without a code", "an uncoded error shows the engine message")
    refusals = []
    controller.reveal(SecretFieldCatalog.IDENTITY_SSN)
    controller.handleCommandOutput("")
    controller.handleCommandExit(2)
    Assert.check(refusals.length === 1 && refusals[0].message.indexOf("exited with code 2") !== -1, "empty output with a failing exit is reported")
  }

  function testPasswordHistory() {
    controller.reveal(SecretFieldCatalog.PASSWORD_HISTORY)
    Assert.check(controller.passwordHistory === null, "history is null until the reply arrives")
    revealReply(loginId, SecretFieldCatalog.PASSWORD_HISTORY, [{ password: "old-1", last_used_date: "2024-01-01T00:00:00Z" }])
    Assert.check(controller.passwordHistory && controller.passwordHistory.length === 1 && controller.passwordHistory[0].password === "old-1", "history entries stored")
    controller.conceal(SecretFieldCatalog.PASSWORD_HISTORY)
    Assert.check(controller.passwordHistory === null && historyConcealments === 1, "concealing history notifies the owner once")
  }

  function startExpiryCheck() {
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    revealReply(loginId, SecretFieldCatalog.LOGIN_PASSWORD, password)
  }

  // Each field is dropped revealDurationMs (400 ms here) after its own
  // reveal; a later reveal of another field does not extend it.
  function revealSecondFieldLater() {
    Assert.check(controller.isRevealed(SecretFieldCatalog.LOGIN_PASSWORD), "password still shown before its reveal duration")
    controller.reveal(SecretFieldCatalog.NOTES)
    revealReply(loginId, SecretFieldCatalog.NOTES, "private notes")
  }

  function checkFirstFieldExpiredOnItsOwnTime() {
    Assert.check(!controller.isRevealed(SecretFieldCatalog.LOGIN_PASSWORD), "password dropped on its own reveal time, although notes were revealed later")
    Assert.check(controller.isRevealed(SecretFieldCatalog.NOTES), "notes stay shown until their own reveal duration")
  }

  function startTotpCheck() {
    commands = []
    controller.reveal(SecretFieldCatalog.LOGIN_TOTP)
    Assert.check(commands.length === 1 && argvContains(lastCommand(), "--field=login.totp"), "TOTP reveal requested once")
    totpReply(loginId, "123456", 1)
    Assert.check(controller.totpCode === "123456" && controller.totpSecondsRemaining === 1, "TOTP code and seconds remaining stored")
  }

  function checkTotpRefreshedOnce() {
    Assert.check(commands.length === 2, "exactly one refresh at the period boundary (" + commands.length + " commands)")
    totpReply(loginId, "654321", 30)
    Assert.check(controller.totpCode === "654321" && controller.totpSecondsRemaining === 30, "refreshed TOTP code stored")
  }

  function stopTotpByDeselection() {
    controller.itemId = otherId
    Assert.check(controller.totpCode === "" && controller.totpRevealDeadline === 0, "deselecting drops the TOTP code and stops the countdown")
    controller.itemId = loginId
    controller.reveal(SecretFieldCatalog.LOGIN_TOTP)
    totpReply(loginId, "111111", 1)
    controller.active = false
    Assert.check(controller.totpCode === "", "hiding the overlay drops the TOTP code")
    controller.active = true
    commands = []
  }

  property int stepIndex: 0
  property real waitStartedAt: 0
  readonly property var steps: [
    { run: testNoReleaseWithoutAction },
    { run: testRevealArgumentsAndStorage },
    { run: testRevealToggleOffClears },
    { run: testSelectionChangeClearsAndIgnoresStaleReply },
    { run: testStaleFailureIgnored },
    { run: testDeactivationClears },
    { run: testCopyArgumentsAndRepeatGuard },
    { run: testExitBeforeOutputOrdering },
    { run: resetState },
    { run: testReleaseLimitExceeded },
    { run: testErrorMessages },
    { run: testPasswordHistory },
    { run: resetState },
    { run: startExpiryCheck },
    { waitMs: 250, run: revealSecondFieldLater },
    { waitMs: 250, run: checkFirstFieldExpiredOnItsOwnTime },
    { waitMs: 300, run: function() { Assert.check(!controller.isRevealed(SecretFieldCatalog.NOTES) && Object.keys(controller.revealExpiresAt).length === 0, "notes dropped after their own reveal duration") } },
    { run: startTotpCheck },
    { waitMs: 1600, run: checkTotpRefreshedOnce },
    { waitMs: 600, run: function() { Assert.check(commands.length === 2, "no further TOTP release within the period") } },
    { run: stopTotpByDeselection },
    { waitMs: 1600, run: function() { Assert.check(commands.length === 0, "no TOTP refresh after deselection or hiding") } }
  ]

  Timer {
    interval: 25
    repeat: true
    running: true
    onTriggered: {
      if (testRunner.stepIndex >= testRunner.steps.length) {
        stop()
        Qt.exit(Assert.exitCode())
        return
      }
      var step = testRunner.steps[testRunner.stepIndex]
      if (step.waitMs) {
        if (testRunner.waitStartedAt === 0) testRunner.waitStartedAt = Date.now()
        if (Date.now() - testRunner.waitStartedAt < step.waitMs) return
        testRunner.waitStartedAt = 0
      }
      step.run()
      testRunner.stepIndex++
    }
  }

  Component.onCompleted: console.log("Running SecretReleaseController tests...")
}

import QtQuick
import "lib"
import "../components" as Components
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// Automatic TOTP refreshes are budgeted releases: more than 30 releases
// within 60 s hard-lock the vault. Time is compressed (one second lasts
// secondDurationMs) so the whole 120-second reveal window runs in a few
// hundred milliseconds. A period shorter than the minimum automatic refresh
// interval is never refreshed automatically, and no automatic refresh comes
// sooner than that interval after the previous one, whatever the engine
// reports as `seconds_remaining`.
Item {
  id: testRunner
  width: 200
  height: 100

  readonly property string loginId: "login-1"
  readonly property int secondDurationMs: 20
  readonly property int revealWindowSeconds: 120
  readonly property int revealWindowMs: revealWindowSeconds * secondDurationMs

  // Reply the engine stub gives to every TOTP release.
  property int replyPeriod: 30
  property int replySecondsRemaining: 30
  property int releases: 0
  // Controller state captured as soon as a reply is applied: a 1 s code
  // expires within one compressed second, before the next step runs.
  property string shownCode: ""
  property int shownSecondsRemaining: 0
  property real scheduledRefreshAt: -1

  Components.SecretReleaseController {
    id: controller
    helperPath: "/usr/bin/omawarden"
    active: true
    itemId: testRunner.loginId
    secondDurationMs: testRunner.secondDurationMs
    totpRevealDurationMs: testRunner.revealWindowMs
    totpCountdownIntervalMs: 5
    onCommandRequested: function(argv) {
      testRunner.releases++
      Qt.callLater(testRunner.replyToTotpRelease)
    }
  }

  function replyToTotpRelease() {
    controller.handleCommandOutput(JSON.stringify({
      ok: true,
      id: testRunner.loginId,
      field: SecretFieldCatalog.LOGIN_TOTP,
      value: "123456",
      seconds_remaining: testRunner.replySecondsRemaining,
      period: testRunner.replyPeriod
    }))
    controller.handleCommandExit(0)
    testRunner.shownCode = controller.totpCode
    testRunner.shownSecondsRemaining = controller.totpSecondsRemaining
    testRunner.scheduledRefreshAt = controller.totpNextRefreshAt
  }

  function startScenario(period, secondsRemaining) {
    controller.conceal(SecretFieldCatalog.LOGIN_TOTP)
    testRunner.replyPeriod = period
    testRunner.replySecondsRemaining = secondsRemaining
    testRunner.releases = 0
    testRunner.shownCode = ""
    testRunner.shownSecondsRemaining = 0
    testRunner.scheduledRefreshAt = -1
    controller.reveal(SecretFieldCatalog.LOGIN_TOTP)
  }

  // Upper bound for a period at or above the minimum interval: the explicit
  // reveal, plus at most one automatic refresh per minimum interval.
  function automaticRefreshBound() {
    return 1 + Math.floor(testRunner.revealWindowSeconds / controller.minimumAutomaticTotpRefreshSeconds)
  }

  function checkShortPeriodShown(period) {
    Assert.check(testRunner.shownCode === "123456" && testRunner.shownSecondsRemaining === period, "period " + period + ": the code is shown with its countdown (" + testRunner.shownSecondsRemaining + " s)")
    Assert.check(testRunner.scheduledRefreshAt === 0, "period " + period + ": no automatic refresh is scheduled")
    Assert.check(testRunner.releases === 1, "period " + period + ": the explicit reveal is the only release so far (" + testRunner.releases + ")")
  }

  function checkShortPeriodWindow(period) {
    Assert.check(testRunner.releases === 1, "period " + period + ": one release over the whole 120 s reveal window (" + testRunner.releases + ")")
    Assert.check(!controller.isRevealed(SecretFieldCatalog.LOGIN_TOTP), "period " + period + ": the expired code is dropped")
    Assert.check(!controller.isPending(SecretFieldCatalog.LOGIN_TOTP) && controller.requestedFields[SecretFieldCatalog.LOGIN_TOTP] !== true, "period " + period + ": the field is concealed, so the next press reveals it again")
    controller.toggleReveal(SecretFieldCatalog.LOGIN_TOTP)
    Assert.check(testRunner.releases === 2, "period " + period + ": the user reveals the code again explicitly")
  }

  property int stepIndex: 0
  property real waitStartedAt: 0
  readonly property var steps: [
    { run: function() {
      Assert.check(controller.minimumAutomaticTotpRefreshSeconds === 15, "the minimum automatic refresh interval is 15 s")
      startScenario(1, 1)
    } },
    { waitMs: 10, run: function() { checkShortPeriodShown(1) } },
    { waitMs: revealWindowMs + 200, run: function() { checkShortPeriodWindow(1) } },
    { run: function() { startScenario(2, 2) } },
    { waitMs: 10, run: function() { checkShortPeriodShown(2) } },
    { waitMs: revealWindowMs + 200, run: function() { checkShortPeriodWindow(2) } },
    // The engine reports one second remaining on every reply: without the
    // minimum interval this would refresh every second.
    { run: function() { startScenario(15, 1) } },
    { waitMs: revealWindowMs + 200, run: function() {
      Assert.check(testRunner.releases >= 2, "period 15: automatic refresh still runs (" + testRunner.releases + " releases)")
      Assert.check(testRunner.releases <= automaticRefreshBound(), "period 15: at most " + automaticRefreshBound() + " releases over the 120 s reveal window (" + testRunner.releases + ")")
      Assert.check(!controller.isRevealed(SecretFieldCatalog.LOGIN_TOTP), "period 15: the code is dropped at the end of the reveal window")
    } },
    { run: function() { startScenario(30, 1) } },
    { waitMs: revealWindowMs + 200, run: function() {
      Assert.check(testRunner.releases <= automaticRefreshBound(), "period 30: at most " + automaticRefreshBound() + " releases over the 120 s reveal window (" + testRunner.releases + ")")
    } }
  ]

  Timer {
    interval: 5
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

  Component.onCompleted: console.log("Running TOTP refresh budget tests...")
}

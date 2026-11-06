import QtQuick
import "lib"
import "../components" as Components
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// A release command that does not answer in time is reported as timed out,
// the owner is asked to stop it (then to kill it), its late output is
// ignored, and the next command is requested only after it has exited. A
// reply that names another item or field is never confirmed or stored.
Item {
  id: testRunner
  width: 200
  height: 100

  readonly property string firstId: "login-1"
  readonly property string secondId: "login-2"
  readonly property int timeoutMs: 150

  property var commands: []
  property var copies: []
  property var refusals: []
  property var stopRequests: []

  Components.SecretReleaseController {
    id: controller
    helperPath: "/usr/bin/omawarden"
    active: true
    itemId: testRunner.firstId
    commandTimeoutMs: testRunner.timeoutMs
    repeatedCopyIntervalMs: 0
    onCommandRequested: function(argv) { testRunner.commands = testRunner.commands.concat([argv]) }
    onCommandStopRequested: function(forceful) { testRunner.stopRequests = testRunner.stopRequests.concat([forceful]) }
    onCopyConfirmed: function(label, seconds) { testRunner.copies = testRunner.copies.concat([label]) }
    onReleaseRefused: function(code, message) { testRunner.refusals = testRunner.refusals.concat([message]) }
  }

  function copyReply(id, field) {
    return JSON.stringify({ ok: true, id: id, field: field, copied: true, clear_after_seconds: 30 })
  }

  function startStalledCopy() {
    controller.copyField(SecretFieldCatalog.NOTES, "notes")
    Assert.check(commands.length === 1, "the first copy is requested")
  }

  function checkTimeoutReported() {
    Assert.check(stopRequests.length === 1 && stopRequests[0] === false, "a timed-out command is stopped (" + JSON.stringify(stopRequests) + ")")
    Assert.check(refusals.length === 1 && refusals[0].indexOf("did not respond in time") !== -1, "the timeout is reported to the user")
    Assert.check(controller.busy, "the slot stays taken until the stopped process exits")
    controller.itemId = secondId
    controller.copyField(SecretFieldCatalog.LOGIN_PASSWORD, "password")
    Assert.check(commands.length === 1, "the next copy waits for the stopped process to exit")
    controller.handleCommandOutput(copyReply(firstId, SecretFieldCatalog.NOTES))
    Assert.check(copies.length === 0, "late output of the abandoned command is not confirmed as any copy")
  }

  function checkForcefulStopThenExit() {
    Assert.check(stopRequests.length === 2 && stopRequests[1] === true, "a process that does not exit is stopped forcefully (" + JSON.stringify(stopRequests) + ")")
    Assert.check(commands.length === 1, "still no new command before the exit")
    controller.handleCommandExit(-1)
    Assert.check(commands.length === 2, "the queued copy is requested once the stopped process has exited")
    var argv = commands[1]
    Assert.check(argv.indexOf("--id=" + secondId) !== -1 && argv.indexOf("--field=login.password") !== -1, "the queued copy carries its own id and field")
    Assert.check(refusals.length === 1, "the exit of an abandoned command reports nothing further")
  }

  function checkMismatchedCopyRefused() {
    controller.handleCommandOutput(copyReply(firstId, SecretFieldCatalog.NOTES))
    controller.handleCommandExit(0)
    Assert.check(copies.length === 0, "a copy reply for another item and field is not confirmed")
    Assert.check(refusals.length === 2 && refusals[1].indexOf("different request") !== -1, "the mismatched reply is reported")
    Assert.check(!controller.busy, "the controller is idle after the mismatched reply")
  }

  function checkMismatchedRevealRefused() {
    refusals = []
    controller.reveal(SecretFieldCatalog.LOGIN_PASSWORD)
    controller.handleCommandOutput(JSON.stringify({ ok: true, id: firstId, field: SecretFieldCatalog.LOGIN_PASSWORD, value: "first-password" }))
    controller.handleCommandExit(0)
    Assert.check(!controller.isRevealed(SecretFieldCatalog.LOGIN_PASSWORD), "a reveal reply for another item is not stored")
    Assert.check(!controller.isPending(SecretFieldCatalog.LOGIN_PASSWORD), "the field does not stay pending after a mismatched reply")
    Assert.check(refusals.length === 1, "the mismatched reveal reply is reported")
  }

  function checkMatchingCopyConfirmed() {
    controller.copyField(SecretFieldCatalog.LOGIN_PASSWORD, "password")
    controller.handleCommandOutput(copyReply(secondId, SecretFieldCatalog.LOGIN_PASSWORD))
    controller.handleCommandExit(0)
    Assert.check(copies.length === 1 && copies[0] === "password", "a reply for the requested id and field is confirmed")
  }

  property int stepIndex: 0
  property real waitStartedAt: 0
  readonly property var steps: [
    { run: startStalledCopy },
    { waitMs: timeoutMs + 60, run: checkTimeoutReported },
    { waitMs: timeoutMs + 60, run: checkForcefulStopThenExit },
    { run: checkMismatchedCopyRefused },
    { run: checkMismatchedRevealRefused },
    { run: checkMatchingCopyConfirmed }
  ]

  Timer {
    interval: 10
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

  Component.onCompleted: console.log("Running secret release timeout tests...")
}

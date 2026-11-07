import QtQuick
import qs.Commons as Commons
import "./SecretFieldCatalog.js" as SecretFieldCatalog

// Releases item secrets one field at a time through the omawarden CLI
// (contracts.md section 3) and holds a revealed value only while it is shown.
//
// Nothing is released automatically: reveal() and copyField() run only on an
// explicit user action. Every revealed value is dropped when the selected item
// changes, when the controller becomes inactive (overlay hidden, vault locked,
// logout, another view) and after revealDurationMs. A revealed TOTP code is
// refreshed automatically at most once per period, at the period boundary
// reported by `seconds_remaining`, never sooner than
// minimumAutomaticTotpRefreshSeconds after the previous automatic refresh,
// and is dropped after totpRevealDurationMs. A code whose period is shorter
// than that minimum is never refreshed automatically: it is shown with its
// countdown, dropped when it expires, and revealed again only by the user.
//
// The controller never starts a process itself: it emits commandRequested()
// with the argv, and the owner feeds the output back through
// handleCommandOutput() and handleCommandExit(). One command runs at a time:
// the next one is requested only after the previous process has exited. A
// command that does not answer within commandTimeoutMs is reported as timed
// out and abandoned: the owner is asked to stop it (commandStopRequested),
// its output is ignored, and the slot stays taken until it exits. A reply is
// accepted only for the item id and field it was requested for.
Item {
  id: controller
  visible: false

  property string helperPath: "omawarden"
  property bool active: false
  property string itemId: ""
  property int clipboardClearSeconds: 30

  // Durations are named defaults; the suites shorten them.
  property int revealDurationMs: 30000
  property int totpRevealDurationMs: 120000
  property int totpCountdownIntervalMs: 1000
  property int repeatedCopyIntervalMs: 1000
  property int commandTimeoutMs: 15000
  readonly property int maximumQueuedRequests: 4
  readonly property int defaultTotpPeriodSeconds: 30
  // Automatic TOTP refreshes are budgeted releases (contracts.md 3.5); a
  // period of 1 s would otherwise exhaust the budget within half a minute.
  readonly property int minimumAutomaticTotpRefreshSeconds: 15
  // Length of one second in milliseconds; a suite shortens it to compress time.
  property int secondDurationMs: 1000

  // field identifier -> revealed value (string; an array for password_history)
  property var revealedValues: ({})
  // field identifier -> true while a reveal has been asked for and not concealed
  property var requestedFields: ({})
  // field identifier -> time its revealed value is dropped, revealDurationMs
  // after that field's own reveal (the TOTP code has its own deadline)
  property var revealExpiresAt: ({})
  property int totpSecondsRemaining: 0
  property int totpPeriod: defaultTotpPeriodSeconds
  property real totpRevealDeadline: 0
  // When the shown code expires; 0 while no code is shown or a refresh is in flight.
  property real totpCodeExpiresAt: 0
  // When the next automatic refresh is due; 0 when none is scheduled.
  property real totpNextRefreshAt: 0
  property real totpLastAutomaticRefreshAt: 0

  property var pendingRequests: []
  property var activeRequest: null
  property int revealGeneration: 0
  property var lastCopyTimes: ({})

  readonly property string totpCode: revealedValue(SecretFieldCatalog.LOGIN_TOTP)
  readonly property var passwordHistory: isRevealed(SecretFieldCatalog.PASSWORD_HISTORY) ? revealedValues[SecretFieldCatalog.PASSWORD_HISTORY] : null
  readonly property bool busy: activeRequest !== null

  signal commandRequested(var argv)
  // forceful: the process did not exit after the first stop request.
  signal commandStopRequested(bool forceful)
  signal copyConfirmed(string label, int clearSeconds)
  signal releaseRefused(string errorCode, string message)
  signal passwordHistoryConcealed()

  Commons.Translations {
    id: strings
    directory: Qt.resolvedUrl("../i18n")
  }

  onActiveChanged: {
    if (!controller.active) controller.reset()
  }
  onItemIdChanged: controller.concealAll()

  // Runs until the earliest entry of revealExpiresAt.
  Timer {
    id: revealExpiry
    repeat: false
    onTriggered: controller.concealExpiredValues()
  }

  Timer {
    id: totpCountdown
    interval: controller.totpCountdownIntervalMs
    repeat: true
    running: controller.active && controller.totpRevealDeadline > 0
    onTriggered: controller.advanceTotpCountdown()
  }

  Timer {
    id: commandWatchdog
    interval: controller.commandTimeoutMs
    repeat: false
    onTriggered: controller.abandonActiveRequest()
  }

  // ---- Queries -------------------------------------------------------------

  function isRevealed(field) {
    return Object.prototype.hasOwnProperty.call(controller.revealedValues, field)
  }

  function revealedValue(field) {
    return controller.isRevealed(field) ? String(controller.revealedValues[field]) : ""
  }

  // A reveal was asked for and its value has not arrived yet.
  function isPending(field) {
    return controller.requestedFields[field] === true && !controller.isRevealed(field)
  }

  function hasRequestedValues() {
    return Object.keys(controller.requestedFields).length > 0
  }

  // ---- User actions --------------------------------------------------------

  function reveal(field) {
    if (!field || controller.requestedFields[field] === true) return
    var request = { kind: "reveal", field: field, itemId: controller.itemId }
    if (!controller.canEnqueue(request)) return
    // Marked before dispatch: a reply is only accepted for a requested field.
    controller.markRequested(field)
    if (field === SecretFieldCatalog.LOGIN_TOTP) {
      controller.totpRevealDeadline = Date.now() + controller.totpRevealDurationMs
    }
    controller.enqueue(request)
  }

  function toggleReveal(field) {
    if (controller.requestedFields[field] === true) controller.conceal(field)
    else controller.reveal(field)
  }

  function copyField(field, label) {
    if (!field || !controller.copyIntervalElapsed(field)) return
    var request = { kind: "copy", field: field, itemId: controller.itemId, label: label || field }
    if (!controller.enqueue(request)) return
    var times = Object.assign({}, controller.lastCopyTimes)
    times[controller.copyKey(field)] = Date.now()
    controller.lastCopyTimes = times
  }

  function conceal(field) {
    var wasRequested = controller.requestedFields[field] === true || controller.isRevealed(field)
    controller.forgetField(field)
    if (field === SecretFieldCatalog.LOGIN_TOTP) controller.resetTotpTiming()
    if (field === SecretFieldCatalog.PASSWORD_HISTORY && wasRequested) controller.passwordHistoryConcealed()
  }

  // Drops every revealed value of the current item, and ignores replies to
  // reveals that are still queued or running.
  function concealAll() {
    controller.revealGeneration++
    var fields = Object.keys(controller.requestedFields).concat(Object.keys(controller.revealedValues))
    fields.forEach(function(field) { controller.conceal(field) })
    controller.pendingRequests = controller.pendingRequests.filter(function(request) {
      return request.kind !== "reveal"
    })
    revealExpiry.stop()
  }

  // Inactive: nothing revealed, nothing queued.
  function reset() {
    controller.concealAll()
    controller.pendingRequests = []
    controller.lastCopyTimes = ({})
  }

  // ---- Process wiring ------------------------------------------------------

  // Output of an abandoned command is never read.
  function handleCommandOutput(text) {
    var request = controller.activeRequest
    if (!request || request.abandoned) return
    request.output = String(text || "")
    controller.completeActiveRequest()
  }

  function handleCommandExit(exitCode) {
    var request = controller.activeRequest
    if (!request) return
    request.exitCode = exitCode
    if (request.abandoned) controller.retireAbandonedRequest()
    else controller.completeActiveRequest()
  }

  // ---- Internals -----------------------------------------------------------

  function copyKey(field) {
    return controller.itemId + "\n" + field
  }

  function copyIntervalElapsed(field) {
    var last = controller.lastCopyTimes[controller.copyKey(field)] || 0
    return Date.now() - last >= controller.repeatedCopyIntervalMs
  }

  function markRequested(field) {
    var requested = Object.assign({}, controller.requestedFields)
    requested[field] = true
    controller.requestedFields = requested
  }

  function forgetField(field) {
    var requested = Object.assign({}, controller.requestedFields)
    var values = Object.assign({}, controller.revealedValues)
    var expiries = Object.assign({}, controller.revealExpiresAt)
    delete requested[field]
    delete values[field]
    delete expiries[field]
    controller.requestedFields = requested
    controller.revealedValues = values
    controller.revealExpiresAt = expiries
  }

  function resetTotpTiming() {
    controller.totpRevealDeadline = 0
    controller.totpCodeExpiresAt = 0
    controller.totpNextRefreshAt = 0
    controller.totpLastAutomaticRefreshAt = 0
    controller.totpSecondsRemaining = 0
  }

  function scheduleRevealExpiry(field) {
    var expiries = Object.assign({}, controller.revealExpiresAt)
    expiries[field] = Date.now() + controller.revealDurationMs
    controller.revealExpiresAt = expiries
    controller.restartRevealExpiry()
  }

  function restartRevealExpiry() {
    var expiries = controller.revealExpiresAt
    var times = Object.keys(expiries).map(function(field) { return expiries[field] })
    if (times.length === 0) {
      revealExpiry.stop()
      return
    }
    revealExpiry.interval = Math.max(1, Math.min.apply(null, times) - Date.now())
    revealExpiry.restart()
  }

  // Drops each value whose own reveal duration has elapsed.
  function concealExpiredValues() {
    var now = Date.now()
    var expiries = controller.revealExpiresAt
    Object.keys(expiries).filter(function(field) { return expiries[field] <= now })
      .forEach(function(field) { controller.conceal(field) })
    controller.restartRevealExpiry()
  }

  function advanceTotpCountdown() {
    var now = Date.now()
    if (now >= controller.totpRevealDeadline) {
      controller.conceal(SecretFieldCatalog.LOGIN_TOTP)
      return
    }
    if (controller.totpCodeExpiresAt <= 0) return
    controller.totpSecondsRemaining = Math.max(0, Math.ceil((controller.totpCodeExpiresAt - now) / controller.secondDurationMs))
    if (controller.totpNextRefreshAt > 0) controller.refreshTotpWhenDue(now)
    else if (now >= controller.totpCodeExpiresAt) controller.conceal(SecretFieldCatalog.LOGIN_TOTP)
  }

  function refreshTotpWhenDue(now) {
    if (now >= controller.totpNextRefreshAt) controller.requestTotpRefresh(now)
  }

  // One release per period: the next refresh is only due at the boundary
  // the previous reply reported.
  function requestTotpRefresh(now) {
    controller.totpCodeExpiresAt = 0
    controller.totpNextRefreshAt = 0
    controller.totpLastAutomaticRefreshAt = now
    var request = { kind: "reveal", field: SecretFieldCatalog.LOGIN_TOTP, itemId: controller.itemId }
    if (!controller.enqueue(request)) controller.conceal(SecretFieldCatalog.LOGIN_TOTP)
  }

  function sameRequest(first, second) {
    return first.kind === second.kind && first.field === second.field && first.itemId === second.itemId
  }

  function isDuplicate(request) {
    var outstanding = controller.pendingRequests.slice()
    if (controller.activeRequest) outstanding.push(controller.activeRequest)
    return outstanding.some(function(other) { return controller.sameRequest(other, request) })
  }

  function canEnqueue(request) {
    if (!controller.active || !request.itemId) return false
    if (controller.pendingRequests.length >= controller.maximumQueuedRequests) return false
    return !controller.isDuplicate(request)
  }

  function enqueue(request) {
    if (!controller.canEnqueue(request)) return false
    request.generation = controller.revealGeneration
    controller.pendingRequests = controller.pendingRequests.concat([request])
    controller.dispatchNext()
    return true
  }

  function argumentsFor(request) {
    if (request.kind === "copy") {
      return SecretFieldCatalog.copyArguments(controller.helperPath, request.itemId, request.field, controller.clipboardClearSeconds)
    }
    return SecretFieldCatalog.revealArguments(controller.helperPath, request.itemId, request.field)
  }

  function dispatchNext() {
    if (controller.activeRequest || controller.pendingRequests.length === 0) return
    var request = controller.pendingRequests[0]
    controller.pendingRequests = controller.pendingRequests.slice(1)
    request.output = null
    request.exitCode = null
    controller.activeRequest = request
    commandWatchdog.restart()
    controller.commandRequested(controller.argumentsFor(request))
  }

  function completeActiveRequest() {
    var request = controller.activeRequest
    if (request.output === null || request.exitCode === null) return
    controller.finishRequest(request, SecretFieldCatalog.parseReleaseResponse(request.output, request.exitCode))
  }

  // First expiry: report the timeout and ask the owner to stop the process.
  // Second expiry (still no exit): ask for a forceful stop. The slot is freed
  // only by the exit, so the next command never meets a running process.
  function abandonActiveRequest() {
    var request = controller.activeRequest
    if (!request) return
    if (request.abandoned) {
      controller.commandStopRequested(true)
      return
    }
    request.abandoned = true
    request.output = ""
    commandWatchdog.restart()
    controller.commandStopRequested(false)
    controller.applyResponse(request, SecretFieldCatalog.failure("", strings.t("error.release_timed_out", "The omawarden engine did not respond in time.")))
  }

  function releaseActiveRequest() {
    commandWatchdog.stop()
    controller.activeRequest.output = ""
    controller.activeRequest = null
  }

  function retireAbandonedRequest() {
    controller.releaseActiveRequest()
    controller.dispatchNext()
  }

  function finishRequest(request, response) {
    controller.releaseActiveRequest()
    controller.applyResponse(request, response)
    controller.dispatchNext()
  }

  function answersRequest(request, response) {
    return response.id === request.itemId && response.field === request.field
  }

  function mismatchedReply() {
    return SecretFieldCatalog.failure("", strings.t("error.release_mismatched", "The omawarden engine answered a different request. Try again."))
  }

  function applyResponse(request, response) {
    if (!response.ok) {
      controller.reportFailure(request, response)
    } else if (!controller.answersRequest(request, response)) {
      controller.reportFailure(request, controller.mismatchedReply())
    } else if (request.kind === "copy") {
      controller.copyConfirmed(request.label, response.clearAfterSeconds)
    } else {
      controller.applyReveal(request, response)
    }
  }

  // The reveal is still asked for, on the same item, by an active controller.
  function isCurrentRequest(request) {
    return controller.active
      && request.generation === controller.revealGeneration
      && request.itemId === controller.itemId
      && controller.requestedFields[request.field] === true
  }

  // A reply is stored only for the reveal still asked for, on the same item;
  // applyResponse has already checked that it answers this request.
  function applyReveal(request, response) {
    if (!controller.isCurrentRequest(request)) return
    var values = Object.assign({}, controller.revealedValues)
    values[request.field] = response.value
    controller.revealedValues = values
    if (request.field === SecretFieldCatalog.LOGIN_TOTP) controller.applyTotpTiming(response)
    else controller.scheduleRevealExpiry(request.field)
  }

  function applyTotpTiming(response) {
    controller.totpPeriod = response.period > 0 ? response.period : controller.defaultTotpPeriodSeconds
    var remaining = Math.max(1, Math.min(response.secondsRemaining, controller.totpPeriod))
    controller.totpSecondsRemaining = remaining
    controller.totpCodeExpiresAt = Date.now() + remaining * controller.secondDurationMs
    controller.totpNextRefreshAt = controller.nextAutomaticTotpRefresh()
  }

  // 0 (no automatic refresh) for a period shorter than the minimum; otherwise
  // the period boundary, but never sooner than the minimum interval after the
  // previous automatic refresh, whatever `seconds_remaining` reported.
  function nextAutomaticTotpRefresh() {
    var minimumIntervalMs = controller.minimumAutomaticTotpRefreshSeconds * controller.secondDurationMs
    if (controller.totpPeriod < controller.minimumAutomaticTotpRefreshSeconds) return 0
    return Math.max(controller.totpCodeExpiresAt, controller.totpLastAutomaticRefreshAt + minimumIntervalMs)
  }

  function failureMessage(response) {
    var key = SecretFieldCatalog.errorMessageKey(response.errorCode)
    if (key) return strings.t(key, response.error)
    return response.error || strings.t("error.release_failed", "The omawarden engine could not release this value.")
  }

  function announceRefusal(response) {
    controller.releaseRefused(response.errorCode || "", controller.failureMessage(response))
  }

  // A refused copy is always reported: the user asked for it. A refused
  // reveal the user has since moved away from (another item, a concealed
  // field, a hidden overlay) must not cancel the reveal now pending or show
  // its error over another item; only a refusal that locked the vault is
  // still reported.
  function reportFailure(request, response) {
    if (request.kind === "copy") {
      controller.announceRefusal(response)
    } else if (controller.isCurrentRequest(request)) {
      controller.conceal(request.field)
      controller.announceRefusal(response)
    } else if (SecretFieldCatalog.errorLocksVault(response.errorCode)) {
      controller.announceRefusal(response)
    }
  }
}

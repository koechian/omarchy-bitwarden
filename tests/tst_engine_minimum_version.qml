import QtQuick
import QtQuick.Controls
import "../components"

Item {
  id: testRunner

  property int failures: 0
  function check(cond, msg) {
    if (!cond) {
      failures++
      console.error("FAIL: " + msg)
    } else {
      console.log("PASS: " + msg)
    }
  }

  // The first omawarden engine that redacts items and releases secrets per
  // field (ADR 0027); 0.11.0 is the last engine that hands out the whole vault.
  readonly property string minimumEngineVersion: "0.12.0"

  DependencyCheckView { id: dependencyView }

  function readSource(path) {
    var request = new XMLHttpRequest()
    request.open("GET", path, false)
    request.send()
    return request.responseText || ""
  }

  function parseSemVer(v) {
    if (!v || typeof v !== "string") return null
    var clean = String(v).replace(/^omawarden[\s-]+|^v/i, "").trim()
    var match = clean.match(/^(\d+)\.(\d+)(?:\.(\d+))?/)
    if (!match) return null
    var major = parseInt(match[1], 10)
    var minor = parseInt(match[2], 10)
    var patch = (match[3] !== undefined && match[3] !== "") ? parseInt(match[3], 10) : 0
    return [major, minor, patch]
  }

  function compareSemVer(v1, v2) {
    var a = parseSemVer(v1)
    var b = parseSemVer(v2)
    if (!a && !b) return 0
    if (!a) return -1
    if (!b) return 1
    for (var i = 0; i < 3; i++) {
      if (a[i] > b[i]) return 1
      if (a[i] < b[i]) return -1
    }
    return 0
  }

  function isEngineVersionSatisfied(ver) {
    if (!ver) return false
    var parsed = parseSemVer(ver)
    if (!parsed) return false
    var min = parseSemVer(minimumEngineVersion)
    if (!min) return false
    for (var i = 0; i < 3; i++) {
      if (parsed[i] > min[i]) return true
      if (parsed[i] < min[i]) return false
    }
    return true
  }

  Component.onCompleted: {
    console.log("Running Minimum Engine Version Enforcement Tests...")

    // The overlay and the dependency view enforce the same minimum.
    var rootSource = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    var rootMinimum = (rootSource.match(/readonly property string minimumEngineVersion: "([^"]+)"/) || [])[1]
    check(rootMinimum === minimumEngineVersion, "the overlay requires omawarden >= " + minimumEngineVersion + " (found " + rootMinimum + ")")
    check(dependencyView.minimumEngineVersion === minimumEngineVersion, "the dependency view requires omawarden >= " + minimumEngineVersion)

    var rejected = [
      "", "0.8.1", "0.10.0", "0.11.0", "omawarden-0.11.0", "0.11.0-1", "0.11.9",
      "0.11.0-dev", "0.11.0.dev", "0.11.0.r45.ga1b2c3d-1", "omawarden 0.11.0 (32cf259 2026-09-19)",
      "unknown", "r45.ga1b2c3d", "dev", null, undefined
    ]
    rejected.forEach(function(version) {
      check(!isEngineVersionSatisfied(version), "version " + JSON.stringify(version) + " is rejected (< " + minimumEngineVersion + " or unparsable)")
      check(!dependencyView.isEngineVersionSatisfied(version), "the dependency view rejects " + JSON.stringify(version))
    })

    var accepted = [
      "0.12.0", "omawarden-0.12.0", "0.12.0-1", "0.12.0-dev", "0.12.0.dev", "0.12.0.r12.g9f8e7d-1",
      "0.12.1", "0.13.0", "1.0.0-rc1", "omawarden 0.12.0 (32cf259 2026-11-06)"
    ]
    accepted.forEach(function(version) {
      check(isEngineVersionSatisfied(version), "version " + JSON.stringify(version) + " is accepted (>= " + minimumEngineVersion + ")")
      check(dependencyView.isEngineVersionSatisfied(version), "the dependency view accepts " + JSON.stringify(version))
    })

    // Report results
    if (failures > 0) {
      console.error("TOTAL FAILURES: " + failures)
    } else {
      console.log("ALL MINIMUM ENGINE VERSION TESTS PASSED!")
    }
    Qt.exit(failures === 0 ? 0 : 1)
  }
}

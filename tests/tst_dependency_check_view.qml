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

  DependencyCheckView {
    id: depView
    anchors.fill: parent
  }

  Component.onCompleted: {
    console.log("Running DependencyCheckView Unit Tests...")

    // 1. Initial State
    check(depView.dependencyModel !== null, "dependencyModel exists")
    check(depView.dependencyModel.count === 3, "dependencyModel has 3 items")
    check(depView.dependencyModel.get(0).pkgName === "omawarden", "first pkg is omawarden")
    check(depView.dependencyModel.get(1).pkgName === "libsecret", "second pkg is libsecret")
    check(depView.dependencyModel.get(2).pkgName === "wl-clipboard", "third pkg is wl-clipboard")
    check(depView.missingPackages.length === 0, "initial missingPackages is empty")

    // 2. Reset to checking
    depView.resetToChecking()
    check(depView.dependencyModel.get(0).status === "checking", "omawarden status is checking")
    check(depView.dependencyModel.get(1).status === "checking", "libsecret status is checking")
    check(depView.dependencyModel.get(2).status === "checking", "wl-clipboard status is checking")

    // 3. Parse pacman stdout with omawarden-bin provider
    var mockStdout = "libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n"
    depView.parsePacmanStdout(mockStdout)
    check(depView.dependencyModel.get(1).status === "installed", "libsecret is installed")
    check(depView.dependencyModel.get(1).version === "0.21.7-1", "libsecret version is 0.21.7-1")
    check(depView.dependencyModel.get(2).status === "installed", "wl-clipboard is installed")
    check(depView.dependencyModel.get(2).version === "1:2.3.0-1", "wl-clipboard version is 1:2.3.0-1")
    check(depView.dependencyModel.get(0).status === "checking", "omawarden is still checking")

    // 4. Parse pacman stderr with omawarden missing
    var mockStderr = "error: package 'omawarden' was not found\nwarning: 'omawarden' is a file, you might want to use -p/--file.\n"
    depView.parsePacmanStderr(mockStderr)
    check(depView.dependencyModel.get(0).status === "missing", "omawarden status marked missing from stderr")

    // 5. Finalize check
    var missing = depView.finalizeCheck()
    check(missing.length === 1, "missing length is 1")
    check(missing[0] === "omawarden", "missing[0] is omawarden")
    check(depView.missingPackages.length === 1, "depView.missingPackages is updated")

    // 6. Get install package names retains omawarden
    var installNames = depView.getInstallPackageNames()
    check(installNames.length === 1, "installNames length is 1")
    check(installNames[0] === "omawarden", "installNames includes omawarden for user provider selection")

    // 7. Parse stdout with omawarden-bin satisfying omawarden (version >= 0.12.0)
    var mockAurStdout = "omawarden-bin 0.12.0-1\n"
    depView.parsePacmanStdout(mockAurStdout)
    check(depView.dependencyModel.get(0).status === "installed", "omawarden is satisfied by omawarden-bin >= 0.12.0")
    check(depView.dependencyModel.get(0).version === "0.12.0-1", "omawarden version set to 0.12.0-1")
    check(depView.dependencyModel.get(0).installedPackage === "omawarden-bin", "omawarden installedPackage is omawarden-bin")

    var missingAfter = depView.finalizeCheck()
    check(missingAfter.length === 0, "all dependencies satisfied, missing length is 0")
    check(depView.missingPackages.length === 0, "depView.missingPackages is empty when all installed")

    // 7b. Outdated version test: omawarden-bin 0.11.0 must be rejected (< 0.12.0)
    depView.resetToChecking()
    depView.parsePacmanStdout("libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\nomawarden-bin 0.11.0-1\n")
    check(depView.dependencyModel.get(0).status === "missing", "omawarden 0.11.0 marked missing due to minimum version requirement")
    var missingOutdated = depView.finalizeCheck()
    check(missingOutdated.indexOf("omawarden") !== -1, "missingOutdated contains omawarden")

    // 7c. Outdated VCS version test: omawarden-git 0.11.0.r45 must be rejected (< 0.12.0)
    depView.resetToChecking()
    check(depView.dependencyModel.get(0).installedPackage === "", "installedPackage is reset to empty string on resetToChecking")
    var mockOldGitStdout = "libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\nomawarden-git 0.11.0.r45.ga1b2c3d-1\n"
    depView.parsePacmanStdout(mockOldGitStdout)
    check(depView.dependencyModel.get(0).status === "missing", "omawarden-git 0.11.0.r45 marked missing due to minimum version requirement")
    var missingOldGit = depView.finalizeCheck()
    check(missingOldGit.indexOf("omawarden") !== -1, "missingOldGit contains omawarden")

    // 7d. Satisfied VCS version test: omawarden-git 0.12.0.r12 (>= 0.12.0)
    depView.resetToChecking()
    var mockGitStdout = "libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\nomawarden-git 0.12.0.r12.ga1b2c3d-1\n"
    depView.parsePacmanStdout(mockGitStdout)
    check(depView.dependencyModel.get(0).status === "installed", "omawarden is satisfied by omawarden-git >= 0.12.0")
    check(depView.dependencyModel.get(0).version === "0.12.0.r12.ga1b2c3d-1", "omawarden version set to git version")
    check(depView.dependencyModel.get(0).installedPackage === "omawarden-git", "omawarden installedPackage is omawarden-git")

    var missingAfterGit = depView.finalizeCheck()
    check(missingAfterGit.length === 0, "all dependencies satisfied with omawarden-git >= 0.12.0, missing length is 0")
    check(depView.missingPackages.length === 0, "depView.missingPackages is empty when omawarden-git >= 0.12.0 is installed")

    // 8. Signals test: recheck only; the view never launches an installer
    var recheckEmitted = false
    depView.recheckRequested.connect(function() { recheckEmitted = true })

    depView.recheckRequested()
    check(recheckEmitted, "recheckRequested signal emitted")
    check(depView.installRequested === undefined, "no installRequested signal exists")
    check(depView.isInstalling === undefined, "no installer state exists")

    // 9. Overlay view gating test (modeled after OmarchyBitwarden.qml effectiveView logic)
    function computeEffectiveView(dependenciesMissing, currentView, authState) {
      if (dependenciesMissing && currentView !== "settings") return "dependency_check"
      if (currentView !== "auto") return currentView
      if (authState.status === "unlocked" && Boolean(authState.has_session)) return "search"
      if (authState.status === "locked" && Boolean(authState.has_session)) return "unlock"
      return "login"
    }

    var authUnlocked = { status: "unlocked", has_session: true }
    var authLocked = { status: "locked", has_session: true }
    var authUnauthenticated = { status: "unauthenticated", has_session: false }

    // When dependencies are missing, normal views must be blocked and route to "dependency_check"
    check(computeEffectiveView(true, "auto", authUnlocked) === "dependency_check", "Blocks search view when dependencies missing")
    check(computeEffectiveView(true, "auto", authLocked) === "dependency_check", "Blocks unlock view when dependencies missing")
    check(computeEffectiveView(true, "auto", authUnauthenticated) === "dependency_check", "Blocks login view when dependencies missing")

    // Settings can still be opened when user explicitly requests settings
    check(computeEffectiveView(true, "settings", authUnlocked) === "settings", "Allows settings view even when dependencies missing")

    // When dependencies are satisfied, normal views are unlocked
    check(computeEffectiveView(false, "auto", authUnlocked) === "search", "Routes to search view when dependencies satisfied and unlocked")
    check(computeEffectiveView(false, "auto", authLocked) === "unlock", "Routes to unlock view when dependencies satisfied and locked")
    check(computeEffectiveView(false, "auto", authUnauthenticated) === "login", "Routes to login view when dependencies satisfied and unauthenticated")

    // 10. Install command is displayed as text, built from the missing packages
    depView.resetToChecking()
    check(depView.installCommand === "", "No install command while nothing is missing")
    depView.parsePacmanStderr("error: package 'omawarden' was not found\nerror: package 'libsecret' was not found\nerror: package 'wl-clipboard' was not found\n")
    depView.finalizeCheck()
    check(depView.installCommand === "paru -S --needed libsecret wl-clipboard",
          "Install command names the missing system packages and never the source-built engine")
    check(depView.engineMissing === true, "A missing engine is reported separately")
    check(depView.engineBuildInstructions.indexOf("~/.local/bin") !== -1, "Engine build instructions name the install location")
    check(typeof depView.copyInstallCommand === "function", "Install command can be copied")
    depView.resetToChecking()
    depView.parsePacmanStdout("omawarden-bin 0.12.0-1\nlibsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    depView.finalizeCheck()
    check(depView.installCommand === "", "Install command clears once everything is installed")

    // 11. Missing package via stderr
    depView.resetToChecking()
    depView.parsePacmanStdout("libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    depView.parsePacmanStderr("error: package 'omawarden' was not found\n")
    check(depView.dependencyModel.get(0).status === "missing", "omawarden missing when not found in pacman")

    var missingAur = depView.finalizeCheck()
    check(missingAur.indexOf("omawarden") !== -1, "missing packages includes omawarden")

    // 12. Robustness: parsePacmanStderr must not overwrite installed status
    depView.resetToChecking()
    depView.parsePacmanStdout("omawarden-bin 0.12.0-1\nlibsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    depView.parsePacmanStderr("error: package 'omawarden' was not found\n")
    check(depView.dependencyModel.get(0).status === "installed", "parsePacmanStderr does not overwrite installed omawarden-bin")
    check(depView.dependencyModel.get(0).installedPackage === "omawarden-bin", "installedPackage remains omawarden-bin")

    // 13. Robustness: stderr arrives BEFORE stdout when candidate provider is installed
    depView.resetToChecking()
    depView.parsePacmanStderr("error: package 'omawarden' was not found\nerror: package 'omawarden-git' was not found\n")
    depView.parsePacmanStdout("omawarden-bin 0.12.0-1\nlibsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    check(depView.dependencyModel.get(0).status === "installed", "omawarden-bin satisfies dependency even if stderr finished first")
    check(depView.dependencyModel.get(0).installedPackage === "omawarden-bin", "installedPackage is correctly omawarden-bin when stderr arrived first")
    var missingInverted = depView.finalizeCheck()
    check(missingInverted.length === 0, "missing count is 0 when stderr finished before stdout")

    // 14. A locally built engine on PATH satisfies the check when pacman has no engine package
    depView.resetToChecking()
    depView.parsePacmanStdout("libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    depView.parsePacmanStderr("error: package 'omawarden' was not found\nerror: package 'omawarden-bin' was not found\nerror: package 'omawarden-git' was not found\n")
    check(depView.engineNeedsLocalProbe() === true, "Engine without a package needs a local probe")
    depView.applyLocalEngineProbe("omawarden 0.12.0 (c84c59d 2026-11-06)\n")
    check(depView.dependencyModel.get(0).status === "installed", "Local engine 0.12.0 counts as installed")
    check(depView.dependencyModel.get(0).isLocalFallback === true, "Local engine is marked as a local build")
    check(depView.dependencyModel.get(0).version === "0.12.0", "Local engine version is recorded")
    check(depView.finalizeCheck().length === 0, "Nothing is missing once the local engine is found")
    check(depView.installCommand === "", "No install command once the local engine is found")

    // 15. A local engine older than the minimum stays missing
    depView.resetToChecking()
    depView.parsePacmanStdout("libsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    depView.applyLocalEngineProbe("omawarden 0.11.0 (cc8d22b 2026-11-03)\n")
    check(depView.dependencyModel.get(0).status === "missing", "Local engine 0.11.0 is rejected")
    check(depView.finalizeCheck().indexOf("omawarden") !== -1, "Rejected local engine is reported missing")

    // 16. Unrecognised probe output changes nothing
    depView.resetToChecking()
    depView.applyLocalEngineProbe("")
    depView.applyLocalEngineProbe("sh: omawarden: not found")
    check(depView.dependencyModel.get(0).status === "checking", "Empty or unrecognised probe output leaves the engine unresolved")
    check(depView.parseEngineVersionOutput("omawarden 0.12.0-dev") === "0.12.0-dev", "Development versions are parsed")

    // 17. A packaged engine needs no local probe
    depView.resetToChecking()
    depView.parsePacmanStdout("omawarden-bin 0.12.0-1\nlibsecret 0.21.7-1\nwl-clipboard 1:2.3.0-1\n")
    check(depView.engineNeedsLocalProbe() === false, "Packaged engine skips the local probe")

    console.log("ALL DEPENDENCY CHECK VIEW TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}

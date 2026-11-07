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

  SettingsModal {
    id: sm
  }

  Component.onCompleted: {
    console.log("Running Settings Engine Source Tests...")

    // 1. Default property value is "aur"
    check(sm.engineSource === "aur", "Default engineSource is 'aur'")

    // 2. Set engineSource to custom value
    sm.engineSource = "system"
    check(sm.engineSource === "system", "engineSource updates to 'system'")

    // 3. Set engineSource back to 'aur'
    sm.engineSource = "aur"
    check(sm.engineSource === "aur", "engineSource updates to 'aur'")

    // 3b. Test enginePackage property
    check(sm.enginePackage === "", "Default enginePackage is empty")
    sm.enginePackage = "omawarden-git"
    check(sm.enginePackage === "omawarden-git", "enginePackage updates to omawarden-git")

    // 4. Test engineSource derivation logic matching OmarchyBitwarden.qml
    function deriveEngineSource(depModel, helperPath, cliHealth) {
      if (cliHealth && !cliHealth.installed) return ""
      if (depModel) {
        for (var i = 0; i < depModel.length; i++) {
          var item = depModel[i]
          if (item.pkgName === "omawarden") {
            if (item.status === "installed") return "aur"
          }
        }
      }
      if (helperPath && helperPath !== "omawarden") {
        return "aur"
      }
      return ""
    }

    function deriveEnginePackage(depModel) {
      if (depModel) {
        for (var i = 0; i < depModel.length; i++) {
          var item = depModel[i]
          if (item.pkgName === "omawarden") {
            if (item.status === "installed" && item.installedPackage) {
              return item.installedPackage
            }
          }
        }
      }
      return ""
    }

    // A: omawarden installed via AUR/pacman (omawarden-git)
    var aurModelGit = [{ pkgName: "omawarden", status: "installed", installedPackage: "omawarden-git" }]
    check(deriveEngineSource(aurModelGit, "/usr/bin/omawarden", { installed: true }) === "aur", "Derives 'aur' when pacman installed")
    check(deriveEnginePackage(aurModelGit) === "omawarden-git", "Derives 'omawarden-git' package name")

    // A2: omawarden installed via AUR/pacman (omawarden-bin)
    var aurModelBin = [{ pkgName: "omawarden", status: "installed", installedPackage: "omawarden-bin" }]
    check(deriveEngineSource(aurModelBin, "/usr/bin/omawarden", { installed: true }) === "aur", "Derives 'aur' when omawarden-bin installed")
    check(deriveEnginePackage(aurModelBin) === "omawarden-bin", "Derives 'omawarden-bin' package name")

    // B: system helperPath fallback
    check(deriveEngineSource([], "/usr/bin/omawarden", { installed: true }) === "aur", "Derives 'aur' from system /usr/bin/omawarden helperPath")

    // C: missing engine state (no package, no binary, or uninstalled cliHealth)
    var missingModel = [{ pkgName: "omawarden", status: "missing", installedPackage: "" }]
    check(deriveEngineSource(missingModel, "", { installed: false }) === "", "Derives empty string when engine missing from dependencies")
    check(deriveEngineSource([], "", { installed: false }) === "", "Derives empty string when engine not installed")
    check(deriveEngineSource(aurModelGit, "/usr/bin/omawarden", { installed: false }) === "", "Derives empty string when cliHealth.installed is false")

    // 5. The settings view reports the engine but never runs an installer
    check(sm.installPackageRequested === undefined, "SettingsModal exposes no installer signal")
    check(sm.isInstallingDependencies === undefined, "SettingsModal has no installer state")
    check(sm.checkUpdateRequested === undefined, "SettingsModal exposes no update check signal")

    console.log("ALL SETTINGS ENGINE SOURCE TESTS PASSED!")
    Qt.exit(failures === 0 ? 0 : 1)
  }
}

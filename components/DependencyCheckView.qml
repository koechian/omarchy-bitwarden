import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

Item {
  id: depViewRoot

  property var dependencyModel: defaultModel
  property var missingPackages: []
  property bool isChecking: false

  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color borderColor: Commons.Color.popups.border
  property color background: Commons.Color.popups.background
  property color cardBackground: Qt.rgba(Commons.Color.background.r, Commons.Color.background.g, Commons.Color.background.b, 0.25)
  property string fontFamily: ""

  readonly property color textOnAccent: StatusPalette.textOn(accent)

  // The first engine that redacts items and releases secrets per field (ADR 0027).
  readonly property string minimumEngineVersion: "0.12.0"

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

  signal recheckRequested()

  ListModel {
    id: defaultModel

    ListElement {
      pkgName: "omawarden"
      aurPkgName: "omawarden"
      required: true
      title: "Bitwarden Engine & Daemon"
      description: "High-performance Rust backend providing end-to-end encryption, TOTP generation, and Unix domain socket IPC (distributed via AUR omawarden-bin / omawarden-git)."
      status: "idle"     // "idle" | "checking" | "installed" | "missing"
      version: ""
      installedPackage: ""
      isLocalFallback: false
    }

    ListElement {
      pkgName: "libsecret"
      aurPkgName: "libsecret"
      required: true
      title: "Secret Service & Keyring"
      description: "Provides secret-tool CLI for securely persisting vault session tokens and API credentials in the system keyring."
      status: "idle"
      version: ""
      installedPackage: ""
      isLocalFallback: false
    }

    ListElement {
      pkgName: "wl-clipboard"
      aurPkgName: "wl-clipboard"
      required: true
      title: "Wayland Clipboard Utilities"
      description: "Provides wl-copy and wl-paste for secure password and TOTP copying with auto-clearing timeout."
      status: "idle"
      version: ""
      installedPackage: ""
      isLocalFallback: false
    }
  }

  function parsePacmanStdout(output) {
    var text = (output || "").trim()
    if (!text) return

    var lines = text.split("\n")
    for (var i = 0; i < lines.length; i++) {
      var match = lines[i].trim().match(/^(\S+)\s+(.+)$/)
      if (match) {
        var name = match[1]
        var ver = match[2]
        for (var j = 0; j < dependencyModel.count; j++) {
          var item = dependencyModel.get(j)
          if (item.pkgName === name || item.aurPkgName === name || (item.pkgName === "omawarden" && (name === "omawarden-bin" || name === "omawarden-git"))) {
            if (item.pkgName === "omawarden" && !isEngineVersionSatisfied(ver)) {
              dependencyModel.setProperty(j, "status", "missing")
              dependencyModel.setProperty(j, "version", ver)
              dependencyModel.setProperty(j, "installedPackage", name)
              dependencyModel.setProperty(j, "isLocalFallback", false)
            } else {
              dependencyModel.setProperty(j, "status", "installed")
              dependencyModel.setProperty(j, "version", ver)
              dependencyModel.setProperty(j, "installedPackage", name)
              dependencyModel.setProperty(j, "isLocalFallback", false)
            }
            break
          }
        }
      }
    }
  }

  function parsePacmanStderr(errOutput) {
    var text = (errOutput || "").trim()
    if (!text) return

    var lines = text.split("\n")
    for (var i = 0; i < lines.length; i++) {
      var match = lines[i].trim().match(/package '([^']+)' was not found/)
      if (match) {
        var missingName = match[1]
        for (var j = 0; j < dependencyModel.count; j++) {
          var item = dependencyModel.get(j)
          if (item.status === "installed") continue
          if (item.pkgName === missingName || item.aurPkgName === missingName) {
            dependencyModel.setProperty(j, "status", "missing")
            dependencyModel.setProperty(j, "version", "")
            dependencyModel.setProperty(j, "installedPackage", "")
            dependencyModel.setProperty(j, "isLocalFallback", false)
            break
          }
        }
      }
    }
  }

  function finalizeCheck() {
    var missing = []
    for (var i = 0; i < dependencyModel.count; i++) {
      var item = dependencyModel.get(i)
      if (item.status === "checking") {
        dependencyModel.setProperty(i, "status", "missing")
        missing.push(item.pkgName)
      } else if (item.status === "missing") {
        missing.push(item.pkgName)
      }
    }
    depViewRoot.missingPackages = missing
    return missing
  }

  function resetToChecking() {
    depViewRoot.missingPackages = []
    for (var i = 0; i < dependencyModel.count; i++) {
      dependencyModel.setProperty(i, "status", "checking")
      dependencyModel.setProperty(i, "version", "")
      dependencyModel.setProperty(i, "installedPackage", "")
      dependencyModel.setProperty(i, "isLocalFallback", false)
    }
  }

  function getInstallPackageNames() {
    return depViewRoot.missingPackages.slice()
  }

  function engineRowIndex() {
    for (var i = 0; i < dependencyModel.count; i++) {
      if (dependencyModel.get(i).pkgName === "omawarden") return i
    }
    return -1
  }

  // True when pacman did not report a satisfying engine package, so the
  // overlay should look for a locally built engine on PATH.
  function engineNeedsLocalProbe() {
    var index = engineRowIndex()
    return index >= 0 && dependencyModel.get(index).status !== "installed"
  }

  // Extracts the version from `omawarden --version` output
  // ("omawarden 0.12.0 (c84c59d 2026-11-06)"); empty when unrecognised.
  function parseEngineVersionOutput(output) {
    var match = String(output || "").trim().match(/^omawarden\s+(\d+\.\d+\.\d+\S*)/)
    return match ? match[1] : ""
  }

  // Records a locally built engine found on PATH. This fork's engine is not
  // packaged, so a satisfying local build counts as installed.
  function applyLocalEngineProbe(output) {
    var version = parseEngineVersionOutput(output)
    var index = engineRowIndex()
    if (!version || index < 0) return
    var satisfied = isEngineVersionSatisfied(version)
    dependencyModel.setProperty(index, "status", satisfied ? "installed" : "missing")
    dependencyModel.setProperty(index, "version", version)
    dependencyModel.setProperty(index, "installedPackage", localEnginePackageLabel)
    dependencyModel.setProperty(index, "isLocalFallback", true)
  }

  readonly property string localEnginePackageLabel: "local build"
  readonly property bool engineMissing: missingPackages.indexOf("omawarden") !== -1
  readonly property string engineBuildInstructions: "Build omawarden " + minimumEngineVersion
    + " or later from this plugin's repository and install it to ~/.local/bin (see the README), then press Recheck."

  // The command the user runs to install the missing system packages. The
  // overlay only displays it; it never launches an installer itself. The
  // engine is built from source in this fork, so it is never part of it.
  readonly property var missingSystemPackages: missingPackages.filter(function (name) { return name !== "omawarden" })
  readonly property string installCommand: missingSystemPackages.length > 0
    ? "paru -S --needed " + missingSystemPackages.join(" ")
    : ""

  function copyInstallCommand() {
    installCommandField.selectAll()
    installCommandField.copy()
    installCommandField.deselect()
  }

  Flickable {
    id: flickable
    anchors.fill: parent
    contentWidth: width
    contentHeight: Math.max(height, mainColumn.implicitHeight + 40)
    boundsBehavior: Flickable.StopAtBounds
    clip: true

    ColumnLayout {
      id: mainColumn
      anchors.centerIn: parent
      width: Math.min(parent.width - 48, 640)
      spacing: 16

      // 1. Header
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 6

        RowLayout {
          spacing: 10

          Text {
            textFormat: Text.PlainText
            text: "\uf0ad"
            font.family: depViewRoot.fontFamily
            font.pixelSize: Style.fontPx(1.833)
            color: depViewRoot.accent
          }

          Text {
            textFormat: Text.PlainText
            text: "System Dependencies Required"
            color: depViewRoot.foreground
            font.pixelSize: Style.font.heading
            font.bold: true
          }

          Rectangle {
            height: 20
            width: setupBadge.implicitWidth + 12
            radius: 4
            color: Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.08)
            border.color: depViewRoot.borderColor
            border.width: 1

            Text {
              textFormat: Text.PlainText
              id: setupBadge
              anchors.centerIn: parent
              text: "Prerequisite Setup"
              color: depViewRoot.accent
              font.pixelSize: Style.font.caption
              font.bold: true
            }
          }
        }

        Text {
          textFormat: Text.PlainText
          text: "Omarchy Bitwarden requires native Arch / AUR packages to provide background encryption, system keyring session caching, and Wayland clipboard management."
          color: depViewRoot.muted
          font.pixelSize: Style.font.bodySmall
          wrapMode: Text.WordWrap
          Layout.fillWidth: true
        }
      }

      // 2. Package Cards List
      ColumnLayout {
        Layout.fillWidth: true
        spacing: 10

        Repeater {
          model: depViewRoot.dependencyModel

          delegate: Rectangle {
            Layout.fillWidth: true
            implicitHeight: cardLayout.implicitHeight + 20
            radius: 8
            color: {
              if (model.status === "installed") return StatusPalette.tint(StatusPalette.installed, 0.2)
              if (model.status === "missing") return StatusPalette.tint(StatusPalette.missing, 0.2)
              return depViewRoot.cardBackground
            }
            border.color: {
              if (model.status === "installed") return StatusPalette.tint(StatusPalette.installed, 0.4)
              if (model.status === "missing") return StatusPalette.tint(StatusPalette.missing, 0.4)
              return depViewRoot.borderColor
            }
            border.width: 1

            RowLayout {
              id: cardLayout
              anchors.fill: parent
              anchors.margins: 12
              spacing: 12

              // State Indicator Dot
              Rectangle {
                width: 10
                height: 10
                radius: 5
                color: {
                  if (model.status === "installed") return StatusPalette.installed
                  if (model.status === "missing") return StatusPalette.missing
                  if (model.status === "checking") return StatusPalette.checking
                  return depViewRoot.muted
                }
              }

              // Details
              ColumnLayout {
                Layout.fillWidth: true
                spacing: 3

                RowLayout {
                  spacing: 8

                  Text {
                    textFormat: Text.PlainText
                    text: model.pkgName
                    color: depViewRoot.foreground
                    font.pixelSize: Style.font.subtitle
                    font.bold: true
                  }

                  Rectangle {
                    height: 18
                    width: reqTagText.implicitWidth + 8
                    radius: 3
                    color: Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.08)
                    Text {
                      textFormat: Text.PlainText
                      id: reqTagText
                      anchors.centerIn: parent
                      text: {
                        if (model.pkgName === "omawarden") {
                          if (model.isLocalFallback) return "Local build"
                          if (model.status === "installed" && model.installedPackage) {
                            return "AUR: " + model.installedPackage
                          }
                          return "Build from source"
                        }
                        return "Core System Package"
                      }
                      color: {
                        if (model.pkgName === "omawarden") return depViewRoot.accent
                        return depViewRoot.muted
                      }
                      font.pixelSize: Style.font.caption
                      font.bold: true
                    }
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: model.version ? ("v" + model.version) : ""
                    color: StatusPalette.installed
                    font.pixelSize: Style.font.bodySmall
                    font.bold: true
                    visible: model.status === "installed" && Boolean(model.version)
                  }
                }

                Text {
                  textFormat: Text.PlainText
                  text: model.title
                  color: depViewRoot.foreground
                  font.pixelSize: Style.font.bodySmall
                  font.weight: Font.DemiBold
                }

                Text {
                  textFormat: Text.PlainText
                  text: model.description
                  color: depViewRoot.muted
                  font.pixelSize: Style.font.caption
                  wrapMode: Text.WordWrap
                  Layout.fillWidth: true
                }
              }

              // Status Badge Pill
              Rectangle {
                implicitWidth: statusText.implicitWidth + 16
                implicitHeight: 24
                radius: 12
                color: {
                  if (model.status === "installed") return StatusPalette.tint(StatusPalette.installed, 0.5)
                  if (model.status === "missing") return StatusPalette.tint(StatusPalette.missing, 0.5)
                  if (model.status === "checking") return StatusPalette.tint(StatusPalette.checking, 0.5)
                  return Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.08)
                }
                border.color: {
                  if (model.status === "installed") return StatusPalette.installed
                  if (model.status === "missing") return StatusPalette.missing
                  if (model.status === "checking") return StatusPalette.checking
                  return depViewRoot.borderColor
                }
                border.width: 1

                Text {
                  textFormat: Text.PlainText
                  id: statusText
                  anchors.centerIn: parent
                  text: {
                    if (model.status === "installed") return "✓ Ready"
                    if (model.status === "missing") {
                      if (model.pkgName === "omawarden" && Boolean(model.version) && !depViewRoot.isEngineVersionSatisfied(model.version)) {
                        return "▲ Requires >= " + depViewRoot.minimumEngineVersion
                      }
                      return "✗ Missing"
                    }
                    if (model.status === "checking") return "⏳ Checking"
                    return "Pending"
                  }
                  color: {
                    if (model.status === "installed") return StatusPalette.installed
                    if (model.status === "missing") {
                      if (model.pkgName === "omawarden" && Boolean(model.version) && !depViewRoot.isEngineVersionSatisfied(model.version)) {
                        return StatusPalette.checking
                      }
                      return StatusPalette.missing
                    }
                    if (model.status === "checking") return StatusPalette.checking
                    return depViewRoot.foreground
                  }
                  font.pixelSize: Style.font.bodySmall
                  font.bold: true
                }
              }
            }
          }
        }
      }

      // 3. Action Buttons & Info
      RowLayout {
        Layout.fillWidth: true
        spacing: 12

        // Recheck Button
        Rectangle {
          implicitHeight: 36
          implicitWidth: recheckTxt.implicitWidth + 24
          radius: 6
          color: recheckMouse.pressed ? Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.12) : (recheckMouse.containsMouse ? Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.08) : Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.04))
          border.color: depViewRoot.borderColor
          border.width: 1

          Text {
            textFormat: Text.PlainText
            id: recheckTxt
            anchors.centerIn: parent
            text: depViewRoot.isChecking ? "Checking..." : "↻ Recheck"
            color: depViewRoot.isChecking ? depViewRoot.muted : depViewRoot.foreground
            font.pixelSize: Style.font.bodySmall
            font.bold: true
          }

          MouseArea {
            id: recheckMouse
            anchors.fill: parent
            enabled: !depViewRoot.isChecking
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: depViewRoot.recheckRequested()
          }
        }

        Text {
          textFormat: Text.PlainText
          Layout.fillWidth: true
          text: {
            if (depViewRoot.isChecking) return "Checking Dependencies..."
            if (depViewRoot.missingPackages.length > 0) return "Missing: " + depViewRoot.getInstallPackageNames().join(", ")
            return "✓ All Dependencies Installed"
          }
          color: (!depViewRoot.isChecking && depViewRoot.missingPackages.length === 0) ? StatusPalette.installed : depViewRoot.muted
          font.pixelSize: Style.font.body
          font.bold: true
          elide: Text.ElideRight
        }
      }

      // Install command: shown as selectable text for the user to run in a terminal
      Rectangle {
        visible: !depViewRoot.isChecking && Boolean(depViewRoot.installCommand)
        Layout.fillWidth: true
        implicitHeight: 36
        radius: 6
        color: Qt.rgba(depViewRoot.foreground.r, depViewRoot.foreground.g, depViewRoot.foreground.b, 0.08)
        border.color: depViewRoot.borderColor
        border.width: 1

        RowLayout {
          anchors.fill: parent
          anchors.leftMargin: 10
          anchors.rightMargin: 6
          spacing: 8

          TextEdit {
            textFormat: Text.PlainText
            id: installCommandField
            Layout.fillWidth: true
            text: depViewRoot.installCommand
            readOnly: true
            selectByMouse: true
            color: depViewRoot.foreground
            selectionColor: depViewRoot.accent
            selectedTextColor: depViewRoot.textOnAccent
            font.family: "monospace"
            font.pixelSize: Style.font.bodySmall
            wrapMode: TextEdit.WrapAnywhere
          }

          Rectangle {
            implicitWidth: copyCmdText.implicitWidth + 16
            implicitHeight: 24
            radius: 4
            color: copyCmdMouse.containsMouse ? Qt.lighter(depViewRoot.accent, 1.1) : depViewRoot.accent

            Text {
              textFormat: Text.PlainText
              id: copyCmdText
              anchors.centerIn: parent
              text: copyCmdTimer.running ? "Copied" : "Copy"
              color: depViewRoot.textOnAccent
              font.pixelSize: Style.font.caption
              font.bold: true
            }

            MouseArea {
              id: copyCmdMouse
              anchors.fill: parent
              hoverEnabled: true
              cursorShape: Qt.PointingHandCursor
              onClicked: {
                depViewRoot.copyInstallCommand()
                copyCmdTimer.restart()
              }
            }

            Timer {
              id: copyCmdTimer
              interval: 1500
            }
          }
        }
      }

      Text {
        textFormat: Text.PlainText
        visible: !depViewRoot.isChecking && Boolean(depViewRoot.installCommand)
        text: "Run the command above in a terminal, then press Recheck. Replace paru with yay if that is your AUR helper."
        color: depViewRoot.muted
        font.pixelSize: Style.font.caption
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
      }

      Text {
        textFormat: Text.PlainText
        visible: !depViewRoot.isChecking && depViewRoot.engineMissing
        text: depViewRoot.engineBuildInstructions
        color: depViewRoot.muted
        font.pixelSize: Style.font.caption
        horizontalAlignment: Text.AlignHCenter
        wrapMode: Text.WordWrap
        Layout.fillWidth: true
      }
    }
  }
}

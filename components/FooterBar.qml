import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: footerRoot

  property string overlayVersion: ""
  property string backendVersion: ""
  property bool isEngineInstalled: true
  property bool isUnlocked: true
  property bool isBusy: false
  property color background: "transparent"
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color borderColor: Commons.Color.menu.border
  property string fontFamily: ""

  signal actionPaletteTriggered()
  signal generatePasswordTriggered()
  signal syncTriggered()
  signal lockTriggered()
  signal settingsTriggered()

  height: 30
  Layout.fillWidth: true
  color: footerRoot.background
  border.width: 0
  radius: 0

  // 1. Top border matching Omarchy theme border
  Rectangle {
    anchors.top: parent.top
    anchors.left: parent.left
    anchors.right: parent.right
    height: 1
    color: footerRoot.borderColor
  }

  RowLayout {
    anchors.fill: parent
    anchors.topMargin: 3
    anchors.leftMargin: 2
    anchors.rightMargin: 2
    spacing: 4

    // 2. Bottom Left: Ghost Actions, Sync, Lock, Settings
    RowLayout {
      spacing: 2

      // Unlocked Actions Group
      RowLayout {
        spacing: 2
        visible: footerRoot.isUnlocked

        // Actions Ghost Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: actionsBtnRow.implicitWidth + 12
          radius: 4
          color: actionsMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: actionsBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                textFormat: Text.PlainText
                text: "\uf0e7"
                font.family: footerRoot.fontFamily
                color: actionsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                textFormat: Text.PlainText
                text: "Actions"
                color: actionsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              textFormat: Text.PlainText
              text: "Ctrl+K"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
            }
          }

          MouseArea {
            id: actionsMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: footerRoot.actionPaletteTriggered()
          }
        }

        // Generate Password Ghost Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: generateBtnRow.implicitWidth + 12
          radius: 4
          color: generateMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: generateBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                textFormat: Text.PlainText
                text: "\uf084"
                font.family: footerRoot.fontFamily
                color: generateMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                textFormat: Text.PlainText
                text: "Generate"
                color: generateMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              textFormat: Text.PlainText
              text: "Ctrl+G"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
            }
          }

          MouseArea {
            id: generateMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: footerRoot.generatePasswordTriggered()
          }
        }

        // Sync Ghost Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: syncBtnRow.implicitWidth + 12
          radius: 4
          color: syncMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: syncBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                textFormat: Text.PlainText
                text: "\uf021"
                font.family: footerRoot.fontFamily
                color: syncMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                textFormat: Text.PlainText
                text: "Sync"
                color: syncMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              textFormat: Text.PlainText
              text: "Ctrl+R"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
            }
          }

          MouseArea {
            id: syncMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: footerRoot.syncTriggered()
          }
        }

        // Lock Ghost Button
        Rectangle {
          implicitHeight: 22
          implicitWidth: lockBtnRow.implicitWidth + 12
          radius: 4
          color: lockMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
          border.width: 0

          RowLayout {
            id: lockBtnRow
            anchors.centerIn: parent
            spacing: 4
            RowLayout {
              spacing: 3
              Text {
                textFormat: Text.PlainText
                text: "\uf023"
                font.family: footerRoot.fontFamily
                color: lockMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
              }
              Text {
                textFormat: Text.PlainText
                text: "Lock"
                color: lockMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
                font.pixelSize: Style.font.bodySmall
                font.weight: Font.Medium
              }
            }
            Text {
              textFormat: Text.PlainText
              text: "Ctrl+L"
              color: footerRoot.muted
              font.pixelSize: Style.fontPx(0.75)
            }
          }

          MouseArea {
            id: lockMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: footerRoot.lockTriggered()
          }
        }
      }

      // Settings Ghost Button (Always visible on bottom-left)
      Rectangle {
        implicitHeight: 22
        implicitWidth: settingsBtnRow.implicitWidth + 12
        radius: 4
        color: settingsMouse.containsMouse ? Qt.rgba(footerRoot.foreground.r, footerRoot.foreground.g, footerRoot.foreground.b, 0.08) : "transparent"
        border.width: 0

        RowLayout {
          id: settingsBtnRow
          anchors.centerIn: parent
          spacing: 4
          RowLayout {
            spacing: 3
            Text {
              textFormat: Text.PlainText
              text: "\uf013"
              font.family: footerRoot.fontFamily
              color: settingsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
              font.pixelSize: Style.font.bodySmall
            }
            Text {
              textFormat: Text.PlainText
              text: "Settings"
              color: settingsMouse.containsMouse ? footerRoot.foreground : footerRoot.muted
              font.pixelSize: Style.font.bodySmall
              font.weight: Font.Medium
            }
          }
          Text {
            textFormat: Text.PlainText
            text: "Ctrl+,"
            color: footerRoot.muted
            font.pixelSize: Style.fontPx(0.75)
          }
        }

        MouseArea {
          id: settingsMouse
          anchors.fill: parent
          hoverEnabled: true
          cursorShape: Qt.PointingHandCursor
          onClicked: footerRoot.settingsTriggered()
        }
      }
    }

    Item { Layout.fillWidth: true }

    // 3. Bottom Right: Plain version info + missing engine badge
    RowLayout {
      spacing: 3

      Text {
        textFormat: Text.PlainText
        text: "Omarchy Bitwarden " + footerRoot.overlayVersion
        color: footerRoot.muted
        font.pixelSize: Style.font.caption
      }

      Text {
        textFormat: Text.PlainText
        text: "•"
        color: footerRoot.muted
        font.pixelSize: Style.font.caption
      }

      Text {
        textFormat: Text.PlainText
        visible: footerRoot.isEngineInstalled
        text: "Omawarden " + footerRoot.backendVersion
        color: footerRoot.muted
        font.pixelSize: Style.font.caption
      }

      // Missing Engine Badge (install instructions are on the dependency check view)
      Rectangle {
        visible: !footerRoot.isEngineInstalled
        implicitHeight: 18
        implicitWidth: dlBadgeRow.implicitWidth + 10
        radius: 4
        color: StatusPalette.tint(StatusPalette.danger, 0.15)
        border.color: StatusPalette.danger
        border.width: 1

        RowLayout {
          id: dlBadgeRow
          anchors.centerIn: parent
          spacing: 3
          Text {
            textFormat: Text.PlainText
            text: "\uf071"
            font.family: footerRoot.fontFamily
            color: StatusPalette.danger
            font.pixelSize: Style.fontPx(0.75)
          }
          Text {
            textFormat: Text.PlainText
            text: "Engine Missing"
            color: StatusPalette.danger
            font.pixelSize: Style.font.caption
            font.weight: Font.DemiBold
          }
        }
      }
    }
  }
}

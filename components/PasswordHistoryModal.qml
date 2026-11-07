import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// Password history of one login. The entries are released once, when the
// modal opens, through `vault reveal --field password_history` and passed in
// as `historyEntries` (null while the reply is outstanding). Entries stay
// masked until shown here. The engine refuses to copy password history
// (`field_not_copyable`), so the modal offers no copy action.
Rectangle {
  id: historyModalRoot

  property bool active: false
  property var item: null
  property var historyEntries: null
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""

  property bool allRevealed: false
  property var revealedIndexes: ({})
  readonly property QtObject strings: Commons.Translations {
    directory: Qt.resolvedUrl("../i18n")
  }
  readonly property bool isRetrieving: historyModalRoot.active && historyModalRoot.historyEntries === null
  readonly property var historyList: historyModalRoot.getHistoryList()

  signal closeRequested()

  anchors.fill: parent
  color: StatusPalette.scrim(0.65)
  visible: active
  z: 110

  Keys.onEscapePressed: historyModalRoot.closeRequested()

  Keys.onPressed: function(event) {
    if (event.key === Qt.Key_Escape) {
      historyModalRoot.closeRequested()
      event.accepted = true
    } else if (event.modifiers & Qt.ControlModifier) {
      if (event.key === Qt.Key_T) {
        historyModalRoot.toggleAllRevealed()
        event.accepted = true
      }
    }
  }

  onActiveChanged: {
    allRevealed = false
    revealedIndexes = {}
    if (active) historyModalRoot.forceActiveFocus()
  }

  onHistoryEntriesChanged: {
    if (historyModalRoot.historyEntries === null) {
      allRevealed = false
      revealedIndexes = {}
    }
  }

  function toggleAllRevealed() {
    allRevealed = !allRevealed
    var copy = {}
    var list = historyModalRoot.historyList
    for (var i = 0; i < list.length; i++) {
      copy[i] = allRevealed
    }
    revealedIndexes = copy
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return ""
    try {
      var d = new Date(dateStr)
      if (!isNaN(d.getTime())) {
        var year = d.getFullYear()
        var month = String(d.getMonth() + 1).padStart(2, '0')
        var day = String(d.getDate()).padStart(2, '0')
        var hours = String(d.getHours()).padStart(2, '0')
        var minutes = String(d.getMinutes()).padStart(2, '0')
        return year + "-" + month + "-" + day + " " + hours + ":" + minutes
      }
    } catch (e) {}
    return String(dateStr).substring(0, 16).replace("T", " ")
  }

  function getHistoryList() {
    if (!Array.isArray(historyModalRoot.historyEntries)) return []
    // Show newest first
    return historyModalRoot.historyEntries.slice().reverse()
  }

  function isIndexRevealed(idx) {
    if (allRevealed) return true
    return Boolean(revealedIndexes && revealedIndexes[idx])
  }

  function toggleReveal(idx) {
    var list = historyModalRoot.historyList
    var copy = {}
    if (allRevealed) {
      for (var i = 0; i < list.length; i++) {
        copy[i] = (i !== idx)
      }
      allRevealed = false
    } else {
      copy = Object.assign({}, revealedIndexes || {})
      copy[idx] = !Boolean(copy[idx])
    }
    revealedIndexes = copy
  }

  MouseArea {
    anchors.fill: parent
    onClicked: historyModalRoot.closeRequested()
  }

  Rectangle {
    id: modalCard
    anchors.centerIn: parent
    width: Math.min(parent.width - 48, 520)
    height: Math.min(parent.height - 48, 440)
    radius: 8
    color: historyModalRoot.cardBackground
    border.color: historyModalRoot.borderColor
    border.width: 1

    MouseArea {
      anchors.fill: parent
    }

    ColumnLayout {
      anchors.fill: parent
      anchors.margins: 16
      spacing: 12

      // Modal Header
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          textFormat: Text.PlainText
          text: "\uf1da"
          font.family: historyModalRoot.fontFamily
          font.pixelSize: Style.font.title
          color: historyModalRoot.accent
        }

        Text {
          textFormat: Text.PlainText
          text: "Password History: " + (historyModalRoot.item ? (historyModalRoot.item.name || "Item") : "")
          color: historyModalRoot.foreground
          font.pixelSize: Style.font.subtitle
          font.weight: Font.DemiBold
          elide: Text.ElideRight
          Layout.fillWidth: true
          Layout.preferredWidth: 0
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: historyModalRoot.borderColor
      }

      // Scrollable History Content
      ScrollView {
        Layout.fillWidth: true
        Layout.fillHeight: true
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

        ColumnLayout {
          width: modalCard.width - 32
          spacing: 8

          Text {
            visible: historyModalRoot.isRetrieving
            textFormat: Text.PlainText
            text: historyModalRoot.strings.t("history.retrieving", "Retrieving password history…")
            color: historyModalRoot.muted
            font.pixelSize: Style.font.bodySmall
            Layout.alignment: Qt.AlignCenter
          }

          Repeater {
            model: historyModalRoot.historyList

            Rectangle {
              id: entryCard
              property bool isEntryRevealed: historyModalRoot.allRevealed || Boolean(historyModalRoot.revealedIndexes && historyModalRoot.revealedIndexes[index])

              Layout.fillWidth: true
              implicitHeight: entryCol.implicitHeight + 16
              radius: 6
              color: Qt.rgba(historyModalRoot.foreground.r, historyModalRoot.foreground.g, historyModalRoot.foreground.b, 0.05)
              border.color: historyModalRoot.borderColor
              border.width: 1

              ColumnLayout {
                id: entryCol
                anchors.fill: parent
                anchors.margins: 8
                spacing: 6

                // Last Used Date
                RowLayout {
                  Layout.fillWidth: true
                  spacing: 6

                  Text {
                    textFormat: Text.PlainText
                    text: (modelData.last_used_date ? historyModalRoot.formatDateTime(modelData.last_used_date) : "Unknown date")
                    color: historyModalRoot.muted
                    font.pixelSize: Style.font.caption
                    font.weight: Font.Medium
                    Layout.fillWidth: true
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: "#" + (historyModalRoot.historyList.length - index)
                    color: historyModalRoot.muted
                    font.pixelSize: Style.fontPx(0.75)
                  }
                }

                // Password Row
                RowLayout {
                  Layout.fillWidth: true
                  spacing: 8

                  Text {
                    textFormat: Text.PlainText
                    text: entryCard.isEntryRevealed ? ((modelData && modelData.password) ? modelData.password : "") : "••••••••••••••••"
                    color: historyModalRoot.foreground
                    font.pixelSize: Style.font.body
                    font.family: entryCard.isEntryRevealed ? "monospace" : "sans-serif"
                    font.weight: Font.Medium
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                  }

                  // Toggle Mask Ghost Button
                  GhostIconButton {
                    iconText: entryCard.isEntryRevealed ? "\uf070" : "\uf06e"
                    tooltip: entryCard.isEntryRevealed ? "Hide password" : "Show password"
                    fontFamily: historyModalRoot.fontFamily
                    onClicked: historyModalRoot.toggleReveal(index)
                  }
                }
              }
            }
          }

          // Empty state fallback (just in case)
          Text {
            textFormat: Text.PlainText
            visible: !historyModalRoot.isRetrieving && historyModalRoot.historyList.length === 0
            text: "No password history available for this item."
            color: historyModalRoot.muted
            font.pixelSize: Style.font.bodySmall
            Layout.alignment: Qt.AlignCenter
          }
        }
      }

      Rectangle {
        Layout.fillWidth: true
        height: 1
        color: historyModalRoot.borderColor
      }

      // Footer
      RowLayout {
        Layout.fillWidth: true
        spacing: 8

        Text {
          textFormat: Text.PlainText
          text: historyModalRoot.strings.tn("history.entry_count", historyModalRoot.historyList.length).arg(historyModalRoot.historyList.length)
          color: historyModalRoot.muted
          font.pixelSize: Style.font.caption
          Layout.fillWidth: true
        }

        // Toggle Mask Ghost Button
        GhostIconButton {
          visible: historyModalRoot.historyList.length > 0
          iconText: historyModalRoot.allRevealed ? "\uf070" : "\uf06e"
          tooltip: historyModalRoot.allRevealed ? "Hide all passwords (Ctrl+T)" : "Show all passwords (Ctrl+T)"
          fontFamily: historyModalRoot.fontFamily
          onClicked: historyModalRoot.toggleAllRevealed()
        }

        // Close Button
        Rectangle {
          implicitHeight: 26
          implicitWidth: closeBtnText.implicitWidth + 16
          radius: 4
          color: Qt.rgba(historyModalRoot.foreground.r, historyModalRoot.foreground.g, historyModalRoot.foreground.b, 0.08)
          border.color: historyModalRoot.borderColor
          border.width: 1

          Text {
            textFormat: Text.PlainText
            id: closeBtnText
            anchors.centerIn: parent
            text: "Close"
            color: historyModalRoot.foreground
            font.pixelSize: Style.font.caption
            font.weight: Font.Medium
          }

          MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: historyModalRoot.closeRequested()
          }
        }
      }
    }
  }
}

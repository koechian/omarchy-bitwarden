import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

Item {
  id: toastRoot

  property string statusMessage: ""
  property string errorMessage: ""
  property bool isBusy: false
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color cardBackground: Commons.Color.popups.background
  property color borderColor: Commons.Color.popups.border
  property string fontFamily: ""
  property int maxMessageWidth: 560

  signal clearRequested()

  visible: Boolean(statusMessage || errorMessage || isBusy)
  implicitHeight: contentRow.implicitHeight + 10
  implicitWidth: contentRow.implicitWidth + 20

  Rectangle {
    anchors.fill: parent
    radius: 6
    color: errorMessage ? StatusPalette.tint(StatusPalette.danger, 0.95) : toastRoot.cardBackground
    border.color: errorMessage ? StatusPalette.danger : (isBusy ? toastRoot.accent : toastRoot.borderColor)
    border.width: 1

    Behavior on opacity {
      NumberAnimation { duration: Style.duration(150); easing.type: Easing.OutCubic }
    }

    RowLayout {
      id: contentRow
      anchors.centerIn: parent
      spacing: 6

      Text {
        textFormat: Text.PlainText
        text: isBusy ? "\uf021" : (errorMessage ? "\uf071" : "\uf129")
        font.family: toastRoot.fontFamily
        font.pixelSize: Style.font.bodySmall
        color: errorMessage ? StatusPalette.textOnTint(StatusPalette.danger, 0.95, toastRoot.cardBackground) : (isBusy ? toastRoot.accent : toastRoot.foreground)
      }

      Text {
        textFormat: Text.PlainText
        id: messageText
        text: errorMessage || statusMessage || (isBusy ? "Processing..." : "")
        color: errorMessage ? StatusPalette.textOnTint(StatusPalette.danger, 0.95, toastRoot.cardBackground) : toastRoot.foreground
        font.pixelSize: Style.font.bodySmall
        font.weight: Font.Medium
        elide: Text.ElideRight
        Layout.preferredWidth: implicitWidth
        Layout.maximumWidth: toastRoot.maxMessageWidth

        MouseArea {
          id: messageHoverArea
          anchors.fill: parent
          hoverEnabled: true
          acceptedButtons: Qt.NoButton
        }

        // The full message for a truncated toast. The default ToolTip
        // content item is AutoText, so this one renders plain text: toast
        // messages carry engine and server text.
        ToolTip {
          id: messageToolTip
          visible: messageHoverArea.containsMouse && messageText.truncated
          delay: 300
          text: messageText.text
          contentItem: Text {
            textFormat: Text.PlainText
            text: messageToolTip.text
            font: messageToolTip.font
            color: messageToolTip.palette.toolTipText
            wrapMode: Text.Wrap
          }
        }
      }

      Text {
        textFormat: Text.PlainText
        visible: !isBusy && Boolean(errorMessage || statusMessage)
        text: "\uf00d"
        font.family: toastRoot.fontFamily
        color: errorMessage ? StatusPalette.tint(StatusPalette.textOnTint(StatusPalette.danger, 0.95, toastRoot.cardBackground), 0.7) : Qt.rgba(toastRoot.foreground.r, toastRoot.foreground.g, toastRoot.foreground.b, 0.6)
        font.pixelSize: Style.font.caption
        MouseArea {
          anchors.fill: parent
          cursorShape: Qt.PointingHandCursor
          onClicked: toastRoot.clearRequested()
        }
      }
    }
  }
}

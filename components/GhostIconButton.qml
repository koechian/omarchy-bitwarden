import QtQuick
import QtQuick.Controls
import qs.Commons
import qs.Commons as Commons

Rectangle {
  id: ghostBtnRoot

  property string iconText: ""
  property int iconPixelSize: Style.font.body
  property color foreground: Commons.Color.foreground
  property color muted: Commons.Color.muted
  property color iconColor: mouseArea.containsMouse ? foreground : muted
  property color hoverBackground: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.08)
  property string tooltip: ""
  property string fontFamily: ""
  readonly property real disabledOpacity: 0.4

  signal clicked()

  // A disabled button (for example "open" on a URI that may not be opened)
  // stays visible but dimmed, and its MouseArea is disabled with it.
  opacity: enabled ? 1 : disabledOpacity

  implicitWidth: 22
  implicitHeight: 22
  radius: 4
  color: mouseArea.containsMouse ? hoverBackground : "transparent"

  Text {
    textFormat: Text.PlainText
    anchors.centerIn: parent
    text: ghostBtnRoot.iconText
    color: ghostBtnRoot.iconColor
    font.pixelSize: ghostBtnRoot.iconPixelSize
    font.family: ghostBtnRoot.fontFamily
    verticalAlignment: Text.AlignVCenter
    horizontalAlignment: Text.AlignHCenter
  }

  MouseArea {
    id: mouseArea
    anchors.fill: parent
    hoverEnabled: true
    cursorShape: ghostBtnRoot.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
    onClicked: ghostBtnRoot.clicked()
  }
}

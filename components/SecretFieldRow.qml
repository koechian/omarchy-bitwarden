import QtQuick
import QtQuick.Layouts
import qs.Commons
import qs.Commons as Commons

// One secret of a redacted item: a masked placeholder until the user reveals
// it, the revealed value while the release controller holds it, and a copy
// action that goes through `vault copy-field`. The row reads the revealed
// value from the controller's map and keeps no copy of it.
RowLayout {
  id: secretRow

  property string field: ""
  property string label: ""
  property var revealedValues: ({})
  property var requestedFields: ({})
  // Optional function(text) -> display text for a revealed value.
  property var revealedFormatter: null
  property string maskText: "••••••••••••••••"
  property string pendingText: ""
  property bool revealable: true
  property bool revealedMonospace: true
  property string revealTooltip: ""
  property string copyTooltip: ""
  property color foreground: Commons.Color.foreground
  property color muted: Commons.Color.muted
  property string fontFamily: ""
  property int keyPixelSize: Style.font.caption
  property int valuePixelSize: Style.font.body

  readonly property bool revealed: Boolean(secretRow.revealedValues) && Object.prototype.hasOwnProperty.call(secretRow.revealedValues, secretRow.field)
  readonly property bool pending: !secretRow.revealed && Boolean(secretRow.requestedFields) && secretRow.requestedFields[secretRow.field] === true
  readonly property string displayedText: secretRow.revealed ? secretRow.formattedRevealedText() : (secretRow.pending ? secretRow.pendingText : secretRow.maskText)

  signal revealToggled()
  signal copyRequested()

  function formattedRevealedText() {
    var text = String(secretRow.revealedValues[secretRow.field])
    return (typeof secretRow.revealedFormatter === "function") ? secretRow.revealedFormatter(text) : text
  }

  Layout.fillWidth: true
  spacing: 8

  ColumnLayout {
    Layout.fillWidth: true
    Layout.preferredWidth: 0
    spacing: 2

    Text {
      textFormat: Text.PlainText
      text: secretRow.label
      color: secretRow.muted
      font.pixelSize: secretRow.keyPixelSize
      elide: Text.ElideRight
      Layout.fillWidth: true
      Layout.preferredWidth: 0
    }

    Text {
      objectName: "secretFieldValue"
      textFormat: Text.PlainText
      text: secretRow.displayedText
      color: secretRow.foreground
      font.pixelSize: secretRow.valuePixelSize
      font.family: (secretRow.revealed && secretRow.revealedMonospace) ? "monospace" : "sans-serif"
      font.weight: Font.Medium
      elide: Text.ElideRight
      Layout.fillWidth: true
      Layout.preferredWidth: 0
    }
  }

  GhostIconButton {
    visible: secretRow.revealable
    iconText: (secretRow.revealed || secretRow.pending) ? "" : ""
    tooltip: secretRow.revealTooltip
    fontFamily: secretRow.fontFamily
    onClicked: secretRow.revealToggled()
  }

  GhostIconButton {
    iconText: ""
    tooltip: secretRow.copyTooltip
    fontFamily: secretRow.fontFamily
    onClicked: secretRow.copyRequested()
  }
}

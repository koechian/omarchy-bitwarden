import QtQuick
import qs.Ui

// Bar entry for Omarchy Bitwarden: a lock glyph that opens or closes the vault
// overlay. It shows no vault data and starts no engine command; the overlay
// itself handles unlock and every secret release.
BarWidget {
  id: root
  moduleName: "icyleaf.bitwarden"

  readonly property string overlayIdentifier: "icyleaf.bitwarden"

  function toggleOverlay() {
    if (!root.bar || !root.bar.shell || typeof root.bar.shell.toggle !== "function")
      return
    root.bar.shell.toggle(root.overlayIdentifier, "{}")
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    text: "󰌾"
    tooltipText: "Bitwarden"
    onPressed: function (mouseButton) {
      if (mouseButton === Qt.LeftButton)
        root.toggleOverlay()
    }
  }
}

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "./CardFormatter.js" as CardFormatter
import "./SecretFieldCatalog.js" as SecretFieldCatalog
import "./UriPolicy.js" as UriPolicy
import qs.Commons
import qs.Commons as Commons

// Details of one redacted vault item (contracts.md 3.2). Secrets are shown
// as masked placeholders where the item's `has_*` flag is true and are
// omitted where it is false. A secret appears only after the user reveals it:
// the inspector asks for it with revealToggleRequested() and displays the
// value the release controller passes back in `revealedValues`. Secret copies
// are requested by field identifier (secretCopyRequested), never by value.
ScrollView {
  id: inspectorRoot

  property var item: null
  property var revealedValues: ({})
  property var requestedFields: ({})
  property int totpSecondsRemaining: 0
  property int totpPeriod: 30
  property color foreground: Commons.Color.foreground
  property color accent: Commons.Color.accent
  property color muted: Commons.Color.muted
  property color borderColor: Commons.Color.menu.border
  property string fontFamily: ""
  readonly property int keyPixelSize: Style.font.caption
  readonly property int valuePixelSize: Style.font.body
  readonly property int totpWarningSeconds: 5
  readonly property string passwordMask: "••••••••••••••••"
  readonly property string totpMask: "••• •••"
  readonly property string cardCodeMask: "•••"

  readonly property QtObject strings: Commons.Translations {
    directory: Qt.resolvedUrl("../i18n")
  }
  readonly property string retrievingText: inspectorRoot.strings.t("inspector.retrieving", "Retrieving…")
  readonly property var uriEntries: UriPolicy.itemUris(inspectorRoot.item)
  readonly property var customFields: SecretFieldCatalog.customFieldsWithValue(inspectorRoot.item)

  // Non-secret values only (usernames, URIs, names, dates).
  signal copyRequested(string text, bool isSensitive, string label)
  signal secretCopyRequested(string field, string label)
  signal revealToggleRequested(string field)
  signal openUriRequested(string uri)
  signal passwordHistoryRequested(var item)

  // A secret row bound to this inspector's revealed values and signals.
  component InspectorSecretRow: SecretFieldRow {
    property var inspector: null
    property string copyLabel: ""
    visible: Boolean(inspector) && SecretFieldCatalog.isPresent(inspector.item, field)
    revealedValues: inspector ? inspector.revealedValues : ({})
    requestedFields: inspector ? inspector.requestedFields : ({})
    pendingText: inspector ? inspector.retrievingText : ""
    foreground: inspector ? inspector.foreground : Commons.Color.foreground
    muted: inspector ? inspector.muted : Commons.Color.muted
    fontFamily: inspector ? inspector.fontFamily : ""
    keyPixelSize: inspector ? inspector.keyPixelSize : Style.font.caption
    valuePixelSize: inspector ? inspector.valuePixelSize : Style.font.body
    revealTooltip: (revealed ? "Hide " : "Show ") + copyLabel
    copyTooltip: "Copy " + copyLabel
    onRevealToggled: inspector.revealToggleRequested(field)
    onCopyRequested: inspector.secretCopyRequested(field, copyLabel)
  }

  clip: true
  ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
  ScrollBar.vertical: ScrollBar {
    id: inspVScrollBar
    policy: ScrollBar.AsNeeded
    contentItem: Rectangle {
      implicitWidth: 4
      radius: 2
      color: inspVScrollBar.pressed ? Qt.rgba(inspectorRoot.foreground.r, inspectorRoot.foreground.g, inspectorRoot.foreground.b, 0.4) : (inspVScrollBar.hovered ? Qt.rgba(inspectorRoot.foreground.r, inspectorRoot.foreground.g, inspectorRoot.foreground.b, 0.25) : Qt.rgba(inspectorRoot.foreground.r, inspectorRoot.foreground.g, inspectorRoot.foreground.b, 0.15))
    }
  }

  function hasSecret(field) {
    return SecretFieldCatalog.isPresent(inspectorRoot.item, field)
  }

  function isRevealed(field) {
    return Boolean(inspectorRoot.revealedValues) && Object.prototype.hasOwnProperty.call(inspectorRoot.revealedValues, field)
  }

  function isPending(field) {
    return !inspectorRoot.isRevealed(field) && Boolean(inspectorRoot.requestedFields) && inspectorRoot.requestedFields[field] === true
  }

  // Revealed text, the retrieving notice, or the mask.
  function secretDisplayText(field, mask) {
    if (inspectorRoot.isRevealed(field)) return String(inspectorRoot.revealedValues[field])
    return inspectorRoot.isPending(field) ? inspectorRoot.retrievingText : mask
  }

  function sectionText(sectionName, key) {
    var section = inspectorRoot.item ? inspectorRoot.item[sectionName] : null
    var value = section ? section[key] : null
    return (value === undefined || value === null) ? "" : String(value)
  }

  function joinedSectionText(sectionName, keys, separator) {
    return keys.map(function(key) { return inspectorRoot.sectionText(sectionName, key) }).filter(Boolean).join(separator)
  }

  function identityFullName() {
    return inspectorRoot.joinedSectionText("identity", ["title", "firstName", "middleName", "lastName"], " ")
  }

  function identityAddress() {
    return inspectorRoot.joinedSectionText("identity", ["address1", "address2", "city", "state", "postalCode", "country"], ", ")
  }

  function cardExpiry(separator) {
    return inspectorRoot.sectionText("card", "expMonth") + separator + inspectorRoot.sectionText("card", "expYear")
  }

  function formatRevealedCardNumber(number) {
    return CardFormatter.formatRevealedCardNumber(number, inspectorRoot.sectionText("card", "brand"))
  }

  function passwordHistoryCount() {
    var count = inspectorRoot.item && inspectorRoot.item.login ? Number(inspectorRoot.item.login.password_history_count) : 0
    return count > 0 ? count : 0
  }

  function getItemIcon(item) {
    if (!item) return ""
    if (item.type_name === "card") return ""
    if (item.type_name === "identity") return ""
    if (item.type_name === "note") return ""
    return ""
  }

  readonly property var categoryLabels: ({ "login": "Login", "card": "Card", "identity": "Identity", "note": "Secure Note", "secure_note": "Secure Note" })

  function getItemCategoryLabel(item) {
    if (!item) return ""
    var label = inspectorRoot.categoryLabels[item.type_name || item.category || ""]
    return label || item.sub_title || item.type_name || "Item"
  }

  function formatDateTime(dateStr) {
    if (!dateStr) return ""
    try {
      let d = new Date(dateStr)
      if (!isNaN(d.getTime())) {
        let year = d.getFullYear()
        let month = String(d.getMonth() + 1).padStart(2, '0')
        let day = String(d.getDate()).padStart(2, '0')
        let hours = String(d.getHours()).padStart(2, '0')
        let minutes = String(d.getMinutes()).padStart(2, '0')
        return year + "-" + month + "-" + day + " " + hours + ":" + minutes
      }
    } catch (e) {}
    return String(dateStr).substring(0, 16).replace("T", " ")
  }

  ColumnLayout {
    width: Math.max(0, inspectorRoot.availableWidth - 12)
    spacing: 12

    // ----------------------------------------------------
    // ITEM INSPECTOR VIEW
    // ----------------------------------------------------
    ColumnLayout {
      visible: inspectorRoot.item !== null
      Layout.fillWidth: true
      spacing: 8

      // Header: Icon + Name + Badges
      RowLayout {
        Layout.fillWidth: true
        spacing: 10

        Item {
          id: inspIconContainer
          Layout.preferredWidth: 24
          Layout.preferredHeight: 24

          Text {
            textFormat: Text.PlainText
            anchors.centerIn: parent
            text: inspectorRoot.getItemIcon(inspectorRoot.item)
            font.family: inspectorRoot.fontFamily
            font.pixelSize: Style.font.title
            color: inspectorRoot.muted
          }
        }

        ColumnLayout {
          Layout.fillWidth: true
          Layout.preferredWidth: 0
          spacing: 3

          RowLayout {
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            spacing: 6

            Text {
              objectName: "inspectorItemName"
              textFormat: Text.PlainText
              text: inspectorRoot.item ? (inspectorRoot.item.name || "Untitled") : ""
              color: inspectorRoot.foreground
              font.pixelSize: Style.font.body
              font.weight: Font.DemiBold
              elide: Text.ElideRight
              Layout.fillWidth: true
              Layout.preferredWidth: 0
            }

            // Monochrome Favorite Badge
            Rectangle {
              visible: Boolean(inspectorRoot.item && inspectorRoot.item.favorite)
              implicitHeight: 18
              implicitWidth: favRow.implicitWidth + 10
              radius: 3
              color: Qt.rgba(inspectorRoot.foreground.r, inspectorRoot.foreground.g, inspectorRoot.foreground.b, 0.08)
              border.color: inspectorRoot.borderColor
              border.width: 1

              RowLayout {
                id: favRow
                anchors.centerIn: parent
                spacing: 3
                Text {
                  textFormat: Text.PlainText
                  text: ""
                  font.family: inspectorRoot.fontFamily
                  font.pixelSize: Style.fontPx(0.75)
                  color: inspectorRoot.muted
                }
                Text {
                  textFormat: Text.PlainText
                  text: "Favorite"
                  color: inspectorRoot.muted
                  font.pixelSize: Style.font.caption
                  font.weight: Font.Medium
                }
              }
            }

            // Organization Badge
            Rectangle {
              visible: Boolean(inspectorRoot.item && inspectorRoot.item.organization_name)
              implicitHeight: 18
              implicitWidth: orgText.implicitWidth + 8
              radius: 3
              color: StatusPalette.tint(StatusPalette.organization, 0.2)
              border.color: StatusPalette.tint(StatusPalette.organization, 0.5)
              border.width: 1

              Text {
                id: orgText
                textFormat: Text.PlainText
                anchors.centerIn: parent
                text: " " + (inspectorRoot.item ? (inspectorRoot.item.organization_name || "") : "")
                font.family: inspectorRoot.fontFamily
                color: StatusPalette.organization
                font.pixelSize: Style.font.caption
                font.weight: Font.Medium
              }
            }

            // Folder Badge
            Rectangle {
              visible: Boolean(inspectorRoot.item && inspectorRoot.item.folder_name)
              implicitHeight: 18
              implicitWidth: folderText.implicitWidth + 8
              radius: 3
              color: StatusPalette.tint(StatusPalette.folder, 0.2)
              border.color: StatusPalette.tint(StatusPalette.folder, 0.5)
              border.width: 1

              Text {
                id: folderText
                textFormat: Text.PlainText
                anchors.centerIn: parent
                text: " " + (inspectorRoot.item ? (inspectorRoot.item.folder_name || "") : "")
                font.family: inspectorRoot.fontFamily
                color: StatusPalette.folder
                font.pixelSize: Style.font.caption
                font.weight: Font.Medium
              }
            }
          }

          Text {
            textFormat: Text.PlainText
            text: inspectorRoot.item ? inspectorRoot.getItemCategoryLabel(inspectorRoot.item) : ""
            color: inspectorRoot.muted
            font.pixelSize: Style.font.bodySmall
            elide: Text.ElideRight
            Layout.fillWidth: true
            Layout.preferredWidth: 0
          }
        }
      }

      // --------------------------------------------------
      // LOGIN CREDENTIALS SECTION
      // --------------------------------------------------
      Rectangle {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.login)
        Layout.fillWidth: true
        implicitHeight: loginColumnLayout.implicitHeight + 20
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        ColumnLayout {
          id: loginColumnLayout
          anchors.fill: parent
          anchors.margins: 10
          spacing: 8

          // Username
          RowLayout {
            visible: inspectorRoot.sectionText("login", "username") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Username"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.sectionText("login", "username")
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy username"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.sectionText("login", "username"), false, "username")
            }
          }

          Rectangle {
            visible: inspectorRoot.sectionText("login", "username") !== "" && inspectorRoot.hasSecret(SecretFieldCatalog.LOGIN_PASSWORD)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // Password (masked until revealed)
          InspectorSecretRow {
            inspector: inspectorRoot
            field: SecretFieldCatalog.LOGIN_PASSWORD
            label: "Password"
            copyLabel: "password"
            maskText: inspectorRoot.passwordMask
          }

          Rectangle {
            visible: (inspectorRoot.sectionText("login", "username") !== "" || inspectorRoot.hasSecret(SecretFieldCatalog.LOGIN_PASSWORD)) && inspectorRoot.uriEntries.length > 0
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // URIs: the full value is shown; only http and https open.
          Repeater {
            model: inspectorRoot.uriEntries

            ColumnLayout {
              id: uriWrapper
              Layout.fillWidth: true
              spacing: 8

              required property int index
              required property var modelData
              readonly property bool isOpenable: Boolean(modelData && modelData.isOpenable)
              readonly property string uri: (modelData && modelData.uri) ? modelData.uri : ""

              Rectangle {
                visible: uriWrapper.index > 0
                Layout.fillWidth: true
                implicitHeight: 1
                color: inspectorRoot.borderColor
              }

              RowLayout {
                Layout.fillWidth: true
                spacing: 8

                ColumnLayout {
                  Layout.fillWidth: true
                  Layout.preferredWidth: 0
                  spacing: 2
                  Text {
                    textFormat: Text.PlainText
                    text: uriWrapper.isOpenable ? "Website" : inspectorRoot.strings.t("inspector.label.uri", "URI")
                    color: inspectorRoot.muted
                    font.pixelSize: inspectorRoot.keyPixelSize
                  }
                  Text {
                    objectName: "inspectorUriValue"
                    textFormat: Text.PlainText
                    text: uriWrapper.uri
                    color: inspectorRoot.foreground
                    font.pixelSize: inspectorRoot.valuePixelSize
                    font.weight: Font.Medium
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                  }
                }

                GhostIconButton {
                  objectName: "inspectorUriOpenButton"
                  iconText: ""
                  enabled: uriWrapper.isOpenable
                  tooltip: uriWrapper.isOpenable ? "Open website" : "Only http and https links can be opened"
                  onClicked: inspectorRoot.openUriRequested(uriWrapper.uri)
                }

                GhostIconButton {
                  iconText: ""
                  tooltip: "Copy URI"
                  onClicked: inspectorRoot.copyRequested(uriWrapper.uri, false, uriWrapper.isOpenable ? "website URL" : "URI")
                }
              }
            }
          }

          Rectangle {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.LOGIN_TOTP)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // TOTP: masked until revealed; a revealed code counts down locally.
          ColumnLayout {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.LOGIN_TOTP)
            Layout.fillWidth: true
            spacing: 4

            RowLayout {
              Layout.fillWidth: true
              spacing: 8

              ColumnLayout {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                spacing: 2

                RowLayout {
                  spacing: 6
                  Text { textFormat: Text.PlainText; text: "TOTP Code"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
                  Text {
                    visible: inspectorRoot.isRevealed(SecretFieldCatalog.LOGIN_TOTP)
                    textFormat: Text.PlainText
                    text: inspectorRoot.strings.t("inspector.totp_period_remaining", "%1 s").arg(inspectorRoot.totpSecondsRemaining)
                    color: (inspectorRoot.totpSecondsRemaining > inspectorRoot.totpWarningSeconds) ? inspectorRoot.muted : StatusPalette.danger
                    font.pixelSize: inspectorRoot.keyPixelSize
                  }
                }

                Text {
                  objectName: "inspectorTotpValue"
                  textFormat: Text.PlainText
                  text: inspectorRoot.secretDisplayText(SecretFieldCatalog.LOGIN_TOTP, inspectorRoot.totpMask)
                  color: inspectorRoot.isRevealed(SecretFieldCatalog.LOGIN_TOTP) ? inspectorRoot.accent : inspectorRoot.foreground
                  font.pixelSize: Style.font.title
                  font.family: "monospace"
                  font.weight: Font.Bold
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                  Layout.preferredWidth: 0
                }
              }

              GhostIconButton {
                iconText: (inspectorRoot.isRevealed(SecretFieldCatalog.LOGIN_TOTP) || inspectorRoot.isPending(SecretFieldCatalog.LOGIN_TOTP)) ? "" : ""
                tooltip: "Show TOTP code"
                onClicked: inspectorRoot.revealToggleRequested(SecretFieldCatalog.LOGIN_TOTP)
              }

              GhostIconButton {
                iconText: ""
                tooltip: "Copy TOTP code"
                onClicked: inspectorRoot.secretCopyRequested(SecretFieldCatalog.LOGIN_TOTP, "TOTP code")
              }
            }

            // Progress Bar
            Rectangle {
              visible: inspectorRoot.isRevealed(SecretFieldCatalog.LOGIN_TOTP)
              Layout.fillWidth: true
              implicitHeight: 3
              radius: 2
              color: Qt.rgba(inspectorRoot.foreground.r, inspectorRoot.foreground.g, inspectorRoot.foreground.b, 0.1)

              Rectangle {
                height: parent.height
                radius: 2
                width: parent.width * Math.min(1, inspectorRoot.totpSecondsRemaining / Math.max(1, inspectorRoot.totpPeriod))
                color: (inspectorRoot.totpSecondsRemaining > inspectorRoot.totpWarningSeconds) ? inspectorRoot.accent : StatusPalette.danger
              }
            }
          }

          Rectangle {
            visible: Boolean(inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.has_passkey)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // Passkey Status & Creation Date
          RowLayout {
            visible: Boolean(inspectorRoot.item && inspectorRoot.item.login && inspectorRoot.item.login.has_passkey)
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2

              Text { textFormat: Text.PlainText; text: "Passkey"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.sectionText("login", "passkey_created_at") ? ("Created " + inspectorRoot.formatDateTime(inspectorRoot.sectionText("login", "passkey_created_at"))) : "Stored in vault"
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }
          }
        }
      }

      // --------------------------------------------------
      // CARD DETAILS SECTION
      // --------------------------------------------------
      Rectangle {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.card)
        Layout.fillWidth: true
        implicitHeight: cardColumnLayout.implicitHeight + 20
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        ColumnLayout {
          id: cardColumnLayout
          anchors.fill: parent
          anchors.margins: 10
          spacing: 8

          // Cardholder
          RowLayout {
            visible: inspectorRoot.sectionText("card", "cardholderName") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Cardholder"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.sectionText("card", "cardholderName")
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy cardholder"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.sectionText("card", "cardholderName"), false, "cardholder name")
            }
          }

          Rectangle {
            visible: inspectorRoot.sectionText("card", "cardholderName") !== "" && inspectorRoot.sectionText("card", "brand") !== ""
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // Card Brand
          RowLayout {
            visible: inspectorRoot.sectionText("card", "brand") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Brand"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.sectionText("card", "brand")
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }
          }

          Rectangle {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.CARD_NUMBER)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // Card Number: last four digits until revealed
          InspectorSecretRow {
            objectName: "inspectorCardNumberRow"
            inspector: inspectorRoot
            field: SecretFieldCatalog.CARD_NUMBER
            label: "Card Number"
            copyLabel: "card number"
            maskText: CardFormatter.formatMaskedLastFour(inspectorRoot.sectionText("card", "number_last_four"))
            revealedFormatter: inspectorRoot.formatRevealedCardNumber
          }

          Rectangle {
            visible: inspectorRoot.sectionText("card", "expMonth") !== "" || inspectorRoot.sectionText("card", "expYear") !== ""
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // Expires
          RowLayout {
            visible: inspectorRoot.sectionText("card", "expMonth") !== "" || inspectorRoot.sectionText("card", "expYear") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Expires"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.cardExpiry(" / ")
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.family: "monospace"
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy expiration date"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.cardExpiry("/"), false, "expiration date")
            }
          }

          Rectangle {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.CARD_CODE)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          // Security Code
          InspectorSecretRow {
            inspector: inspectorRoot
            field: SecretFieldCatalog.CARD_CODE
            label: "Security Code"
            copyLabel: "security code"
            maskText: inspectorRoot.cardCodeMask
          }
        }
      }

      // --------------------------------------------------
      // IDENTITY DETAILS SECTION
      // --------------------------------------------------
      Rectangle {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.identity)
        Layout.fillWidth: true
        implicitHeight: identityColumnLayout.implicitHeight + 20
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        ColumnLayout {
          id: identityColumnLayout
          anchors.fill: parent
          anchors.margins: 10
          spacing: 8

          RowLayout {
            visible: inspectorRoot.sectionText("identity", "firstName") !== "" || inspectorRoot.sectionText("identity", "lastName") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Full Name"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.identityFullName()
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy full name"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.identityFullName(), false, "full name")
            }
          }

          Rectangle {
            visible: inspectorRoot.sectionText("identity", "email") !== ""
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          RowLayout {
            visible: inspectorRoot.sectionText("identity", "email") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Email"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.sectionText("identity", "email")
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy email"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.sectionText("identity", "email"), false, "email")
            }
          }

          Rectangle {
            visible: inspectorRoot.sectionText("identity", "phone") !== ""
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          RowLayout {
            visible: inspectorRoot.sectionText("identity", "phone") !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Phone"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.sectionText("identity", "phone")
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy phone"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.sectionText("identity", "phone"), false, "phone number")
            }
          }

          Rectangle {
            visible: inspectorRoot.identityAddress() !== ""
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          RowLayout {
            visible: inspectorRoot.identityAddress() !== ""
            Layout.fillWidth: true
            spacing: 8

            ColumnLayout {
              Layout.fillWidth: true
              Layout.preferredWidth: 0
              spacing: 2
              Text { textFormat: Text.PlainText; text: "Address"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
              Text {
                textFormat: Text.PlainText
                text: inspectorRoot.identityAddress()
                color: inspectorRoot.foreground
                font.pixelSize: inspectorRoot.valuePixelSize
                font.weight: Font.Medium
                elide: Text.ElideRight
                Layout.fillWidth: true
                Layout.preferredWidth: 0
              }
            }

            GhostIconButton {
              iconText: ""
              tooltip: "Copy address"
              onClicked: inspectorRoot.copyRequested(inspectorRoot.identityAddress(), false, "address")
            }
          }

          Rectangle {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.IDENTITY_SSN)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          InspectorSecretRow {
            inspector: inspectorRoot
            field: SecretFieldCatalog.IDENTITY_SSN
            label: inspectorRoot.strings.t("inspector.label.ssn", "Social Security Number")
            copyLabel: "social security number"
          }

          Rectangle {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.IDENTITY_PASSPORT_NUMBER)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          InspectorSecretRow {
            inspector: inspectorRoot
            field: SecretFieldCatalog.IDENTITY_PASSPORT_NUMBER
            label: inspectorRoot.strings.t("inspector.label.passport_number", "Passport Number")
            copyLabel: "passport number"
          }

          Rectangle {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.IDENTITY_LICENSE_NUMBER)
            Layout.fillWidth: true
            implicitHeight: 1
            color: inspectorRoot.borderColor
          }

          InspectorSecretRow {
            inspector: inspectorRoot
            field: SecretFieldCatalog.IDENTITY_LICENSE_NUMBER
            label: inspectorRoot.strings.t("inspector.label.license_number", "License Number")
            copyLabel: "license number"
          }
        }
      }

      // --------------------------------------------------
      // SECURE NOTE SECTION (masked until revealed)
      // --------------------------------------------------
      Rectangle {
        visible: inspectorRoot.hasSecret(SecretFieldCatalog.NOTES)
        Layout.fillWidth: true
        implicitHeight: notesColumnLayout.implicitHeight + 20
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        ColumnLayout {
          id: notesColumnLayout
          anchors.fill: parent
          anchors.margins: 10
          spacing: 8

          RowLayout {
            Layout.fillWidth: true
            Text { textFormat: Text.PlainText; text: "Notes"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
            Item { Layout.fillWidth: true }
            GhostIconButton {
              iconText: (inspectorRoot.isRevealed(SecretFieldCatalog.NOTES) || inspectorRoot.isPending(SecretFieldCatalog.NOTES)) ? "" : ""
              tooltip: "Show notes"
              onClicked: inspectorRoot.revealToggleRequested(SecretFieldCatalog.NOTES)
            }
            GhostIconButton {
              iconText: ""
              tooltip: "Copy notes"
              onClicked: inspectorRoot.secretCopyRequested(SecretFieldCatalog.NOTES, "notes")
            }
          }

          Rectangle { Layout.fillWidth: true; implicitHeight: 1; color: inspectorRoot.borderColor }

          Text {
            objectName: "inspectorNotesValue"
            Layout.fillWidth: true
            Layout.preferredWidth: 0
            text: inspectorRoot.secretDisplayText(SecretFieldCatalog.NOTES, inspectorRoot.passwordMask)
            color: inspectorRoot.foreground
            font.pixelSize: inspectorRoot.valuePixelSize
            lineHeight: 1.35
            wrapMode: Text.WrapAnywhere
            textFormat: Text.PlainText
          }
        }
      }

      // Empty Secure Note Placeholder
      Rectangle {
        visible: Boolean(inspectorRoot.item && inspectorRoot.item.type_name === "note" && !inspectorRoot.hasSecret(SecretFieldCatalog.NOTES) && inspectorRoot.customFields.length === 0)
        Layout.fillWidth: true
        Layout.preferredHeight: 60
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        RowLayout {
          anchors.centerIn: parent
          spacing: 6
          Text {
            textFormat: Text.PlainText
            text: ""
            font.family: inspectorRoot.fontFamily
            color: inspectorRoot.muted
            font.pixelSize: Style.font.body
          }
          Text {
            textFormat: Text.PlainText
            text: "This secure note has no text or custom fields."
            color: inspectorRoot.muted
            font.pixelSize: Style.font.bodySmall
          }
        }
      }

      // --------------------------------------------------
      // CUSTOM FIELDS SECTION (rows without a value are hidden)
      // --------------------------------------------------
      Rectangle {
        visible: inspectorRoot.customFields.length > 0
        Layout.fillWidth: true
        implicitHeight: customFieldsColumnLayout.implicitHeight + 20
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        ColumnLayout {
          id: customFieldsColumnLayout
          anchors.fill: parent
          anchors.margins: 10
          spacing: 8

          Text {
            textFormat: Text.PlainText
            text: "Custom Fields"
            color: inspectorRoot.muted
            font.pixelSize: inspectorRoot.keyPixelSize
          }

          Repeater {
            model: inspectorRoot.customFields

            ColumnLayout {
              id: customFieldRow
              Layout.fillWidth: true
              spacing: 8

              required property var modelData
              readonly property string field: SecretFieldCatalog.customFieldIdentifier(modelData.index)
              readonly property string fieldName: modelData.name ? String(modelData.name) : "Field"
              readonly property bool isHiddenField: SecretFieldCatalog.isHiddenCustomField(modelData)

              Rectangle {
                Layout.fillWidth: true
                implicitHeight: 1
                color: inspectorRoot.borderColor
              }

              // Hidden field: masked until revealed
              InspectorSecretRow {
                visible: customFieldRow.isHiddenField
                inspector: inspectorRoot
                field: customFieldRow.field
                label: customFieldRow.fieldName
                copyLabel: customFieldRow.fieldName
                maskText: inspectorRoot.passwordMask
              }

              // Text, boolean or other field: the redacted item shows text and
              // boolean values; copying still goes through copy-field.
              RowLayout {
                visible: !customFieldRow.isHiddenField
                Layout.fillWidth: true
                spacing: 8

                ColumnLayout {
                  Layout.fillWidth: true
                  Layout.preferredWidth: 0
                  spacing: 2

                  Text {
                    textFormat: Text.PlainText
                    text: customFieldRow.fieldName
                    color: inspectorRoot.muted
                    font.pixelSize: inspectorRoot.keyPixelSize
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                  }

                  Text {
                    textFormat: Text.PlainText
                    text: SecretFieldCatalog.hasPublicCustomValue(customFieldRow.modelData) ? String(customFieldRow.modelData.value === undefined || customFieldRow.modelData.value === null ? "" : customFieldRow.modelData.value) : inspectorRoot.passwordMask
                    color: inspectorRoot.foreground
                    font.pixelSize: inspectorRoot.valuePixelSize
                    font.weight: Font.Medium
                    elide: Text.ElideRight
                    Layout.fillWidth: true
                    Layout.preferredWidth: 0
                  }
                }

                GhostIconButton {
                  iconText: ""
                  tooltip: "Copy field value"
                  onClicked: inspectorRoot.secretCopyRequested(customFieldRow.field, customFieldRow.fieldName)
                }
              }
            }
          }
        }
      }

      // --------------------------------------------------
      // ITEM HISTORY SECTION
      // --------------------------------------------------
      Rectangle {
        visible: Boolean(inspectorRoot.item && (inspectorRoot.item.created_at || inspectorRoot.item.updated_at || inspectorRoot.hasSecret(SecretFieldCatalog.PASSWORD_HISTORY)))
        Layout.fillWidth: true
        implicitHeight: historyColumnLayout.implicitHeight + 20
        radius: 6
        color: Commons.Color.popups.background
        border.color: inspectorRoot.borderColor
        border.width: 1

        ColumnLayout {
          id: historyColumnLayout
          anchors.fill: parent
          anchors.margins: 10
          spacing: 8

          Text {
            textFormat: Text.PlainText
            text: "Item history"
            color: inspectorRoot.muted
            font.pixelSize: inspectorRoot.keyPixelSize
          }

          // Created At
          ColumnLayout {
            visible: Boolean(inspectorRoot.item && inspectorRoot.item.created_at)
            Layout.fillWidth: true
            spacing: 8

            Rectangle {
              Layout.fillWidth: true
              implicitHeight: 1
              color: inspectorRoot.borderColor
            }

            RowLayout {
              Layout.fillWidth: true
              spacing: 8

              ColumnLayout {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                spacing: 2
                Text { textFormat: Text.PlainText; text: "Created"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
                Text {
                  textFormat: Text.PlainText
                  text: (inspectorRoot.item && inspectorRoot.item.created_at) ? inspectorRoot.formatDateTime(inspectorRoot.item.created_at) : ""
                  color: inspectorRoot.foreground
                  font.pixelSize: inspectorRoot.valuePixelSize
                  font.weight: Font.Medium
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                  Layout.preferredWidth: 0
                }
              }
            }
          }

          // Updated At
          ColumnLayout {
            visible: Boolean(inspectorRoot.item && inspectorRoot.item.updated_at)
            Layout.fillWidth: true
            spacing: 8

            Rectangle {
              Layout.fillWidth: true
              implicitHeight: 1
              color: inspectorRoot.borderColor
            }

            RowLayout {
              Layout.fillWidth: true
              spacing: 8

              ColumnLayout {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                spacing: 2
                Text { textFormat: Text.PlainText; text: "Updated"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
                Text {
                  textFormat: Text.PlainText
                  text: (inspectorRoot.item && inspectorRoot.item.updated_at) ? inspectorRoot.formatDateTime(inspectorRoot.item.updated_at) : ""
                  color: inspectorRoot.foreground
                  font.pixelSize: inspectorRoot.valuePixelSize
                  font.weight: Font.Medium
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                  Layout.preferredWidth: 0
                }
              }
            }
          }

          // Password History entry (login items whose flag is set)
          ColumnLayout {
            visible: inspectorRoot.hasSecret(SecretFieldCatalog.PASSWORD_HISTORY)
            Layout.fillWidth: true
            spacing: 8

            Rectangle {
              Layout.fillWidth: true
              implicitHeight: 1
              color: inspectorRoot.borderColor
            }

            RowLayout {
              Layout.fillWidth: true
              spacing: 8

              ColumnLayout {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                spacing: 2
                Text { textFormat: Text.PlainText; text: "Password History"; color: inspectorRoot.muted; font.pixelSize: inspectorRoot.keyPixelSize }
                Text {
                  textFormat: Text.PlainText
                  text: inspectorRoot.strings.tn("inspector.password_history_count", inspectorRoot.passwordHistoryCount()).arg(inspectorRoot.passwordHistoryCount())
                  color: inspectorRoot.foreground
                  font.pixelSize: inspectorRoot.valuePixelSize
                  font.weight: Font.Medium
                  elide: Text.ElideRight
                  Layout.fillWidth: true
                  Layout.preferredWidth: 0
                }
              }

              GhostIconButton {
                iconText: ""
                tooltip: "View password history (Ctrl+H)"
                onClicked: inspectorRoot.passwordHistoryRequested(inspectorRoot.item)
              }
            }
          }
        }
      }
    }
  }
}

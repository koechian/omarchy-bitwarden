import QtQuick
import "lib"
import "../components" as Components
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// ItemInspector, VaultItemList and PasswordHistoryModal with redacted items
// (contracts.md 3.2): masked placeholders where a has_* flag is true, no row
// where it is false, the card's last four digits, revealed values only from
// the controller's map, full URIs with "open" limited to http/https, and
// markup-shaped names rendered as literal text.
Item {
  id: testRunner
  width: 900
  height: 900

  readonly property string markupName: "<img src=\"https://example.invalid/x\">"

  readonly property var loginItem: ({
    id: "login-1",
    name: "GitHub",
    type: 1,
    type_name: "login",
    sub_title: "octocat",
    has_notes: true,
    login: {
      username: "octocat",
      uris: [{ uri: "https://github.com/login?next=%2Fsettings" }, { uri: "file:///etc/passwd" }, { uri: "smb://nas/share" }],
      has_passkey: false,
      has_password: true,
      has_totp: true,
      has_password_history: true,
      password_history_count: 2
    },
    fields: [
      { index: 0, name: "Account", type: 0, has_value: true, value: "1234" },
      { index: 1, name: "PIN", type: 1, has_value: true },
      { index: 2, name: "Unused", type: 0, has_value: false, value: "" }
    ]
  })

  readonly property var cardItem: ({
    id: "card-1",
    name: "Visa",
    type: 3,
    type_name: "card",
    has_notes: false,
    card: { cardholderName: "Alice Doe", brand: "Visa", expMonth: "12", expYear: "2028", number_last_four: "4444", has_number: true, has_code: false }
  })

  readonly property var identityItem: ({
    id: "identity-1",
    name: "Alice",
    type: 4,
    type_name: "identity",
    has_notes: false,
    identity: { firstName: "Alice", lastName: "Doe", email: "alice@example.com", has_ssn: true, has_passport_number: false, has_license_number: false }
  })

  property var openedUris: []
  property var revealRequests: []
  property var secretCopies: []

  Components.ItemInspector {
    id: inspector
    width: 600
    height: 1400
    item: testRunner.loginItem
    onOpenUriRequested: function(uri) { testRunner.openedUris = testRunner.openedUris.concat([uri]) }
    onRevealToggleRequested: function(field) { testRunner.revealRequests = testRunner.revealRequests.concat([field]) }
    onSecretCopyRequested: function(field, label) { testRunner.secretCopies = testRunner.secretCopies.concat([field]) }
  }

  Components.VaultItemList {
    id: itemList
    x: 620
    width: 280
    height: 200
    items: [{ id: "markup-1", name: testRunner.markupName, type_name: "login", sub_title: testRunner.markupName }]
    selectedIndex: 0
  }

  Components.PasswordHistoryModal {
    id: historyModal
    active: false
    item: testRunner.loginItem
  }

  Text {
    id: literalReference
    textFormat: Text.PlainText
    text: testRunner.markupName
    font.pixelSize: 12
  }

  // Depth-first search through children and content items, each node once.
  function collect(node, predicate, found, visited) {
    var list = found || []
    var seen = visited || []
    if (!node || seen.indexOf(node) !== -1) return list
    seen.push(node)
    if (predicate(node)) list.push(node)
    var kids = node.children || []
    for (var i = 0; i < kids.length; i++) collect(kids[i], predicate, list, seen)
    if (node.contentItem && node.contentItem !== node) collect(node.contentItem, predicate, list, seen)
    return list
  }

  function byObjectName(root, name) {
    return collect(root, function(node) { return node.objectName === name })
  }

  function visibleTextExists(root, text) {
    return collect(root, function(node) { return node.text === text && isShown(node) }).length > 0
  }

  // Effective visibility up to (not including) the test runner.
  function isShown(node) {
    for (var current = node; current && current !== testRunner; current = current.parent) {
      if (current.visible === false) return false
    }
    return true
  }

  function secretRowValue(label) {
    var rows = collect(inspector, function(node) { return node.label === label && node.hasOwnProperty("displayedText") })
    return rows.length > 0 ? rows[0] : null
  }

  function testLoginMasks() {
    var passwordRow = secretRowValue("Password")
    Assert.check(passwordRow !== null && isShown(passwordRow), "password row shown when has_password is true")
    Assert.check(passwordRow && passwordRow.displayedText === inspector.passwordMask, "password shows the mask until revealed")
    var totp = byObjectName(inspector, "inspectorTotpValue")[0]
    Assert.check(totp && isShown(totp) && totp.text === inspector.totpMask, "TOTP is masked until revealed")
    var notes = byObjectName(inspector, "inspectorNotesValue")[0]
    Assert.check(notes && isShown(notes) && notes.text === inspector.passwordMask, "notes are masked until revealed")
    var pin = secretRowValue("PIN")
    Assert.check(pin && isShown(pin) && pin.displayedText === inspector.passwordMask, "hidden custom field is masked")
    Assert.check(visibleTextExists(inspector, "1234"), "text custom field shows its public value")
    Assert.check(!visibleTextExists(inspector, "Unused"), "custom field without a value is hidden")
    Assert.check(visibleTextExists(inspector, "2 previous passwords"), "password history count comes from password_history_count")
  }

  function testRevealedValuesDisplayed() {
    inspector.requestedFields = ({ "login.password": true, "login.totp": true, "custom.1": true })
    inspector.revealedValues = ({ "login.password": "Correct-Horse", "login.totp": "123456" })
    inspector.totpSecondsRemaining = 17
    Assert.check(secretRowValue("Password").displayedText === "Correct-Horse", "revealed password displayed")
    Assert.check(byObjectName(inspector, "inspectorTotpValue")[0].text === "123456", "revealed TOTP displayed")
    Assert.check(visibleTextExists(inspector, "17 s"), "TOTP countdown displayed while revealed")
    Assert.check(secretRowValue("PIN").displayedText === "Retrieving…", "pending reveal shows the retrieving notice")
    inspector.revealedValues = ({})
    inspector.requestedFields = ({})
    Assert.check(secretRowValue("Password").displayedText === inspector.passwordMask, "cleared value returns to the mask")
  }

  function testUris() {
    var values = byObjectName(inspector, "inspectorUriValue").map(function(node) { return node.text })
    Assert.check(values.indexOf("https://github.com/login?next=%2Fsettings") !== -1, "full https URI displayed, not just scheme://host")
    Assert.check(values.indexOf("file:///etc/passwd") !== -1 && values.indexOf("smb://nas/share") !== -1, "non-web URIs displayed in full")
    var buttons = byObjectName(inspector, "inspectorUriOpenButton")
    Assert.check(buttons.length === 3, "one open button per URI")
    Assert.check(buttons[0].enabled === true, "open enabled for https")
    Assert.check(buttons[1].enabled === false && buttons[2].enabled === false, "open disabled for file:// and smb://")
    buttons[0].clicked()
    Assert.check(openedUris.length === 1 && openedUris[0] === "https://github.com/login?next=%2Fsettings", "open request carries the https URI")
  }

  function testCardAndIdentity() {
    inspector.item = testRunner.cardItem
    var number = secretRowValue("Card Number")
    Assert.check(number && isShown(number) && number.displayedText === "•••• •••• •••• 4444", "card number masked with number_last_four")
    var code = secretRowValue("Security Code")
    Assert.check(code && !isShown(code), "security code row hidden when has_code is false")
    inspector.revealedValues = ({ "card.number": "4111111111114444" })
    Assert.check(number.displayedText === "4111 1111 1111 4444", "revealed card number formatted")
    inspector.revealedValues = ({})
    Assert.check(byObjectName(inspector, "inspectorNotesValue")[0] && !isShown(byObjectName(inspector, "inspectorNotesValue")[0]), "notes hidden when has_notes is false")

    inspector.item = testRunner.identityItem
    var ssn = secretRowValue("Social Security Number")
    Assert.check(ssn && isShown(ssn) && ssn.displayedText === inspector.passwordMask, "SSN masked when has_ssn is true")
    var passport = secretRowValue("Passport Number")
    Assert.check(passport && !isShown(passport), "passport row hidden when has_passport_number is false")
    inspector.item = testRunner.loginItem
  }

  function testMarkupNameRendersLiterally() {
    inspector.item = ({ id: "markup-1", name: testRunner.markupName, type_name: "note", has_notes: false })
    var nameText = byObjectName(inspector, "inspectorItemName")[0]
    Assert.check(nameText.textFormat === Text.PlainText, "inspector item name uses PlainText")
    Assert.check(nameText.text === testRunner.markupName, "inspector item name keeps the literal markup")
    Assert.check(nameText.implicitWidth > 100, "inspector item name lays out the literal characters (" + Math.round(nameText.implicitWidth) + "px)")

    var listTexts = collect(itemList, function(node) { return node.text === testRunner.markupName })
    Assert.check(listTexts.length >= 1, "vault list shows the markup-shaped name")
    listTexts.forEach(function(node) {
      Assert.check(node.textFormat === Text.PlainText, "vault list text uses PlainText")
    })
    Assert.check(literalReference.implicitWidth > 100, "literal reference renders the characters (" + Math.round(literalReference.implicitWidth) + "px)")
    inspector.item = testRunner.loginItem
  }

  function testPasswordHistoryModal() {
    historyModal.active = true
    historyModal.historyEntries = null
    Assert.check(visibleTextExists(historyModal, "Retrieving password history…"), "history modal shows the retrieving notice until entries arrive")
    historyModal.historyEntries = [{ password: "old-1", last_used_date: "2024-01-01T00:00:00Z" }, { password: "old-2", last_used_date: "" }]
    Assert.check(!visibleTextExists(historyModal, "old-1") && !visibleTextExists(historyModal, "old-2"), "history entries are masked until shown")
    Assert.check(collect(historyModal, function(node) { return node.tooltip === "Copy history password" }).length === 0, "history modal offers no copy action")
    historyModal.toggleAllRevealed()
    Assert.check(visibleTextExists(historyModal, "old-1"), "show all reveals the released entries")
    historyModal.historyEntries = null
    Assert.check(!visibleTextExists(historyModal, "old-1"), "concealed history removes the entries")
    historyModal.active = false
  }

  Component.onCompleted: {
    console.log("Running redacted ItemInspector tests...")
    testLoginMasks()
    testRevealedValuesDisplayed()
    testUris()
    testCardAndIdentity()
    testMarkupNameRendersLiterally()
    testPasswordHistoryModal()
    Assert.check(revealRequests.length === 0 && secretCopies.length === 0, "rendering and selection request no release")
    Qt.exit(Assert.exitCode())
  }
}

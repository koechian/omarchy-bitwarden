import QtQuick
import "lib"
import "../components/SecretFieldCatalog.js" as SecretFieldCatalog

// The overlay fails closed on an engine that does not redact: a `vault list`
// reply in which any item carries a secret value (contracts.md 3.2) is
// discarded whole, is never stored in rawVaultItems or
// lastVaultItemsRawText, and the user is told to install the hardened
// engine. The classification runs here against fixtures; the handling in
// OmarchyBitwarden.qml (which needs the Quickshell runtime) is checked at
// the source level.
Item {
  id: testRunner

  // The redacted shape of contracts.md 3.2: flags instead of secrets.
  function redactedLogin() {
    return {
      id: "login-1", name: "GitHub", type: 1, type_name: "login", sub_title: "octocat", favorite: false,
      has_notes: true,
      login: { username: "octocat", uris: [{ uri: "https://github.com" }], has_passkey: false, passkey_created_at: null,
               has_password: true, has_totp: true, has_password_history: true, password_history_count: 2 },
      fields: [
        { index: 0, name: "Account", type: 0, has_value: true, value: "1234" },
        { index: 1, name: "PIN", type: 1, has_value: true },
        { index: 2, name: "2FA on", type: 2, has_value: true, value: "true" },
        { index: 3, name: "Linked", type: 3, has_value: false }
      ]
    }
  }

  function redactedCard() {
    return { id: "card-1", name: "Visa", type: 3, type_name: "card", sub_title: "Visa •••• 4444", favorite: false, has_notes: false,
             card: { cardholderName: "Alice Doe", brand: "Visa", expMonth: "12", expYear: "2028", number_last_four: "4444", has_number: true, has_code: true },
             fields: [] }
  }

  function redactedIdentity() {
    return { id: "identity-1", name: "Alice", type: 4, type_name: "identity", sub_title: "Alice Doe", favorite: false, has_notes: false,
             identity: { title: null, firstName: "Alice", lastName: "Doe", email: "alice@example.com",
                         has_ssn: true, has_passport_number: false, has_license_number: false },
             fields: [] }
  }

  function redactedListing() {
    return [redactedLogin(), redactedCard(), redactedIdentity()]
  }

  // One listing per secret an unredacting engine may send.
  readonly property var leaks: [
    ["notes", function(listing) { listing[0].notes = "private notes" }],
    ["internal search text", function(listing) { listing[0].search_text = "github octocat private notes" }],
    ["login.password", function(listing) { listing[0].login.password = "Correct-Horse-Battery-1" }],
    ["login.totp", function(listing) { listing[0].login.totp = "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP" }],
    ["login.password_history", function(listing) { listing[0].login.password_history = [{ password: "old" }] }],
    ["login.passwordHistory", function(listing) { listing[0].login.passwordHistory = [{ password: "old" }] }],
    ["item passwordHistory", function(listing) { listing[0].passwordHistory = [{ password: "old" }] }],
    ["card.number", function(listing) { listing[1].card.number = "4111111111114444" }],
    ["card.code", function(listing) { listing[1].card.code = "123" }],
    ["identity.ssn", function(listing) { listing[2].identity.ssn = "123-45-6789" }],
    ["identity.passportNumber", function(listing) { listing[2].identity.passportNumber = "X1234567" }],
    ["identity.licenseNumber", function(listing) { listing[2].identity.licenseNumber = "D1234567" }],
    ["hidden custom field value", function(listing) { listing[0].fields[1].value = "0000" }],
    ["linked custom field value", function(listing) { listing[0].fields[3].value = "linked-secret" }],
    ["custom field of an unknown type", function(listing) { listing[1].fields = [{ index: 0, name: "Future", type: 9, value: "future-secret" }] }]
  ]

  function readSource(path) {
    var request = new XMLHttpRequest()
    request.open("GET", path, false)
    request.send()
    return request.responseText || ""
  }

  function functionBody(source, name) {
    var start = source.indexOf("function " + name + "(")
    if (start === -1) return ""
    var open = source.indexOf("{", start)
    var depth = 0
    for (var i = open; i < source.length; i++) {
      if (source[i] === "{") depth++
      else if (source[i] === "}" && --depth === 0) return source.substring(open, i + 1)
    }
    return ""
  }

  function testClassification() {
    Assert.check(SecretFieldCatalog.classifyVaultListing(redactedListing()) === SecretFieldCatalog.LISTING_REDACTED, "a redacted listing is accepted")
    Assert.check(SecretFieldCatalog.classifyVaultListing([]) === SecretFieldCatalog.LISTING_REDACTED, "an empty listing is accepted")
    leaks.forEach(function(leak) {
      var listing = redactedListing()
      leak[1](listing)
      Assert.check(SecretFieldCatalog.classifyVaultListing(listing) === SecretFieldCatalog.LISTING_UNREDACTED, "a listing carrying " + leak[0] + " is rejected")
    })
    var empty = redactedListing()
    empty[0].notes = null
    empty[0].login.password = ""
    empty[0].login.password_history = []
    empty[0].fields[1].value = null
    Assert.check(SecretFieldCatalog.classifyVaultListing(empty) === SecretFieldCatalog.LISTING_REDACTED, "absent, null or empty secret keys carry no secret")
    Assert.check(SecretFieldCatalog.classifyVaultListing({ ok: false, error: "Vault is locked", error_code: "vault_locked" }) === SecretFieldCatalog.LISTING_NOT_A_LISTING, "an error envelope is not a listing")
    Assert.check(SecretFieldCatalog.classifyVaultListing(null) === SecretFieldCatalog.LISTING_NOT_A_LISTING, "a missing reply is not a listing")
    Assert.check(SecretFieldCatalog.classifyVaultListing([null, 7, "x"]) === SecretFieldCatalog.LISTING_REDACTED, "entries that are not objects carry no secret")
  }

  function testOverlayHandling() {
    var root = readSource(Qt.resolvedUrl("../OmarchyBitwarden.qml"))
    Assert.check(root.length > 0, "OmarchyBitwarden.qml readable (set QML_XHR_ALLOW_FILE_READ=1)")
    var apply = functionBody(root, "applyVaultListing")
    Assert.check(/SecretFieldCatalog\.classifyVaultListing\(listing\)/.test(apply), "every listing is classified before it is used")
    Assert.check(/LISTING_UNREDACTED\] = root\.rejectUnredactedListing/.test(apply) && /LISTING_REDACTED\] = root\.storeVaultListing/.test(apply), "only a redacted listing is stored; an unredacted one is rejected")
    Assert.check((root.match(/root\.rawVaultItems = listing/g) || []).length === 1 && /root\.rawVaultItems = listing/.test(functionBody(root, "storeVaultListing")), "rawVaultItems is assigned a listing only in storeVaultListing")
    Assert.check((root.match(/root\.lastVaultItemsRawText = (?!"")/g) || []).length === 1 && /root\.lastVaultItemsRawText = rawText/.test(functionBody(root, "storeVaultListing")), "the raw listing text is kept only for a stored listing")
    var reject = functionBody(root, "rejectUnredactedListing")
    Assert.check(/root\.discardVaultListing\(\)/.test(reject), "an unredacted listing is discarded")
    Assert.check(/root\.errorMessage = root\.strings\.t\("error\.engine_not_redacting"/.test(reject) && /minimumEngineVersion/.test(reject), "the user is told to install the hardened engine")
    var discard = functionBody(root, "discardVaultListing")
    Assert.check(/root\.rawVaultItems = \[\]/.test(discard) && /root\.lastVaultItemsRawText = ""/.test(discard) && /root\.filteredItems = \[\]/.test(discard), "discarding clears every copy of the listing")
    Assert.check(/root\.applyVaultListing\(JSON\.parse\(cleanText\), cleanText\)/.test(root), "the list reply goes straight to applyVaultListing")
    var catalog = JSON.parse(readSource(Qt.resolvedUrl("../i18n/en.json")))
    Assert.check(String(catalog["error.engine_not_redacting"] || "").indexOf("%1") !== -1, "the error names the minimum engine version")
  }

  Component.onCompleted: {
    console.log("Running unredacted listing rejection tests...")
    testClassification()
    testOverlayHandling()
    Qt.exit(Assert.exitCode())
  }
}

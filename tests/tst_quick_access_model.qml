import QtQuick
import "lib"
import "../components/QuickAccessModel.js" as QuickAccessModel

// State and ranking of the bar dropdown: which view an `auth status` reply
// selects, which items are listed, what each row can copy, and that a
// listing carrying secrets is refused.
Item {
  id: testRunner

  readonly property var items: [
    { id: "1", name: "github", type_name: "login", favorite: false,
      login: { username: "octocat", has_password: true, has_totp: true } },
    { id: "2", name: "Amazon", type_name: "login", favorite: false,
      login: { username: "", has_password: true, has_totp: false } },
    { id: "3", name: "Zulip", type_name: "login", favorite: true,
      login: { username: "zed", has_password: false, has_totp: false } },
    { id: "4", name: "Visa", type_name: "card", favorite: true,
      card: { has_number: true } },
    { id: "5", name: "Empty", type_name: "login", favorite: false,
      login: { username: "", has_password: false, has_totp: false } }
  ]

  function ids(list) {
    return list.map(function(item) { return item.id }).join(",")
  }

  Component.onCompleted: {
    console.log("Running quick access model tests...")

    // 1. Views selected by `auth status`.
    Assert.check(QuickAccessModel.viewForAuthStatus('{"status":"unlocked","has_session":true}') === QuickAccessModel.VIEW_UNLOCKED, "unlocked status shows the list")
    Assert.check(QuickAccessModel.viewForAuthStatus('{"status":"locked","has_session":true}') === QuickAccessModel.VIEW_LOCKED, "locked status with a session shows the password field")
    Assert.check(QuickAccessModel.viewForAuthStatus('{"status":"locked","has_session":false}') === QuickAccessModel.VIEW_SIGNED_OUT, "locked status without a session asks to sign in")
    Assert.check(QuickAccessModel.viewForAuthStatus('{"status":"unauthenticated"}') === QuickAccessModel.VIEW_SIGNED_OUT, "unauthenticated status asks to sign in")
    Assert.check(QuickAccessModel.viewForAuthStatus("") === QuickAccessModel.VIEW_ENGINE_UNAVAILABLE, "no reply means the engine is unavailable")
    Assert.check(QuickAccessModel.viewForAuthStatus("not json") === QuickAccessModel.VIEW_ENGINE_UNAVAILABLE, "an unparsable reply means the engine is unavailable")
    Assert.check(QuickAccessModel.viewForAuthStatus('{"ok":false}') === QuickAccessModel.VIEW_ENGINE_UNAVAILABLE, "a reply without a status means the engine is unavailable")

    // 2. Listed items and ranking.
    Assert.check(ids(QuickAccessModel.rankItems(items, "")) === "3,2,1", "empty query lists login items, favourites first, then by name ignoring case")
    Assert.check(ids(QuickAccessModel.rankItems(items, "git")) === "1", "a query ranks with the overlay's search")
    Assert.check(ids(QuickAccessModel.rankItems(items, "visa")) === "", "cards are not listed")
    Assert.check(ids(QuickAccessModel.rankItems(items, "empty")) === "", "a login with nothing to copy is not listed")
    Assert.check(QuickAccessModel.rankItems(null, "").length === 0, "a missing listing lists nothing")

    // 3. Copy actions.
    Assert.check(QuickAccessModel.canCopy(items[0], QuickAccessModel.COPY_USERNAME), "a username can be copied")
    Assert.check(QuickAccessModel.canCopy(items[0], QuickAccessModel.COPY_TOTP), "a code can be copied when the item has TOTP")
    Assert.check(!QuickAccessModel.canCopy(items[1], QuickAccessModel.COPY_USERNAME), "an empty username cannot be copied")
    Assert.check(!QuickAccessModel.canCopy(items[1], QuickAccessModel.COPY_TOTP), "no code without TOTP")
    Assert.check(!QuickAccessModel.canCopy(items[0], "notes"), "unknown copy kinds are refused")
    Assert.check(QuickAccessModel.primaryCopyKind(items[0]) === QuickAccessModel.COPY_PASSWORD, "Enter copies the password")
    Assert.check(QuickAccessModel.primaryCopyKind(items[2]) === QuickAccessModel.COPY_USERNAME, "Enter copies the username when there is no password")
    Assert.check(QuickAccessModel.primaryCopyKind(items[4]) === "", "Enter copies nothing when there is nothing to copy")
    Assert.check(QuickAccessModel.secretField(QuickAccessModel.COPY_PASSWORD) === "login.password", "password copies use the login.password field")
    Assert.check(QuickAccessModel.secretField(QuickAccessModel.COPY_TOTP) === "login.totp", "code copies use the login.totp field")
    Assert.check(QuickAccessModel.secretField(QuickAccessModel.COPY_USERNAME) === "", "usernames are not released by the daemon")

    // 4. Paste sequence and details.
    Assert.check(QuickAccessModel.canCopySequence(items[0]), "the paste sequence needs a password and a code")
    Assert.check(!QuickAccessModel.canCopySequence(items[1]), "no paste sequence without a code")
    Assert.check(!QuickAccessModel.canCopySequence(items[2]), "no paste sequence without a password")
    Assert.check(JSON.stringify(QuickAccessModel.sequenceArguments("-x1")) === JSON.stringify(["vault", "copy-sequence", "--id=-x1", "--fields=login.password,login.totp"]), "sequence argv carries only the id and the fields, password first")
    Assert.check(QuickAccessModel.websiteOf({ login: { uris: [{ uri: "" }, { uri: "https://a.example" }] } }) === "https://a.example", "the first non-empty website is shown")
    Assert.check(QuickAccessModel.websiteOf({ login: { uris: ["https://b.example"] } }) === "https://b.example", "plain string websites are shown")
    Assert.check(QuickAccessModel.websiteOf(items[1]) === "" && QuickAccessModel.websiteOf(null) === "", "no website without URIs")
    Assert.check(QuickAccessModel.copyConfirmation(QuickAccessModel.COPY_PASSWORD, 30) === "Password copied. The clipboard clears in 30 s.", "confirmation names the clear delay")
    Assert.check(QuickAccessModel.copyConfirmation(QuickAccessModel.COPY_USERNAME, 0) === "Username copied.", "confirmation without a clear delay")

    // 5. Listings.
    var redacted = JSON.stringify([{ id: "1", name: "a", type_name: "login", login: { username: "u", has_password: true } }])
    var unredacted = JSON.stringify([{ id: "1", name: "a", type_name: "login", login: { username: "u", password: "hunter2" } }])
    Assert.check(QuickAccessModel.redactedListing(redacted).length === 1, "a redacted listing is accepted")
    Assert.check(QuickAccessModel.redactedListing(unredacted) === null, "a listing carrying a password is refused")
    Assert.check(QuickAccessModel.redactedListing('{"ok":false,"error_code":"vault_locked"}') === null, "an error envelope is not a listing")
    Assert.check(QuickAccessModel.redactedListing("") === null, "an empty reply is not a listing")

    // 6. Selection bounds.
    Assert.check(QuickAccessModel.clampIndex(5, 3) === 2 && QuickAccessModel.clampIndex(-1, 3) === 0, "selection stays inside the list")
    Assert.check(QuickAccessModel.clampIndex(0, 0) === -1, "an empty list has no selection")

    Qt.exit(Assert.exitCode())
  }
}

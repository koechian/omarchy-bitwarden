import QtQuick
import "lib"
import "../components/VaultSearch.js" as VaultSearch

// Local search over redacted items: public fields are searchable, secrets
// are not present to search, and scope filters behave as before.
Item {
  id: testRunner

  readonly property var items: [
    { id: "1", name: "GitHub", type_name: "login", sub_title: "octocat", favorite: false,
      login: { username: "octocat", uris: [{ uri: "https://github.com/login" }], has_password: true },
      has_notes: true, folder_name: "Work", folder_id: "f-work" },
    { id: "2", name: "Visa", type_name: "card", sub_title: "Visa •••• 4444", favorite: true,
      card: { brand: "Visa", cardholderName: "Alice Doe", number_last_four: "4444", has_number: true }, has_notes: false,
      organization_id: "org-1", organization_name: "Acme" },
    { id: "3", name: "Recovery", type_name: "note", sub_title: "Secure Note", has_notes: true,
      fields: [{ index: 0, name: "Account", type: 0, has_value: true, value: "ACC-778" }, { index: 1, name: "PIN", type: 1, has_value: true }] }
  ]

  function ids(list) {
    return list.map(function(item) { return item.id }).join(",")
  }

  Component.onCompleted: {
    console.log("Running local vault search tests...")
    var all = { vaultScope: "all", folderScope: "all", category: "all" }
    Assert.check(ids(VaultSearch.filterItems(items, "", all)) === "2,1,3", "empty query lists favorites first")
    Assert.check(ids(VaultSearch.filterItems(items, "github.com", all)) === "1", "URIs are searchable")
    Assert.check(ids(VaultSearch.filterItems(items, "4444", all)) === "2", "card last four digits are searchable")
    Assert.check(ids(VaultSearch.filterItems(items, "acc-778", all)) === "3", "public custom field values are searchable")
    Assert.check(ids(VaultSearch.filterItems(items, "work", all)) === "1", "folder names are searchable")
    Assert.check(ids(VaultSearch.filterItems(items, "gthb", all)) === "1", "subsequence fallback on names")
    Assert.check(VaultSearch.filterItems(items, "github zzz", all).length === 0, "every word must match")
    Assert.check(ids(VaultSearch.filterItems(items, "", { vaultScope: "personal", folderScope: "all", category: "all" })) === "1,3", "personal scope excludes organization items")
    Assert.check(ids(VaultSearch.filterItems(items, "", { vaultScope: "org-1", folderScope: "all", category: "all" })) === "2", "organization scope")
    Assert.check(ids(VaultSearch.filterItems(items, "", { vaultScope: "all", folderScope: "none", category: "all" })) === "2,3", "no-folder scope")
    Assert.check(ids(VaultSearch.filterItems(items, "", { vaultScope: "all", folderScope: "all", category: "note" })) === "3", "category filter")
    var searchText = VaultSearch.buildSearchText(items[2])
    Assert.check(searchText.indexOf("pin") !== -1 && searchText.indexOf("undefined") === -1, "hidden custom fields contribute their name only")
    Assert.check(VaultSearch.indexOfItem(items, "3") === 2 && VaultSearch.indexOfItem(items, "missing") === 0, "selection index lookup")
    // Recent use.
    var used = [
      { id: "a", name: "Alpha", type_name: "login", favorite: false, usage_score: 0, login: { username: "a" } },
      { id: "b", name: "Alpine", type_name: "login", favorite: false, usage_score: 2.5, login: { username: "b" } },
      { id: "c", name: "Alps", type_name: "login", favorite: false, usage_score: 0.05, login: { username: "c" } },
      { id: "d", name: "Beta", type_name: "login", favorite: false, usage_score: 4, login: { username: "d" } },
      { id: "e", name: "Gamma", type_name: "login", favorite: false, usage_score: "junk", login: { username: "e" } }
    ]
    var recent = { vaultScope: "all", folderScope: "all", category: "recent" }
    Assert.check(ids(VaultSearch.filterItems(used, "", recent)) === "d,b", "the recent category lists items from the minimum score, most used first")
    Assert.check(ids(VaultSearch.filterItems(used, "alp", recent)) === "b", "a query inside the recent category keeps to recent items")
    Assert.check(ids(VaultSearch.filterItems(used, "alp", all)) === "b,c,a", "recent use orders matches of the same strength")
    Assert.check(ids(VaultSearch.filterItems(used, "alpha", all))[0] === "a", "recent use never outranks a stronger match")
    var favouriteAndUsed = [
      { id: "u", name: "Used", type_name: "login", favorite: false, usage_score: 5 },
      { id: "f", name: "Favourite", type_name: "login", favorite: true, usage_score: 0 }
    ]
    Assert.check(ids(VaultSearch.filterItems(favouriteAndUsed, "", all)) === "f,u", "without a query recent use does not outrank a favourite")
    Assert.check(VaultSearch.usageScore(used[4]) === 0 && VaultSearch.usageScore(null) === 0, "a missing or malformed score counts as never used")
    Assert.check(VaultSearch.usageBoost({ usage_score: 100 }) === 300, "the boost is capped")
    Qt.exit(Assert.exitCode())
  }
}

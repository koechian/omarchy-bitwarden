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
    Qt.exit(Assert.exitCode())
  }
}

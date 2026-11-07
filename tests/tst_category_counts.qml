import QtQuick
import "lib"
import "../components" as Components

// CategoryTabBar counts the items of each category inside the active vault
// and folder scopes, with the same scope rules as the item list
// (VaultSearch.matchVaultScope / matchFolderScope). The reference below is
// the counting rule the tab bar has always applied; every category, vault
// scope and folder scope combination must give the same count.
Item {
  id: testRunner
  width: 600
  height: 100

  readonly property var items: [
    { id: "1", type_name: "login" },
    { id: "2", type_name: "login", folder_id: "f-work", folder_name: "Work" },
    { id: "3", type_name: "card", organization_id: "org-acme", organization_name: "Acme" },
    { id: "4", type_name: "card", organization_id: "org-acme", organization_name: "Acme", folder_id: "f-work", folder_name: "Work" },
    { id: "5", type_name: "identity", folder_name: "Personal" },
    { id: "6", type_name: "note", organization_id: "org-beta" },
    { id: "7", type_name: "note", folder_id: "f-home" },
    { id: "8", type_name: "login", organization_name: "Acme" }
  ]
  readonly property var vaultScopes: ["all", "", "personal", "org-acme", "Acme", "org-beta", "org-missing"]
  readonly property var folderScopes: ["all", "", "none", "f-work", "Work", "Personal", "f-home", "f-missing"]
  readonly property var categories: ["all", "login", "card", "identity", "note"]

  Components.CategoryTabBar {
    id: tabBar
    rawVaultItems: testRunner.items
  }

  function referenceInScope(item, vaultScope, folderScope) {
    var inVault = vaultScope === "all"
      || (vaultScope === "personal" ? !item.organization_id : (item.organization_id === vaultScope || item.organization_name === vaultScope))
    var inFolder = folderScope === "all"
      || (folderScope === "none" ? !(item.folder_id || item.folder_name) : (item.folder_id === folderScope || item.folder_name === folderScope))
    return inVault && inFolder
  }

  function referenceCount(category, vaultScope, folderScope) {
    var vault = vaultScope || "all"
    var folder = folderScope || "all"
    return items.filter(function(item) {
      return referenceInScope(item, vault, folder) && (category === "all" || item.type_name === category)
    }).length
  }

  function checkCombination(category, vaultScope, folderScope) {
    tabBar.activeVaultScope = vaultScope
    tabBar.activeFolderScope = folderScope
    var expected = referenceCount(category, vaultScope, folderScope)
    var actual = tabBar.getCategoryCount(category)
    if (actual !== expected) {
      Assert.check(false, "count of " + category + " in vault " + JSON.stringify(vaultScope) + ", folder " + JSON.stringify(folderScope) + ": expected " + expected + ", got " + actual)
      return 1
    }
    return 0
  }

  Component.onCompleted: {
    console.log("Running category count tests...")
    var mismatches = 0
    var combinations = 0
    categories.forEach(function(category) {
      vaultScopes.forEach(function(vaultScope) {
        folderScopes.forEach(function(folderScope) {
          mismatches += checkCombination(category, vaultScope, folderScope)
          combinations++
        })
      })
    })
    Assert.check(mismatches === 0, "category counts match the scope rules in all " + combinations + " combinations")

    tabBar.activeVaultScope = "all"
    tabBar.activeFolderScope = "all"
    Assert.check(tabBar.getCategoryCount("all") === 8 && tabBar.getCategoryCount("login") === 3, "unscoped counts: 8 items, 3 logins")
    tabBar.activeVaultScope = "personal"
    tabBar.activeFolderScope = "none"
    Assert.check(tabBar.getCategoryCount("all") === 2 && tabBar.getCategoryCount("login") === 2, "personal items (no organization id) outside any folder: two logins")
    tabBar.rawVaultItems = []
    Assert.check(tabBar.getCategoryCount("all") === 0, "an empty vault counts zero")
    tabBar.rawVaultItems = null
    Assert.check(tabBar.getCategoryCount("login") === 0, "a missing listing counts zero")
    Qt.exit(Assert.exitCode())
  }
}

import QtQuick

// Stand-in for Omarchy's qs.Commons Translations, whose real implementation
// reads catalogs through Quickshell's FileView. Reads `<directory>/en.json`
// with XMLHttpRequest instead (the suites run with QML_XHR_ALLOW_FILE_READ=1)
// and implements t() / tn() with English plural rules.
QtObject {
  id: root

  property var directory: ""
  readonly property var strings: root.loadCatalog(root.directory)

  function loadCatalog(directoryUrl) {
    var path = String(directoryUrl || "").replace(/\/+$/, "")
    if (!path) return ({})
    var request = new XMLHttpRequest()
    request.open("GET", path + "/en.json", false)
    request.send()
    try {
      var parsed = JSON.parse(request.responseText || "{}")
      return (parsed && typeof parsed === "object") ? parsed : ({})
    } catch (e) {
      return ({})
    }
  }

  function t(key, fallback) {
    var value = root.strings[key]
    if (value && typeof value === "object") value = value.other
    if (typeof value === "string" && value.length > 0) return value
    return fallback !== undefined ? fallback : key
  }

  function tn(key, count, fallback) {
    var value = root.strings[key]
    if (value && typeof value === "object") value = (count === 1 && value.one) ? value.one : value.other
    if (typeof value === "string" && value.length > 0) return value
    return fallback !== undefined ? fallback : key
  }
}

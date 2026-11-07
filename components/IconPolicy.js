.pragma library

function extractHost(serverUrl) {
  if (!serverUrl) return ""
  var str = String(serverUrl).trim()
  var match = str.match(/^(?:https?:\/\/)?(?:[^@\n]+@)?([^:\/\n?#]+)/i)
  return match ? match[1].toLowerCase() : ""
}

function extractOrigin(serverUrl) {
  if (!serverUrl) return ""
  var str = String(serverUrl).trim()
  if (!str.match(/^https?:\/\//i)) {
    str = "https://" + str
  }
  var match = str.match(/^(https?:\/\/[^\/\s?#]+)/i)
  return match ? match[1].toLowerCase() : ""
}

function isSameOrigin(urlA, urlB) {
  var origA = extractOrigin(urlA)
  var origB = extractOrigin(urlB)
  return Boolean(origA && origB && origA === origB)
}

function isOfficialServer(serverUrl) {
  var host = extractHost(serverUrl)
  if (!host) return true
  return host === "bitwarden.com" || host.endsWith(".bitwarden.com") ||
         host === "bitwarden.eu" || host.endsWith(".bitwarden.eu")
}

function urlToLocalPath(fileUrl) {
  if (!fileUrl) return ""
  var str = String(fileUrl)
  if (str.indexOf("file://") === 0) {
    str = str.substring(7)
  }
  return decodeURIComponent(str)
}


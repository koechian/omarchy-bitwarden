import QtQuick
import "lib"
import "../components" as Components

// The password generator's coloured output is the overlay's only RichText
// sink. Its content is escaped by the component itself, so markup-shaped
// generator output renders literally and loads nothing.
Item {
  id: testRunner
  width: 480
  height: 360

  readonly property string markupShapedOutput: "<img src=\"https://example.invalid/x\">&amp;'1"

  Components.PasswordGeneratorModal {
    id: generatorModal
    active: false
    width: 480
    height: 360
  }

  function findByObjectName(item, name) {
    if (!item) return null
    if (item.objectName === name) return item
    var kids = item.children
    for (var i = 0; i < kids.length; i++) {
      var found = testRunner.findByObjectName(kids[i], name)
      if (found) return found
    }
    return null
  }

  Component.onCompleted: {
    console.log("Running RichText escaping tests...")
    var styled = generatorModal.formatStyledPassword(testRunner.markupShapedOutput)
    Assert.check(styled.indexOf("<img") === -1 && styled.indexOf("&lt;img") !== -1, "generator escapes '<' before the RichText sink")
    Assert.check(styled.indexOf("&amp;amp;") !== -1, "generator escapes '&' so entities stay literal")
    Assert.check(styled.indexOf("&quot;") !== -1 && styled.indexOf("&#39;") !== -1, "generator escapes both quote characters")
    Assert.check(/<font color='#[0-9a-fA-F]{6,8}'>1<\/font>/.test(styled), "digits are coloured with the theme accent only")

    generatorModal.generatedPassword = testRunner.markupShapedOutput
    var sink = testRunner.findByObjectName(generatorModal, "generatedPasswordText")
    Assert.check(sink !== null && sink.textFormat === TextEdit.RichText, "generator output sink is the RichText TextEdit")
    var rendered = sink ? sink.getText(0, sink.length) : ""
    Assert.check(rendered === testRunner.markupShapedOutput, "markup-shaped generator output renders literally: " + rendered)
    Qt.exit(Assert.exitCode())
  }
}

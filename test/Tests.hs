import ConfCrypt.Parser.Tests (parserTests)
import ConfCrypt.Commands.Tests (commandTests)
import ConfCrypt.Encryption.Tests (encryptionTests)
import ConfCrypt.CLI.API.Tests (cliAPITests)
import ConfCrypt.Template.Tests (templateTests)
import Test.Tasty (TestTree, defaultMain, testGroup)

main :: IO ()
main = defaultMain $ testGroup "all tests" [
    appTests,
    libraryTests
    ]

appTests :: TestTree
appTests = testGroup "all application tests" [
    cliAPITests
    ]

libraryTests :: TestTree
libraryTests = testGroup "all library tests"[
    parserTests,
    commandTests,
    encryptionTests,
    templateTests
    ]

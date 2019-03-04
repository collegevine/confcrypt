module Tests (appTests, libraryTests) where
    
import ConfCrypt.Parser.Tests (parserTests)
import ConfCrypt.Commands.Tests (commandTests)
import ConfCrypt.Encryption.Tests (encryptionTests)
import ConfCrypt.CLI.API.Tests (cliAPITests)
import Test.Tasty (TestTree, testGroup)

appTests :: TestTree
appTests = testGroup "all application tests" [
    cliAPITests
    ]

libraryTests :: TestTree
libraryTests = testGroup "all library tests"[
    parserTests,
    commandTests,
    encryptionTests
    ]

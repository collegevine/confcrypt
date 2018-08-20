import ConfCrypt.Parser.Tests (parserTests)
import Test.Tasty (TestTree, defaultMain, testGroup)

main :: IO ()
main = defaultMain $ testGroup "all tests" [
    appTests,
    libraryTests
    ]

appTests :: TestTree
appTests = testGroup "all application tests" [
    ]

libraryTests :: TestTree
libraryTests = testGroup "all library tests"[
    parserTests
    ]

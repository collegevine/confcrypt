import Tests
import Test.Tasty (defaultMain, testGroup)

main :: IO ()
main = defaultMain $ testGroup "all tests" [
    appTests,
    libraryTests
    ]
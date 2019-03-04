import Tests
import Test.Tasty (defaultMainWithIngredients, testGroup)
import Test.Tasty.Ingredients.ConsoleReporter (consoleTestReporter)
import ConsoleReporter (thresholdRunner)

main :: IO ()
main = defaultMainWithIngredients [thresholdRunner, consoleTestReporter]
     $ testGroup "all tests" [
     appTests,
     libraryTests
     ]
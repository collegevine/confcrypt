module Main where

import ConfCrypt.CLI.Engine (run)
import ConfCrypt.CLI.API (cliParser)
import System.Environment (getArgs)
import Data.Foldable (traverse_)
import Data.Text (Text, intercalate, unpack)
import Options.Applicative (customExecParser, ParserPrefs, prefs, showHelpOnEmpty)

main :: IO ()
main = do
    parsedArguments <- customExecParser (prefs showHelpOnEmpty) cliParser
    results <- run parsedArguments
    traverse_ (putStrLn . unpack) results
    -- The ^ `putStrLn` call is important to preserve the trailing newline. Consider
    -- moving this into the library to make the code read more clearly.
    -- There's no reason that `writeFullContentsToBuffer` can't tag each line with a trailing newline

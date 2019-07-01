module Main where

import ConfCrypt.CLI.Engine (run)
import ConfCrypt.CLI.API (cliParser)
import System.Environment (getArgs)
import Data.Foldable (traverse_)
import Data.Text (Text, intercalate, unpack)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import Options.Applicative (customExecParser, ParserPrefs, prefs, showHelpOnEmpty)

main :: IO ()
main = do
    parsedArguments <- customExecParser (prefs showHelpOnEmpty) cliParser
    (results, outputPath) <- run parsedArguments
    case outputPath of
        Nothing -> traverse_ (putStrLn . unpack) results
        Just fp -> T.writeFile fp $ T.intercalate "\n" results <> "\n"
    -- The ^ `putStrLn` call is important to preserve the trailing newline. Consider
    -- moving this into the library to make the code read more clearly.
    -- There's no reason that `writeFullContentsToBuffer` can't tag each line with a trailing newline

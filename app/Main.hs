module Main where

import ConfCrypt.CLI.Engine (run)
import ConfCrypt.CLI.API (cliParser)
import System.Environment (getArgs)
import Data.Foldable (traverse_)
import Data.Text (Text, intercalate, unpack)
import Options.Applicative (execParser)

main :: IO ()
main = do
    parsedArguments <- execParser cliParser
    results <- run parsedArguments
    traverse_ (putStrLn . unpack) results

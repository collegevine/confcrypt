module Main where

import ConfCrypt.CLI.Engine (run)
import System.Environment (getArgs)
import Data.Foldable (traverse_)
import Data.Text (Text, intercalate, unpack)

main :: IO ()
main = do
    args <- getArgs
    results <- run args
    traverse_ (putStrLn . unpack) results

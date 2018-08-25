module ConfCrypt.CLI.API (
    KeyAndConf(..),
    Conf(..),
    AnyCommand(..),
    cliParser
) where

import ConfCrypt.Commands (AddConfCrypt(..), EditConfCrypt(..), DeleteConfCrypt(..))

import Options.Applicative

data KeyAndConf = KeyAndConf {key :: FilePath, conf :: FilePath}
    deriving (Eq, Show)
newtype Conf = Conf FilePath
    deriving (Eq, Show)

data AnyCommand
    = RC KeyAndConf
    | AC KeyAndConf AddConfCrypt
    | EC KeyAndConf EditConfCrypt
    | WC KeyAndConf
    | DC Conf DeleteConfCrypt
    | VC KeyAndConf
    deriving (Eq, Show)

cliParser :: ParserInfo AnyCommand
cliParser = undefined

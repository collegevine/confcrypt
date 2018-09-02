module ConfCrypt.Default (
    defaultConf,
    defaultLines,
    emptyConfCryptFile
    ) where

import ConfCrypt.Parser (parseConfCrypt)
import ConfCrypt.Types

import Data.Either (fromRight)
import qualified Data.Map as M
import qualified Data.Text as T

defaultConf :: T.Text
defaultConf = "# confcrypt schema#more things\n\
    \# Configuration parameters may be either a String, Int, or Boolean\n\
    \# Parameter schema take the following shape:\n\
    \# schema := [term | value | comment]\n\
    \#   term := confname : type\n\
    \#   confname := [a-z,A-Z,_,0-9]\n\
    \#   type := String | Int | Boolean\n\
    \#   value := confname = String\n\
    \#   comment := # String\n\

    \# For example:\n\
    \DB_CONN_STR : String\n\
    \DB_CONN_STR = Connection String\n\
    \ USE_SSL : Boolean\n\
    \ USE_SSL = True\n\
    \ TIMEOUT_MS : Int\n\
    \ TIMEOUT_MS = 300"

emptyConfCryptFile :: ConfCryptFile
emptyConfCryptFile = ConfCryptFile {
    fileName = "empty",
    fileContents = M.empty,
    parameters = []
    }

defaultLines :: ConfCryptFile
defaultLines = fromRight emptyConfCryptFile $ parseConfCrypt "default Config" defaultConf
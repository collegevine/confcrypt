module ConfCrypt.Parser.Tests (
    parserTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Parser (parseConfCrypt)

import Data.Either (isRight)
import qualified Data.Text as T
import qualified Data.Map as M
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit


parserTests :: TestTree
parserTests = testGroup "config file parser" [
    properties,
    explicitFiles
    ]
properties :: TestTree
properties = testGroup "parser properties" [
    ]

explicitFiles :: TestTree
explicitFiles = testGroup "specific test files" [
    testCase "default config" $ do
        let res = parseConfCrypt "default config" defaultConf
        isRight res @=? True
   ,testCase "empty config" $ do
        let res = parseConfCrypt "empty conf" ""
        isRight res @=? True
   ,testCase "all comments" $ do
        let res = parseConfCrypt "all comments" allComments
        isRight res @=? True
   ,testCase "multiple line breaks" $ do
        let res = parseConfCrypt "line breaks" multipleLineBreaks
        isRight res @=? True
   ,testCase "requires a trailing newline" $ do
        let Right res = parseConfCrypt "No newline" "# {"
            Right res' = parseConfCrypt "No newline" "# {\n"
        M.size (fileContents res) @=? 0
        M.size (fileContents res') @=? 1
    ,testCase "Can parse simple param schema pair" $ do
        let simplePair = "T : INT\n\
                         \T = D\n\
                         \Y : INT\n\
                         \Y = l\499890\n"
            Right res = parseConfCrypt "simple pairs" simplePair
        M.size (fileContents res) @=? 4
        length (parameters res) @=? 2
    ,testCase "Types are case insensitive" $ do
        let simplePair = "T : InT\n\
                         \T = D\n\
                         \Y : int\n\
                         \Y = l\499890\n"
            Right res = parseConfCrypt "simple pairs" simplePair
        M.size (fileContents res) @=? 4
        length (parameters res) @=? 2
    ]



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

allComments :: T.Text
allComments = "# Configuration parameters may be either a String, Int, or Boolean\n\
    \# Parameter schema take the following shape:\n\
    \# schema := [term | value | comment]\n\
    \#   term := confname : type\n\
    \#   confname := [a-z,A-Z,_,0-9]\n\
    \#   type := String | Int | Boolean\n\
    \#   value := confname = String\n\
    \#   comment := # String\n"

multipleLineBreaks :: T.Text
multipleLineBreaks = "# For example:\n\n\n\
    \DB_CONN_STR : String\n\n\
    \DB_CONN_STR = Connection String\n\
    \ USE_SSL : Boolean\n\n\n\n\
    \ USE_SSL = True\n\n\
    \ TIMEOUT_MS : Int\n\
    \ TIMEOUT_MS = 300"
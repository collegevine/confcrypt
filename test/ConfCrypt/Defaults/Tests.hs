module ConfCrypt.Defaults.Tests (
    defaultInfoTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Defaults (defaultLines)

import qualified Data.Map as M
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit

defaultInfoTests :: TestTree
defaultInfoTests = testGroup "defaults" [
    testCase "defaultLines represents the proper file" $ do
        (parameters defaultLines) @=? [
            Parameter {paramName = "DB_CONN_STR", paramValue = "Connection String", paramType = Just CString},
            Parameter {paramName = "USE_SSL", paramValue = "True", paramType = Just CBoolean}
            ]
        (fileContents defaultLines) @=? M.fromList [
            (CommentLine {cText = "  comment := # String"},LineNumber 9),
            (CommentLine {cText = "  confname := [a-z,A-Z,_,0-9]"},LineNumber 6),
            (CommentLine {cText = "  term := confname : type"},LineNumber 5),
            (CommentLine {cText = "  type := String | Int | Boolean"},LineNumber 7),
            (CommentLine {cText = "  value := confname = String"},LineNumber8),
            (CommentLine {cText = "Configuration parameters may be either a String, Int, or Boolean"},LineNumber 2),
            (CommentLine {cText = "For example:"},LineNumber 10),
            (CommentLine {cText = "Parameter schema take the following shape:"},LineNumber 3),
            (CommentLine {cText = "confcrypt schema#more things"},LineNumber 1),
            (CommentLine {cText = "schema := [term | value | comment]"},LineNumber 4),
            (SchemaLine (Schema {sName = "DB_CONN_STR", sType = CString}),LineNumber 11),
            (SchemaLine (Schema {sName = "TIMEOUT_MS", sType = CInt}),LineNumber 15),
            (SchemaLine (Schema {sName = "USE_SSL", sType = CBoolean}),LineNumber 13),
            (ParameterLine (ParamLine {pName = "DB_CONN_STR", pValue = "Connection String"}),LineNumber 12),(ParameterLine (ParamLine {pName = "USE_SSL", pValue = "True"}),LineNumber 14)
            ]

    ]

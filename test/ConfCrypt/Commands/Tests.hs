module ConfCrypt.Commands.Tests (
    commandTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Commands
import ConfCrypt.Parser

import ConfCrypt.Common

import Control.Monad.Except (runExcept)
import Control.Monad.Writer (execWriter)
import Data.Monoid ((<>))
import Data.List (sort, nub)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck (NonEmptyList(..))
import Test.Tasty.HUnit
import qualified Data.Text as T
import qualified Data.Map as M

commandTests :: TestTree
commandTests = testGroup "command tests" [
    modifyFileProperties,
    bufferWriteProperties,
    readProperties
    ]

modifyFileProperties :: TestTree
modifyFileProperties = testGroup "modify file properties" [
    testProperty "genNewFileState f [] == f" $ \ccf -> let
        res = runExcept $ genNewFileState (fileContents ccf) [] :: Either ConfCryptError (M.Map ConfCryptElement LineNumber)
        in res == Right (fileContents ccf)

   ,testProperty "genNewFileState f [delete all in f] == []" $ \ccf -> let
        contents = fileContents ccf
        deletes = (,Remove) <$> M.keys contents
        res = runExcept $ genNewFileState contents deletes
        in either (const False)
                  (all isComment . M.keys)
                  res

   ,testProperty "genNewFileState [] additions == additions" $ \paramPairs -> let
        schemata = SchemaLine . fst <$> paramPairs
        params = (\p -> ParameterLine $ ParamLine (paramName p) (paramValue p)) . snd <$> paramPairs
        edits =  (,Add) <$> (nub $ schemata <> params)
        res = runExcept $ genNewFileState M.empty edits
        in if null edits
           then True
           else either (const False)
                       (\m -> (length edits) == (M.size m)) -- rather weak check
                       res

    ]

bufferWriteProperties :: TestTree
bufferWriteProperties  = testGroup "Buffer write" [
    testProperty "parse (writerBuffer xs) == xs" $ \(ValidCCF ccf)-> let
        fc = fileContents ccf
        output = (<> "\n") . T.intercalate "\n" . execWriter $ writeFullContentsToBuffer fc
        parseRes = parseConfCrypt "" output
        in either (const False)
                  (\ccf' -> fileContents ccf' == fc)
                  parseRes
    ]

readProperties :: TestTree
readProperties = testGroup "read file contents" [
    -- read file == read (read file)
    ]

isComment (CommentLine _) = True
isComment _ = False

module ConfCrypt.Common where

import ConfCrypt.Types

import Control.Arrow
import Data.Char (isAlphaNum, isPrint, isSpace, isAscii)
import Data.List (nub)
import qualified Data.Map as M
import qualified Data.Text as T
import Test.QuickCheck

instance Arbitrary Parameter where
    arbitrary =
        Parameter <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary Schema where
    arbitrary =
        Schema <$> arbitrary <*> arbitrary

instance Arbitrary SchemaType where
    arbitrary = elements [CString, CInt, CBoolean]

instance {-# OVERLAPPING #-} Arbitrary (Schema, Parameter) where
    arbitrary = do
        schema <- arbitrary
        value <- arbitrary
        pure (schema, Parameter {paramName = sName schema,
                                 paramValue = value,
                                 paramType = Just $ sType schema}
             )

instance  Arbitrary ConfCryptFile where
    arbitrary = do
        fName <- arbitrary
        sp <- arbitrary
        comments <- commentLineGen
        extraParams <- arbitrary
        let extraParams' = ParameterLine . fst . parameterToLines <$> extraParams
            initialLines = comments <> extraParams'
            lines = second LineNumber <$> zip (foldr linearize initialLines sp) [1..]
            params = snd <$> sp
        pure ConfCryptFile {
            fileName = fName,
            fileContents = M.fromList lines,
            parameters = params<>extraParams
            }
        where
            linearize (s,p) acc = SchemaLine s : toPl p : acc

newtype ValidCCF = ValidCCF ConfCryptFile deriving Show
newtype ValidSchema = ValidSchema Schema

instance Arbitrary ValidSchema where
    arbitrary =
        fmap ValidSchema $ Schema <$> arbitrary `suchThat` validIdentifier <*> arbitrary

instance {-# OVERLAPPING #-} Arbitrary (ValidSchema, Parameter) where
    arbitrary = do
        (ValidSchema s) <- arbitrary
        value <- arbitrary `suchThat` printableNonEmpty
        pure (ValidSchema s, Parameter {paramName = sName s,
                                        paramValue = value,
                                        paramType = Just $ sType s}
             )

commentLineGen = fmap CommentLine <$> arbitrary `suchThat` (all printableNonEmpty)

printableNonEmpty :: T.Text -> Bool
printableNonEmpty line =
    ((> 0) $ T.length line) && (all isPrint $ T.unpack line) && not (all isSpace $ T.unpack line)

instance Arbitrary ValidCCF where
    arbitrary = do
        sp <- arbitrary
        fName <- arbitrary
        comments <- commentLineGen
        let rawLines = nub $ foldr linearize comments sp
            lines = second LineNumber <$> zip rawLines [1..]
            params = snd <$> sp
        pure . ValidCCF $ ConfCryptFile {
            fileName = fName,
            fileContents = M.fromList lines,
            parameters = params
            }
        where
            linearize (ValidSchema s,p) acc = SchemaLine s : toPl p : acc

validIdentifier :: T.Text -> Bool
validIdentifier t = let
    properChars = all (\c -> c == '_' || (isAscii c && isAlphaNum c)) $ T.unpack t
    nonEmpty = T.length t > 0
    in nonEmpty && properChars

toPl p = ParameterLine $ ParamLine {pName = paramName p, pValue = paramValue p}

instance Arbitrary ConfCryptElement where
    arbitrary = oneof [CommentLine <$> arbitrary, SchemaLine <$> arbitrary, toPl <$> arbitrary]

instance Arbitrary T.Text where
    arbitrary = T.pack <$> arbitrary

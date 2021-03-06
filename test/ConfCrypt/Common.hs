module ConfCrypt.Common where

import ConfCrypt.Types

import Control.Arrow
import Control.Monad.Identity (Identity)
import Data.Char (isAlphaNum, isPrint, isSpace, isAscii, isLatin1)
import Data.List (nub)
import Data.ByteArray (pack)
import qualified Data.Map as M
import qualified Data.Text as T
import qualified Data.ByteString as BS
import Crypto.Random (withDRG, drgNewSeed, seedFromInteger, MonadRandom(..))
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

commentLineGen = fmap CommentLine <$> arbitrary `suchThat` all printableNonEmpty

printableNonEmpty :: T.Text -> Bool
printableNonEmpty line =
    ((> 0) $ T.length line) && all isPrint (T.unpack line) && not (all isSpace $ T.unpack line)

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

newtype Latin1Text = Latin1Text T.Text deriving Show
instance Arbitrary Latin1Text where
    arbitrary = Latin1Text <$> arbitrary `suchThat` (all isLatin1 . T.unpack)

-- This is a key for testing only. Please, please don't be stupid enough to ever use this to
-- actually encrypt something in the real world.
dangerousTestKey :: BS.ByteString
dangerousTestKey = "-----BEGIN RSA PRIVATE KEY-----\n\
\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\n\
\-----END RSA PRIVATE KEY-----"

instance MonadRandom Identity where
    getRandomBytes n = pure . pack . BS.unpack $ BS.replicate n 42

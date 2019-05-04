-- |
-- Module:          ConfCrypt.Types
-- Copyright:       (c) 2018 Chris Coffey
--                  (c) 2018 CollegeVine
-- License:         MIT
-- Maintainer:      Chris Coffey
-- Stability:       experimental
-- Portability:     portable
--
-- Core types and some small helper functions used to construct ConfCrypt.
module ConfCrypt.Types (
    -- * Core types
    ConfCryptM,
    -- ** Errors
    ConfCryptError(..),
    -- ** Runtime Environment
    ConfCryptFile(..),
    Parameter(..),
    -- ** File Format
    ConfCryptElement(..),
    LineNumber(..),
    SchemaType(..),
    ParamLine(..),
    Schema(..),

    -- ** Key constraints
    LocalKey,
    KMSKey,

    -- * Helpers
    unWrapSchema,
    isParameter,
    typeToOutputString,
    parameterToLines
) where

import Conduit (ResourceT)
import Control.Monad.Reader (MonadReader, ReaderT, runReaderT)
import Control.Monad.Except (MonadError, ExceptT, runExceptT)
import Control.DeepSeq (NFData)
import qualified Crypto.PubKey.RSA.Types as RSA
import GHC.Generics (Generic)
import qualified Data.Text as T
import qualified Data.Map.Strict as M
import Text.Megaparsec.Error (ShowErrorComponent, showErrorComponent)

-- | The core transformer stack for ConfCrypt. The most important parts are the 'ReaderT' and
-- 'ResourceT', as 'ExceptT' can be replaced with explicit return type.
type ConfCryptM m ctx =
    ReaderT (ConfCryptFile, ctx) (
                ExceptT ConfCryptError (
                    ResourceT m
                )
        )

-- | The possible errors produced during a confcrypt operation.
data ConfCryptError
    = ParserError T.Text
    | NonRSAKey
    | KeyUnpackingError T.Text
    | DecryptionError T.Text
    | AWSDecryptionError T.Text
    | AWSEncryptionError T.Text
    | EncryptionError RSA.Error
    | MissingLine T.Text
    | UnknownParameter T.Text
    | WrongFileAction T.Text
    | CleanupError T.Text
    | FormatParseError T.Text
    deriving (Generic, Eq, Ord)

instance Show ConfCryptError where
    show (ParserError msg) = "ParserError: "<> T.unpack msg
    show NonRSAKey = "NonRSAKey"
    show (KeyUnpackingError msg) = "KeyUnpackingError: "<> T.unpack msg
    show (DecryptionError msg) = "DecryptionError: "<> T.unpack msg
    show (AWSDecryptionError msg) = "AWSDecryptionError: "<> T.unpack msg
    show (AWSEncryptionError msg) = "AWSEncryptionError: "<> T.unpack msg
    show (EncryptionError err) = "EncryptionError: "<> show err
    show (MissingLine msg) = "MissingLine: "<> T.unpack msg
    show (UnknownParameter msg) = "UnknownParameter: "<> T.unpack msg
    show (WrongFileAction msg) = "WrongFileAction: "<> T.unpack msg
    show (CleanupError msg) = "CleanupError: "<> T.unpack msg
    show (FormatParseError msg) = "Format parse error: "<> T.unpack msg

instance ShowErrorComponent ConfCryptError where
    showErrorComponent (ParserError msg) = T.unpack msg
    showErrorComponent _ = "Not a parsable error"

instance Ord RSA.Error where
    (<=) l r = show l <= show r

-- | As indicated in the Readme, a ConfCrypt file
data ConfCryptFile =
    ConfCryptFile {
        fileName :: T.Text,
        fileContents :: M.Map ConfCryptElement LineNumber,
        parameters :: [Parameter]
        } deriving (Show, Generic, NFData)

-- | The syntax used to describe a confcrypt file. A line in a confcrypt file may be one of 'Schema',
-- 'ParamLine', or comment. The grammar itself is described in the readme and 'Confcrypt.Parser'.
data ConfCryptElement
    = SchemaLine Schema
    | CommentLine {cText ::T.Text}
    | ParameterLine  ParamLine
    deriving (Show, Generic, NFData)

-- | this implementation means that there can only be a single parameter or schema with the same name.
-- Attempting to add multiple with the same name is undefined behavior and will result in missing data.
instance Eq ConfCryptElement where
    (==) (SchemaLine l) (SchemaLine r) = sName l == sName r
    (==) (ParameterLine l) (ParameterLine r) = pName l == pName r
    (==) (CommentLine l) (CommentLine r) = l == r
    (==) _ _ = False

-- | In order to
instance Ord ConfCryptElement where
    (<=) (SchemaLine l) (SchemaLine r) = sName l <= sName r
    (<=) (SchemaLine l) (CommentLine _) = False
    (<=) (SchemaLine l) (ParameterLine _) = True
    (<=) (ParameterLine l) (ParameterLine r) = pName l <= pName r
    (<=) (ParameterLine l) (CommentLine _) = False
    (<=) (ParameterLine l) (SchemaLine _) = False
    (<=) (CommentLine l) (CommentLine  r) = l <= r
    (<=) (CommentLine l) (ParameterLine _) = True
    (<=) (CommentLine l) (SchemaLine _) = True

-- | A parameter consists of both a 'ParamLine' and 'Schema' line from the confcr
data Parameter = Parameter {paramName :: T.Text, paramValue :: T.Text, paramType :: Maybe SchemaType}
    deriving (Eq, Ord, Show, Generic, NFData)

-- | A parsed parameter line from a confcrypt file
data ParamLine = ParamLine {pName :: T.Text, pValue :: T.Text}
    deriving (Eq, Ord, Show, Generic, NFData)

-- | A parsed schema line from a confcrypt file
data Schema = Schema {sName :: T.Text, sType :: SchemaType}
    deriving (Eq, Ord, Show, Generic, NFData)

-- | Self explanitory
newtype LineNumber = LineNumber Int
    deriving (Eq, Ord, Show, Generic, NFData)

-- | Indicates which types a
data SchemaType
    = CString -- ^ Maps to 'String'
    | CInt -- ^ Maps to 'Int'
    | CBoolean -- ^ Maps to 'Bool'
    deriving (Eq, Ord, Show, Generic, NFData, Read)


-- | A special purpose 'Show' function for convert
typeToOutputString ::
    SchemaType
    -> T.Text
typeToOutputString CString = "String"
typeToOutputString CInt = "Int"
typeToOutputString CBoolean = "Boolean"

-- | Convert a parameter into a 'ParameterLine' and 'SchemaLine' if possible.
parameterToLines ::
    Parameter
    -> (ParamLine, Maybe Schema)
parameterToLines Parameter {paramName, paramValue, paramType} =
    (ParamLine paramName paramValue, Schema paramName <$> paramType)

-- | Checks whether the provided line from a confcrypt file is a 'Parameter'
isParameter :: ConfCryptElement -> Bool
isParameter (ParameterLine _) = True
isParameter _ = False

-- | Attempts to unwrap a line from a confcrypt file into a 'Schema'
unWrapSchema :: ConfCryptElement -> Maybe Schema
unWrapSchema (SchemaLine s) = Just s
unWrapSchema _ = Nothing

-- | This constraint provides a type-level check that the wrapped key type is local to the
-- current machine. For use with things like RSA keys.
class LocalKey key

-- | This constraint provides a type-level check that the wrapped key type exists off-system inside
-- an externally provided Key Management System (KMS). For use with AWS KMS or Azure KMS.
class KMSKey key

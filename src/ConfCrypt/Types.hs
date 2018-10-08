module ConfCrypt.Types where

import Control.Monad.Reader (MonadReader, ReaderT, runReaderT)
import Control.Monad.Except (MonadError, ExceptT, runExceptT)
import Control.Monad.Trans.Resource (ResourceT)
import Control.Monad.Writer (MonadWriter, WriterT, execWriterT)
import Control.DeepSeq (NFData)
import qualified Crypto.PubKey.RSA.Types as RSA
import GHC.Generics (Generic)
import qualified Data.Text as T
import qualified Data.Map.Strict as M

type ConfCryptM m ctx =
    ReaderT (ConfCryptFile, ctx) (
            WriterT [T.Text] (
                ExceptT ConfCryptError (
                    ResourceT m)
                )
        )


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
    deriving (Show, Generic, Eq, Ord)

instance Ord RSA.Error where
    (<=) l r = show l <= show r

data ConfCryptFile =
    ConfCryptFile {
        fileName :: T.Text,
        fileContents :: M.Map ConfCryptElement LineNumber,
        parameters :: [Parameter]
        } deriving (Show, Generic, NFData)

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

-- | TODO ccoffey talk about this as a gotcha. The requirement is that for two
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

data Parameter = Parameter {paramName :: T.Text, paramValue :: T.Text, paramType :: Maybe SchemaType}
    deriving (Eq, Ord, Show, Generic, NFData)
data ParamLine = ParamLine {pName :: T.Text, pValue :: T.Text}
    deriving (Eq, Ord, Show, Generic, NFData)
data Schema = Schema {sName :: T.Text, sType :: SchemaType}
    deriving (Eq, Ord, Show, Generic, NFData)

newtype LineNumber = LineNumber Int
    deriving (Eq, Ord, Show, Generic, NFData)

data SchemaType
    = CString
    | CInt
    | CBoolean
    deriving (Eq, Ord, Show, Generic, NFData, Read)

class LocalKey key
class KMSKey key

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

isParameter :: ConfCryptElement -> Bool
isParameter (ParameterLine _) = True
isParameter _ = False

unWrapSchema :: ConfCryptElement -> Maybe Schema
unWrapSchema (SchemaLine s) = Just s
unWrapSchema _ = Nothing

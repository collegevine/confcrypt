module ConfCrypt.Types where

import qualified Data.Text as T
import qualified Data.Map as M
import Control.DeepSeq (NFData)
import GHC.Generics (Generic)

data ConfCryptError =
    ParserError T.Text
    deriving (Show, Generic, NFData, Eq, Ord)

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
    deriving (Eq, Ord, Show, Generic, NFData)

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
    deriving (Eq, Ord, Show, Generic, NFData)

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

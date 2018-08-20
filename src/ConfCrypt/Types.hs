module ConfCrypt.Types where

import qualified Data.Text as T
import qualified Data.Map as M

data ConfCryptFile =
    ConfCryptFile {
        fileName :: T.Text,
        fileContents :: M.Map ConfCryptElement LineNumber,
        parameters :: [Parameter]
        } deriving (Show)

data ConfCryptElement
    = SchemaLine Schema
    | CommentLine {cText ::T.Text}
    | ParameterLine  ParamLine
    deriving (Eq, Ord, Show)

data Parameter = Parameter {paramName :: T.Text, paramValue :: T.Text, paramType :: Maybe SchemaType}
    deriving (Eq, Ord, Show)
data ParamLine = ParamLine {pName :: T.Text, pValue :: T.Text}
    deriving (Eq, Ord, Show)
data Schema = Schema {sName :: T.Text, sType :: SchemaType}
    deriving (Eq, Ord, Show)

newtype LineNumber = LineNumber Int
    deriving (Eq, Ord, Show)

data SchemaType
    = CString
    | CInt
    | CBoolean
    deriving (Eq, Ord, Show)

-- | Convert a parameter into a 'ParameterLine' and 'SchemaLine' if possible.
parameterToLines ::
    Parameter
    -> (ParamLine, Maybe Schema)
parameterToLines Parameter {paramName, paramValue, paramType} =
    (ParamLine paramName paramValue, Schema paramName <$> paramType)

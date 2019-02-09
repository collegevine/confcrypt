module ConfCrypt.Template (
    renderTemplate
    ) where

import Text.Megaparsec
import Text.Megaparsec.Char
import Data.Text
import ConfCrypt.Types (Parameter(..))
import qualified Data.Text as T

-- "text %k=%v %%"
-- "text foo=bar %"
-- ["text ", k, "=", v, " %"]
-- %[a-z] %x %y %z


renderTemplate :: Text -> Parameter -> Text
renderTemplate template param = case parse parseTemplate "" template of
    Left err -> pack . show $ err
    Right parsed -> foldMap replaceVars parsed
    where
        replaceVars (Text_ t)         = t
        replaceVars (Variable_ Name)  = paramName param
        replaceVars (Variable_ Value) = paramValue param
        replaceVars (Variable_ Type)  = T.pack . show . paramType $ param


type Parser = Parsec MyParseError Text
type ApplyTemplate = Text -> Text -> Text -> Text
newtype MyParseError = MyParseError Text deriving (Show, Ord, Eq)

-- type Parser = Parsec ParseError Text

parseTemplate :: Parser [Template]
parseTemplate =
    many (txt <|> var)
    where
        var = Variable_ <$> parseVariable
        txt = Text_ <$> parseLiteral

data Template = Variable_ Variable | Text_ Text
    deriving Show

parseLiteral :: Parser Text
parseLiteral = let
    escapedPercent = do
        _ <- try $ string' "%%"
        pure "%"
    otherText = pack <$> some (noneOf ['%'])
    in escapedPercent <|> otherText


data Variable = Name | Value | Type deriving Show

parseVariable :: Parser Variable
parseVariable = let
    tryName = do
        _ <- try $ string' "%n"
        pure Name
    tryVal = do
        _ <- try $ string' "%v"
        pure Value
    tryType = do
        _ <- try $ string' "%t"
        pure Type
    unrecognized = do
        _ <- string' "%"
        invalid <- anySingle
        fail $ "Unrecognized variable " ++ [invalid]
    in tryName <|> tryVal <|> tryType <|> unrecognized

module ConfCrypt.Template (
    renderTemplate
    ) where

import ConfCrypt.Types (Parameter(..), typeToOutputString)
import Control.Monad (void)
import Data.Maybe (maybe)
import Data.Text (Text, pack)
import Text.Megaparsec (Parsec, (<|>), anySingle, try, noneOf, many, some, parse)
import Text.Megaparsec.Char (string')
import Text.Megaparsec.Error (errorBundlePretty)

-- "text %k=%v %%"
-- "text foo=bar %"
-- ["text ", k, "=", v, " %"]
-- %[a-z] %x %y %z


renderTemplate :: Text -> Either Text (Parameter -> Text)
renderTemplate template = case parse parseTemplate "" template of
    Left err -> Left . pack $ show err
    Right parsed -> Right (\param -> foldMap (replaceVars param) parsed)
    where
        replaceVars p (Text_ t)         = t
        replaceVars p (Variable_ Name)  = paramName p
        replaceVars p (Variable_ Value) = paramValue p
        replaceVars p (Variable_ Type)  = maybe "" typeToOutputString $ paramType p


type Parser = Parsec TemplateParseError Text
newtype TemplateParseError = TemplateParseError Text deriving (Show, Ord, Eq)

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
parseLiteral = "%" <$ try (string' "%%") <|> pack <$> some (noneOf ("%" :: String))


data Variable = Name | Value | Type deriving Show

parseVariable :: Parser Variable
parseVariable =
        Name  <$ try (string' "%n")
    <|> Value <$ try (string' "%v")
    <|> Type  <$ try (string' "%t")
    <|> unrecognized
    where
        unrecognized = do
            void $ string' "%"
            invalid <- anySingle
            fail $ "Unrecognized variable " ++ [invalid]

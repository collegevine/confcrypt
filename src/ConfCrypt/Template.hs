module ConfCrypt.Template (
    renderTemplate
    ) where

import Data.Text (Text, pack)
import ConfCrypt.Types (Parameter(..))
import Control.Monad (void)
import Text.Megaparsec (Parsec, (<|>), anySingle, try, noneOf, many, some, parse)
import Text.Megaparsec.Char (string')

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
        replaceVars (Variable_ Type)  = pack . show . paramType $ param


type Parser = Parsec MyParseError Text
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

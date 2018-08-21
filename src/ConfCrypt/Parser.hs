module ConfCrypt.Parser (
    parseConfCrypt
) where

import ConfCrypt.Types

import Control.Applicative ((<|>))
import Control.Applicative.Combinators (manyTill, many)
import Data.Maybe (listToMaybe)
import Text.Megaparsec (Parsec, parse, getPosition, SourcePos(..), unPos, (<?>), try)
import Text.Megaparsec.Char (char, space, eol, anyChar, string, digitChar, alphaNumChar,
    oneOf, symbolChar, separatorChar, letterChar, digitChar)
import qualified Data.Text as T
import qualified Data.Map as M

type Parser = Parsec ConfCryptError T.Text

-- TODO handle duplicates
parseConfCrypt ::
    FilePath
    -> T.Text
    -> Either ConfCryptError ConfCryptFile
parseConfCrypt filename contents =
    case parse confCryptParser filename contents of
        Left err -> Left $ ParserError (T.pack $ show err)
        Right rawLines -> Right $ assembleConfCrypt rawLines
    where
        findParamSchema lines (ParamLine {pName}) = listToMaybe . fmap fst . M.toList $ M.filterWithKey (\s _ ->
            (Just True) == (((==) pName . sName) <$> unWrapSchema s) ) lines
        assembleConfCrypt :: [(ConfCryptElement, LineNumber)] -> ConfCryptFile
        assembleConfCrypt assocList = let
            contentsMap = M.fromList assocList
            rawParams = (\(ParameterLine p) -> p) <$> [p | p <- M.keys contentsMap, isParameter p]
            params = [Parameter {
                paramName = pName p,
                paramValue = pValue p,
                paramType = fmap sType $ unWrapSchema =<< findParamSchema contentsMap p} | p <- rawParams]
            in ConfCryptFile {
                fileName = T.pack filename,
                fileContents = contentsMap,
                parameters = params
                }


confCryptParser :: Parser [(ConfCryptElement, LineNumber)]
confCryptParser =
    many lineParser
    where
        lineParser = try parseComment <|> try parseSchema <|> try parseParameter

parseComment :: Parser (ConfCryptElement, LineNumber)
parseComment = do
    lineNum <- parseLineNum
    _ <- space
    _ <- char '#'
    line <- T.pack <$> manyTill anyChar eol
    _ <- many eol
    pure (CommentLine line, lineNum)

parseSchema :: Parser (ConfCryptElement, LineNumber)
parseSchema = do
    lineNum <- parseLineNum
    _ <- space
    name <- validName
    _ <- space
    _ <- char ':'
    _ <- space
    tpe <- parseType
    _ <- many eol
    pure (SchemaLine Schema {sName= name, sType= tpe}, lineNum)

parseType :: Parser SchemaType
parseType = let
    tryString = do
        _ <- try $ string "String"
        pure CString
    tryInt = do
        _ <- try $ string "Int"
        pure CInt
    tryBoolean = do
        _ <- try $ string "Boolean"
        pure CBoolean
    in tryString <|> tryInt <|> tryBoolean

parseParameter :: Parser (ConfCryptElement, LineNumber)
parseParameter = do
    lineNum <- parseLineNum
    _ <- space
    name <- validName
    _ <- space
    _ <- char '='
    _ <- space
    value <- validValue
    _ <- many eol
    pure (ParameterLine ParamLine {pName= name, pValue = value}, lineNum)

parseLineNum :: Parser LineNumber
parseLineNum =
    LineNumber . unPos . sourceLine <$> getPosition

validName :: Parser T.Text
validName =
    T.pack <$> many (letterChar <|> digitChar <|> (char '_'))

validValue :: Parser T.Text
validValue =
    T.pack <$> many anyChar

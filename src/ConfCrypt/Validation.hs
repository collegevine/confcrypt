-- |
-- Module:          ConfCrypt.Validation
-- Copyright:       (c) 2018 Chris Coffey
--                  (c) 2018 CollegeVine
-- License:         MIT
-- Maintainer:      Chris Coffey
-- Stability:       experimental
-- Portability:     portable


module ConfCrypt.Validation (
    -- * Rule validation
    runAllRules,

    -- ** Individual rules
    parameterTypesMatchSchema,
    logMissingSchemas,
    logMissingParameters
    ) where

import ConfCrypt.Types
import ConfCrypt.Encryption (decryptValue, MonadDecrypt)

import Control.Monad.Except (runExcept, catchError)
import Control.Monad.Reader (MonadReader, ask)
import Data.Char (isDigit)
import Data.Maybe (isNothing)
import qualified Data.Text as T
import qualified Data.Map as M

-- | Apply all validation rules, accumulating the errors across rules.
runAllRules :: (Monad m,
    MonadDecrypt m key,
    MonadReader (ConfCryptFile, key) m) =>
    m [T.Text]
runAllRules = do
    (ccf, privateKey) <- ask
    a <- parameterTypesMatchSchema privateKey ccf
    b <- logMissingSchemas ccf
    c <- logMissingParameters ccf
    pure $ filter (not . T.null) $ a <> b <> c

-- | For each (Schema, Parameter)  pair, confirm that the parameter's value type matches the schema.
parameterTypesMatchSchema :: (Monad m, MonadDecrypt m key) =>
    key
    -> ConfCryptFile
    -> m [T.Text]
parameterTypesMatchSchema key ConfCryptFile {parameters} =
    traverse decryptAndCompare parameters
    where
        decryptAndCompare Parameter {paramName, paramValue, paramType} =
            catchError (runRule paramType paramName =<< decryptValue key paramValue)
                       (const $ pure ("Error: Could not decrypt " <> paramName))
        runRule paramType paramName val =
            case paramType of
                Nothing -> pure ""
                Just CInt | all isDigit $ T.unpack val -> pure ""
                Just CBoolean | T.toLower val == "true" || T.toLower val == "false" -> pure ""
                Just CString | not (T.null val) -> pure ""
                Just CString | T.null val -> pure $ "Warning: "<> paramName <> " is empty"
                Just pt -> pure $ "Error: "<> paramName <> " does not match the schema type " <> typeToOutputString pt

-- | Raise an error if there are parameters without a schema
logMissingSchemas :: Monad m =>
    ConfCryptFile
    -> m [T.Text]
logMissingSchemas ConfCryptFile {parameters} =
    traverse logMissingSchema parameters
    where
        logMissingSchema Parameter {paramName, paramType}
            | isNothing paramType = pure $ "Error: " <> paramName <> " does not have a schema"
            | otherwise = pure ""

-- | Raise an error if there are schema without a parameter
logMissingParameters :: Monad m =>
    ConfCryptFile
    -> m [T.Text]
logMissingParameters ConfCryptFile {fileContents} =
    traverse logMissingParameter . M.toList $ M.filterWithKey (\k _ -> isSchema k) fileContents
    where
        isSchema (SchemaLine _) = True
        isSchema _ = False
        paramForName name (ParameterLine ParamLine {pName}) = name == pName
        paramForName name _ = False

        logMissingParameter (SchemaLine Schema {sName}, _)
            | M.null $ M.filterWithKey (\k _ -> paramForName sName k) fileContents  = pure $ "Error: no matching parameter for schema "<> sName
            | otherwise = pure ""
        logMissingParameter _ =  pure ""


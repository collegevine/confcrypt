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
import Control.Monad.Trans (liftIO, MonadIO)
import Data.Char (isDigit)
import Data.Foldable (traverse_)
import Data.Maybe (isNothing)
import qualified Data.Text as T
import qualified Data.Map as M

-- | Apply all validation rules, accumulating the errors across rules.
runAllRules :: (MonadIO m,
    MonadDecrypt m key,
    MonadReader (ConfCryptFile, key) m) =>
    m [T.Text]
runAllRules = do
    (ccf, privateKey) <- ask
    parameterTypesMatchSchema privateKey ccf
    logMissingSchemas ccf
    logMissingParameters ccf
    return []

-- | For each (Schema, Parameter)  pair, confirm that the parameter's value type matches the schema.
parameterTypesMatchSchema :: (MonadIO m, MonadDecrypt m key) =>
    key
    -> ConfCryptFile
    -> m ()
parameterTypesMatchSchema key ConfCryptFile {parameters} =
    traverse_ decryptAndCompare parameters
    where
        decryptAndCompare Parameter {paramName, paramValue, paramType} =
            catchError (runRule paramType paramName =<< decryptValue key paramValue)
                       (pure $ liftIO $ putStrLn ("Error: Could not decrypt " <> T.unpack paramName))
        runRule paramType paramName val =
            case paramType of
                Nothing -> pure ()
                Just CInt | all isDigit $ T.unpack val -> pure ()
                Just CBoolean | T.toLower val == "true" || T.toLower val == "false" -> pure ()
                Just CString | not (T.null val) -> pure ()
                Just CString | T.null val -> liftIO $ putStrLn ("Warning: "<> T.unpack paramName <> " is empty")
                Just pt -> liftIO $ putStrLn ("Error: "<> T.unpack paramName <> " does not match the schema type " <> T.unpack (typeToOutputString pt))

-- | Raise an error if there are parameters without a schema
logMissingSchemas :: MonadIO m =>
    ConfCryptFile
    -> m ()
logMissingSchemas ConfCryptFile {parameters} =
    traverse_ logMissingSchema parameters
    where
        logMissingSchema Parameter {paramName, paramType}
            | isNothing paramType = liftIO $ putStrLn ("Error: " <> T.unpack paramName <> " does not have a schema")
            | otherwise = pure ()

-- | Raise an error if there are schema without a parameter
logMissingParameters :: MonadIO m =>
    ConfCryptFile
    -> m ()
logMissingParameters ConfCryptFile {fileContents} =
    traverse_ logMissingParameter . M.toList $ M.filterWithKey (\k _ -> isSchema k) fileContents
    where
        isSchema (SchemaLine _) = True
        isSchema _ = False
        paramForName name (ParameterLine ParamLine {pName}) = name == pName
        paramForName name _ = False

        logMissingParameter (SchemaLine Schema {sName}, _)
            | M.null $ M.filterWithKey (\k _ -> paramForName sName k) fileContents  = liftIO $ putStrLn ("Error: no matching parameter for schema "<> T.unpack sName)
            | otherwise = pure ()
        logMissingParameter _ =  pure ()


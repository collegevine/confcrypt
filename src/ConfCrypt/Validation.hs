module ConfCrypt.Validation (
    runAllRules,

    -- | Individual rules
    parameterTypesMatchSchema,
    logMissingSchemas,
    logMissingParameters
    ) where

import ConfCrypt.Types
import ConfCrypt.Encryption (decryptValue)

import Control.Monad.Except (runExcept)
import Control.Monad.Writer (MonadWriter, tell)
import Control.Monad.Reader (MonadReader, ask)
import Data.Char (isDigit)
import Data.Foldable (traverse_)
import Data.Maybe (isNothing)
import qualified Data.Text as T
import qualified Data.Map as M
import qualified Crypto.PubKey.RSA.Types as RSA

runAllRules :: (Monad m, MonadWriter [T.Text] m, MonadReader (ConfCryptFile, RSA.PrivateKey) m) =>
    m ()
runAllRules = do
    (ccf, privateKey) <- ask
    parameterTypesMatchSchema privateKey ccf
    logMissingSchemas ccf
    logMissingParameters ccf

-- | For each (Schema, Parameter)  pair, confirm that the parameter's value type matches the schema.
parameterTypesMatchSchema :: (Monad m, MonadWriter [T.Text] m) =>
    RSA.PrivateKey
    -> ConfCryptFile
    -> m ()
parameterTypesMatchSchema privateKey ConfCryptFile {parameters} =
    traverse_ decryptAndCompare parameters
    where
        decryptAndCompare Parameter {paramName, paramValue, paramType} =
            case runExcept (decryptValue privateKey paramValue) of
                Left _ -> tell ["Error: Could not decrypt " <> paramName]
                Right val ->
                    case paramType of
                        Nothing -> pure ()
                        Just CInt | all isDigit $ T.unpack val -> pure ()
                        Just CBoolean | T.toLower val == "true" || T.toLower val == "false" -> pure ()
                        Just CString | not (T.null val) -> pure ()
                        Just CString | T.null val -> tell ["Warning: "<> paramName <> " is empty"]
                        Just pt -> tell ["Error: "<> paramName <> " does not match the schema type " <> typeToOutputString pt]

logMissingSchemas :: (Monad m, MonadWriter [T.Text] m) =>
    ConfCryptFile
    -> m ()
logMissingSchemas ConfCryptFile {parameters} =
    traverse_ logMissingSchema parameters
    where
        logMissingSchema Parameter {paramName, paramType}
            | isNothing paramType = tell ["Error: " <> paramName <> " does not have a scheam"]
            | otherwise = pure ()

logMissingParameters :: (Monad m, MonadWriter [T.Text] m) =>
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
            | M.null $ M.filterWithKey (\k _ -> paramForName sName k) fileContents  = tell ["Error: no matching parameter for schema "<> sName]
            | otherwise = pure ()
        logMissingParameter _ =  pure ()


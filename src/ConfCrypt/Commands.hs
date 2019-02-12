module ConfCrypt.Commands (
    -- * Commands
    Command,
    evaluate,

    -- * Supported Commands
    ReadConfCrypt(..),
    GetConfCrypt(..),
    AddConfCrypt(..),
    EditConfCrypt(..),
    DeleteConfCrypt(..),
    ValidateConfCrypt(..),
    NewConfCrypt(..),

    -- * Utilities
    FileAction(..),
    -- ** Exported for testing
    genNewFileState,
    writeFullContentsToBuffer
    ) where

import ConfCrypt.Default (defaultLines)
import ConfCrypt.Types
import ConfCrypt.Encryption (MonadEncrypt, MonadDecrypt, encryptValue, decryptValue, TextKey(..), RemoteKey(..))
import ConfCrypt.Validation (runAllRules)
import ConfCrypt.Providers.AWS (AWSCtx)
import ConfCrypt.Template (renderTemplate)

import Control.Arrow (second)
import Control.Monad (unless, (<=<))
import Control.Monad.Reader (ask)
import Control.Monad.Except (throwError, runExcept, MonadError, Except)
import Crypto.Random (MonadRandom)
import Data.List (find, sortOn)
import Data.Maybe (maybeToList)
import GHC.Generics (Generic)
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Data.Text as T
import qualified Data.Map as M

-- | Commands may perform one of the following operations to a line of a confcrypt file
data FileAction
    = Add
    | Edit
    | Remove

-- | All confcrypt commands can be generalized into an 'evaluate' call. In reality, instances likely
-- need to provide some environment, although that's not required as everything could be contained
-- as record fields of the command argument itself.
class Monad m => Command a m where
    evaluate :: a -> m [T.Text]

-- | Read and return the full contents of an encrypted file. Provides support for using a local RSA key or an externl KMS service
data ReadConfCrypt = ReadConfCrypt {rTemplate :: Maybe T.Text}
    deriving (Eq, Read, Show, Generic)

instance (Monad m, MonadDecrypt (ConfCryptM m key) key) => Command ReadConfCrypt (ConfCryptM m key) where
    evaluate (ReadConfCrypt template) = do
        (ccFile, ctx) <- ask
        let params = parameters ccFile
        case template of
            Nothing -> do
                transformed <- mapM (\p -> decryptedParam p <$> decryptValue ctx (paramValue p)) params
                processReadLines transformed ccFile
            Just tpl ->
                case renderTemplate tpl of
                    Left e -> pure ["" :: T.Text] -- how to return an error from here?
                    Right parsedTpl -> do
                        params' <- sequence $ decryptParam ctx <$> params
                        pure $ parsedTpl <$> params'

        where
            decryptParam ctx param = do
                value' <- decryptValue ctx $ paramValue param
                pure param {paramValue = value'}

            decryptedParam param v = ParameterLine ParamLine {pName = paramName param, pValue = v}

            -- Given a transformation, apply it to the current file contents then write them to the output buffer
            processReadLines transformed ccFile =
                    writeFullContentsToBuffer False =<<  genNewFileState (fileContents ccFile) transformedLines
                where
                transformedLines = [(p, Edit)| p <- transformed]

-- | Used to get the decrypted value of a single encrypted config parameter
data GetConfCrypt = GetConfCrypt {gName :: T.Text}
    deriving (Eq, Read, Show, Generic)

instance (Monad m, MonadDecrypt (ConfCryptM m key) key) => Command GetConfCrypt (ConfCryptM m key) where
    evaluate (GetConfCrypt name) = do
        (ccFile, ctx) <- ask
        let mParam = find ((==name) . paramName) (parameters ccFile)
        traverse (decrypt ctx) $ maybeToList mParam
        where
            decrypt ctx = decryptValue ctx . paramValue

-- | Used to add a new config parameter to the file
data AddConfCrypt = AddConfCrypt {aName :: T.Text, aValue :: T.Text, aType :: SchemaType}
    deriving (Eq, Read, Show, Generic)

instance (Monad m, MonadRandom m, MonadEncrypt (ConfCryptM m key) key) =>
    Command AddConfCrypt (ConfCryptM m key) where
    evaluate ac@AddConfCrypt {aName, aValue, aType} =  do
        (ccFile, ctx ) <- ask
        encryptedValue <- encryptValue ctx aValue
        let contents = fileContents ccFile
            instructions = [(SchemaLine sl, Add), (ParameterLine (pl {pValue = encryptedValue}), Add)]
        newcontents <- genNewFileState contents instructions
        writeFullContentsToBuffer False newcontents
        where
            (pl, Just sl) = parameterToLines Parameter {paramName = aName, paramValue = aValue, paramType = Just aType}

-- | Modify the value or type of a parameter in-place. This should result in a diff touching only the impacted lines.
-- Very important that this property holds to make reviews easier.
data EditConfCrypt = EditConfCrypt {eName:: T.Text, eValue :: T.Text, eType :: SchemaType}
    deriving (Eq, Read, Show, Generic)

instance (Monad m, MonadRandom m, MonadEncrypt (ConfCryptM m key) key) =>
    Command EditConfCrypt (ConfCryptM m key) where
    evaluate ec@EditConfCrypt {eName, eValue, eType} = do
        (ccFile, ctx) <- ask

        -- Editing an existing parameter requires that the file is inplace. Its not difficult to fall back into
        -- 'add' behavior in the case where the parameter isn't present, but I'm not implementing that right now.
        unless ( any ((==) eName . paramName) $ parameters ccFile) $
            throwError $ UnknownParameter eName

        rawEncrypted <- encryptValue ctx eValue
        editOutput ccFile ec rawEncrypted
        where
        -- Editing consists of replacing the encrypted value assocaited and type assocaited with a given parameter
        -- then writing the changes as in-place updates to the file.
        editOutput ccFile EditConfCrypt {eName, eValue, eType} encryptedValue = do
                let contents = fileContents ccFile
                    instructions = [(SchemaLine sl, Edit),
                                    (ParameterLine (pl {pValue = encryptedValue}), Edit)
                                ]
                newcontents <- genNewFileState contents instructions
                writeFullContentsToBuffer False newcontents
                where
                    (pl, Just sl) = parameterToLines Parameter {paramName = eName, paramValue = eValue, paramType = Just eType}

-- | Removes a particular parameter and schema from the config file. This does not require an encryption key because the
-- lines may simply be deleted based on the parameter name.
data DeleteConfCrypt = DeleteConfCrypt {dName:: T.Text}
    deriving (Eq, Read, Show, Generic)
instance Monad m => Command DeleteConfCrypt (ConfCryptM m ()) where
    evaluate DeleteConfCrypt {dName} = do
        (ccFile, ()) <- ask

        unless (any ((==) dName . paramName) $ parameters ccFile) $
            throwError $ UnknownParameter dName

        let contents = fileContents ccFile
            instructions = fmap (second (const Remove)) . M.toList $ M.filterWithKey findNamedLine contents

        newcontents <- genNewFileState contents instructions
        writeFullContentsToBuffer False newcontents
        where
            findNamedLine (SchemaLine Schema {sName}) _ = dName == sName
            findNamedLine (ParameterLine ParamLine {pName}) _ = dName == pName
            findNamedLine _ _ = False

-- | Run all of the rules in 'ConfCrypt.Validation' on this file.
data ValidateConfCrypt = ValidateConfCrypt
instance (Monad m, MonadDecrypt (ConfCryptM m key) key) => Command ValidateConfCrypt (ConfCryptM m key) where
    evaluate _ = runAllRules

-- | Dumps the contents of 'defaultLines' to the output buffer. This is the same example config used
-- in the readme.
data NewConfCrypt = NewConfCrypt
instance Monad m => Command NewConfCrypt (ConfCryptM m ()) where
    evaluate _ =
        writeFullContentsToBuffer False (fileContents defaultLines)


-- | Given a known file state and some edits, apply the edits and produce the new file contents
genNewFileState :: (Monad m, MonadError ConfCryptError m) =>
    M.Map ConfCryptElement LineNumber -- ^ initial file state
    -> [(ConfCryptElement, FileAction)] -- ^ edits
    -> m (M.Map ConfCryptElement LineNumber) -- ^ new file, with edits applied in-place
genNewFileState fileContents [] = pure fileContents
genNewFileState fileContents ((CommentLine _, _):rest) = genNewFileState fileContents rest
genNewFileState fileContents ((line, action):rest) =
    case M.toList (mLine line) of
        [] ->
            case action of
                Add -> let
                    nums =  M.elems fileContents
                    LineNumber highestLineNum = if null nums then LineNumber 0 else maximum nums
                    fc' = M.insert line (LineNumber $ highestLineNum + 1) fileContents
                    in genNewFileState fc' rest
                _ -> throwError $ MissingLine (T.pack $ show line)
        [(key, lineNum@(LineNumber lnValue))] ->
            case action of
                Remove -> let
                    fc' = M.delete key fileContents
                    fc'' = (\(LineNumber l) -> if l > lnValue then LineNumber (l - 1) else LineNumber l) <$> fc'
                    in genNewFileState fc'' rest
                Edit -> let
                    fc' = M.delete key fileContents
                    fc'' = M.insert line lineNum fc'
                    in genNewFileState fc'' rest
                _ -> throwError $ WrongFileAction ((<> " is an Add, but the line already exists. Did you mean to edit?"). T.pack $ show line)
        _ -> error "viloates map key uniqueness"

    where
        mLine l = M.filterWithKey (\k _ -> k == l) fileContents

-- | Writes the provided 'ConfCryptFile' (provided as a Map) to the output buffer in line-number order. This
-- allows for producing an easily diffable output and makes in-place edits easy to spot in source control diffs.
writeFullContentsToBuffer :: Monad m =>
    Bool
    -> M.Map ConfCryptElement LineNumber
    -> m [T.Text]
writeFullContentsToBuffer wrap contents =
    return $ toDisplayLine wrap <$> sortedLines
    where
        sortedLines = fmap fst . sortOn snd $ M.toList contents

        toDisplayLine ::
            Bool
            -> ConfCryptElement
            -> T.Text
        toDisplayLine _ (CommentLine comment) = "# " <> comment
        toDisplayLine _ (SchemaLine (Schema name tpe)) = name <> " : " <> typeToOutputString tpe
        toDisplayLine wrap (ParameterLine (ParamLine name val)) = name <> " = " <> if wrap then wrapEncryptedValue val else val

-- TODO remove this
-- | Because the encrypted results are stored as UTF8 text, its possible for an encrypted value
-- to embed end-of-line (eol) characters into the output value. This means rather than relying on eol
-- as our delimeter we need to explicitly wrap encrypted values in something very unlikely to occur w/in
-- an encrypted value.
wrapEncryptedValue ::
    T.Text
    -> T.Text
wrapEncryptedValue v = "BEGIN"<>v<>"END"

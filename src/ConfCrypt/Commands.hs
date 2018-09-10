module ConfCrypt.Commands (
    -- | Command class
    Command,
    evaluate,

    -- | Supported Commands
    ReadConfCrypt(..),
    AddConfCrypt(..),
    EditConfCrypt(..),
    DeleteConfCrypt(..),
    ValidateConfCrypt(..),
    EncryptWholeConfCrypt(..),
    NewConfCrypt(..),

    -- | Exported for testing
    genNewFileState,
    writeFullContentsToBuffer,

    FileAction(..)
    ) where

import ConfCrypt.Default (defaultLines)
import ConfCrypt.Types
import ConfCrypt.Encryption (encryptValue, decryptValue)
import ConfCrypt.Validation (runAllRules)
import ConfCrypt.Providers.AWS (AWSCtx)

import Control.Arrow (second)
import Control.Monad (unless)
import Control.Monad.Trans (lift)
import Control.Monad.Reader (ask)
import Control.Monad.Except (throwError, runExcept, MonadError)
import Control.Monad.Writer (tell, MonadWriter)
import Crypto.Random (MonadRandom)
import Data.Foldable (foldrM, traverse_)
import Data.List (sortOn)
import GHC.Generics (Generic)
import qualified Crypto.PubKey.RSA.Types as RSA
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Map as M


data FileAction
    = Add
    | Edit
    | Remove

class Monad m => Command a m where
    evaluate :: a -> m ()

data ReadConfCrypt = ReadConfCrypt
instance Monad m => Command ReadConfCrypt (ConfCryptM m RSA.PrivateKey) where
    evaluate _ = do
        (ccFile, pk) <- ask
        let params = parameters ccFile
        transformed <- mapM (\p -> decryptedParam  p . runExcept $ decryptValue pk (paramValue p)) params
        processReadLines transformed ccFile
        where
            decryptedParam param (Left e) = throwError e
            decryptedParam param (Right v) = pure . ParameterLine $ ParamLine {pName = paramName param, pValue = v}

 -- TODO reduce the duplication
instance Command ReadConfCrypt (ConfCryptM IO AWSCtx) where
    evaluate _ = do
        (ccFile, pk) <- ask
        let params = parameters ccFile
        transformed <- mapM (\p -> decryptedParam  p <$> decryptValue pk (paramValue p)) params
        processReadLines transformed ccFile
        where
            decryptedParam param v = ParameterLine $ ParamLine {pName = paramName param, pValue = v}

processReadLines transformed ccFile =
        writeFullContentsToBuffer False =<<  genNewFileState (fileContents ccFile) transformedLines
    where
    transformedLines = [(p, Edit)| p <- transformed]

data AddConfCrypt = AddConfCrypt {aName :: T.Text, aValue :: T.Text, aType :: SchemaType}
    deriving (Eq, Read, Show, Generic)
instance (Monad m, MonadRandom m) => Command AddConfCrypt (ConfCryptM m RSA.PublicKey) where
    evaluate AddConfCrypt {aName, aValue, aType} =  do
        (ccFile, pubKey) <- ask
        rawEncrypted <- lift . lift . lift $ encryptValue pubKey aValue
        encryptedValue <- either throwError pure rawEncrypted
        let contents = fileContents ccFile
            instructions = [(SchemaLine sl, Add), (ParameterLine (pl {pValue = encryptedValue}), Add)]
        newcontents <- genNewFileState contents instructions
        writeFullContentsToBuffer False newcontents
        where
            (pl, Just sl) = parameterToLines $ Parameter {paramName = aName, paramValue = aValue, paramType = Just aType}


data EditConfCrypt = EditConfCrypt {eName:: T.Text, eValue :: T.Text, eType :: SchemaType}
    deriving (Eq, Read, Show, Generic)
instance (Monad m, MonadRandom m) => Command EditConfCrypt (ConfCryptM m RSA.PublicKey) where
    --TODO this implementation is extremely similar 'Add', factor it out
    evaluate EditConfCrypt {eName, eValue, eType} = do
        (ccFile, pk) <- ask

        -- Editing an existing parameter requires that the file is inplace. Its not difficult to fall back into
        -- 'add' behavior in the case where the parameter isn't present, but I'm not implementing that right now.
        unless ( any ((==) eName . paramName) $ parameters ccFile) $
            throwError $ UnknownParameter eName

        rawEncrypted <- lift . lift . lift $ encryptValue pk eValue
        encryptedValue <- either throwError pure rawEncrypted
        let contents = fileContents ccFile
            instructions = [(SchemaLine sl, Edit),
                            (ParameterLine (pl {pValue = encryptedValue}), Edit)
                           ]
        newcontents <- genNewFileState contents instructions
        writeFullContentsToBuffer False newcontents
        where
            (pl, Just sl) = parameterToLines $ Parameter {paramName = eName, paramValue = eValue, paramType = Just eType}



data DeleteConfCrypt = DeleteConfCrypt {dName:: T.Text}
    deriving (Eq, Read, Show, Generic)
instance (Monad m, MonadRandom m) => Command DeleteConfCrypt (ConfCryptM m ()) where
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

data ValidateConfCrypt = ValidateConfCrypt
instance (Monad m) => Command ValidateConfCrypt (ConfCryptM m RSA.PrivateKey) where
    evaluate _ = runAllRules

data EncryptWholeConfCrypt = EncryptWholeConfCrypt
instance (Monad m, MonadRandom m) => Command EncryptWholeConfCrypt (ConfCryptM m RSA.PublicKey) where
    evaluate = undefined

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

writeFullContentsToBuffer :: (Monad m, MonadWriter [T.Text] m) =>
    Bool
    -> M.Map ConfCryptElement LineNumber
    -> m ()
writeFullContentsToBuffer wrap contents =
    traverse_ (tell . singleton . toDisplayLine wrap) sortedLines
    where
        sortedLines = fmap fst . sortOn snd $ M.toList contents
        singleton x = [x]

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

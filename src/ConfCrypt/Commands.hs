module ConfCrypt.Commands (
    Command,
    ReadConfCrypt,
    evaluate,

    -- | Exported for testing
    genNewFileState,
    writeFullContentsToBuffer
    ) where

import ConfCrypt.Types

import Control.Monad.Reader (ask)
import Control.Monad.Except (throwError, MonadError)
import Control.Monad.Writer (tell, MonadWriter)
import Crypto.PubKey.OpenSsh (OpenSshPrivateKey)
import Crypto.PubKey.RSA.Types (PrivateKey)
import Crypto.PubKey.RSA.PKCS15 (encrypt, decrypt)
import Data.Foldable (foldrM, traverse_)
import Data.List (sortOn)
import GHC.Generics (Generic)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import qualified Data.Map as M

data FileAction
    = Add
    | Edit
    | Remove

class Monad m => Command a b m | a -> b where
    evaluate :: a -> m b

data ReadConfCrypt = ReadConfCrypt
instance Monad m => Command ReadConfCrypt Int (ConfCryptM m PrivateKey) where
    evaluate _ = do
        (ccFile, pk) <- ask
        let params = parameters ccFile
        tranformed <- mapM (\p -> decryptedParam  p $ decryptValue pk (paramValue p)) params
        let transformedLines = undefined
        newcontents <- genNewFileState (fileContents ccFile) transformedLines
        writeFullContentsToBuffer newcontents
        pure 0
        where
            decryptedParam param (Left e) = throwError e
            decryptedParam param (Right v) = pure $ param {paramValue = v}

-- | Given a known file state and some edits, apply the edits and produce the new file contents
genNewFileState :: (Monad m, MonadError ConfCryptError m) =>
    M.Map ConfCryptElement LineNumber -- ^ initial file state
    -> [(ConfCryptElement, FileAction)] -- ^ edits
    -> m (M.Map ConfCryptElement LineNumber) -- ^ new file, with edits applied in-place
genNewFileState fileContents [] = pure fileContents
genNewFileState fileContents ((line, action):rest) =
    case M.toList (mLine line) of
        [] ->
            case action of
                Add -> let
                    LineNumber highestLineNum = maximum $ M.elems fileContents
                    fc' = M.insert line (LineNumber $ highestLineNum + 1) fileContents
                    in genNewFileState fc' rest
                _ -> throwError $ MissingLine (T.pack $ show line)
        [(key, lineNum)] ->
            case action of
                Remove -> let
                    fc' = M.delete key fileContents
                    in genNewFileState fc' rest
                Edit -> let
                    fc' = M.delete key fileContents
                    fc'' = M.insert line lineNum fc'
                    in genNewFileState fc'' rest
                _ -> throwError $ WrongFileAction ((<> " should be an Add"). T.pack $ show line)
        _ -> error "viloates map key uniqueness"

    where
        mLine (ParameterLine (ParamLine pname _)) = M.filterWithKey (\k _ -> findParam pname k) fileContents
        mLine (SchemaLine (Schema sname _)) = M.filterWithKey (\k _ -> findSchema sname k) fileContents
        mLine _ = fileContents
        findParam name (ParameterLine (ParamLine pname _)) = name == pname
        findParam name _ = False
        findSchema name (SchemaLine (Schema sname _)) = name == sname
        findSchema name _ = False

writeFullContentsToBuffer :: (Monad m, MonadWriter [T.Text] m) =>
    M.Map ConfCryptElement LineNumber
    -> m ()
writeFullContentsToBuffer contents =
    traverse_ (tell . singleton . toDisplayLine) sortedLines
    where
        sortedLines = fmap fst . sortOn snd $ M.toList contents
        singleton x = [x]

decryptValue ::
    PrivateKey
    -> T.Text
    -> Either ConfCryptError T.Text
decryptValue privateKey encryptedValue =
    either (Left . DecryptionError) (Right . T.decodeUtf8) $ decrypt Nothing privateKey (T.encodeUtf8 encryptedValue)

toDisplayLine ::
    ConfCryptElement
    -> T.Text
toDisplayLine (CommentLine comment) = "# " <> comment
toDisplayLine (SchemaLine (Schema name tpe)) = name <> " : " <> (T.pack $ show tpe)
toDisplayLine (ParameterLine (ParamLine name val)) = name <> " = " <> val


module ConfCrypt.Commands (
    Command,
    ReadConfCrypt,
    evaluate,

    -- | Exported for testing
    genNewFileState,
    writeFullContentsToBuffer,

    FileAction(..)
    ) where

import ConfCrypt.Types
import ConfCrypt.Encryption (encryptValue, decryptValue)

import Control.Arrow (second)
import Control.Monad.Reader (ask)
import Control.Monad.Except (throwError, MonadError)
import Control.Monad.Writer (tell, MonadWriter)
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

class Monad m => Command a b m | a -> b where
    evaluate :: a -> m b

data ReadConfCrypt = ReadConfCrypt
instance Monad m => Command ReadConfCrypt Int (ConfCryptM m RSA.PrivateKey) where
    evaluate _ = do
        (ccFile, pk) <- ask
        let params = parameters ccFile
        transformed <- mapM (\p -> decryptedParam  p $ decryptValue pk (paramValue p)) params
        let transformedLines = fmap (second (const Edit)) . M.toList $ findParameterLines ccFile transformed
        newcontents <- genNewFileState (fileContents ccFile) transformedLines
        writeFullContentsToBuffer newcontents
        pure 0
        where
            decryptedParam param (Left e) = throwError e
            decryptedParam param (Right v) = pure $ param {paramValue = v}

findParameterLines ::
    ConfCryptFile
    -> [Parameter]
    -> M.Map ConfCryptElement LineNumber
findParameterLines (ConfCryptFile {fileContents}) params =
    M.filterWithKey (\k _ -> isMatchingParam names k) fileContents
    where
        names = paramName <$> params
        isMatchingParam names (ParameterLine (ParamLine {pName})) = pName `elem` names -- TODO convert to set if people start using with large sets
        isMatchingParam _ _ = False

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
                    LineNumber highestLineNum = if null nums then LineNumber 1 else maximum nums
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
                _ -> throwError $ WrongFileAction ((<> " should be an Add"). T.pack $ show line)
        _ -> error "viloates map key uniqueness"

    where
        mLine l = M.filterWithKey (\k _ -> k == l) fileContents

writeFullContentsToBuffer :: (Monad m, MonadWriter [T.Text] m) =>
    M.Map ConfCryptElement LineNumber
    -> m ()
writeFullContentsToBuffer contents =
    traverse_ (tell . singleton . toDisplayLine) sortedLines
    where
        sortedLines = fmap fst . sortOn snd $ M.toList contents
        singleton x = [x]

toDisplayLine ::
    ConfCryptElement
    -> T.Text
toDisplayLine (CommentLine comment) = "# " <> comment
toDisplayLine (SchemaLine (Schema name tpe)) = name <> " : " <> typeToOutputString tpe
toDisplayLine (ParameterLine (ParamLine name val)) = name <> " = " <> val


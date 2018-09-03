module ConfCrypt.CLI.Engine (
    run
    ) where

import ConfCrypt.Types
import ConfCrypt.Commands
import ConfCrypt.Parser
import ConfCrypt.Encryption
import ConfCrypt.Default (emptyConfCryptFile)
import ConfCrypt.CLI.API

import Control.DeepSeq (force)
import Control.Monad.Reader (MonadReader, ReaderT, runReaderT, withReaderT)
import Control.Monad.Except (MonadError, ExceptT, runExceptT)
import Control.Monad.Writer (MonadWriter, WriterT, execWriterT)
import Crypto.PubKey.RSA.Types (PublicKey, PrivateKey)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import System.Exit (exitSuccess, exitFailure, exitWith, ExitCode(..))

run ::
    AnyCommand  -- ^ Command line arguments
    -> IO [T.Text]
run NC = do
    res <- runConfCrypt emptyConfCryptFile $ evaluate NewConfCrypt
    either (\e -> print e *> exitFailure)
           pure
           res
run parsedArguments = do
    let filePath = confFilePath parsedArguments
    lines <- T.readFile filePath
    configParsingResults <- parseConfCrypt filePath <$> pure lines
    case configParsingResults of
        --TODO print errors to stdErr
        Left err -> print err *> exitFailure
        Right parsedConfiguration -> do
            result <- case parsedArguments of
                    RC KeyAndConf {key} ->
                        runConfCrypt parsedConfiguration $ do
                            rsaKey <- loadRSAKey key
                            withReaderT (injectPrivateKey rsaKey) $ evaluate ReadConfCrypt
                    VC KeyAndConf {key} ->
                        runConfCrypt parsedConfiguration $ do
                            rsaKey <- loadRSAKey key
                            withReaderT (injectPrivateKey rsaKey) $ evaluate ValidateConfCrypt
                    WC KeyAndConf {key} ->
                        runConfCrypt parsedConfiguration $ do
                            rsaKey <- loadRSAKey key
                            withReaderT (injectPubKey rsaKey) $ evaluate EncryptWholeConfCrypt

                    AC KeyAndConf {key} cmd ->
                        runConfCrypt parsedConfiguration $ do
                            rsaKey <- loadRSAKey key
                            withReaderT (injectPubKey rsaKey) $ evaluate cmd
                    EC KeyAndConf {key} cmd ->
                        runConfCrypt parsedConfiguration $ do
                            rsaKey <- loadRSAKey key
                            withReaderT (injectPubKey rsaKey) $ evaluate cmd
                    DC _ cmd ->
                        runConfCrypt parsedConfiguration $ evaluate cmd
            either (\e -> print e *> exitFailure) pure result
    where
        injectPubKey :: PublicKey -> (ConfCryptFile, ()) -> (ConfCryptFile, PublicKey)
        injectPubKey key (conf, _) = (conf, key)
        injectPrivateKey :: PrivateKey -> (ConfCryptFile, ()) -> (ConfCryptFile, PrivateKey)
        injectPrivateKey key (conf, _) = (conf, key)

runConfCrypt :: Monad m =>
    ConfCryptFile ->
    ConfCryptM m () a
    -> m (Either ConfCryptError [T.Text])
runConfCrypt file action =
     runExceptT . execWriterT $ runReaderT action (file, ())

confFilePath :: AnyCommand -> FilePath
confFilePath  (RC KeyAndConf {conf}) = conf
confFilePath  (WC KeyAndConf {conf}) = conf
confFilePath  (VC KeyAndConf {conf}) = conf
confFilePath  (AC KeyAndConf {conf} _) = conf
confFilePath  (EC KeyAndConf {conf} _) = conf
confFilePath  (DC (Conf conf) _) = conf

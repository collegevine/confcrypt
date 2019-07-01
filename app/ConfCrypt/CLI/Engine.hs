module ConfCrypt.CLI.Engine (
    run
    ) where

import ConfCrypt.Types (ConfCryptError(..), ConfCryptFile(..), ConfCryptM)
import ConfCrypt.Commands (NewConfCrypt(..), ReadConfCrypt(..), ValidateConfCrypt(..),
    AddConfCrypt(..), DeleteConfCrypt(..), evaluate)
import ConfCrypt.Parser (parseConfCrypt)
import ConfCrypt.Encryption
import ConfCrypt.Default (emptyConfCryptFile)
import ConfCrypt.Providers.AWS (AWSCtx, loadAwsCtx, KMSKeyId(..))
import ConfCrypt.CLI.API (AnyCommand(..), Conf(..), KeyAndConf(..),
    KeyProvider(..), ParsedKey(..), InPlace(..))

import Conduit (ResourceT, runResourceT)
import Control.Exception (catch)
import Control.DeepSeq (force)
import Control.Monad.Reader (MonadReader, ReaderT, runReaderT, withReaderT)
import Control.Monad.Except (MonadError, ExceptT, runExceptT)
import Crypto.PubKey.RSA.Types (PublicKey, PrivateKey)
import qualified Data.Text as T
import qualified Data.Text.IO as T
import System.Exit (exitSuccess, exitFailure, exitWith, ExitCode(..))

-- | After command line arguments have been parsed, the following steps are performed. First,
-- read the config file and ensure it can be parsed. Next, inject the encryption/decryption context
-- into the environment. The context to inject is determined by the command line flags. Finally, evaluate
-- the command provided on the command line and return the results as a list of output lines.
--
-- This wraps and drives the core ConfCrypt library.
run ::
    AnyCommand  -- ^ Command line arguments
    -> IO ([T.Text], Maybe FilePath)
run NC = do
    res <- runConfCrypt emptyConfCryptFile $ evaluate NewConfCrypt
    either (\e -> print e *> exitFailure)
           (pure . (,Nothing))
           res
run (VER version) = pure ([version], Nothing)
run parsedArguments = do
    let filePath = confFilePath parsedArguments
    lines <- T.readFile filePath
    configParsingResults <- parseConfCrypt filePath <$> pure lines
    -- This allows threading the file path into the return, for use in
    -- in-place edits
    let overwritePath = if overwriteExisting parsedArguments
                        then Just filePath
                        else Nothing
    case configParsingResults of
        --TODO print errors to stdErr
        Left err -> print err *> exitFailure
        Right parsedConfiguration -> do
            result <- case parsedArguments of

                -- Requires Decryption
                RC KeyAndConf {key, provider} cmd ->
                        runConfCrypt parsedConfiguration $ runWithDecrypt key provider cmd
                GC KeyAndConf {key, provider} cmd ->
                        runConfCrypt parsedConfiguration $ runWithDecrypt key provider cmd
                VC KeyAndConf {key, provider} ->
                    runConfCrypt parsedConfiguration $ runWithDecrypt key provider ValidateConfCrypt

                -- Requires Encryption
                AC KeyAndConf {key, provider} cmd _ ->
                    runConfCrypt parsedConfiguration $ runWithEncrypt key provider cmd
                EC KeyAndConf {key, provider} cmd _ ->
                    runConfCrypt parsedConfiguration $ runWithEncrypt key provider cmd

                -- Doesn't care about encryption
                DC _ cmd _ ->
                    runConfCrypt parsedConfiguration $ evaluate cmd
            either (\e -> print e *> exitFailure)
                   (pure . (, overwritePath))
                   result
    where

        -- Inject an encryption context into the currently loaded environment. This varies dependng
        -- on whether its a local RSA key or a KMS key
        runWithEncrypt (KmsId k) AWS cmd = do
            ctx <- loadAwsCtx (KMSKeyId k)
            withReaderT (injectAWSCtx ctx) $ evaluate cmd
        runWithEncrypt UnNecessary AWS cmd = do
            ctx <- loadAwsCtx (KMSKeyId "dummy")
            withReaderT (injectAWSCtx ctx) $ evaluate cmd
        runWithEncrypt (OnDisk k) LocalRSA cmd = do
            rsaKey <- loadRSAKey k
            withReaderT (injectPubKey rsaKey) $ evaluate cmd

        -- Inject a decryption context into the currently loaded environment. This varies dependng
        -- on whether its a local RSA key or a KMS key
        runWithDecrypt (KmsId k) AWS cmd = do
            ctx <- loadAwsCtx (KMSKeyId k)
            withReaderT (injectAWSCtx ctx) $ evaluate cmd
        runWithDecrypt UnNecessary AWS cmd = do
            ctx <- loadAwsCtx (KMSKeyId "dummy")
            withReaderT (injectAWSCtx ctx) $ evaluate cmd
        runWithDecrypt (OnDisk k) LocalRSA cmd = do
            rsaKey <- loadRSAKey k
            withReaderT (injectPrivateKey rsaKey) $ evaluate cmd

        -- lensing functions
        injectAWSCtx :: AWSCtx -> (ConfCryptFile, ()) -> (ConfCryptFile, RemoteKey AWSCtx)
        injectAWSCtx ctx (conf, _) = (conf, RemoteKey ctx)
        injectPubKey :: PublicKey -> (ConfCryptFile, ()) -> (ConfCryptFile, TextKey PublicKey)
        injectPubKey key (conf, _) = (conf, TextKey key)
        injectPrivateKey :: PrivateKey -> (ConfCryptFile, ()) -> (ConfCryptFile, TextKey PrivateKey)
        injectPrivateKey key (conf, _) = (conf, TextKey key)


runConfCrypt ::
    ConfCryptFile
    -> ConfCryptM IO () [T.Text]
    -> IO (Either ConfCryptError [T.Text])
runConfCrypt file action =
    runResourceT . runExceptT $ runReaderT action (file, ())

confFilePath :: AnyCommand -> FilePath
confFilePath  (RC KeyAndConf {conf} _) = conf
confFilePath  (GC KeyAndConf {conf} _) = conf
confFilePath  (VC KeyAndConf {conf}) = conf
confFilePath  (AC KeyAndConf {conf} _ _) = conf
confFilePath  (EC KeyAndConf {conf} _ _) = conf
confFilePath  (DC (Conf conf) _ _) = conf

overwriteExisting :: AnyCommand -> Bool
overwriteExisting  (AC _ _ Overwrite) = True
overwriteExisting  (EC _ _ Overwrite) = True
overwriteExisting  (DC _ _ Overwrite) = True
overwriteExisting  _ = False


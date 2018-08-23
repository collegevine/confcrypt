module ConfCrypt.Encryption (
    KeyProjection,
    encryptValue,
    decryptValue,
    loadRSAKey,

    -- | Exported for Testing
    unpackPrivateRSAKey
    ) where

import ConfCrypt.Types

import Control.Monad.Trans (liftIO, MonadIO)
import Control.Monad.Except (MonadError, throwError)
import Crypto.PubKey.OpenSsh (OpenSshPublicKey(..), OpenSshPrivateKey(..), decodePublic, decodePrivate)
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.Types.PubKey.RSA (PrivateKey(..), PublicKey(..))
import Crypto.PubKey.RSA.PKCS15 (encrypt, decrypt)
import Crypto.Random.Types (MonadRandom)
import qualified Data.ByteString as BS
import Data.Text as T
import Data.Text.Encoding as T

class KeyProjection key where
    project :: RSA.KeyPair -> key

instance KeyProjection RSA.PublicKey where
    project = RSA.toPublicKey

instance KeyProjection RSA.PrivateKey where
    project = RSA.toPrivateKey

loadRSAKey :: (MonadIO m, Monad m, MonadError ConfCryptError m, KeyProjection key) =>
    FilePath
    -> m key
loadRSAKey privateKey = do
    prvBytes <- liftIO $ BS.readFile privateKey
    project <$> unpackPrivateRSAKey prvBytes

unpackPrivateRSAKey :: (MonadError ConfCryptError m) =>
    BS.ByteString
    -> m  RSA.KeyPair
unpackPrivateRSAKey rawPrivateKey =
    case decodePrivate rawPrivateKey of
        Left errMsg -> throwError . KeyUnpackingError $ T.pack errMsg
        Right (OpenSshPrivateKeyDsa _ _ ) -> throwError NonRSAKey
        Right (OpenSshPrivateKeyRsa key ) -> pure $ toKeyPair key
    where
    -- The joys of a needlessly fragmented library ecosystem...
        cryptonitePub key = RSA.PublicKey {
            RSA.public_size = public_size key,
            RSA.public_n = public_n key,
            RSA.public_e = public_e key
            }
        toKeyPair key = RSA.KeyPair $ RSA.PrivateKey {
            RSA.private_pub = cryptonitePub $ private_pub key,
            RSA.private_d = private_d key,
            RSA.private_p = private_p key,
            RSA.private_q = private_q key,
            RSA.private_dP = private_dP key,
            RSA.private_dQ = private_dQ key,
            RSA.private_qinv = private_qinv key
            }

decryptValue ::
    RSA.PrivateKey
    -> T.Text
    -> Either ConfCryptError T.Text
decryptValue privateKey encryptedValue =
    either (Left . DecryptionError) (Right . T.decodeUtf8) $ decrypt Nothing privateKey (T.encodeUtf8 encryptedValue)

-- | Encrypt a
encryptValue :: MonadRandom m =>
    RSA.PublicKey
    -> T.Text
    -> m (Either ConfCryptError T.Text)
encryptValue publicKey nakedValue = do
    res <- encrypt publicKey bytes
    pure $ either (Left . EncryptionError) (Right . T.decodeUtf8) res
    where
        bytes = T.encodeUtf8 nakedValue

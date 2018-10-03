module ConfCrypt.Providers.AWS (
    AWSCtx(..),
    KMSKeyId(..),
    loadAwsCtx
    ) where

import ConfCrypt.Types

import Control.Monad.Trans.AWS as AWS
import qualified Data.Text as T
import Control.Lens (lens)

-- | Wraps a KMS key id. For more on KMS keys, see https://docs.aws.amazon.com/kms/latest/developerguide/crypto-intro.html
newtype KMSKeyId = KMSKeyId {keyId :: T.Text}
    deriving (Show, Eq)

-- | Confcrypt reqires the pair of 'KMSKeyId' and 'AWS.Env' to run any operations in an AWS context.
data AWSCtx =
    AWSCtx {env :: AWS.Env, kmsKey :: KMSKeyId}

instance HasEnv (ConfCryptFile, AWSCtx) where
    environment = lens getEnv setEnv
        where
            getEnv :: (ConfCryptFile, AWSCtx) -> AWS.Env
            getEnv (_, AWSCtx {env}) = env
            setEnv :: (ConfCryptFile, AWSCtx) -> AWS.Env -> (ConfCryptFile, AWSCtx)
            setEnv (file, ctx) env' = (file, ctx {env = env'})

-- | Load the 'AWSCtx'. It first checks for configuration in environment variables, then a local config file. The
-- discovery logic is described in 'AWs'
loadAwsCtx keyId = do
    env <- AWS.newEnv AWS.Discover
    pure AWSCtx {env = env, kmsKey = keyId}

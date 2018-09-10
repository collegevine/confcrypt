module ConfCrypt.Providers.AWS (
    AWSCtx(..),
    KMSKeyId(..)
    ) where

import ConfCrypt.Types

import Control.Monad.Trans.AWS as AWS
import qualified Data.Text as T
import Control.Lens (lens)

newtype KMSKeyId = KMSKeyId {keyId :: T.Text}
    deriving (Show, Eq)

data AWSCtx =
    AWSCtx {env :: AWS.Env, key :: KMSKeyId}

instance HasEnv (ConfCryptFile, AWSCtx) where
    environment = lens getEnv setEnv
        where
            getEnv :: (ConfCryptFile, AWSCtx) -> AWS.Env
            getEnv (_, AWSCtx {env}) = env
            setEnv :: (ConfCryptFile, AWSCtx) -> AWS.Env -> (ConfCryptFile, AWSCtx)
            setEnv (file, ctx) env' = (file, ctx {env = env'})


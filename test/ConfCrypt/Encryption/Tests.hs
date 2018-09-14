module ConfCrypt.Encryption.Tests (
    encryptionTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Encryption

import ConfCrypt.Common

import Control.Monad.Except (runExcept, runExceptT)
import Data.Monoid ((<>))
import Data.List (sort, nub)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit
import Test.QuickCheck (NonEmptyList(..), ioProperty)
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.Types.PubKey.RSA
import Crypto.Random
import qualified Data.Text as T
import qualified Data.ByteString as BS


encryptionTests :: TestTree
encryptionTests = testGroup "encryption" [
    testProperty "decrypt . encrypt == id" $ \(Latin1Text value) -> let
        drg = drgNewSeed $ seedFromInteger 42
        in case runExcept (unpackPrivateRSAKey dangerousTestKey) of
                Left err -> ioProperty $ pure False
                Right keyPair -> ioProperty $ do
                    rawEncrypted <- runExceptT $ encryptValue (project keyPair :: RSA.PublicKey) value
                    encrypted <- either (error "fail to encrypt") pure rawEncrypted
                    decrypted <- pure . runExcept $ decryptValue (TextKey $ project keyPair :: TextKey RSA.PrivateKey) encrypted
                    pure $ either (const False)
                                  (== value)
                                  decrypted

   ,testCase "can encrypt and decrypt the term Foobar" $
        case runExcept (unpackPrivateRSAKey dangerousTestKey) of
            Left err -> assertFailure "Could not unpack RSA Key"
            Right keyPair -> do
                rawEncrypted <- runExceptT $ encryptValue (project keyPair :: RSA.PublicKey) "Foobar"
                encrypted <- either (const $ assertFailure "Could not enrypt") pure rawEncrypted
                let decrypted = runExcept $ decryptValue (TextKey $ project keyPair :: TextKey RSA.PrivateKey) encrypted
                either (const (assertFailure "Could not decrypt"))
                       (@=? "Foobar")
                       decrypted

    ]

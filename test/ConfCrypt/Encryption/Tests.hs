module ConfCrypt.Encryption.Tests (
    encryptionTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Encryption

import ConfCrypt.Common

import Control.Monad.Except (runExcept)
import Data.Monoid ((<>))
import Data.List (sort, nub)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.HUnit
import Test.QuickCheck (NonEmptyList(..), ioProperty)
import Crypto.Types.PubKey.RSA
import Crypto.Random
import qualified Data.Text as T
import qualified Data.ByteString as BS


encryptionTests :: TestTree
encryptionTests = testGroup "encryption" [
    testProperty "decrypt . encrypt == id" $ \(Latin1Text value) -> let
        drg = drgNewSeed $ seedFromInteger 42
        in case runExcept (unpackPrivateRSAKey dangerousTestKey) of
                Left err -> False
                Right keyPair -> let
                    (encrypted, _) = withDRG drg $ encryptValue (project keyPair) value
                    decrypted = decryptValue (project keyPair) =<< encrypted
                    in either (const False)
                              (== value)
                              decrypted
   ,testCase "can encrypt and decrypt the term Foobar" $
        case runExcept (unpackPrivateRSAKey dangerousTestKey) of
            Left err -> assertFailure "Could not unpack RSA Key"
            Right keyPair -> do
                encrypted <- encryptValue (project keyPair) "Foobar"
                let decrypted = decryptValue (project keyPair) =<< encrypted
                either (const (assertFailure "Could not decrypt"))
                       (@=? "Foobar")
                       decrypted

    ]

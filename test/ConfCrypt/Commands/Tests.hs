module ConfCrypt.Commands.Tests (
    commandTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Commands
import ConfCrypt.Parser
import ConfCrypt.Default
import ConfCrypt.Encryption (unpackPrivateRSAKey, project, TextKey(..))

import ConfCrypt.Common

import Conduit (runResourceT)
import Control.Monad.Identity (runIdentity)
import Control.Monad.Reader (runReaderT)
import Control.Monad.Except (runExcept, runExceptT)
--import Control.Monad.Writer (execWriter, execWriterT)
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.Random (withDRG, drgNewSeed, seedFromInteger)
import Data.Monoid ((<>))
import Data.List (sort, nub)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck (NonEmptyList(..))
import Test.Tasty.HUnit
import qualified Data.Text as T
import qualified Data.Text.IO as T
import qualified Data.Map as M

commandTests :: TestTree
commandTests = testGroup "command tests" [
    modifyFileProperties,
--    bufferWriteProperties,
    readTests,
    addTests
    ]

modifyFileProperties :: TestTree
modifyFileProperties = testGroup "modify file properties" [
    testProperty "genNewFileState f [] == f" $ \ccf -> let
        res = runExcept $ genNewFileState (fileContents ccf) [] :: Either ConfCryptError (M.Map ConfCryptElement LineNumber)
        in res == Right (fileContents ccf)

   ,testProperty "genNewFileState f [delete all in f] == []" $ \ccf -> let
        contents = fileContents ccf
        deletes = (,Remove) <$> M.keys contents
        res = runExcept $ genNewFileState contents deletes
        in either (const False)
                  (all isComment . M.keys)
                  res

   ,testProperty "genNewFileState [] additions == additions" $ \paramPairs -> let
        schemata = SchemaLine . fst <$> paramPairs
        params = (\p -> ParameterLine $ ParamLine (paramName p) (paramValue p)) . snd <$> paramPairs
        edits =  (,Add) <$> nub (schemata <> params)
        res = runExcept $ genNewFileState M.empty edits
        in null edits || either (const False)
                                (\m -> length edits == M.size m) -- rather weak check
                                res

    ]

{-bufferWriteProperties :: TestTree
bufferWriteProperties  = testGroup "Buffer write" [
    testProperty "parse (writerBuffer xs) == xs" $ \(ValidCCF ccf)-> let
        fc = fileContents ccf
        output = (<> "\n") . T.intercalate "\n" . execWriter $ writeFullContentsToBuffer True fc
        parseRes = parseConfCrypt "" output
        in either (const False)
                  (\ccf' -> fileContents ccf' == fc)
                  parseRes
    ]-}

readTests :: TestTree
readTests = testGroup "Read" [
    testCase "reading produces decrypted results" $ do
        let filePath = "testFile"
        lines <- T.readFile filePath
        let testLines = parseConfCrypt filePath lines
        res <- getReadResult testLines
        case res of
            Left e ->
                assertFailure $ show e
            Right lines ->
                lines @=? ["Test : String" :: T.Text,"Test = Foobar", "Test2 : Int", "Test2 = 42"]

   ,testCase "reading an empty file is an empty file" $ do
        let testLines = parseConfCrypt "empty test file" "# just a comment"
        res <- getReadResult testLines
        case res of
            Left e ->
                assertFailure $ show e
            Right lines ->
                lines @=? []

    -- TODO implement the 'Arbitrary' instance to make this rule possible
   -- ,testProperty "read . encrypt . read == id" $ \x -> x == 0
    ]
    where
        getReadResult :: Either ConfCryptError ConfCryptFile -> IO (Either ConfCryptError [T.Text])
        getReadResult testLines = do
            probablyKP <- runExceptT $ unpackPrivateRSAKey dangerousTestKey
            privateKey <- either (assertFailure . show) (pure . project ) probablyKP :: IO RSA.PrivateKey
            ccf <- either (assertFailure . show) pure testLines
            runResourceT . runExceptT $ runReaderT (evaluate ReadConfCrypt) (ccf, TextKey privateKey) :: IO (Either ConfCryptError [T.Text])


addTests :: TestTree
addTests = testGroup "Add" [
    {- testCase "add x [] == [x]" $ do
        probablyKP <- runExceptT $ unpackPrivateRSAKey dangerousTestKey
        publicKey <- either (assertFailure . show) (pure . project ) probablyKP :: IO RSA.PublicKey
        let dummyAdd = AddConfCrypt  {aName= "Test", aValue = "Foo", aType = CString}
        res <- runResourceT . runExceptT . execWriterT $ runReaderT (evaluate dummyAdd) (emptyConfCryptFile, TextKey publicKey) :: IO ( Either ConfCryptError [T.Text] )
        case res of
            Left e ->
                assertFailure $ show e
            Right lines ->
                lines @=? ["Test : String" :: T.Text,"Test = y7wDxwsamscCOlqEcR0MgatspFf0NG0Wv32flD8cyh80tkN30g1iLlobxJhf/qfgm8ISRgtSSsxEsh5ujg7DS8d5oMhoFZcZnK0QuRcBDuoG8gRNiF1LHh4hhUJWksqdd8HNmuNHr45a97Alezj8GF8abTs3RoVCTV46PYmSP0avd0Oudfjn9iTF2C/q+S74fH64TSDKmgWrrexGpA07Yc8vjMW1MuFoS3NpONsuYwUr2pSCuvWCdfbs2ZfGqGG3CY0E/lfTJTOnw7J5HKelRuvE54Ey32bLLiSRd6Ot+O2WJLBGi0I0rkn0ZP3l9vP/URu9Wft4j3a/yLOeAM/NUmI/1SQrXjq8a1sTZGcC2+H4RfyLuV1sFPjTZ6zr/gWCasLgSRyRpvlX98H5GlPrjLPfHp493C2CiHljrSxXE8zvJO5/MXwenVqWShq7PXFGZs8NnwLMl6moXYGFJGooLKvslgSwNYX1BB15BJBhMbDIQoplTNhZUXgMhwJau5DBtWpt0x235vCRBK94Ryba8KLzWnIUKydSbdNGqNc0oaPhXOdGqSIex4PDwhepQ8c8+r/cyKBQDoGLS09q2Vx3ZPIAJYrsEreOH0PFRUIdkumBEXR9GdDot5MG0OmM29nHbuh86rDauXl2oXK/GWoqAq7yKNYAY/+JdpRhsDXP7lE="]
    -}
   testCase "add x [x] == Error case" $ do
        probablyKP <- runExceptT $ unpackPrivateRSAKey dangerousTestKey
        publicKey <- either (assertFailure . show) (pure . project ) probablyKP :: IO RSA.PublicKey
        let dummyAdd = AddConfCrypt  {aName= "Test", aValue = "Foo", aType = CString}
            ccf = ConfCryptFile "containsX"
                                (M.fromList [(SchemaLine Schema {sName= "Test", sType = CString},LineNumber 1),
                                             (ParameterLine ParamLine {pName ="Test", pValue="Foo"},LineNumber 2)])
                                [Parameter "Test" "Foo" ( Just CString )]
        res <- runResourceT . runExceptT $ runReaderT (evaluate dummyAdd) (ccf, TextKey publicKey) :: IO (Either ConfCryptError [T.Text])
        case res of
            Left (WrongFileAction _) -> assertBool "hmm" True
            _ -> assertFailure "Expected a WrongFileAction error"

    {-,testCase "add x [y] == [y,x] (ordering matters)" $ do
        probablyKP <- runExceptT $ unpackPrivateRSAKey dangerousTestKey
        publicKey <- either (assertFailure . show) (pure . project ) probablyKP :: IO RSA.PublicKey
        let dummyAdd = AddConfCrypt  {aName= "Test", aValue = "Foo", aType = CString}
            ccf = ConfCryptFile "containsY"
                                (M.fromList [(SchemaLine Schema {sName= "Fizz", sType = CString},LineNumber 1),
                                             (ParameterLine ParamLine {pName ="Fizz", pValue="Foo"},LineNumber 2)])
                                [Parameter "Test" "Fizz" (Just CString)]
        res <- runResourceT . runExceptT . execWriterT $ runReaderT (evaluate dummyAdd) (ccf, TextKey publicKey) :: IO (Either ConfCryptError [T.Text])
        case res of
            Left e ->
                assertFailure $ show e
            Right lines ->
                lines @=? ["Fizz : String", "Fizz = Foo","Test : String" :: T.Text,"Test = y7wDxwsamscCOlqEcR0MgatspFf0NG0Wv32flD8cyh80tkN30g1iLlobxJhf/qfgm8ISRgtSSsxEsh5ujg7DS8d5oMhoFZcZnK0QuRcBDuoG8gRNiF1LHh4hhUJWksqdd8HNmuNHr45a97Alezj8GF8abTs3RoVCTV46PYmSP0avd0Oudfjn9iTF2C/q+S74fH64TSDKmgWrrexGpA07Yc8vjMW1MuFoS3NpONsuYwUr2pSCuvWCdfbs2ZfGqGG3CY0E/lfTJTOnw7J5HKelRuvE54Ey32bLLiSRd6Ot+O2WJLBGi0I0rkn0ZP3l9vP/URu9Wft4j3a/yLOeAM/NUmI/1SQrXjq8a1sTZGcC2+H4RfyLuV1sFPjTZ6zr/gWCasLgSRyRpvlX98H5GlPrjLPfHp493C2CiHljrSxXE8zvJO5/MXwenVqWShq7PXFGZs8NnwLMl6moXYGFJGooLKvslgSwNYX1BB15BJBhMbDIQoplTNhZUXgMhwJau5DBtWpt0x235vCRBK94Ryba8KLzWnIUKydSbdNGqNc0oaPhXOdGqSIex4PDwhepQ8c8+r/cyKBQDoGLS09q2Vx3ZPIAJYrsEreOH0PFRUIdkumBEXR9GdDot5MG0OmM29nHbuh86rDauXl2oXK/GWoqAq7yKNYAY/+JdpRhsDXP7lE="]
    -}

    ]

isComment (CommentLine _) = True
isComment _ = False


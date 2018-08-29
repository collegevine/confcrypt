module ConfCrypt.Commands.Tests (
    commandTests
    ) where

import ConfCrypt.Types
import ConfCrypt.Commands
import ConfCrypt.Parser
import ConfCrypt.Encryption (unpackPrivateRSAKey, project)

import ConfCrypt.Common

import Control.Monad.Identity (runIdentity)
import Control.Monad.Reader (runReaderT)
import Control.Monad.Except (runExcept, runExceptT)
import Control.Monad.Writer (execWriter, execWriterT)
import qualified Crypto.PubKey.RSA.Types as RSA
import Crypto.Random (withDRG, drgNewSeed, seedFromInteger)
import Data.Monoid ((<>))
import Data.List (sort, nub)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck (NonEmptyList(..))
import Test.Tasty.HUnit
import qualified Data.Text as T
import qualified Data.Map as M

commandTests :: TestTree
commandTests = testGroup "command tests" [
    modifyFileProperties,
    bufferWriteProperties,
    readTests
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
        edits =  (,Add) <$> (nub $ schemata <> params)
        res = runExcept $ genNewFileState M.empty edits
        in if null edits
           then True
           else either (const False)
                       (\m -> (length edits) == (M.size m)) -- rather weak check
                       res

    ]

bufferWriteProperties :: TestTree
bufferWriteProperties  = testGroup "Buffer write" [
    testProperty "parse (writerBuffer xs) == xs" $ \(ValidCCF ccf)-> let
        fc = fileContents ccf
        output = (<> "\n") . T.intercalate "\n" . execWriter $ writeFullContentsToBuffer True fc
        parseRes = parseConfCrypt "" output
        in either (const False)
                  (\ccf' -> fileContents ccf' == fc)
                  parseRes
    ]

readTests :: TestTree
readTests = testGroup "Read" [
    testCase "reading produces decrypted results" $ do
        let testLines = parseConfCrypt "test file" testFile
        probablyKP <- runExceptT $ unpackPrivateRSAKey dangerousTestKey
        privateKey <- either (assertFailure . show) (pure . project ) probablyKP :: IO RSA.PrivateKey
        ccf <- either (assertFailure . show) pure testLines
        let res = runIdentity . runExceptT . execWriterT $ runReaderT (evaluate ReadConfCrypt) (ccf, privateKey) :: Either ConfCryptError [T.Text]
        case res of
            Left e ->
                assertFailure $ show e
            Right lines ->
                lines @=? ["Test : String" :: T.Text,"Test = Foobar", "Test2 : Int", "Test2 = 42"]

   ,testCase "reading an empty file is an empty file" $ do
        let testLines = parseConfCrypt "empty test file" "# just a comment"
        probablyKP <- runExceptT $ unpackPrivateRSAKey dangerousTestKey
        privateKey <- either (assertFailure . show) (pure . project ) probablyKP :: IO RSA.PrivateKey
        ccf <- either (assertFailure . show) pure testLines
        let res = runIdentity . runExceptT . execWriterT $ runReaderT (evaluate ReadConfCrypt) (ccf, privateKey) :: Either ConfCryptError [T.Text]
        case res of
            Left e ->
                assertFailure $ show e
            Right lines ->
                lines @=? []

    -- TODO implement the 'Arbitrary' instance to make this rule possible
   -- ,testProperty "read . encrypt . read == id" $ \x -> x == 0
    ]

isComment (CommentLine _) = True
isComment _ = False

testFile :: T.Text
testFile = "Test : String\n\
           \Test = Ld5RCo+QrF8ts8dRVJOEuHjwS8zU/K21qR0Oy/SaS4FTEmpr42jzesaaVEprYTIqRkGi0QrS9oEHlYRHU377KWVs0N/Oh65BaUT8XSEOi+XK2eyLHjYZOj/3ARbpxgCWsK5VXN5KZHPY2guYLrotDFgF87qQEPfAI9E06R3sNKlgPrbXnfhwVe+SqAj2/1m/TVf2MjAY+ar9sb2sX8Zt072LGH/uUXFqdkc4nGjx0TDDnnNWIh4TnYNNpnPB0uQKg1EfJD5C5uwBO13BdCDP9v5GNaeAoRBs0bJpiM8X5q2VJaiBC73abs8txw+MW6ASJkHDUyi/RLf0TWEPqTzK5/BSCHZDeiA6RFQEhrL1yGZ4Uc0QA6C6H/n6W0DcimMS5tk088XSPLpi1onaL0ZR3WsMV0zwxXpAmnr/h4tr9komxSOBmLgX1mAdshGfQmPQMmVBL2eY4ohconSoP2r4mWuHBWD5AmgHwhnndSSborNdUkgFxKm5++44nHIoXCgoMfgW4rJBD9f2OZcJb/hUradf2iIWhwUnnPPpMvzFGYjWhyjkiI73luv31i3VtUcamA0aU3U3IGjc5+yuNM85olFIAgdA2lOWAgNOsfrzDTjeJ+xB7fyvb//ViQzyKSDrqm53hfeF4DxLwhxNM608eVlA+UzLqYZUirq5xpuJgFQ=\n\
           \Test2 : Int\n\
           \Test2 = ADRg4daslh0ZDXVrHpSn1AQwReck2UKzjei+Zn34VzbqlvBI4rq9DzYDyWYiOpl+4lP6J6sHT+IbV/ObMC4Z6qELmIDergo/OuoZEEIfn1HWMSHwbxajzPjGvjWehCf0I8lO2+9QXhDvi3kF24ehWRaIIvcQaCV7ALPfucqjgAoxZ7l01RUTiMdy5mpkExWsADMzU5WLbuQJ80SCxJHPNtjLdy2ajwVVmC6WhVZWPH5lGjp6W9XLbyod2u8uYj2Y12VctjuECZxctqEsZbT9kJU/Wh+nDEQmOedQLEIWK7+U7wU6kE0bQhQqNXnh+958dkSMkzh+4lUjg5EW1ykLXalm+sulf7j4NkLCjsR3oARlUO02JvHriZbfGSdOPm1T6TC2J7IAQwDCQQWv/ls/y9wsKUTemAx/jO+I1iObJ+jsXrMTZVCczFbcC2bBwI8PLn9cVtQEAh7ZToel111r10aoD4yLbizgvrE18sL2Kj+dKjPxVEafGatLz//wb5gK/Pn1VVW02nv9AWLAeN21ymV1VKWsyj+P2JQjd/jiWS9WuEGhuWL3HtvZIqTjsng4HFdORSvx05oU6slYdhQ2f+w/1/1F5I0pefmOoTr8yVl3kcmmCxgyWjQlFjRa4/nbwJvW+hu8Br+p1YJn6rq5kQhUlOxp/NJ+S0ui+M2mwLE=\n"

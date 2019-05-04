module ConfCrypt.CLI.API.Tests (
    cliAPITests
    ) where

import ConfCrypt.CLI.API
import ConfCrypt.Commands (GetConfCrypt(..), AddConfCrypt(..), EditConfCrypt(..), DeleteConfCrypt(..), ReadConfCrypt(..))
import ConfCrypt.Types

import ConfCrypt.Common

import Options.Applicative (execParserPure, ParserResult(..), defaultPrefs)
import Test.Tasty
import Test.Tasty.HUnit

localTestConf :: KeyAndConf
localTestConf = KeyAndConf (OnDisk "testKey") LocalRSA "test.econf"

cliAPITests :: TestTree
cliAPITests = testGroup "cli api" [
    apiTests
    ]

apiTests :: TestTree
apiTests = testGroup "specific cases" [
    readCases,
    getCases,
    addCases,
    editCases,
    deleteCases,
    validateCases
    ]

readCases :: TestTree
readCases = testGroup "read" [
    testCase "read requires a key" $ do
        let args = ["rsa", "read", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ,testCase "read requires a config file" $ do
        let args = ["rsa", "read", "--key", "testKey"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "read preserves the provided key file with -k" $ do
        let args = ["rsa", "read", "-k", "testKey", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (RC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") _) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an RC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "read preserves the provided key file with --key" $ do
        let args = ["rsa", "read", "--key", "testKey","test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (RC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") _) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an RC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ,testCase "read preserves the provided key file with --key" $ do
        let args = ["rsa", "read", "--key", "testKey","test.econf", "--format", "foo"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (RC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (ReadConfCrypt (Just "foo"))) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an RC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ]

getCases :: TestTree
getCases = testGroup "get" [
    testCase "get requires a key" $ do
        let args = ["rsa", "get", "--name", "Test", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ,testCase "get requires a config file" $ do
        let args = ["rsa", "get", "--key", "testKey", "--name", "Test"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "get preserves the provided key file with -k" $ do
        let args = ["rsa", "get", "-k", "testKey", "--name", "Test", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (GC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (GetConfCrypt "Test")) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed a GC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "get preserves the provided key file with --key" $ do
        let args = ["rsa", "get", "--key", "testKey", "--name", "Test", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (GC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (GetConfCrypt "Test")) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed a GC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ]

addCases :: TestTree
addCases = testGroup "add" [
    testCase "requires a key" $ do
        let args = ["rsa", "add", "--name", "test", "--type", "String", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a name" $ do
        let args = ["rsa", "add", "--key", "testKey", "--type", "String", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a type" $ do
        let args = ["rsa", "add", "--key", "testKey", "--name", "test", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a value" $ do
        let args = ["rsa", "add", "--key", "testKey", "--name", "test", "--type", "String", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a config file" $ do
        let args = ["rsa", "add", "--key", "testKey", "--name", "test", "--type", "String", "--value", "foo"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "preserves the provided arguments " $ do
        let args =  ["rsa", "add", "--key", "testKey", "--name", "test", "--type", "String", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (AC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (AddConfCrypt "test" "foo" CString)) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an AC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "supports alternative argument labels" $ do
        let args =  ["rsa", "add", "-k", "testKey", "-n", "test", "-t", "String", "-v", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (AC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (AddConfCrypt "test" "foo" CString)) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an AC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ]

editCases :: TestTree
editCases = testGroup "edit" [
    testCase "requires a key" $ do
        let args = ["rsa", "edit", "--name", "test", "--type", "String", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a name" $ do
        let args = ["rsa", "edit", "--key", "testKey", "--type", "String", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a type" $ do
        let args = ["rsa", "edit", "--key", "testKey", "--name", "test", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a value" $ do
        let args = ["rsa", "edit", "--key", "testKey", "--name", "test", "--type", "String", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a config file" $ do
        let args = ["rsa", "edit", "--key", "testKey", "--name", "test", "--type", "String", "--value", "foo"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "preserves the provided arguments " $ do
        let args =  ["rsa", "edit", "--key", "testKey", "--name", "test", "--type", "String", "--value", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (EC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (EditConfCrypt "test" "foo" CString)) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an AC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "supports alternative argument labels" $ do
        let args =  ["rsa", "edit", "-k", "testKey", "-n", "test", "-t", "String", "-v", "foo", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (EC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") (EditConfCrypt "test" "foo" CString)) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an AC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ]

deleteCases :: TestTree
deleteCases = testGroup "delete" [
    testCase "requires a name" $ do
        let args = ["delete", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "requires a config file" $ do
        let args = ["delete", "--name", "test", "--value", "foo"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "preserves the provided arguments " $ do
        let args =  ["delete", "--name", "test", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (DC (Conf "test.econf") (DeleteConfCrypt "test")) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed a DC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"

   ,testCase "supports alternative argument labels" $ do
        let args =  ["delete", "-n", "test", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (DC (Conf "test.econf") (DeleteConfCrypt "test")) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed a DC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ]

validateCases :: TestTree
validateCases = testGroup "validate" [
    testCase "validate requires a key" $ do
        let args = ["rsa", "validate", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "validate requires a config file" $ do
        let args = ["rsa", "validate", "--key", "testKey"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Failure _ -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "validate preserves the provided key file with -k" $ do
        let args = ["rsa", "validate", "-k", "testKey", "test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (VC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") ) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an VC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
   ,testCase "validate preserves the provided key file with --key" $ do
        let args = ["rsa", "validate", "--key", "testKey","test.econf"]
            res = execParserPure defaultPrefs cliParser args
        case res of
            Success (VC (KeyAndConf (OnDisk "testKey") LocalRSA "test.econf") ) -> assertBool "can't fail" True
            Success a -> assertFailure ("Incorrectly parsed: "<> show a)
            Failure _ -> assertFailure "Should have parsed an VC"
            CompletionInvoked _ -> assertFailure "Incorrectly triggered completion"
    ]


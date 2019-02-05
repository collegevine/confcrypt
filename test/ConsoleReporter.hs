{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NoMonomorphismRestriction #-}

module ConsoleReporter (thresholdRunner, Threshold(..) ) where

import Control.Applicative
import Control.Monad (mfilter)
import Control.Monad.IO.Class (liftIO)
import Data.Maybe (fromMaybe)
import Data.Monoid (Sum(..))
import Data.Proxy (Proxy(..))
import Data.Tagged (Tagged(..))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import Generics.Deriving.Monoid (memptydefault, mappenddefault)
import Options.Applicative (metavar)

import qualified Control.Concurrent.STM as STM
import qualified Control.Monad.State as State
import qualified Data.Functor.Compose as Functor
import qualified Data.IntMap as IntMap
import qualified Test.Tasty as Tasty
import qualified Test.Tasty.Providers as Tasty
import qualified Test.Tasty.Options as Tasty
import qualified Test.Tasty.Runners as Tasty

--------------------------------------------------------------------------------
newtype Threshold = Threshold Double
  deriving (Ord, Eq, Typeable)
instance Tasty.IsOption (Maybe Threshold) where
  defaultValue = Just $ Threshold 80
  parseValue = Just . mfilter inRange . fmap Threshold . Tasty.safeRead
  optionName = Tagged "threshold"
  optionHelp = Tagged "A success threshold percentage"
  optionCLParser = Tasty.mkOptionCLParser (metavar "NUMBER")

inRange :: Threshold -> Bool
inRange (Threshold x) = x `elem` [0..100]

--------------------------------------------------------------------------------
data Summary = Summary { summaryFailures :: Sum Int
                       , summaryErrors :: Sum Int
                       , summarySuccesses :: Sum Int
                       } deriving (Generic, Show)

instance Monoid Summary where
  mempty = memptydefault
#if !MIN_VERSION_base(4,11,0)
  mappend = mappenddefault
#else
instance Semigroup Summary where
  (<>) = mappenddefault
#endif


--------------------------------------------------------------------------------
{-|

  To run tests using this ingredient, use 'Tasty.defaultMainWithIngredients',
  passing 'thresholdRunner' as one possible ingredient. This ingredient will
  run tests if you pass the @--threshold@ command line option. For example,
  @--threshold 90@ will run all the tests and return an error exit code
  if success percentage is under 90%.

-}
thresholdRunner :: Tasty.Ingredient
thresholdRunner = Tasty.TestReporter optionDescription runner
 where
  optionDescription = [ Tasty.Option (Proxy :: Proxy (Maybe Threshold)) ]
  runner options testTree = do
    Threshold threshold <- Tasty.lookupOption options

    return $ \statusMap ->
      let
        runTest :: (Tasty.IsTest t)
                => Tasty.OptionSet
                -> Tasty.TestName
                -> t
                -> Tasty.Traversal (Functor.Compose (State.StateT IntMap.Key IO) (Const Summary))
        runTest _ _ _ = Tasty.Traversal $ Functor.Compose $ do
          i <- State.get
          summary <- liftIO $ STM.atomically $ do
            status <- STM.readTVar $
              fromMaybe (error "Attempted to lookup test by index outside bounds") $
                IntMap.lookup i statusMap

            case status of
              -- If the test is done, record its result
              Tasty.Done result
                | Tasty.resultSuccessful result ->
                    pure $ mempty { summarySuccesses = Sum 1 }
                | otherwise ->
                    case resultException result of
                      Just _  -> pure $ mempty { summaryErrors = Sum 1 }
                      Nothing -> pure $
                        if resultTimedOut result
                          then mempty { summaryErrors = Sum 1 }
                          else mempty { summaryFailures = Sum 1 }

              -- Otherwise the test has either not been started or is currently
              -- executing
              _ -> STM.retry

          Const summary <$ State.modify (+ 1)

      in do
        (Const summary, _) <-
          flip State.runStateT 0 $ Functor.getCompose $ Tasty.getTraversal $
           Tasty.foldTestTree
             Tasty.trivialFold { Tasty.foldSingle = runTest }
             options
             testTree

        return $ \ _ -> do
          let total = count summary
              ratio2NumOfTests = show $ ceiling $ total * threshold / 100.0
              ratios = mkRatios total summary
              fieldS f = show $ getSum $ f summary
              round2dp x = show $ fromIntegral (round $ x * 1e2) / 1e2
              fieldR f = round2dp $ f ratios
              r0 = "\nNumber of tests: " ++ show total ++ ", Threshold: "
                ++ show threshold ++ "% => " ++ ratio2NumOfTests ++ " tests"
              r1 = "\nFailures: " ++ fieldS summaryFailures
                ++ " (" ++ fieldR rFailures ++ "%)"
              r2 = "Errors: " ++ fieldS summaryErrors
                ++ " (" ++ fieldR rErrors ++ "%)"
              r3 = "Successes: " ++ fieldS summarySuccesses
                ++ " (" ++ fieldR rSuccesses ++ "%)"
          liftIO $ putStrLn $ r0 ++ r1 ++ ", " ++ r2 ++ ", " ++ r3
          return $ check threshold total summary

  resultException r =
    case Tasty.resultOutcome r of
         Tasty.Failure (Tasty.TestThrewException e) -> Just e
         _ -> Nothing

  resultTimedOut r =
    case Tasty.resultOutcome r of
         Tasty.Failure (Tasty.TestTimedOut _) -> True
         _ -> False

data Ratio = Ratio { rFailures :: Double
                   , rErrors :: Double
                   , rSuccesses :: Double
                   }

count :: Summary -> Double
count summary =
  fromIntegral $ getSum $ summarySuccesses summary
                       <> summaryFailures summary
                       <> summaryErrors summary

mkRatios :: Double -> Summary -> Ratio
mkRatios total summary =
  let ratio n = n * 100 / total
      field f = fromIntegral $ getSum $ f summary
  in Ratio { rFailures = ratio (field summaryFailures)
           , rErrors = ratio (field summaryErrors)
           , rSuccesses = ratio (field summarySuccesses) }

check :: Double -> Double -> Summary -> Bool
check threshold total summary =
  let success = fromIntegral $ getSum $ summarySuccesses summary
      ratio = success * 100 / total
  in ratio >= threshold

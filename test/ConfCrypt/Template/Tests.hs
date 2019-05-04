module ConfCrypt.Template.Tests (
    templateTests
    ) where

import ConfCrypt.Template (renderTemplate)
import ConfCrypt.Types (Parameter(..), SchemaType(..))

import Test.Tasty
import Test.Tasty.HUnit

import Data.Text (Text(..))
import Data.Either (isLeft)

templateTests :: TestTree
templateTests = testGroup "format template parser" [
    testCase "basic template works" $ 
        render "%t %n %v" param @=? Right "String name value"
    
    ,testCase "template variables can appear next to any character" $ 
        render "tt%ttt%ntt%vtt" param @=? Right "ttStringttnamettvaluett"
    
    ,testCase "invalid variable names give an error" $
        isLeft (render "%t %a" param) @=? True
    
    ,testCase "%% renders to %" $
        render "%v%%%n%%%t" param @=? Right "value%name%String"
    
    ,testCase "variables can appear more than once" $
        render "%v%v%v" param @=? Right "valuevaluevalue"
    ]

render :: Text -> Parameter -> Either Text Text
render tpl param =
    let renderFunc = renderTemplate tpl
    in renderFunc <*> pure param

param = Parameter "name" "value" (Just CString)
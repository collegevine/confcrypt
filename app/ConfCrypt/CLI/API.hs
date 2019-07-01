module ConfCrypt.CLI.API (
    KeyAndConf(..),
    Conf(..),
    KeyProvider(..),
    AnyCommand(..),
    ParsedKey(..),
    InPlace(..),
    cliParser
) where

import ConfCrypt.Types (SchemaType(..))
import ConfCrypt.Commands (GetConfCrypt(..), AddConfCrypt(..), EditConfCrypt(..), DeleteConfCrypt(..), ReadConfCrypt(..))

import Options.Applicative
       (ParserInfo, Parser, progDesc, command, fullDesc, long, switch,
        metavar, maybeReader, help, strOption, short, info, header, footer,
        strArgument, hsubparser, helper, (<**>), value, option, auto,
        ReadM)
import qualified Data.Text as T
import Paths_confcrypt (version)
import Data.Version (showVersion)
import Text.Read (readMaybe)

data KeyAndConf = KeyAndConf {key :: ParsedKey, provider :: KeyProvider, conf :: FilePath}
    deriving (Eq, Show)
newtype Conf = Conf FilePath
    deriving (Eq, Show)
data InPlace
    = Overwrite
    | StdOut
    deriving (Eq, Show)

data AnyCommand
    = RC KeyAndConf ReadConfCrypt
    | GC KeyAndConf GetConfCrypt
    | AC KeyAndConf AddConfCrypt InPlace
    | EC KeyAndConf EditConfCrypt InPlace
    | DC Conf DeleteConfCrypt InPlace
    | VC KeyAndConf
    | VER T.Text
    | NC
    deriving (Eq, Show)

data KeyProvider
    = AWS
    | LocalRSA
    deriving (Eq, Show)

data ParsedKey
    = OnDisk FilePath
    | KmsId T.Text
    | UnNecessary
    deriving (Eq, Show)

cliParser :: ParserInfo AnyCommand
cliParser = info (commandParser <**> helper) $
        fullDesc <>
        (header "confcrypt: a tool for sane configuration management") <>
        (footer "confcrypt's documentation and source is avaiable at https://github.com/collegevine/confcrypt")


commandParser :: Parser AnyCommand
commandParser = hsubparser
    (
        command "aws" awsCmds
        <>
        command "rsa" rsaCmds
        <>
        command "new" new
        <>
        command "delete" delete
        <>
        command "version" vers
    )

awsCmds :: ParserInfo AnyCommand
awsCmds = info (
    hsubparser (
        command "add" (add AWS)
        <>
        command "edit" (edit AWS)
        <>
        command "read" (readConf AWS)
        <>
        command "get" (get AWS)
        <>
        command "validate" (validate AWS)
        )
    ) $
    fullDesc <>
    (header "Run using a local RSA key. This overloads the --key option to accept a file path to the public key.")

rsaCmds :: ParserInfo AnyCommand
rsaCmds = info (
    hsubparser (
        command "add" (add LocalRSA)
        <>
        command "edit" (edit LocalRSA)
        <>
        command "read" (readConf LocalRSA)
        <>
        command "get" (get LocalRSA)
        <>
        command "validate" (validate LocalRSA)
        )
    ) $
    fullDesc <>
    (header "Run using a local RSA key. This overloads the --key option to accept a file path to the public key.")


vers :: ParserInfo AnyCommand
vers = info (pure . VER . T.pack $ showVersion version)
               (progDesc "The current version of confcrypt" <> fullDesc)

add ::
    KeyProvider
    -> ParserInfo AnyCommand
add provider = info ( AC <$> keyAndConf provider True <*> (AddConfCrypt <$> onlyName <*> onlyValue <*> onlyType) <*> inPlace)
           (progDesc "Add a new parameter to the configuration file. New parameters are added to the end of the file." <>
            fullDesc)

edit ::
    KeyProvider
    -> ParserInfo AnyCommand
edit provider = info ( EC <$> keyAndConf provider True <*> (EditConfCrypt <$> onlyName <*> onlyValue <*> onlyType) <*> inPlace)
           (progDesc "Modify an existing parameter in-place. This should preserve a clean diff." <>
            fullDesc)

delete :: ParserInfo AnyCommand
delete = info ( DC <$> getConf <*> (DeleteConfCrypt <$> onlyName) <*> inPlace)
           (progDesc "Removes an existing parameter from the configuration." <>
            fullDesc)

readConf ::
    KeyProvider
    -> ParserInfo AnyCommand
readConf provider = info ( RC <$> keyAndConf provider False <*> (ReadConfCrypt <$> onlyFormat))
           (progDesc "Read in the provided config and decrypt it with the key. Results are printed to StdOut." <>
            fullDesc)

get ::
    KeyProvider
    -> ParserInfo AnyCommand
get provider = info ( GC <$> keyAndConf provider False <*> (GetConfCrypt <$> onlyName))
            (progDesc "Get a single parameter value from the configuration file." <>
            fullDesc)

validate ::
    KeyProvider
    -> ParserInfo AnyCommand
validate provider = info ( VC <$> keyAndConf provider False)
           (progDesc "Check that the configuration is self-consistent and obeys the confcrypt rules." <>
            fullDesc)

new :: ParserInfo AnyCommand
new  = info (pure NC)
            (progDesc "Produce a new boilerplate confcrypt file. This should be piped into your desired config." <>
             fullDesc)

keyAndConf ::
    KeyProvider
    -> Bool -- This is an ugly bit of overloading
    -> Parser KeyAndConf
keyAndConf AWS True =
    KeyAndConf <$>
        (KmsId . T.pack <$> parseKey) <*>
        pure AWS <*>
        onlyConf
keyAndConf AWS False =
    KeyAndConf <$>
        pure UnNecessary <*>
        pure AWS <*>
        onlyConf
keyAndConf LocalRSA _ =
    KeyAndConf <$>
        (OnDisk <$> parseKey) <*>
        pure LocalRSA <*>
        onlyConf

parseKey :: Parser String
parseKey =
    strOption (
        long "key" <>
        short 'k' <>
        metavar "KEY" <>
        help "The path to the key. May be a KMS id or RSA file path, depending on command"
        )
getConf :: Parser Conf
getConf = Conf <$> onlyConf

onlyConf :: Parser FilePath
onlyConf = strArgument (metavar "CONFIG_FILE")

inPlace :: Parser InPlace
inPlace = toInPlace <$> switch (
    long "in-place" <>
    short 'p' <>
    help "Allows overwriting the existing confcrypt file rather than emitting the results to stdOut."
    )
    where
        toInPlace True = Overwrite
        toInPlace False = StdOut

onlyName :: Parser T.Text
onlyName = strOption (
    long "name" <>
    short 'n' <>
    metavar "PARAMETER_NAME" <>
    help "The name of the configuration parameter. This must consist of consist solely of uppercase letters, digits, and the '_' (underscore) ASCII characters."
    )

onlyValue :: Parser T.Text
onlyValue = strOption (
    long "value" <>
    short 'v' <>
    metavar "PARAMETER_VALUE" <>
    help "The value to set in the config file. This can be any set of characters you want, but there may be issues with multi-byte code points in UTF-8."
    )

onlyType :: Parser SchemaType
onlyType =
      fromString <$> strOption (
        long "type" <>
        short 't' <>
        metavar "PARAMETER_TYPE" <>
        help "The associated type for the variable. Must be one of [String, Int, Boolean]"
        )
    where
        fromString = read . (:) 'C'

onlyFormat :: Parser (Maybe T.Text)
onlyFormat = option maybeOptReader (
    long "format" <>
    short 'f' <>
    metavar "TEMPLATE" <>
    value Nothing <>
    help (
        "Output parameters in a custom format specified by a template, with placeholders being replaced " <>
        "with the values for each parameter. Placeholders consist of a '%' and a single character, " <>
        "a literal '%' can be written as '%%'. Valid placeholders are: %t: type, %n: name, %v: value."
        )
    )

maybeOptReader :: ReadM (Maybe T.Text)
maybeOptReader = maybeReader $ Just. Just . T.pack

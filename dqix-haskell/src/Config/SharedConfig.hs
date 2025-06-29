{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DeriveAnyClass #-}

module Config.SharedConfig
    ( SharedConfig(..)
    , AssessmentConfig(..)
    , ProbeWeights(..)
    , ScoringConfig(..)
    , SharedConfigLoader
    , loadSharedConfig
    , getProbeWeight
    , getProbeWeightWithError
    , getTotalWeight
    , validateConfiguration
    , getScoringLevel
    , isLoaded
    , getConfigPath
    , printConfigurationSummary
    , initializeConfig
    ) where

import Data.Yaml
import GHC.Generics
import Data.Map.Strict (Map)
import qualified Data.Map.Strict as Map
import Control.Exception (try, SomeException)
import System.Directory (doesFileExist, getCurrentDirectory)
import System.FilePath ((</>), takeDirectory)
import Text.Printf (printf)
import Data.IORef
import System.IO.Unsafe (unsafePerformIO)

-- | Configuration structure representing shared-config.yaml
data SharedConfig = SharedConfig
    { assessment :: AssessmentConfig
    , probe_weights :: Map String Double
    , scoring :: ScoringConfig
    } deriving (Show, Generic, FromJSON, ToJSON)

data AssessmentConfig = AssessmentConfig
    { timeout_seconds :: Int
    , concurrent_limit :: Int
    , retry_count :: Int
    , cache_enabled :: Bool
    } deriving (Show, Generic, FromJSON, ToJSON)

-- | Probe weights for externalized configuration
data ProbeWeights = ProbeWeights
    { tls :: Double
    , dns :: Double
    , https :: Double
    , security_headers :: Double
    } deriving (Show, Generic, FromJSON, ToJSON)

data ScoringConfig = ScoringConfig
    { levels :: Map String ScoringLevel
    } deriving (Show, Generic, FromJSON, ToJSON)

data ScoringLevel = ScoringLevel
    { min_score :: Double
    , max_score :: Double
    , description :: String
    } deriving (Show, Generic, FromJSON, ToJSON)

-- | Configuration loader state
data SharedConfigLoader = SharedConfigLoader
    { config :: Maybe SharedConfig
    , configPath :: Maybe FilePath
    , loaded :: Bool
    } deriving (Show)

-- Global configuration state using IORef for mutable singleton
{-# NOINLINE globalConfigRef #-}
globalConfigRef :: IORef SharedConfigLoader
globalConfigRef = unsafePerformIO $ newIORef $ SharedConfigLoader Nothing Nothing False

-- | Initialize configuration manager with automatic loading
-- This implements the externalized weight configuration pattern,
-- eliminating hardcoded weights from probe functions and providing a
-- single source of truth for all probe weights.
initializeConfig :: IO Bool
initializeConfig = do
    result <- loadSharedConfig
    case result of
        Right _ -> do
            putStrLn "✅ Configuration loaded successfully"
            return True
        Left err -> do
            putStrLn $ "❌ Failed to load configuration: " ++ show err
            return False

-- | Load configuration from shared-config.yaml
loadSharedConfig :: IO (Either String SharedConfig)
loadSharedConfig = do
    configPathResult <- findConfigFile
    case configPathResult of
        Nothing -> return $ Left "shared-config.yaml not found in project directory tree"
        Just configPath -> do
            putStrLn $ "Loading configuration from: " ++ configPath
            result <- try $ decodeFileEither configPath
            case result of
                Left (err :: SomeException) -> 
                    return $ Left $ "Failed to read config file: " ++ show err
                Right (Left yamlErr) -> 
                    return $ Left $ "Failed to parse YAML: " ++ show yamlErr
                Right (Right config) -> do
                    -- Validate configuration
                    case validateConfig config of
                        Nothing -> do
                            -- Update global state
                            writeIORef globalConfigRef $ SharedConfigLoader 
                                (Just config) (Just configPath) True
                            return $ Right config
                        Just validationErr -> 
                            return $ Left $ "Configuration validation failed: " ++ validationErr

-- | Get probe weight by name with externalized configuration
-- EXTERNALIZED WEIGHT CONFIGURATION - Single source of truth!
getProbeWeight :: String -> IO Double
getProbeWeight probeName = do
    loader <- readIORef globalConfigRef
    case config loader of
        Nothing -> do
            putStrLn $ "Warning: Configuration not loaded, using default weight 1.0 for " ++ probeName
            return 1.0
        Just cfg -> do
            let configKey = mapProbeName probeName
            case Map.lookup configKey (probe_weights cfg) of
                Just weight -> return weight
                Nothing -> do
                    putStrLn $ "Warning: No weight configured for probe '" ++ probeName ++ "', using default 1.0"
                    return 1.0

-- | Get probe weight with error information
getProbeWeightWithError :: String -> IO (Either String Double)
getProbeWeightWithError probeName = do
    loader <- readIORef globalConfigRef
    case config loader of
        Nothing -> return $ Left "Configuration not loaded"
        Just cfg -> do
            let configKey = mapProbeName probeName
            case Map.lookup configKey (probe_weights cfg) of
                Just weight -> return $ Right weight
                Nothing -> return $ Left $ "No weight configured for probe '" ++ probeName ++ "'"

-- | Get total weight of all core probes
getTotalWeight :: IO Double
getTotalWeight = do
    loader <- readIORef globalConfigRef
    case config loader of
        Nothing -> return 0.0
        Just cfg -> do
            let coreProbes = ["tls", "dns", "https", "security_headers"]
            let weights = map (\probe -> Map.findWithDefault 0.0 probe (probe_weights cfg)) coreProbes
            return $ sum weights

-- | Validate configuration
validateConfiguration :: IO (Maybe String)
validateConfiguration = do
    loader <- readIORef globalConfigRef
    case config loader of
        Nothing -> return $ Just "Configuration not loaded"
        Just cfg -> return $ validateConfig cfg

-- | Internal validation function
validateConfig :: SharedConfig -> Maybe String
validateConfig cfg = 
    let requiredProbes = ["tls", "dns", "https", "security_headers"]
        missingProbes = filter (\probe -> not $ Map.member probe (probe_weights cfg)) requiredProbes
        invalidWeights = filter (\probe -> 
            case Map.lookup probe (probe_weights cfg) of
                Just weight -> weight <= 0.0
                Nothing -> False) requiredProbes
    in if not (null missingProbes)
       then Just $ "Missing weights for probes: " ++ show missingProbes
       else if not (null invalidWeights)
       then Just $ "Invalid weights for probes: " ++ show invalidWeights
       else Nothing

-- | Get scoring level for a given score
getScoringLevel :: Double -> IO String
getScoringLevel score = do
    loader <- readIORef globalConfigRef
    case config loader of
        Nothing -> return "F"
        Just cfg -> do
            let levelsMap = levels (scoring cfg)
            let matchingLevel = Map.toList levelsMap
                                |> filter (\(_, level) -> score >= min_score level && score <= max_score level)
                                |> map fst
                                |> listToMaybe
            return $ case matchingLevel of
                Just level -> level
                Nothing -> "F"
  where
    (|>) = flip ($)
    listToMaybe [] = Nothing
    listToMaybe (x:_) = Just x

-- | Check if configuration is loaded
isLoaded :: IO Bool
isLoaded = do
    loader <- readIORef globalConfigRef
    return $ loaded loader

-- | Get configuration file path
getConfigPath :: IO (Maybe FilePath)
getConfigPath = do
    loader <- readIORef globalConfigRef
    return $ configPath loader

-- | Print configuration summary for debugging
printConfigurationSummary :: IO ()
printConfigurationSummary = do
    putStrLn "\n🔧 DQIX Haskell Implementation - Externalized Weight Configuration"
    putStrLn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    loader <- readIORef globalConfigRef
    case config loader of
        Nothing -> putStrLn "❌ Configuration not loaded"
        Just cfg -> do
            case configPath loader of
                Just path -> putStrLn $ "📊 Configuration loaded from: " ++ path
                Nothing -> return ()
            
            totalWeight <- getTotalWeight
            printf "📊 Total Weight: %.1f\n" totalWeight
            putStrLn "🔗 Configuration Source: shared-config.yaml\n"
            
            putStrLn "🔍 Probe Weight Distribution:"
            let coreProbes = [("tls", "TLS Security"), ("dns", "DNS Security"), 
                             ("https", "HTTPS Access"), ("security_headers", "Security Headers")]
            
            mapM_ (\(probeKey, displayName) -> do
                weight <- getProbeWeight probeKey
                let percentage = (weight / totalWeight) * 100.0
                printf "  ✅ %-20s: %.1f (%.1f%%)\n" displayName weight percentage
                ) coreProbes
            
            putStrLn "\n✨ Single Source of Truth: All weights externally configured"
            putStrLn "🚀 Architecture: Haskell externalized configuration implemented"

-- | Map probe names to config keys for compatibility
mapProbeName :: String -> String
mapProbeName "TLS Security" = "tls"
mapProbeName "tls_security" = "tls"
mapProbeName "DNS Security" = "dns"
mapProbeName "dns_security" = "dns"
mapProbeName "HTTPS Access" = "https"
mapProbeName "https_access" = "https"
mapProbeName "Security Headers" = "security_headers"
mapProbeName "headers" = "security_headers"
mapProbeName name = name

-- | Find shared-config.yaml in project directory tree
findConfigFile :: IO (Maybe FilePath)
findConfigFile = do
    currentDir <- getCurrentDirectory
    searchUpwards currentDir
  where
    searchUpwards dir = do
        let configPath = dir </> "shared-config.yaml"
        exists <- doesFileExist configPath
        if exists
            then return $ Just configPath
            else do
                let parentDir = takeDirectory dir
                if parentDir == dir  -- Reached root directory
                    then return Nothing
                    else searchUpwards parentDir

-- | Convenience functions for external weight access

-- | Get TLS probe weight from external configuration
getTlsWeight :: IO Double
getTlsWeight = getProbeWeight "tls"

-- | Get DNS probe weight from external configuration  
getDnsWeight :: IO Double
getDnsWeight = getProbeWeight "dns"

-- | Get HTTPS probe weight from external configuration
getHttpsWeight :: IO Double
getHttpsWeight = getProbeWeight "https"

-- | Get Security Headers probe weight from external configuration
getSecurityHeadersWeight :: IO Double
getSecurityHeadersWeight = getProbeWeight "security_headers"
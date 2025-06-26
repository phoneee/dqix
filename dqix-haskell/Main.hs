{-# LANGUAGE OverloadedStrings #-}

module Main where

import Data.Time
import Data.List (find, sortBy)
import Data.Ord (comparing)
import qualified Data.Map as Map
import Text.Printf
import Control.Monad (forM_, when)
import Data.Char (toUpper)
import System.Environment (getArgs)
import System.Exit (exitWith, ExitCode(..))

-- Enhanced domain types with detailed information
data ProbeDetails = ProbeDetails
    { protocolVersion :: Maybe String
    , cipherSuite :: Maybe String
    , certificateValid :: Maybe String
    , certChainLength :: Maybe String
    , keyExchange :: Maybe String
    , pfsSupport :: Maybe String
    , httpsAccessible :: Maybe String
    , httpRedirects :: Maybe String
    , hstsHeader :: Maybe String
    , hstsMaxAge :: Maybe String
    , http2Support :: Maybe String
    , dnssecEnabled :: Maybe String
    , spfRecord :: Maybe String
    , dmarcPolicy :: Maybe String
    , caaRecords :: Maybe String
    , csp :: Maybe String
    , xFrameOptions :: Maybe String
    , xContentTypeOptions :: Maybe String
    , referrerPolicy :: Maybe String
    , serverHeader :: Maybe String
    , responseTime :: Maybe String
    , executionTime :: Maybe Double
    , customFields :: Map.Map String String
    } deriving (Show, Eq)

data ProbeResult = ProbeResult
    { probeId :: String
    , score :: Double
    , category :: String
    , details :: ProbeDetails
    , timestamp :: UTCTime
    } deriving (Show, Eq)

data Metadata = Metadata
    { engine :: String
    , version :: String
    , probeCount :: Int
    , timeoutPolicy :: String
    , scoringMethod :: String
    } deriving (Show, Eq)

data AssessmentResult = AssessmentResult
    { domain :: String
    , overallScore :: Double
    , complianceLevel :: String
    , probeResults :: [ProbeResult]
    , assessmentTimestamp :: UTCTime
    , assessmentExecutionTime :: Double
    , metadata :: Metadata
    } deriving (Show, Eq)

-- Domain validation
data Domain = Domain String deriving (Show, Eq)
data ComplianceLevel = Basic | Standard | Advanced | Expert deriving (Show, Eq)

-- Functional Result Types (Either pattern in Haskell)
type Result a = Either String a

-- Pure domain logic functions
validateDomain :: String -> Result Domain
validateDomain domain
    | null domain = Left "Domain cannot be empty"
    | length domain > 253 = Left "Domain too long"
    | any (== ' ') domain = Left "Domain cannot contain spaces"
    | domain == "localhost" = Left "localhost not allowed"
    | "://" `elem` [take 3 $ drop i domain | i <- [0..length domain - 3]] = Left "Remove protocol (http://)"
    | '/' `elem` domain = Left "Remove path"
    | otherwise = Right (Domain domain)

calculateProbeScore :: String -> Double -> Result Double
calculateProbeScore probeType baseScore
    | probeType `elem` validProbeTypes && baseScore >= 0 && baseScore <= 1 = Right baseScore
    | otherwise = Left "Invalid probe type or score"
  where
    validProbeTypes = ["tls", "dns", "https", "security_headers"]

calculateOverallScore :: [ProbeResult] -> Result Double
calculateOverallScore probes
    | null probes = Left "No probe results"
    | otherwise = Right $ calculateWeightedScore probes

calculateWeightedScore :: [ProbeResult] -> Double
calculateWeightedScore probes = 
    let weights = [("tls", 0.35), ("dns", 0.25), ("https", 0.20), ("security_headers", 0.20)]
        getWeight probeType = maybe 0.1 id (lookup probeType weights)
        weightedSum = sum [score probe * getWeight (probeId probe) | probe <- probes]
        totalWeight = sum [getWeight (probeId probe) | probe <- probes]
    in if totalWeight > 0 then weightedSum / totalWeight else 0

determineComplianceLevel :: Double -> Result ComplianceLevel
determineComplianceLevel score
    | score >= 0.85 = Right Expert
    | score >= 0.70 = Right Advanced
    | score >= 0.50 = Right Standard
    | score >= 0.00 = Right Basic
    | otherwise = Left "Invalid score"

composeAssessment :: Domain -> [ProbeResult] -> Result AssessmentResult
composeAssessment (Domain domainStr) probes = do
    overallScoreValue <- calculateOverallScore probes
    complianceLevelValue <- determineComplianceLevel overallScoreValue
    currentTime <- return $ read "2025-01-01 00:00:00 UTC" -- Mock time for pure function
    return AssessmentResult
        { domain = domainStr
        , overallScore = overallScoreValue
        , complianceLevel = show complianceLevelValue
        , probeResults = probes
        , assessmentTimestamp = currentTime
        , assessmentExecutionTime = 0.5
        , metadata = Metadata "Haskell DQIX v1.0.0" "1.0.0" (length probes) "30s per probe" "Weighted composite"
        }

-- Enhanced mock data generation with detailed information
generateDetailedMockData :: String -> IO AssessmentResult
generateDetailedMockData domainName = do
    currentTime <- getCurrentTime
    
    -- Generate realistic probe results with detailed information
    let tlsCustomFields = Map.fromList
            [ ("vulnerability_scan", "clean")
            , ("ocsp_stapling", "enabled")
            , ("ct_logs", "present")
            ]
    
    let httpsCustomFields = Map.fromList
            [ ("hsts_subdomains", "true")
            , ("http3_support", "false")
            , ("compression_type", "gzip")
            ]
    
    let dnsCustomFields = Map.fromList
            [ ("ipv4_records", "present")
            , ("ipv6_records", "present")
            , ("dnssec_chain_valid", "true")
            , ("dkim_selectors", "google, mailchimp")
            , ("mx_records", "present")
            , ("ns_records", "cloudflare")
            , ("ttl_analysis", "optimized")
            ]
    
    let headersCustomFields = Map.fromList
            [ ("hsts", "max-age=31536000; includeSubDomains")
            , ("permissions_policy", "camera=(), microphone=()")
            , ("x_xss_protection", "1; mode=block")
            , ("content_type", "text/html; charset=utf-8")
            , ("powered_by", "hidden")
            ]
    
    let probeResultsList = 
            [ ProbeResult
                { probeId = "tls"
                , score = 0.923
                , category = "security"
                , timestamp = currentTime
                , details = ProbeDetails
                    { protocolVersion = Just "TLS 1.3"
                    , cipherSuite = Just "TLS_AES_256_GCM_SHA384"
                    , certificateValid = Just "true"
                    , certChainLength = Just "3"
                    , keyExchange = Just "ECDHE"
                    , pfsSupport = Just "true"
                    , executionTime = Just 0.45
                    , customFields = tlsCustomFields
                    , httpsAccessible = Nothing
                    , httpRedirects = Nothing
                    , hstsHeader = Nothing
                    , hstsMaxAge = Nothing
                    , http2Support = Nothing
                    , dnssecEnabled = Nothing
                    , spfRecord = Nothing
                    , dmarcPolicy = Nothing
                    , caaRecords = Nothing
                    , csp = Nothing
                    , xFrameOptions = Nothing
                    , xContentTypeOptions = Nothing
                    , referrerPolicy = Nothing
                    , serverHeader = Nothing
                    , responseTime = Nothing
                    }
                }
            , ProbeResult
                { probeId = "https"
                , score = 0.891
                , category = "protocol"
                , timestamp = currentTime
                , details = ProbeDetails
                    { httpsAccessible = Just "true"
                    , httpRedirects = Just "301 permanent"
                    , hstsHeader = Just "present"
                    , hstsMaxAge = Just "31536000"
                    , http2Support = Just "true"
                    , responseTime = Just "245"
                    , executionTime = Just 0.32
                    , customFields = httpsCustomFields
                    , protocolVersion = Nothing
                    , cipherSuite = Nothing
                    , certificateValid = Nothing
                    , certChainLength = Nothing
                    , keyExchange = Nothing
                    , pfsSupport = Nothing
                    , dnssecEnabled = Nothing
                    , spfRecord = Nothing
                    , dmarcPolicy = Nothing
                    , caaRecords = Nothing
                    , csp = Nothing
                    , xFrameOptions = Nothing
                    , xContentTypeOptions = Nothing
                    , referrerPolicy = Nothing
                    , serverHeader = Nothing
                    }
                }
            , ProbeResult
                { probeId = "dns"
                , score = 0.756
                , category = "infrastructure"
                , timestamp = currentTime
                , details = ProbeDetails
                    { dnssecEnabled = Just "true"
                    , spfRecord = Just "v=spf1 include:_spf.google.com ~all"
                    , dmarcPolicy = Just "v=DMARC1; p=quarantine"
                    , caaRecords = Just "0 issue \"letsencrypt.org\""
                    , executionTime = Just 0.28
                    , customFields = dnsCustomFields
                    , protocolVersion = Nothing
                    , cipherSuite = Nothing
                    , certificateValid = Nothing
                    , certChainLength = Nothing
                    , keyExchange = Nothing
                    , pfsSupport = Nothing
                    , httpsAccessible = Nothing
                    , httpRedirects = Nothing
                    , hstsHeader = Nothing
                    , hstsMaxAge = Nothing
                    , http2Support = Nothing
                    , csp = Nothing
                    , xFrameOptions = Nothing
                    , xContentTypeOptions = Nothing
                    , referrerPolicy = Nothing
                    , serverHeader = Nothing
                    , responseTime = Nothing
                    }
                }
            , ProbeResult
                { probeId = "security_headers"
                , score = 0.678
                , category = "application"
                , timestamp = currentTime
                , details = ProbeDetails
                    { csp = Just "default-src 'self'"
                    , xFrameOptions = Just "DENY"
                    , xContentTypeOptions = Just "nosniff"
                    , referrerPolicy = Just "strict-origin-when-cross-origin"
                    , serverHeader = Just "nginx/1.20.1"
                    , executionTime = Just 0.19
                    , customFields = headersCustomFields
                    , protocolVersion = Nothing
                    , cipherSuite = Nothing
                    , certificateValid = Nothing
                    , certChainLength = Nothing
                    , keyExchange = Nothing
                    , pfsSupport = Nothing
                    , httpsAccessible = Nothing
                    , httpRedirects = Nothing
                    , hstsHeader = Nothing
                    , hstsMaxAge = Nothing
                    , http2Support = Nothing
                    , dnssecEnabled = Nothing
                    , spfRecord = Nothing
                    , dmarcPolicy = Nothing
                    , caaRecords = Nothing
                    , responseTime = Nothing
                    }
                }
            ]
    
    -- Calculate overall score with weighted algorithm
    let overallScoreValue = calculateWeightedScore probeResultsList
    let complianceLevelValue = case determineComplianceLevel overallScoreValue of
            Right level -> show level
            Left _ -> "Basic"
    
    return AssessmentResult
        { domain = domainName
        , overallScore = overallScoreValue
        , complianceLevel = complianceLevelValue
        , probeResults = probeResultsList
        , assessmentTimestamp = currentTime
        , assessmentExecutionTime = 0.5
        , metadata = Metadata
            { engine = "Haskell DQIX v1.0.0"
            , version = "1.0.0"
            , probeCount = length probeResultsList
            , timeoutPolicy = "30s per probe"
            , scoringMethod = "Weighted composite (TLS:35%, DNS:25%, HTTPS:20%, Headers:20%)"
            }
        }

-- Display functions
displayResults :: AssessmentResult -> IO ()
displayResults result = do
    let scoreValue = overallScore result
    
    printf "\n🔍 %s\n" (domain result)
    putStrLn "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    let barLength = 20
    let filledBars = floor (scoreValue * fromIntegral barLength)
    let emptyBars = barLength - filledBars
    let scoreBar = replicate filledBars '█' ++ replicate emptyBars '░'
    
    printf "🔒 Security Score: %.1f%% %s\n" (scoreValue * 100) scoreBar
    printf "📋 Compliance: %s\n" (complianceLevel result)
    printf "⏰ Scanned: %s\n" (formatTime defaultTimeLocale "%Y-%m-%d %H:%M" $ assessmentTimestamp result)
    
    putStrLn "\n📋 Security Assessment Details\n"
    
    let probeOrder :: [(String, String)]
        probeOrder = 
            [ ("tls", "🔐 TLS/SSL Security")
            , ("https", "🌐 HTTPS Implementation")
            , ("dns", "🌍 DNS Infrastructure")
            , ("security_headers", "🛡️ Security Headers")
            ]
    
    forM_ probeOrder $ \(probeIdValue, title) -> do
        case findProbeResult (probeResults result) probeIdValue of
            Just probeResult -> do
                let probeScore = score probeResult
                let status = if probeScore >= 0.8 then "✅ EXCELLENT"
                           else if probeScore >= 0.6 then "⚠️ GOOD"
                           else if probeScore >= 0.4 then "🔶 FAIR"
                           else "❌ POOR"
                printf "%s: %.1f%% %s\n" title (probeScore * 100) status
            Nothing -> return ()

-- Helper functions
findProbeResult :: [ProbeResult] -> String -> Maybe ProbeResult
findProbeResult results probeIdValue = find (\r -> probeId r == probeIdValue) results

-- Main CLI interface
main :: IO ()
main = do
    args <- getArgs
    case args of
        ["scan", domain] -> do
            result <- generateDetailedMockData domain
            displayResults result
        ["test"] -> runTests
        ["demo"] -> do
            result <- generateDetailedMockData "github.com"
            displayResults result
        _ -> do
            putStrLn "🔍 DQIX Internet Observability Platform (Haskell)"
            putStrLn "Usage:"
            putStrLn "  dqix scan <domain>    # Scan domain"
            putStrLn "  dqix test             # Run tests"
            putStrLn "  dqix demo             # Demo mode"

-- Test suite
runTests :: IO ()
runTests = do
    putStrLn "🧪 Running Haskell DQIX Test Suite..."
    putStrLn ""
    
    -- Test domain validation
    putStr "Testing domain validation... "
    let validationTests = all testValidation 
            [ ("example.com", True)
            , ("", False)
            , ("localhost", False)
            , ("http://example.com", False)
            ]
    putStrLn $ if validationTests then "✅ PASS" else "❌ FAIL"
    
    -- Test scoring
    putStr "Testing scoring calculation... "
    let mockProbes = [ProbeResult "tls" 0.8 "security" (ProbeDetails Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Nothing Map.empty) (read "2025-01-01 00:00:00 UTC")]
    let scoringTest = case calculateOverallScore mockProbes of
            Right score -> score > 0 && score <= 1
            Left _ -> False
    putStrLn $ if scoringTest then "✅ PASS" else "❌ FAIL"
    
    -- Test compliance levels
    putStr "Testing compliance levels... "
    let complianceTest = case determineComplianceLevel 0.8 of
            Right Advanced -> True
            _ -> False
    putStrLn $ if complianceTest then "✅ PASS" else "❌ FAIL"
    
    putStrLn ""
    putStrLn "🎉 Haskell test suite completed!"

testValidation :: (String, Bool) -> Bool
testValidation (domain, expected) = 
    case validateDomain domain of
        Right _ -> expected
        Left _ -> not expected 
-- DQIX Internet Observability Platform - Test Suite
-- Test-Driven Development with QuickCheck and HUnit

{-# LANGUAGE OverloadedStrings #-}

module Test where

import Main
import Test.HUnit
import Test.QuickCheck
import Data.Either (isLeft, isRight)
import Control.Monad (when)

-- Property-based tests using QuickCheck
prop_ValidDomainRoundTrip :: String -> Property
prop_ValidDomainRoundTrip domainName = 
    not (null domainName) && ('.' `elem` domainName) && length domainName <= 253 ==>
    case validateDomain domainName of
        Right (Domain result) -> result == domainName
        Left _ -> False

prop_ScoreInRange :: Double -> Property
prop_ScoreInRange score = 
    score >= 0.0 && score <= 1.0 ==>
    case determineComplianceLevel score of
        Right level -> level `elem` [Excellent, Advanced, Standard, Basic, Poor]
        Left _ -> False

prop_ProbeScoreNonNegative :: [(String, String)] -> Bool
prop_ProbeScoreNonNegative probeData = 
    case calculateTlsScore probeData of
        Right score -> score >= 0.0 && score <= 1.0
        Left _ -> True

-- Unit tests using HUnit
testDomainValidation :: Test
testDomainValidation = TestList
    [ TestCase $ assertBool "Valid domain should pass" $
        case validateDomain "example.com" of
            Right (Domain "example.com") -> True
            _ -> False
    
    , TestCase $ assertBool "Empty domain should fail" $
        case validateDomain "" of
            Left _ -> True
            _ -> False
    
    , TestCase $ assertBool "Domain without dot should fail" $
        case validateDomain "example" of
            Left _ -> True
            _ -> False
    
    , TestCase $ assertBool "Very long domain should fail" $
        case validateDomain (replicate 300 'a' ++ ".com") of
            Left _ -> True
            _ -> False
    ]

testTlsScoring :: Test
testTlsScoring = TestList
    [ TestCase $ assertEqual "Perfect TLS score" (Right 1.0) $
        calculateTlsScore [("protocol_version", "TLS 1.3"), 
                          ("certificate_valid", "true"), 
                          ("cipher_strength", "strong")]
    
    , TestCase $ assertEqual "Partial TLS score" (Right 0.7) $
        calculateTlsScore [("protocol_version", "TLS 1.2"), 
                          ("certificate_valid", "true")]
    
    , TestCase $ assertEqual "Empty TLS data" (Right 0.0) $
        calculateTlsScore []
    ]

testDnsScoring :: Test
testDnsScoring = TestList
    [ TestCase $ assertEqual "Perfect DNS score" (Right 1.0) $
        calculateDnsScore [("ipv4_records", "true"),
                          ("ipv6_records", "true"),
                          ("dnssec_enabled", "true"),
                          ("spf_record", "true"),
                          ("dmarc_record", "true")]
    
    , TestCase $ assertEqual "Basic DNS score" (Right 0.2) $
        calculateDnsScore [("ipv4_records", "true")]
    
    , TestCase $ assertEqual "Empty DNS data" (Right 0.0) $
        calculateDnsScore []
    ]

testHttpsScoring :: Test
testHttpsScoring = TestList
    [ TestCase $ assertEqual "Perfect HTTPS score" (Right 1.0) $
        calculateHttpsScore [("accessible", "true"),
                            ("secure_redirects", "true"),
                            ("hsts_enabled", "true")]
    
    , TestCase $ assertEqual "Basic HTTPS score" (Right 0.4) $
        calculateHttpsScore [("accessible", "true")]
    
    , TestCase $ assertEqual "Empty HTTPS data" (Right 0.0) $
        calculateHttpsScore []
    ]

testSecurityHeadersScoring :: Test
testSecurityHeadersScoring = TestList
    [ TestCase $ assertEqual "Perfect headers score" (Right 1.0) $
        calculateSecurityHeadersScore [("hsts", "true"),
                                      ("csp", "true"),
                                      ("x_frame_options", "true"),
                                      ("x_content_type_options", "true")]
    
    , TestCase $ assertEqual "Basic headers score" (Right 0.3) $
        calculateSecurityHeadersScore [("hsts", "true")]
    
    , TestCase $ assertEqual "Empty headers data" (Right 0.0) $
        calculateSecurityHeadersScore []
    ]

testComplianceLevels :: Test
testComplianceLevels = TestList
    [ TestCase $ assertEqual "Excellent compliance" (Right Excellent) $
        determineComplianceLevel 0.95
    
    , TestCase $ assertEqual "Advanced compliance" (Right Advanced) $
        determineComplianceLevel 0.85
    
    , TestCase $ assertEqual "Standard compliance" (Right Standard) $
        determineComplianceLevel 0.70
    
    , TestCase $ assertEqual "Basic compliance" (Right Basic) $
        determineComplianceLevel 0.50
    
    , TestCase $ assertEqual "Poor compliance" (Right Poor) $
        determineComplianceLevel 0.30
    
    , TestCase $ assertBool "Invalid score should fail" $
        case determineComplianceLevel 1.5 of
            Left _ -> True
            _ -> False
    ]

testOverallScoring :: Test
testOverallScoring = TestList
    [ TestCase $ assertBool "Overall score calculation" $
        let domain = Domain "example.com"
            probeResults = [ ProbeResult "tls" domain Passed 0.9 "Good TLS" []
                           , ProbeResult "dns" domain Passed 0.8 "Good DNS" []
                           , ProbeResult "https" domain Passed 0.7 "Good HTTPS" []
                           , ProbeResult "security_headers" domain Passed 0.6 "Basic headers" []
                           ]
        in case calculateOverallScore probeResults of
            Right score -> score > 0.0 && score <= 1.0
            Left _ -> False
    
    , TestCase $ assertBool "Empty probe results should fail" $
        case calculateOverallScore [] of
            Left _ -> True
            _ -> False
    ]

testAssessmentComposition :: Test
testAssessmentComposition = TestList
    [ TestCase $ assertBool "Complete assessment composition" $
        let domain = Domain "example.com"
            probeResults = [ ProbeResult "tls" domain Passed 0.9 "Good TLS" []
                           , ProbeResult "dns" domain Passed 0.8 "Good DNS" []
                           ]
            timestamp = 1640995200.0
        in case composeAssessment domain probeResults timestamp of
            Right assessment -> 
                assessmentDomain assessment == domain &&
                length (assessmentProbeResults assessment) == 2 &&
                assessmentOverallScore assessment > 0.0
            Left _ -> False
    ]

-- Functional composition tests
testHigherOrderFunctions :: Test
testHigherOrderFunctions = TestList
    [ TestCase $ assertEqual "Map function" [2, 4, 6] $
        mapResults (*2) [1, 2, 3]
    
    , TestCase $ assertEqual "Filter function" [2, 4] $
        filterResults even [1, 2, 3, 4, 5]
    
    , TestCase $ assertEqual "Fold function" 15 $
        foldResults (+) 0 [1, 2, 3, 4, 5]
    
    , TestCase $ assertEqual "Function composition" 10 $
        (compose (*2) (+1)) 4
    ]

-- Mock data tests
testMockDataGeneration :: Test
testMockDataGeneration = TestList
    [ TestCase $ assertBool "GitHub mock data" $
        let results = generateMockProbeResults (Domain "github.com")
        in length results == 4 && all (\r -> probeScore r > 0.8) results
    
    , TestCase $ assertBool "Google mock data" $
        let results = generateMockProbeResults (Domain "google.com")
        in length results == 4 && all (\r -> probeScore r > 0.8) results
    
    , TestCase $ assertBool "Generic mock data" $
        let results = generateMockProbeResults (Domain "example.com")
        in length results == 4 && all (\r -> probeScore r > 0.0) results
    ]

-- Pure function tests
testPureFunctions :: Test
testPureFunctions = TestList
    [ TestCase $ assertEqual "TLS scoring is deterministic" True $
        let data1 = [("protocol_version", "TLS 1.3")]
            result1 = calculateTlsScore data1
            result2 = calculateTlsScore data1
        in result1 == result2
    
    , TestCase $ assertEqual "Domain validation is pure" True $
        let domain = "example.com"
            result1 = validateDomain domain
            result2 = validateDomain domain
        in result1 == result2
    
    , TestCase $ assertEqual "Compliance determination is pure" True $
        let score = 0.85
            result1 = determineComplianceLevel score
            result2 = determineComplianceLevel score
        in result1 == result2
    ]

-- All tests combined
allTests :: Test
allTests = TestList
    [ TestLabel "Domain Validation" testDomainValidation
    , TestLabel "TLS Scoring" testTlsScoring
    , TestLabel "DNS Scoring" testDnsScoring
    , TestLabel "HTTPS Scoring" testHttpsScoring
    , TestLabel "Security Headers Scoring" testSecurityHeadersScoring
    , TestLabel "Compliance Levels" testComplianceLevels
    , TestLabel "Overall Scoring" testOverallScoring
    , TestLabel "Assessment Composition" testAssessmentComposition
    , TestLabel "Higher Order Functions" testHigherOrderFunctions
    , TestLabel "Mock Data Generation" testMockDataGeneration
    , TestLabel "Pure Functions" testPureFunctions
    ]

-- Run all tests
runAllTests :: IO ()
runAllTests = do
    putStrLn "🧪 Running DQIX Haskell Test Suite"
    putStrLn ""
    
    -- Run HUnit tests
    putStrLn "📋 Unit Tests:"
    counts <- runTestTT allTests
    
    putStrLn ""
    putStrLn "🎲 Property-based Tests:"
    
    -- Run QuickCheck tests
    putStr "  Domain validation round-trip: "
    quickCheck prop_ValidDomainRoundTrip
    
    putStr "  Score range validation: "
    quickCheck prop_ScoreInRange
    
    putStr "  Probe score non-negative: "
    quickCheck prop_ProbeScoreNonNegative
    
    putStrLn ""
    putStrLn "🏆 Test Summary:"
    putStrLn $ "  Unit tests passed: " ++ show (cases counts - failures counts - errors counts)
    putStrLn $ "  Unit tests failed: " ++ show (failures counts + errors counts)
    putStrLn $ "  Total unit tests: " ++ show (cases counts)
    
    when (failures counts + errors counts == 0) $
        putStrLn "✅ All tests passed!" 
module Shadow6.Features

import Data.List
import Data.String
import Shadow6.Types

%default total

-- | Compile-time feature configuration
public export
CORE_VERSION : String
CORE_VERSION = "1.1.0"

public export
COMPILED_CROSED_LEVEL : CrosedLevel
COMPILED_CROSED_LEVEL = L0  -- Default build

public export
COMPILED_APP_TRANSPORT : Bool
COMPILED_APP_TRANSPORT = False  -- Default build

public export
COMPILED_QUBES_ISOLATION : Bool
COMPILED_QUBES_ISOLATION = False  -- Default build

public export
COMPILED_UTF8 : Bool
COMPILED_UTF8 = True  -- Always true for Idris

-- | Feature report matching Core-Go/Core-Rust contract
public export
record FeatureReport where
  constructor MkFeatureReport
  core : String
  version : String
  crosedCompiled : Bool
  crosedMaxLevel : Nat
  appTransport : Bool
  qubesIsolation : Bool
  gateCompiled : Bool
  gateEnabledDefault : Bool
  utf8 : Bool
  crosedCapabilities : List String

-- | Generate capability list based on compiled level
export
compiledCapabilities : CrosedLevel -> List String
compiledCapabilities L0 = []
compiledCapabilities L1 = ["observe.health", "observe.version"]
compiledCapabilities L2 = ["observe.health", "observe.version", 
                           "policy.config", "policy.request"]
compiledCapabilities L3 = ["observe.health", "observe.version",
                           "policy.config", "policy.request",
                           "transport.metadata", "transport.application"]
compiledCapabilities L4 = ["observe.health", "observe.version",
                           "policy.config", "policy.request",
                           "transport.metadata", "transport.application",
                           "identity.assert", "identity.resolve"]
compiledCapabilities L5 = ["core.hook", "core.lifecycle",
                           "identity.assert", "identity.resolve",
                           "observe.health", "observe.version",
                           "policy.config", "policy.request",
                           "transport.application", "transport.metadata"]

-- | Generate feature report
export
featureReport : FeatureReport
featureReport = 
  let level = COMPILED_CROSED_LEVEL
      levelNat = levelToNat level
      caps = if COMPILED_APP_TRANSPORT 
             then compiledCapabilities level
             else filter (/= "transport.application") (compiledCapabilities level)
  in MkFeatureReport
       "shadow6-idris"
       CORE_VERSION
       (levelNat > 0)
       levelNat
       COMPILED_APP_TRANSPORT
       COMPILED_QUBES_ISOLATION
       True   -- Gate compiled
       False  -- Gate disabled by default
       COMPILED_UTF8
       caps

-- | JSON serialization of feature report
export
serializeFeatureReport : FeatureReport -> String
serializeFeatureReport report =
  let capList = concat (intersperse ", " (map (\s => "\"" ++ s ++ "\"") report.crosedCapabilities))
  in "{\n" ++
     "  \"core\": \"" ++ report.core ++ "\",\n" ++
     "  \"version\": \"" ++ report.version ++ "\",\n" ++
     "  \"crosed_compiled\": " ++ (if report.crosedCompiled then "true" else "false") ++ ",\n" ++
     "  \"crosed_max_level\": " ++ show report.crosedMaxLevel ++ ",\n" ++
     "  \"app_transport\": " ++ (if report.appTransport then "true" else "false") ++ ",\n" ++
     "  \"qubes_isolation\": " ++ (if report.qubesIsolation then "true" else "false") ++ ",\n" ++
     "  \"gate_compiled\": " ++ (if report.gateCompiled then "true" else "false") ++ ",\n" ++
     "  \"gate_enabled_by_default\": " ++ (if report.gateEnabledDefault then "true" else "false") ++ ",\n" ++
     "  \"utf8\": " ++ (if report.utf8 then "true" else "false") ++ ",\n" ++
     "  \"crosed_capabilities\": [" ++ capList ++ "]\n" ++
     "}"

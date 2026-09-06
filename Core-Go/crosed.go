package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var crosedCapabilityLevels = map[string]int{
	"observe.version": 1, "observe.health": 1,
	"policy.request": 2, "policy.config": 2,
	"transport.metadata": 3, "transport.application": 3,
	"identity.assert": 4, "identity.resolve": 4,
	"core.lifecycle": 5, "core.hook": 5,
}

type CrosedRequest struct {
	Version        int             `json:"version"`
	ModID          string          `json:"mod_id"`
	Nonce          string          `json:"nonce"`
	IssuedAt       int64           `json:"issued_at"`
	RequestedLevel int             `json:"requested_level"`
	Capabilities   []string        `json:"capabilities"`
	SourceDomain   string          `json:"source_domain,omitempty"`
	TargetDomain   string          `json:"target_domain,omitempty"`
	Payload        json.RawMessage `json:"payload"`
	Signature      string          `json:"signature"`
}

type CrosedTrust struct {
	Mods map[string]CrosedTrustEntry `json:"mods"`
}

type CrosedTrustEntry struct {
	PubKey         string   `json:"pubkey"`
	MaxLevel       int      `json:"max_level"`
	Capabilities   []string `json:"capabilities"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
}

type CrosedResponse struct {
	FeatureReport
	ModID               string   `json:"mod_id"`
	GrantedLevel        int      `json:"granted_level"`
	GrantedCapabilities []string `json:"granted_capabilities"`
	Status              string   `json:"status"`
	Reason              string   `json:"reason,omitempty"`
}

func crosedSignedPayload(request CrosedRequest) []byte {
	if err := validateStrictJSON(request.Payload, nil); err != nil {
		return nil
	}
	var payload any
	decoder := json.NewDecoder(strings.NewReader(string(request.Payload)))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		return nil
	}
	var canonicalPayload strings.Builder
	if err := writePortableJSON(&canonicalPayload, payload, 0); err != nil {
		return nil
	}
	digest := sha256.Sum256([]byte(canonicalPayload.String()))
	capabilities := append([]string(nil), request.Capabilities...)
	sortStrings(capabilities)
	return []byte(strings.Join([]string{
		strconv.Itoa(request.Version), request.ModID, request.Nonce,
		strconv.FormatInt(request.IssuedAt, 10), strconv.Itoa(request.RequestedLevel),
		strings.Join(capabilities, ","), hex.EncodeToString(digest[:]),
		request.SourceDomain, request.TargetDomain,
	}, "\n"))
}

// Match Python/Rust UTF-8 canonical JSON, including HTML characters and U+2028.
func writePortableJSON(out *strings.Builder, value any, depth int) error {
	if depth > 16 {
		return errors.New("Crosed payload nesting exceeds 16 levels")
	}
	switch item := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		out.WriteString(strconv.FormatBool(item))
	case json.Number:
		number, err := item.Int64()
		if err != nil || number < -9007199254740991 || number > 9007199254740991 {
			return errors.New("nonportable Crosed integer")
		}
		out.WriteString(strconv.FormatInt(number, 10))
	case string:
		if len(item) > 16384 || strings.ContainsRune(item, 0) || !utf8.ValidString(item) {
			return errors.New("invalid Crosed string")
		}
		out.WriteByte('"')
		for _, char := range item {
			switch char {
			case '"', '\\':
				out.WriteByte('\\')
				out.WriteRune(char)
			case '\b':
				out.WriteString("\\b")
			case '\f':
				out.WriteString("\\f")
			case '\n':
				out.WriteString("\\n")
			case '\r':
				out.WriteString("\\r")
			case '\t':
				out.WriteString("\\t")
			default:
				if char < 0x20 {
					fmt.Fprintf(out, "\\u%04x", char)
				} else {
					out.WriteRune(char)
				}
			}
		}
		out.WriteByte('"')
	case []any:
		out.WriteByte('[')
		for i, child := range item {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writePortableJSON(out, child, depth+1); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(item))
		for key := range item {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writePortableJSON(out, key, depth+1); err != nil {
				return err
			}
			out.WriteByte(':')
			if err := writePortableJSON(out, item[key], depth+1); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return errors.New("nonportable Crosed JSON")
	}
	return nil
}

func handleCrosedRequest(requestPath, trustPath string, now time.Time) (CrosedResponse, error) {
	report := compiledFeatureReport()
	response := CrosedResponse{FeatureReport: report, Status: "denied"}
	if !report.CrosedCompiled {
		response.Reason = "crosed is not compiled into this core"
		return response, nil
	}
	requestData, err := readOwnerOnlyFile(requestPath, 64*1024)
	if err != nil {
		return response, err
	}
	trustData, err := readOwnerOnlyFile(trustPath, 64*1024)
	if err != nil {
		return response, err
	}
	var request CrosedRequest
	if err := decodeStrict(requestData, &request); err != nil {
		return response, fmt.Errorf("invalid Crosed request: %w", err)
	}
	var trust CrosedTrust
	if err := decodeStrict(trustData, &trust); err != nil {
		return response, fmt.Errorf("invalid Crosed trust store: %w", err)
	}
	response.ModID = request.ModID
	nonce, nonceErr := hex.DecodeString(request.Nonce)
	if request.Version != 1 || !validIdentity(request.ModID) || nonceErr != nil || len(nonce) != 16 || !utf8.Valid(request.Payload) {
		return response, errors.New("invalid Crosed request fields")
	}
	if request.RequestedLevel < 1 || request.RequestedLevel > 5 || request.IssuedAt < now.Unix()-300 || request.IssuedAt > now.Unix()+300 {
		return response, errors.New("invalid Crosed level or request timestamp")
	}
	policy, trusted := trust.Mods[request.ModID]
	if !trusted {
		return response, errors.New("untrusted Crosed mod")
	}
	if policy.MaxLevel < 1 || policy.MaxLevel > 5 || request.RequestedLevel > policy.MaxLevel {
		response.Reason = "requested level exceeds the per-Mod policy"
		return response, nil
	}
	key, err := parsePublicKey(policy.PubKey)
	if err != nil {
		return response, err
	}
	signature, err := hex.DecodeString(request.Signature)
	payload := crosedSignedPayload(request)
	if err != nil || payload == nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, payload, signature) {
		return response, errors.New("invalid Crosed request signature")
	}
	if request.RequestedLevel > report.CrosedMaxLevel {
		response.Reason = "requested level exceeds this Core build"
		return response, nil
	}
	seen := map[string]bool{}
	allowedCapabilities := map[string]bool{}
	for _, capability := range policy.Capabilities {
		allowedCapabilities[capability] = true
	}
	for _, capability := range request.Capabilities {
		if seen[capability] {
			return response, errors.New("duplicate Crosed capability")
		}
		seen[capability] = true
		required, known := crosedCapabilityLevels[capability]
		if !known || !allowedCapabilities[capability] || required > request.RequestedLevel || (capability == "transport.application" && !report.AppTransport) {
			response.Reason = "capability unavailable at requested level or build"
			return response, nil
		}
		response.GrantedCapabilities = append(response.GrantedCapabilities, capability)
	}
	if report.QubesIsolation {
		// Domain-less v1 requests remain compatible with isolation-enabled
		// builds by treating both omitted fields as the same local/default
		// domain.  A partially specified or explicit cross-domain request still
		// fails closed and must satisfy the allowlist below.
		if request.SourceDomain == "" && request.TargetDomain == "" {
			request.SourceDomain, request.TargetDomain = "default", "default"
		}
		if !validCrosedDomain(request.SourceDomain) || !validCrosedDomain(request.TargetDomain) {
			return response, errors.New("Qubes isolation requires valid source and target domains")
		}
		if request.SourceDomain != request.TargetDomain {
			allowed := false
			for _, domain := range policy.AllowedDomains {
				if domain == request.TargetDomain {
					allowed = true
				}
			}
			if !allowed {
				response.Reason = "Qubes cross-domain policy denied"
				return response, nil
			}
		}
	}
	sortStrings(response.GrantedCapabilities)
	response.GrantedLevel, response.Status, response.Reason = request.RequestedLevel, "granted", ""
	return response, nil
}

func readOwnerOnlyFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !secureConfigFile(info) || !secureConfigPath(path) {
		return nil, errors.New("Crosed file must be regular and mode 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !secureConfigFile(opened) || !secureConfigPath(path) {
		return nil, errors.New("Crosed file changed during validation")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("Crosed file exceeds size limit")
	}
	return data, nil
}

func abs64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func validCrosedDomain(value string) bool {
	if len(value) < 1 || len(value) > 32 {
		return false
	}
	for i, character := range value {
		if (character >= 'a' && character <= 'z') || (i > 0 && character >= '0' && character <= '9') || (i > 0 && character == '-') {
			continue
		}
		return false
	}
	return true
}

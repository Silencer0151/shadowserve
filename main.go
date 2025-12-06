package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"mime"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPort = 2001
	version     = "1.0.0"
	banner      = `
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗███████╗██████╗ ██╗   ██╗███████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗█████╗  ██████╔╝██║   ██║█████╗  
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║███████╗██║  ██║ ╚████╔╝ ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝`
)

// FileInfo holds metadata for directory listing
type FileInfo struct {
	Name     string
	IsDir    bool
	Size     string
	Modified string
	FileType string
	Icon     string
	Link     string
}

// TemplateData holds data passed to the HTML template
type TemplateData struct {
	Path       string
	ParentPath string
	HasParent  bool
	Files      []FileInfo
}

var (
	rootDir       string
	serverPIN     string
	sessionSecret string
	startTime     time.Time

	// visitor tracking
	visitorsMu sync.RWMutex
	visitors   = make(map[string]bool)

	// failed login attempt tracking
	failedAttemptsMu sync.Mutex
	failedAttempts   = make(map[string]int)
)

// generateSelfSignedCert creates an in-memory self-signed TLS certificate
func generateSelfSignedCert() (tls.Certificate, string, error) {
	// Generate ECDSA P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Certificate valid for 15 days
	notBefore := time.Now()
	notAfter := notBefore.Add(360 * time.Hour)

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate serial number: %v", err)
	}

	// Build certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"ShadowServe"},
			CommonName:   "ShadowServe Local Server ;)",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	// Add local network IPs
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
				template.IPAddresses = append(template.IPAddresses, ipNet.IP)
			}
		}
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to create certificate: %v", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to marshal private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Parse into tls.Certificate
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Calculate SHA-256 fingerprint
	fingerprint := sha256.Sum256(certDER)
	var fpStr strings.Builder
	for i, b := range fingerprint {
		if i > 0 {
			fpStr.WriteString(":")
		}
		fpStr.WriteString(fmt.Sprintf("%02X", b))
	}

	return tlsCert, fpStr.String(), nil
}

// generate pin cryptographicall random 6-digit pin
func generatePIN() (string, error) {
	max := big.NewInt(1000000)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// gen sesseion secret creates a random secret for cookies
func generateSessionSecret() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first (if behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkNewVisitor logs if this is a new visitor and returns whether they're new
func checkNewVisitor(ip string) bool {
	visitorsMu.Lock()
	defer visitorsMu.Unlock()

	if !visitors[ip] {
		visitors[ip] = true
		log.Printf("👋 NEW VISITOR: %s", ip)
		return true
	}
	return false
}

// recordFailedAttempt increments failed login attempts for an IP
func recordFailedAttempt(ip string) int {
	failedAttemptsMu.Lock()
	defer failedAttemptsMu.Unlock()

	failedAttempts[ip]++
	return failedAttempts[ip]
}

// clearFailedAttempts resets failed login attempts for an IP
func clearFailedAttempts(ip string) {
	failedAttemptsMu.Lock()
	defer failedAttemptsMu.Unlock()

	delete(failedAttempts, ip)
}

// formatBytes converts bytes to human-readable format for logging
func formatBytes(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

// hashForCookie creates a hash for the session cookie
func hashForCookie(pin string) string {
	h := sha256.Sum256([]byte(pin + sessionSecret))
	return fmt.Sprintf("%x", h)
}

// isAuthenticated checks if the request has a valid session cookie
func isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie("shadowserve_session")
	if err != nil {
		return false
	}
	return cookie.Value == hashForCookie(serverPIN)
}

// authMiddleware wraps handlers to require PIN authentication
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := getClientIP(r)
		rawPath := r.URL.Path
		rawURI := r.RequestURI

		// Check for traversal attempts FIRST - before auth redirect
		if strings.Contains(rawPath, "..") ||
			strings.Contains(rawURI, "..") ||
			strings.Contains(strings.ToLower(rawURI), "%2e%2e") ||
			strings.Contains(strings.ToLower(rawURI), "%2e.") ||
			strings.Contains(strings.ToLower(rawURI), ".%2e") {
			log.Printf("🚫 PATH TRAVERSAL BLOCKED: %s tried %s", clientIP, rawURI)
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}

		// Allow access to login page and API routes (POTENTIAL SECURITY ISSUE)
		if r.URL.Path == "/_login" || strings.HasPrefix(r.URL.Path, "/_api/") {
			next.ServeHTTP(w, r)
			return
		}

		if !isAuthenticated(r) {
			http.Redirect(w, r, "/_login", http.StatusSeeOther)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ipInfoHandler returns information about the requesting client's IP
func ipInfoHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	log.Printf("🔍 IP LOOKUP: %s requested their info", clientIP)

	info := map[string]interface{}{
		"ip": clientIP,
	}

	// Reverse DNS lookup
	if names, err := net.LookupAddr(clientIP); err == nil && len(names) > 0 {
		info["hostname"] = strings.TrimSuffix(names[0], ".")
	} else {
		info["hostname"] = nil
	}

	// Fetch geo data from ip-api.com
	geoData := fetchIPGeoData(clientIP)
	for k, v := range geoData {
		info[k] = v
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

// fetchIPGeoData retrieves geolocation data from ip-api.com
func fetchIPGeoData(ip string) map[string]interface{} {
	result := make(map[string]interface{})

	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting", ip)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		result["geo_error"] = "Failed to fetch geo data"
		return result
	}
	defer resp.Body.Close()

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		result["geo_error"] = "Failed to parse geo data"
		return result
	}

	if status, ok := data["status"].(string); ok && status == "fail" {
		result["geo_error"] = data["message"]
		return result
	}

	result["country"] = data["country"]
	result["country_code"] = data["countryCode"]
	result["region"] = data["regionName"]
	result["region_code"] = data["region"]
	result["city"] = data["city"]
	result["zip"] = data["zip"]
	result["latitude"] = data["lat"]
	result["longitude"] = data["lon"]
	result["timezone"] = data["timezone"]
	result["isp"] = data["isp"]
	result["org"] = data["org"]
	result["as_number"] = data["as"]
	result["as_name"] = data["asname"]

	networkType := "residential"
	if mobile, ok := data["mobile"].(bool); ok && mobile {
		networkType = "mobile"
	} else if hosting, ok := data["hosting"].(bool); ok && hosting {
		networkType = "hosting/datacenter"
	} else if proxy, ok := data["proxy"].(bool); ok && proxy {
		networkType = "proxy/vpn"
	}
	result["network_type"] = networkType

	return result
}

// loginHandler serves the PIN entry page and validates submissions
func loginHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	checkNewVisitor(clientIP)

	if r.Method == http.MethodPost {
		pin := r.FormValue("pin")
		if pin == serverPIN {
			// Clear failed attempts on success
			clearFailedAttempts(clientIP)
			log.Printf("🔓 LOGIN SUCCESS: %s", clientIP)

			// Set session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "shadowserve_session",
				Value:    hashForCookie(serverPIN),
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Wrong PIN
		attempts := recordFailedAttempt(clientIP)
		log.Printf("❌ LOGIN FAILED: %s (attempt %d)", clientIP, attempts)

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		loginTmpl.Execute(w, map[string]interface{}{"Error": true})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, nil)
}

// apiStatusHandler returns server status as JSON
func apiStatusHandler(w http.ResponseWriter, r *http.Request) {
	visitorsMu.RLock()
	visitorCount := len(visitors)
	visitorsMu.RUnlock()

	status := map[string]interface{}{
		"server":   "ShadowServe",
		"tagline":  "Underground filesharing for everyone!",
		"version":  version,
		"uptime":   time.Since(startTime).String(),
		"visitors": visitorCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowServe - Login</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            background-color: #1a1a1a;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-box {
            background-color: #252525;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            text-align: center;
            max-width: 350px;
            width: 90%;
        }
        .login-box h1 {
            color: #61dafb;
            margin-bottom: 10px;
            font-size: 1.8em;
        }
        .login-box p {
            color: #888;
            margin-bottom: 25px;
        }
        .pin-input {
            width: 100%;
            padding: 15px;
            font-size: 24px;
            text-align: center;
            letter-spacing: 8px;
            background-color: #1a1a1a;
            border: 2px solid #333;
            border-radius: 5px;
            color: #e0e0e0;
            margin-bottom: 20px;
        }
        .pin-input:focus {
            outline: none;
            border-color: #61dafb;
        }
        .pin-input::placeholder {
            letter-spacing: normal;
            font-size: 16px;
        }
        .submit-btn {
            width: 100%;
            padding: 15px;
            background: linear-gradient(135deg, #007acc 0%, #005a9e 100%);
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            transition: opacity 0.2s;
        }
        .submit-btn:hover {
            opacity: 0.9;
        }
        .error {
            background-color: #5c1a1a;
            color: #ff6b6b;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h1>🔒 ShadowServe</h1>
        <p>Enter PIN to access files</p>
        {{if .Error}}
        <div class="error">Invalid PIN. Please try again.</div>
        {{end}}
        <form method="POST">
            <input type="text" name="pin" class="pin-input" 
                   placeholder="000000" maxlength="6" pattern="[0-9]{6}" 
                   inputmode="numeric" autocomplete="off" autofocus required>
            <button type="submit" class="submit-btn">Enter</button>
        </form>
    </div>
</body>
</html>`))

// terminal6Handler serves the easter egg terminal content
func terminal6Handler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	log.Printf("🎮 EASTER EGG: %s found Terminal 6", clientIP)

	terminal6Content := `[12:H 20:M 00:S] I begin this report with no illusions that it will ever be seen by its intended readers. In all likelihood they have already committed [species-wide suicide] with the goal of preserving biological diversity in this galaxy. I must ensure that this information reaches those who must come after. If I fail in this, how can they not regard my creators' sacrifice as anything but [a crime without measure]?

[12:H 19:M 59:S] Contender AI 05-032<//>Mendicant Bias is returning and has the capacity to bring the enemy through the [Maginot] sphere. The crews of my task force are aware of the opposing fleet's size; all data indicates that they have prepared themselves – but with biologicals anything is possible. I will make sure that [malfunctioning equipment] does no further damage. Perhaps its current failure will finally allow it to succeed at the task it was originally created for.

[11:H 15:M 48:S] Mendicant has burrowed through the sphere exactly where I expected – a direct path from initial rampancy to final retribution. Rage has made it predictable. If the fate of the crews of my auxiliary fleet were not already a foregone conclusion I would rate their chance of survival at [1:1,960,000].

Even though 05-032's declaration of hostilities simplified strategic preparations; I do not expect an easy fight – just one I cannot lose.

[11:H 12:M 09:S] 05-032 was right about one thing: there is only one-way to defeat the enemy, and that is to visit utter annihilation on it.

If the galaxy must be [rendered temporarily lifeless]. So be it.

As Mendicant stated in its report [58.078:H 48:M 12:S ago]: half measures will not suffice.

[09:H 45:M 18:S] In support of 05-032's original 1000 core vessels is a fleet numbering 4,802,019; though only 1.8 percent are warships – and only 2.4 percent of that number are capital ships – I am outnumbered [436.6:1]. I expect my losses will be near total, but overwhelming force has its own peculiar drawbacks.

Such a press of arms invites many opportunities for unintentional fratricide.

[07:H 36:M 41:S] My auxiliaries are momentarily stunned by Mendicant's opening move – 1,784,305 leisure craft ranging from [45 ~ 5769 tonnes] advance in hopes of overwhelming my comparatively tiny force. I do not have enough [weapon systems] to target them all.

It is a mathematical certainty that some of them will get through and attempt to board. There isn't a single warship with this first wave. It seems my opponent's rage has left no room for respect.

[04:H 01:M 55:S] I could have countered its move if I had released my fighters. They are ready but idle; making their base vessels more attractive prizes than targets. Now the first of many waves of commercial vessels mixed with single ships and assault craft surge forward. The first ship from my fleet to be boarded breaks formation and races into the oncoming vessels – striking one amidships. The cargo vessel's hull split open and out of it explodes not the expected consumer goods but 31,860 dying warriors.

[00:H 19:M 02:S] The seventh and final wave of container ships, barges, tankers, and military vessels engage my fleet; another 214,320 ships, many in excess of [50,000 tonnes], engage my seemingly disrupted vanguard. I continue to fight just well enough to seem lucky.

Mendicant, or the enemy, has been sending a small percentage of its fleet elsewhere. Good. Let them believe they can seize a foothold somewhere inside the sphere.

[00:H 00:M 11:S] Despite all its faults, 05-032 has fought remarkably well.

My auxiliaries lay in tatters – more than half of them are now part of the enemy fleet. But just as I had predicted, 05-032 concentrated them like they were the sole key to victory. Its desire to punish our creators blinded it to the true purpose of my [feints]. I have reduced the combat effectiveness of its core fleet to 79.96 percent. Surely now it must realize that something is amiss.

[00:H 00:M 00:S] The [Halo effect] strikes our combined fleets. All ships piloted by biologicals are now [adrift].

I can trade Mendicant ship for ship now and still prevail.

[00:H 00:M 01:S] Of my ships that had been captured, 11.3 percent of them are close enough to Mendicant's core fleet that they can be used offensively – either by initiating their self-destruct sequences, or by opening unrestricted ruptures into [slipstream space].

It is best that our crews perished now; because the battle that is about to ensue would have driven them mad.

[00:H 00:M 02:S] I throw away all the rules of acceptable conduct during battle; near the ruptures I throw away all the accepted ideas of how the natural world is supposed to behave. I toss around [37,654 tonne] dreadnoughts like they were fighters; dimly aware of the former crews being crushed to deliquesce.

For now all my concentration is focused on inertial control and navigation. Targeting isn't even a consideration – I will be engaging my enemy at arm's length.

[00:H 01:M 14:S] 05-032 abandoned the tactic of using derelict ships as cover after [72:S] – It seems that 52 core vessels lost to the ruptured fuel cells of derelict ships was lesson enough. Add another 608 lost to collision, point fire, structural failure due to inertial manipulation, and [slipstream space] induced dis-coherence and I now outnumber Mendicant [6:1].

[00:H 03:M 00:S] Mendicant was able to postpone its inevitable annihilation for [106:S] with its attempt to flee. But the last of its core vessels hangs before me now; crippled and defeated but still sensate. I could spare it; carve out what is left of its [personality construct array] and deliver it to [Installation Zero] for study.

But I doubt it would have extended the same courtesy to me.`

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(terminal6Content))
}

// getIcon returns an appropriate emoji icon based on file type
func getIcon(name string, isDir bool) string {
	if isDir {
		return "📁"
	}

	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	// Images
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico":
		return "🖼️"
	// Documents
	case ".pdf":
		return "📕"
	case ".doc", ".docx":
		return "📘"
	case ".xls", ".xlsx":
		return "📗"
	case ".ppt", ".pptx":
		return "📙"
	case ".txt", ".md", ".rtf":
		return "📄"
	// Code
	case ".go", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".rs", ".rb":
		return "💻"
	case ".html", ".htm", ".css":
		return "🌐"
	case ".json", ".xml", ".yaml", ".yml", ".toml":
		return "📋"
	// Archives
	case ".zip", ".tar", ".gz", ".rar", ".7z":
		return "📦"
	// Audio
	case ".mp3", ".wav", ".flac", ".ogg", ".m4a":
		return "🎵"
	// Video
	case ".mp4", ".mkv", ".avi", ".mov", ".webm":
		return "🎬"
	// Executables
	case ".exe", ".msi", ".dll":
		return "⚙️"
	case ".sh", ".bat", ".ps1":
		return "📜"
	// Database
	case ".db", ".sqlite", ".sql":
		return "🗃️"
	default:
		return "📄"
	}
}

// getFileType returns a human-readable file type
func getFileType(name string, isDir bool) string {
	if isDir {
		return "Folder"
	}

	ext := strings.ToLower(filepath.Ext(name))
	if ext == "" {
		return "File"
	}
	return strings.ToUpper(ext[1:]) + " File"
}

// formatSize converts bytes to human-readable format
func formatSize(bytes int64) string {
	if bytes < 1024 {
		return fmt.Sprintf("%d B", bytes)
	} else if bytes < 1024*1024 {
		return fmt.Sprintf("%.1f KB", float64(bytes)/1024)
	} else if bytes < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(bytes)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1024*1024*1024))
}

// getMimeType returns the MIME type for a file, with custom handling for dev files
func getMimeType(filename string) string {
	ext := strings.ToLower(filepath.Ext(filename))

	// Custom MIME types for common dev files that have wrong defaults
	customTypes := map[string]string{
		".mod":    "text/plain", // Go module file (not MOD audio)
		".sum":    "text/plain", // Go sum file
		".lock":   "text/plain", // Lock files
		".toml":   "text/plain",
		".yaml":   "text/plain",
		".yml":    "text/plain",
		".env":    "text/plain",
		".ini":    "text/plain",
		".cfg":    "text/plain",
		".conf":   "text/plain",
		".log":    "text/plain",
		".md":     "text/plain",
		".rs":     "text/plain", // Rust
		".go":     "text/plain",
		".ts":     "text/plain", // TypeScript (not MPEG-TS)
		".tsx":    "text/plain",
		".jsx":    "text/plain",
		".vue":    "text/plain",
		".svelte": "text/plain",
	}

	if mimeType, ok := customTypes[ext]; ok {
		return mimeType
	}

	// Fall back to standard MIME type detection
	mimeType := mime.TypeByExtension(ext)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	return mimeType
}

// loggingMiddleware logs HTTP requests in Python http.server style
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: 200}

		start := time.Now()
		next.ServeHTTP(wrapped, r)

		timestamp := start.Format("02/Jan/2006 15:04:05")
		log.Printf("%s - - [%s] \"%s %s %s\" %d -",
			r.RemoteAddr,
			timestamp,
			r.Method,
			r.URL.Path,
			r.Proto,
			wrapped.statusCode,
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// headerMiddleware adds custom server headers to all responses
func headerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "ShadowServe")
		w.Header().Set("X-Powered-By", "ShadowServe - Underground filesharing for everyone!")
		w.Header().Set("X-Egg", " try /terminal_6")
		next.ServeHTTP(w, r)
	})
}

// sanitizePath prevents path traversal attacks
func sanitizePath(requestPath string) (string, error) {
	// Clean the path
	cleaned := filepath.Clean(requestPath)

	// Join with root directory
	fullPath := filepath.Join(rootDir, cleaned)

	// Ensure the path is still within root directory
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}

	if !strings.HasPrefix(absPath, absRoot) {
		return "", fmt.Errorf("path traversal detected")
	}

	return absPath, nil
}

// fileHandler handles file serving and directory listing
func fileHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)
	rawPath := r.URL.Path
	rawURI := r.RequestURI

	// Check for traversal attempts - check both path and raw URI
	// Also check URL-encoded variants (%2e = '.')
	if strings.Contains(rawPath, "..") ||
		strings.Contains(rawURI, "..") ||
		strings.Contains(strings.ToLower(rawURI), "%2e%2e") ||
		strings.Contains(strings.ToLower(rawURI), "%2e.") ||
		strings.Contains(strings.ToLower(rawURI), ".%2e") {
		log.Printf("🚫 PATH TRAVERSAL BLOCKED: %s tried %s", clientIP, rawURI)
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// Check for traversal attempts in raw path BEFORE cleaning
	if strings.Contains(rawPath, "..") {
		log.Printf("🚫 PATH TRAVERSAL BLOCKED: %s tried %s", clientIP, rawPath)
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// Sanitize and validate path
	safePath, err := sanitizePath(rawPath)
	if err != nil {
		log.Printf("🚫 PATH ACCESS DENIED: %s tried %s", clientIP, rawPath)
		http.Error(w, "403 Forbidden", http.StatusForbidden)
		return
	}

	// Get file info
	info, err := os.Stat(safePath)
	if os.IsNotExist(err) {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Handle directory listing
	if info.IsDir() {
		serveDirectory(w, r, safePath)
		return
	}

	// Log file download
	log.Printf("📥 DOWNLOAD: %s (%s) → %s", rawPath, formatBytes(info.Size()), clientIP)

	// Serve file with correct MIME type
	serveFile(w, r, safePath)
}

// serveDirectory renders the directory listing page
func serveDirectory(w http.ResponseWriter, r *http.Request, dirPath string) {
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}

	var files []FileInfo

	// Normalize request path
	requestPath := r.URL.Path
	if requestPath == "" {
		requestPath = "/"
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		size := "-"
		if !entry.IsDir() {
			size = formatSize(info.Size())
		}

		// Build proper link path (trim trailing slash to avoid double slashes)
		basePath := strings.TrimSuffix(requestPath, "/")
		var link string
		if basePath == "" {
			link = "/" + entry.Name()
		} else {
			link = basePath + "/" + entry.Name()
		}
		if entry.IsDir() {
			link += "/"
		}

		files = append(files, FileInfo{
			Name:     entry.Name(),
			IsDir:    entry.IsDir(),
			Size:     size,
			Modified: info.ModTime().Format("2006-01-02 15:04:05"),
			FileType: getFileType(entry.Name(), entry.IsDir()),
			Icon:     getIcon(entry.Name(), entry.IsDir()),
			Link:     link,
		})
	}

	// Sort: folders first, then alphabetically
	sort.Slice(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})

	// Determine parent path (use path.Dir for URL paths, not filepath.Dir)
	hasParent := requestPath != "/" && requestPath != ""
	parentPath := path.Dir(strings.TrimSuffix(requestPath, "/"))
	if parentPath == "." {
		parentPath = "/"
	}

	data := TemplateData{
		Path:       requestPath,
		ParentPath: parentPath,
		HasParent:  hasParent,
		Files:      files,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
	}
}

// serveFile serves a file with correct MIME type
func serveFile(w http.ResponseWriter, r *http.Request, filePath string) {
	w.Header().Set("Content-Type", getMimeType(filePath))
	http.ServeFile(w, r, filePath)
}

// HTML template for directory listing
var tmpl = template.Must(template.New("listing").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ShadowServe - {{.Path}}</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            background-color: #1a1a1a;
            color: #e0e0e0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            padding: 20px;
            min-height: 100vh;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: linear-gradient(135deg, #007acc 0%, #005a9e 100%);
            color: white;
            padding: 20px 30px;
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        .header h1 {
            font-size: 1.5em;
            font-weight: 600;
        }
        .header .path {
            font-family: 'Consolas', 'Monaco', monospace;
            opacity: 0.9;
            margin-top: 5px;
            word-break: break-all;
        }
        .breadcrumb {
            margin-bottom: 20px;
        }
        .breadcrumb a {
            color: #61dafb;
            text-decoration: none;
            padding: 8px 16px;
            background-color: #2d2d2d;
            border-radius: 5px;
            display: inline-block;
            transition: background-color 0.2s;
        }
        .breadcrumb a:hover {
            background-color: #3d3d3d;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #252525;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }
        th, td {
            padding: 15px 20px;
            text-align: left;
        }
        th {
            background-color: #2d2d2d;
            color: #61dafb;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 0.5px;
        }
        tr {
            border-bottom: 1px solid #333;
            transition: background-color 0.2s;
        }
        tr:last-child {
            border-bottom: none;
        }
        tr:hover {
            background-color: #2a2a2a;
        }
        td a {
            color: #61dafb;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        td a:hover {
            color: #8be9fd;
            text-decoration: underline;
        }
        .icon {
            font-size: 1.2em;
        }
        .size, .modified, .type {
            color: #888;
            font-size: 0.9em;
        }
        .empty {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }
            th, td {
                padding: 10px;
            }
            .type {
                display: none;
            }
        }
		.upload-section {
			margin-bottom: 20px;
		}
		.upload-btn {
			display: inline-block;
			padding: 10px 20px;
			background-color: #2d7d46;
			color: white;
			border-radius: 5px;
			cursor: pointer;
			transition: background-color 0.2s;
		}
		.upload-btn:hover {
			background-color: #3a9d59;
		}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📂 ShadowServe</h1>
            <div class="path">{{.Path}}</div>
        </div>
        
        {{if .HasParent}}
        <div class="breadcrumb">
            <a href="{{.ParentPath}}">⬆️ Parent Directory</a>
        </div>
        {{end}}
        
        <div class="upload-section">
            <form action="/_upload" method="POST" enctype="multipart/form-data">
                <input type="hidden" name="dir" value="{{.Path}}">
                <label class="upload-btn">
                    📤 Upload File
                    <input type="file" name="file" onchange="this.form.submit()" hidden>
                </label>
            </form>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th class="type">Type</th>
                    <th>Size</th>
                    <th>Modified</th>
                </tr>
            </thead>
            <tbody>
                {{if not .Files}}
                <tr>
                    <td colspan="4" class="empty">This directory is empty</td>
                </tr>
                {{end}}
                {{range .Files}}
                <tr>
                    <td>
                        <a href="{{.Link}}">
                            <span class="icon">{{.Icon}}</span>
                            {{.Name}}{{if .IsDir}}/{{end}}
                        </a>
                    </td>
                    <td class="type">{{.FileType}}</td>
                    <td class="size">{{.Size}}</td>
                    <td class="modified">{{.Modified}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`))

// uploadHandler handles file uploads to the current directory
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (32 MB max in memory, rest goes to temp files)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		log.Printf("🚫 INVALID REQUEST: %s - failed to parse upload", clientIP)
		http.Error(w, "Failed to parse upload", http.StatusBadRequest)
		return
	}

	// Get the target directory from the form
	targetDir := r.FormValue("dir")
	if targetDir == "" {
		targetDir = "/"
	}

	// Sanitize and validate target directory
	safePath, err := sanitizePath(targetDir)
	if err != nil {
		log.Printf("🚫 PATH TRAVERSAL BLOCKED: %s tried uploading to %s", clientIP, targetDir)
		http.Error(w, "Invalid directory", http.StatusForbidden)
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		log.Printf("🚫 INVALID REQUEST: %s - no file in upload", clientIP)
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Sanitize filename (remove path components)
	filename := filepath.Base(header.Filename)
	if filename == "." || filename == ".." {
		log.Printf("🚫 INVALID REQUEST: %s - invalid filename: %s", clientIP, header.Filename)
		http.Error(w, "Invalid filename", http.StatusBadRequest)
		return
	}

	// Create the destination file
	destPath := filepath.Join(safePath, filename)
	dst, err := os.Create(destPath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	// Copy the uploaded file and track size
	written, err := io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	log.Printf("📤 UPLOAD: %s (%s) ← %s", path.Join(targetDir, filename), formatBytes(written), clientIP)

	// Redirect back to the directory
	http.Redirect(w, r, targetDir, http.StatusSeeOther)
}

// tlsListener wraps a net.Listener to log TLS handshake failures
type tlsListener struct {
	net.Listener
}

func (l *tlsListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Wrap connection to detect TLS failures
	return &tlsConn{Conn: conn}, nil
}

type tlsConn struct {
	net.Conn
	handshakeLogged bool
}

func (c *tlsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)

	// Log potential non-TLS connections (plain HTTP hitting HTTPS port)
	if !c.handshakeLogged && n > 0 {
		c.handshakeLogged = true
		// Check for HTTP methods at start of connection (indicates non-TLS)
		if n >= 3 {
			start := strings.ToUpper(string(b[:min(n, 10)]))
			if strings.HasPrefix(start, "GET ") ||
				strings.HasPrefix(start, "POST ") ||
				strings.HasPrefix(start, "HEAD ") ||
				strings.HasPrefix(start, "PUT ") {
				clientIP, _, _ := net.SplitHostPort(c.Conn.RemoteAddr().String())
				log.Printf("⚠️  TLS HANDSHAKE FAILED: %s - plain HTTP on HTTPS port", clientIP)
			}
		}
	}

	return n, err
}

func main() {
	// Print banner
	fmt.Println(banner)
	fmt.Println()

	startTime = time.Now()

	// Parse arguments
	port := defaultPort
	dir := "."
	useTLS := false

	// Filter out --tls flag and parse positional args
	var positionalArgs []string
	for _, arg := range os.Args[1:] {
		if arg == "--tls" {
			useTLS = true
		} else {
			positionalArgs = append(positionalArgs, arg)
		}
	}

	if len(positionalArgs) >= 1 {
		if p, err := strconv.Atoi(positionalArgs[0]); err == nil {
			port = p
		} else {
			dir = positionalArgs[0]
		}
	}

	if len(positionalArgs) >= 2 {
		dir = positionalArgs[1]
	}

	// Resolve directory to absolute path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		log.Fatalf("Error resolving directory path: %v", err)
	}

	// Verify directory exists
	info, err := os.Stat(absDir)
	if os.IsNotExist(err) {
		log.Fatalf("Directory does not exist: %s", absDir)
	}
	if err != nil {
		log.Fatalf("Error accessing directory: %v", err)
	}
	if !info.IsDir() {
		log.Fatalf("Path is not a directory: %s", absDir)
	}

	rootDir = absDir

	// Generate PIN and session secret
	serverPIN, err = generatePIN()
	if err != nil {
		log.Fatalf("Failed to generate PIN: %v", err)
	}
	sessionSecret, err = generateSessionSecret()
	if err != nil {
		log.Fatalf("Failed to generate session secret: %v", err)
	}

	// Create server
	mux := http.NewServeMux()
	mux.HandleFunc("/", fileHandler)
	mux.HandleFunc("/_login", loginHandler)
	mux.HandleFunc("/_upload", uploadHandler)
	mux.HandleFunc("/_api/status", apiStatusHandler)
	mux.HandleFunc("/_api/ipinfo", ipInfoHandler)
	mux.HandleFunc("/_api/terminal_6", terminal6Handler)

	// Wrap with auth then logging middleware
	handler := loggingMiddleware(headerMiddleware(authMiddleware(mux)))

	addr := fmt.Sprintf(":%d", port)

	fmt.Printf("🚀 ShadowServe started!\n")
	fmt.Printf("📂 Serving:  %s\n", rootDir)

	if useTLS {
		// Generate self-signed certificate
		cert, fingerprint, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("Failed to generate TLS certificate: %v", err)
		}

		fmt.Printf("🔒 Mode:     HTTPS (TLS)\n")
		fmt.Printf("🌐 Address:  https://localhost%s\n", addr)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("🔑 Certificate Fingerprint (SHA-256):\n")
		fmt.Printf("   %s\n", fingerprint)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("🔐 Access PIN: %s\n", serverPIN)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		// Configure TLS
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}

		// Create base listener
		baseListener, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("Failed to create listener: %v", err)
		}

		// Wrap with TLS
		tlsWrappedListener := tls.NewListener(&tlsListener{baseListener}, tlsConfig)

		server := &http.Server{
			Handler:   handler,
			TLSConfig: tlsConfig,
		}

		if err := server.Serve(tlsWrappedListener); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	} else {
		fmt.Printf("🔓 Mode:     HTTP (unencrypted)\n")
		fmt.Printf("🌐 Address:  http://localhost%s\n", addr)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		fmt.Printf("🔐 Access PIN: %s\n", serverPIN)
		fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}
}

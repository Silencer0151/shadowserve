package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"time"
)

const (
	defaultPort = 2001
	banner      = `
███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███████╗███████╗██████╗ ██╗   ██╗███████╗
██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝
███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║███████╗█████╗  ██████╔╝██║   ██║█████╗  
╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  
███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝███████║███████╗██║  ██║ ╚████╔╝ ███████╗
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝`
)

// generateSelfSignedCert creates an in-memory self-signed TLS certificate
func generateSelfSignedCert() (tls.Certificate, string, error) {
	// Generate ECDSA P-256 key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Certificate valid for 24 hours
	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour)

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
		// Allow access to login page
		if r.URL.Path == "/_login" {
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

// loginHandler serves the PIN entry page and validates submissions
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		pin := r.FormValue("pin")
		if pin == serverPIN {
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
		// Wrong PIN - show error
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		loginTmpl.Execute(w, map[string]interface{}{"Error": true})
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	loginTmpl.Execute(w, nil)
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
)

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
	// Sanitize and validate path
	safePath, err := sanitizePath(r.URL.Path)
	if err != nil {
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

// upload handler to upload files to current directory
func uploadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed ;[", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (32 MB max in memory, rest goes to temp files)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
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
		http.Error(w, "Invalid directory", http.StatusForbidden)
		return
	}

	// Get the uploaded file
	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Sanitize filename (remove path components)
	filename := filepath.Base(header.Filename)
	if filename == "." || filename == ".." {
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

	// Copy the uploaded file
	if _, err := io.Copy(dst, file); err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	// Redirect back to the directory
	http.Redirect(w, r, targetDir, http.StatusSeeOther)
}

func main() {
	// Print banner
	fmt.Println(banner)
	fmt.Println()

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

	// Wrap with auth then logging middleware
	handler := loggingMiddleware(authMiddleware(mux))

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

		server := &http.Server{
			Addr:      addr,
			Handler:   handler,
			TLSConfig: tlsConfig,
		}

		if err := server.ListenAndServeTLS("", ""); err != nil {
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

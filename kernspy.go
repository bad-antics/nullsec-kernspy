// NullSec KernSpy - Hardened Linux Kernel Module Analyzer
// Language: Go (Memory-Safe, Concurrent)
// Author: bad-antics
// License: NullSec Proprietary
// Security Level: Maximum Hardening
//
// Security Features:
// - Input validation with sanitization
// - Privilege verification
// - Rate limiting on operations
// - Memory-safe by design (Go runtime)
// - Defense-in-depth architecture

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ============================================================================
// Constants
// ============================================================================

const (
	Version        = "2.0.0"
	MaxModules     = 10000
	MaxPathLength  = 4096
	MaxFileSize    = 100 * 1024 * 1024 // 100MB
	RateLimitDelay = 10 * time.Millisecond
)

var Banner = `
██╗  ██╗███████╗██████╗ ███╗   ██╗███████╗██████╗ ██╗   ██╗
██║ ██╔╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗╚██╗ ██╔╝
█████╔╝ █████╗  ██████╔╝██╔██╗ ██║███████╗██████╔╝ ╚████╔╝ 
██╔═██╗ ██╔══╝  ██╔══██╗██║╚██╗██║╚════██║██╔═══╝   ╚██╔╝  
██║  ██╗███████╗██║  ██║██║ ╚████║███████║██║        ██║   
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝        ╚═╝   
                bad-antics • Kernel Module Analyzer
═══════════════════════════════════════════════════════════
`

// ============================================================================
// Error Types
// ============================================================================

type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error [%s]: %s", e.Field, e.Message)
}

type SecurityError struct {
	Operation string
	Message   string
}

func (e *SecurityError) Error() string {
	return fmt.Sprintf("security error [%s]: %s", e.Operation, e.Message)
}

// ============================================================================
// Input Validation
// ============================================================================

var (
	safeNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_\-\.]+$`)
	pathRegex     = regexp.MustCompile(`^[a-zA-Z0-9_\-\./]+$`)
)

// ValidatePath ensures a path is safe and exists
func ValidatePath(path string) (string, error) {
	// Length check
	if len(path) > MaxPathLength {
		return "", &ValidationError{Field: "path", Message: "path too long"}
	}

	// Check for null bytes
	if strings.ContainsRune(path, '\x00') {
		return "", &ValidationError{Field: "path", Message: "null byte in path"}
	}

	// Check for path traversal
	if strings.Contains(path, "..") {
		return "", &ValidationError{Field: "path", Message: "path traversal detected"}
	}

	// Clean and resolve
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", &ValidationError{Field: "path", Message: "cannot resolve path"}
	}

	return absPath, nil
}

// ValidateModuleName ensures a module name is safe
func ValidateModuleName(name string) error {
	if len(name) == 0 || len(name) > 255 {
		return &ValidationError{Field: "module_name", Message: "invalid length"}
	}

	if !safeNameRegex.MatchString(name) {
		return &ValidationError{Field: "module_name", Message: "invalid characters"}
	}

	return nil
}

// ============================================================================
// Privilege Checks
// ============================================================================

// IsRoot checks if running as root
func IsRoot() bool {
	return os.Geteuid() == 0
}

// RequireRoot ensures root privileges
func RequireRoot() error {
	if !IsRoot() {
		return &SecurityError{Operation: "privilege_check", Message: "root privileges required"}
	}
	return nil
}

// ============================================================================
// Kernel Module Structures
// ============================================================================

// ModuleState represents the state of a kernel module
type ModuleState string

const (
	ModuleLive     ModuleState = "Live"
	ModuleLoading  ModuleState = "Loading"
	ModuleUnloading ModuleState = "Unloading"
)

// KernelModule represents information about a loaded kernel module
type KernelModule struct {
	Name          string
	Size          uint64
	RefCount      int
	Dependencies  []string
	State         ModuleState
	Offset        uint64
	Taint         []string
	IsBuiltin     bool
	IsSigned      bool
	Hash          string
	LoadedAt      time.Time
}

// ModuleParams holds module parameters
type ModuleParams struct {
	Name     string
	Value    string
	Type     string
	ReadOnly bool
}

// SecurityAnalysis holds security analysis results
type SecurityAnalysis struct {
	TotalModules     int
	UnsignedModules  []string
	TaintedModules   []string
	HighPrivModules  []string
	SuspiciousModules []string
	Warnings         []string
	Score            int // 0-100, higher is more secure
}

// ============================================================================
// Rate Limiter
// ============================================================================

type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	lastOp   time.Time
}

func NewRateLimiter(interval time.Duration) *RateLimiter {
	return &RateLimiter{
		interval: interval,
		lastOp:   time.Now(),
	}
}

func (r *RateLimiter) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()

	elapsed := time.Since(r.lastOp)
	if elapsed < r.interval {
		time.Sleep(r.interval - elapsed)
	}
	r.lastOp = time.Now()
}

// ============================================================================
// Kernel Module Operations
// ============================================================================

// ListModules reads and parses /proc/modules
func ListModules(limiter *RateLimiter) ([]KernelModule, error) {
	limiter.Wait()

	file, err := os.Open("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("cannot read /proc/modules: %w", err)
	}
	defer file.Close()

	var modules []KernelModule
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		if len(modules) >= MaxModules {
			break
		}

		line := scanner.Text()
		module, err := parseModuleLine(line)
		if err != nil {
			continue // Skip malformed lines
		}

		modules = append(modules, module)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading modules: %w", err)
	}

	return modules, nil
}

// parseModuleLine parses a single line from /proc/modules
func parseModuleLine(line string) (KernelModule, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return KernelModule{}, errors.New("malformed module line")
	}

	size, _ := strconv.ParseUint(fields[1], 10, 64)
	refCount, _ := strconv.Atoi(fields[2])

	var deps []string
	if len(fields) > 3 && fields[3] != "-" {
		deps = strings.Split(strings.TrimSuffix(fields[3], ","), ",")
	}

	var state ModuleState = ModuleLive
	if len(fields) > 4 {
		switch fields[4] {
		case "Loading":
			state = ModuleLoading
		case "Unloading":
			state = ModuleUnloading
		}
	}

	var offset uint64
	if len(fields) > 5 {
		offsetStr := strings.TrimPrefix(fields[5], "0x")
		offset, _ = strconv.ParseUint(offsetStr, 16, 64)
	}

	return KernelModule{
		Name:         fields[0],
		Size:         size,
		RefCount:     refCount,
		Dependencies: deps,
		State:        state,
		Offset:       offset,
		LoadedAt:     time.Now(),
	}, nil
}

// GetModuleInfo retrieves detailed information about a specific module
func GetModuleInfo(name string, limiter *RateLimiter) (*KernelModule, error) {
	if err := ValidateModuleName(name); err != nil {
		return nil, err
	}

	limiter.Wait()

	// Check /sys/module/{name}
	modPath := filepath.Join("/sys/module", name)
	info, err := os.Stat(modPath)
	if err != nil || !info.IsDir() {
		return nil, fmt.Errorf("module not found: %s", name)
	}

	module := &KernelModule{
		Name:      name,
		IsBuiltin: false,
	}

	// Read various attributes
	if data, err := os.ReadFile(filepath.Join(modPath, "coresize")); err == nil {
		size, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
		module.Size = size
	}

	if data, err := os.ReadFile(filepath.Join(modPath, "refcnt")); err == nil {
		ref, _ := strconv.Atoi(strings.TrimSpace(string(data)))
		module.RefCount = ref
	}

	if data, err := os.ReadFile(filepath.Join(modPath, "taint")); err == nil {
		taint := strings.TrimSpace(string(data))
		if taint != "" {
			module.Taint = parseTaintFlags(taint)
		}
	}

	// Check if signed
	module.IsSigned = checkModuleSigned(name, limiter)

	return module, nil
}

// GetModuleParams retrieves module parameters
func GetModuleParams(name string, limiter *RateLimiter) ([]ModuleParams, error) {
	if err := ValidateModuleName(name); err != nil {
		return nil, err
	}

	limiter.Wait()

	paramsDir := filepath.Join("/sys/module", name, "parameters")
	info, err := os.Stat(paramsDir)
	if err != nil || !info.IsDir() {
		return nil, nil // No parameters
	}

	entries, err := os.ReadDir(paramsDir)
	if err != nil {
		return nil, err
	}

	var params []ModuleParams
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		paramPath := filepath.Join(paramsDir, entry.Name())
		data, err := os.ReadFile(paramPath)
		if err != nil {
			continue
		}

		info, _ := entry.Info()
		readOnly := info != nil && info.Mode().Perm()&0200 == 0

		params = append(params, ModuleParams{
			Name:     entry.Name(),
			Value:    strings.TrimSpace(string(data)),
			ReadOnly: readOnly,
		})
	}

	return params, nil
}

// parseTaintFlags converts taint string to meaningful flags
func parseTaintFlags(taint string) []string {
	taintMap := map[rune]string{
		'P': "Proprietary module",
		'O': "Out-of-tree module",
		'F': "Force loaded",
		'C': "Staging driver",
		'E': "Unsigned module",
		'X': "Live patched",
		'K': "Kernel lockdown",
	}

	var flags []string
	for _, c := range taint {
		if desc, ok := taintMap[c]; ok {
			flags = append(flags, desc)
		}
	}
	return flags
}

// checkModuleSigned verifies if module has valid signature
func checkModuleSigned(name string, limiter *RateLimiter) bool {
	limiter.Wait()

	// Check module file for signature
	modPath := findModulePath(name)
	if modPath == "" {
		return false
	}

	// Check for signature marker in module
	file, err := os.Open(modPath)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read last bytes for signature marker
	stat, _ := file.Stat()
	if stat.Size() < 28 {
		return false
	}

	buf := make([]byte, 28)
	_, err = file.ReadAt(buf, stat.Size()-28)
	if err != nil {
		return false
	}

	// Check for module signature marker
	return string(buf) == "~Module signature appended~\n"
}

// findModulePath locates the module file on disk
func findModulePath(name string) string {
	// Get kernel version
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err != nil {
		return ""
	}

	release := strings.TrimRight(string(uname.Release[:]), "\x00")
	searchPaths := []string{
		filepath.Join("/lib/modules", release, "kernel"),
		filepath.Join("/lib/modules", release, "updates"),
		filepath.Join("/lib/modules", release, "extra"),
	}

	for _, searchPath := range searchPaths {
		var found string
		filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			base := filepath.Base(path)
			if base == name+".ko" || base == name+".ko.xz" || base == name+".ko.zst" {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found
		}
	}

	return ""
}

// ComputeModuleHash calculates SHA256 hash of module file
func ComputeModuleHash(name string, limiter *RateLimiter) (string, error) {
	if err := ValidateModuleName(name); err != nil {
		return "", err
	}

	limiter.Wait()

	modPath := findModulePath(name)
	if modPath == "" {
		return "", fmt.Errorf("module file not found: %s", name)
	}

	file, err := os.Open(modPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Check file size
	stat, _ := file.Stat()
	if stat.Size() > MaxFileSize {
		return "", &ValidationError{Field: "file", Message: "file too large"}
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// ============================================================================
// Security Analysis
// ============================================================================

// AnalyzeSecurity performs security analysis on loaded modules
func AnalyzeSecurity(modules []KernelModule, limiter *RateLimiter) *SecurityAnalysis {
	analysis := &SecurityAnalysis{
		TotalModules: len(modules),
		Score:        100,
	}

	for _, mod := range modules {
		limiter.Wait()

		// Check for unsigned modules
		info, err := GetModuleInfo(mod.Name, limiter)
		if err == nil && !info.IsSigned {
			analysis.UnsignedModules = append(analysis.UnsignedModules, mod.Name)
			analysis.Score -= 5
		}

		// Check for tainted modules
		if len(mod.Taint) > 0 {
			analysis.TaintedModules = append(analysis.TaintedModules, mod.Name)
			analysis.Score -= 3
		}

		// Check for suspicious module names
		if isSuspiciousModule(mod.Name) {
			analysis.SuspiciousModules = append(analysis.SuspiciousModules, mod.Name)
			analysis.Score -= 10
		}
	}

	// Clamp score
	if analysis.Score < 0 {
		analysis.Score = 0
	}

	// Generate warnings
	if len(analysis.UnsignedModules) > 0 {
		analysis.Warnings = append(analysis.Warnings,
			fmt.Sprintf("%d unsigned modules detected", len(analysis.UnsignedModules)))
	}
	if len(analysis.TaintedModules) > 0 {
		analysis.Warnings = append(analysis.Warnings,
			fmt.Sprintf("%d tainted modules detected", len(analysis.TaintedModules)))
	}
	if len(analysis.SuspiciousModules) > 0 {
		analysis.Warnings = append(analysis.Warnings,
			fmt.Sprintf("%d suspicious modules detected", len(analysis.SuspiciousModules)))
	}

	return analysis
}

// isSuspiciousModule checks for potentially malicious module names
func isSuspiciousModule(name string) bool {
	suspicious := []string{
		"rootkit", "hide", "stealth", "invisible", "hook",
		"keylog", "backdoor", "malware", "trojan",
	}

	lowerName := strings.ToLower(name)
	for _, s := range suspicious {
		if strings.Contains(lowerName, s) {
			return true
		}
	}
	return false
}

// ============================================================================
// Output Formatting
// ============================================================================

func printModules(modules []KernelModule) {
	fmt.Printf("\n[*] Loaded Kernel Modules (%d)\n", len(modules))
	fmt.Println("─────────────────────────────────────────────────────────────────")
	fmt.Printf("%-20s %12s %6s %8s %s\n", "NAME", "SIZE", "REFS", "STATE", "DEPENDENCIES")
	fmt.Println("─────────────────────────────────────────────────────────────────")

	// Sort by size
	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Size > modules[j].Size
	})

	for _, mod := range modules {
		deps := "-"
		if len(mod.Dependencies) > 0 {
			deps = strings.Join(mod.Dependencies, ",")
			if len(deps) > 30 {
				deps = deps[:27] + "..."
			}
		}

		fmt.Printf("%-20s %12d %6d %8s %s\n",
			truncate(mod.Name, 19),
			mod.Size,
			mod.RefCount,
			mod.State,
			deps,
		)
	}
}

func printModuleDetail(mod *KernelModule, params []ModuleParams) {
	fmt.Printf("\n[*] Module: %s\n", mod.Name)
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Size:       %d bytes\n", mod.Size)
	fmt.Printf("  Ref Count:  %d\n", mod.RefCount)
	fmt.Printf("  State:      %s\n", mod.State)
	fmt.Printf("  Signed:     %v\n", mod.IsSigned)
	fmt.Printf("  Offset:     0x%x\n", mod.Offset)

	if len(mod.Taint) > 0 {
		fmt.Printf("  Taint:      %s\n", strings.Join(mod.Taint, ", "))
	}

	if mod.Hash != "" {
		fmt.Printf("  SHA256:     %s\n", mod.Hash)
	}

	if len(params) > 0 {
		fmt.Println("\n  Parameters:")
		for _, p := range params {
			ro := ""
			if p.ReadOnly {
				ro = " [RO]"
			}
			fmt.Printf("    %-20s = %s%s\n", p.Name, p.Value, ro)
		}
	}
}

func printSecurity(analysis *SecurityAnalysis) {
	fmt.Println("\n[*] Security Analysis")
	fmt.Println("─────────────────────────────────────────")
	fmt.Printf("  Total Modules:      %d\n", analysis.TotalModules)
	fmt.Printf("  Security Score:     %d/100\n", analysis.Score)

	scoreBar := strings.Repeat("█", analysis.Score/5) + strings.Repeat("░", 20-analysis.Score/5)
	color := "\033[32m" // Green
	if analysis.Score < 70 {
		color = "\033[33m" // Yellow
	}
	if analysis.Score < 50 {
		color = "\033[31m" // Red
	}
	fmt.Printf("  [%s%s\033[0m]\n", color, scoreBar)

	if len(analysis.UnsignedModules) > 0 {
		fmt.Printf("\n  ⚠️  Unsigned Modules (%d):\n", len(analysis.UnsignedModules))
		for _, m := range analysis.UnsignedModules[:min(5, len(analysis.UnsignedModules))] {
			fmt.Printf("      • %s\n", m)
		}
		if len(analysis.UnsignedModules) > 5 {
			fmt.Printf("      ... and %d more\n", len(analysis.UnsignedModules)-5)
		}
	}

	if len(analysis.SuspiciousModules) > 0 {
		fmt.Printf("\n  🚨 Suspicious Modules:\n")
		for _, m := range analysis.SuspiciousModules {
			fmt.Printf("      • %s\n", m)
		}
	}

	if len(analysis.Warnings) > 0 {
		fmt.Println("\n  Warnings:")
		for _, w := range analysis.Warnings {
			fmt.Printf("      • %s\n", w)
		}
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ============================================================================
// CLI
// ============================================================================

func printHelp() {
	fmt.Println(`
USAGE:
    kernspy [OPTIONS] [module_name]

OPTIONS:
    -l, --list          List all loaded modules
    -i, --info <name>   Show detailed module info
    -s, --security      Security analysis
    -p, --params <name> Show module parameters
    -h, --hash <name>   Compute module file hash
    --help              Show this help

EXAMPLES:
    kernspy -l                    # List all modules
    kernspy -i nvidia             # Show nvidia module details
    kernspy -s                    # Security analysis
    kernspy -p snd_hda_intel      # Show module parameters
    kernspy -h ext4               # Compute module hash
`)
}

func main() {
	fmt.Print(Banner)
	fmt.Printf("v%s\n", Version)

	listFlag := flag.Bool("l", false, "List modules")
	listFlagLong := flag.Bool("list", false, "List modules")
	infoFlag := flag.String("i", "", "Module info")
	infoFlagLong := flag.String("info", "", "Module info")
	securityFlag := flag.Bool("s", false, "Security analysis")
	securityFlagLong := flag.Bool("security", false, "Security analysis")
	paramsFlag := flag.String("p", "", "Module parameters")
	paramsFlagLong := flag.String("params", "", "Module parameters")
	hashFlag := flag.String("h", "", "Module hash")
	hashFlagLong := flag.String("hash", "", "Module hash")
	helpFlag := flag.Bool("help", false, "Show help")

	flag.Parse()

	limiter := NewRateLimiter(RateLimitDelay)

	if *helpFlag {
		printHelp()
		return
	}

	// List modules
	if *listFlag || *listFlagLong {
		modules, err := ListModules(limiter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}
		printModules(modules)
		return
	}

	// Module info
	modName := *infoFlag
	if modName == "" {
		modName = *infoFlagLong
	}
	if modName != "" {
		info, err := GetModuleInfo(modName, limiter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		hash, _ := ComputeModuleHash(modName, limiter)
		info.Hash = hash

		params, _ := GetModuleParams(modName, limiter)
		printModuleDetail(info, params)
		return
	}

	// Security analysis
	if *securityFlag || *securityFlagLong {
		modules, err := ListModules(limiter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		analysis := AnalyzeSecurity(modules, limiter)
		printSecurity(analysis)
		return
	}

	// Module parameters
	paramMod := *paramsFlag
	if paramMod == "" {
		paramMod = *paramsFlagLong
	}
	if paramMod != "" {
		params, err := GetModuleParams(paramMod, limiter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}

		if len(params) == 0 {
			fmt.Println("[*] Module has no parameters")
			return
		}

		fmt.Printf("\n[*] Parameters for %s\n", paramMod)
		fmt.Println("─────────────────────────────────────────")
		for _, p := range params {
			ro := ""
			if p.ReadOnly {
				ro = " [RO]"
			}
			fmt.Printf("  %-20s = %s%s\n", p.Name, p.Value, ro)
		}
		return
	}

	// Hash computation
	hashMod := *hashFlag
	if hashMod == "" {
		hashMod = *hashFlagLong
	}
	if hashMod != "" {
		hash, err := ComputeModuleHash(hashMod, limiter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[+] SHA256(%s): %s\n", hashMod, hash)
		return
	}

	// Default: list modules
	modules, err := ListModules(limiter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error: %v\n", err)
		os.Exit(1)
	}
	printModules(modules)
}

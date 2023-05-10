package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	jwt "github.com/golang-jwt/jwt/v4"
	vault "github.com/hashicorp/vault/api"
)

var authSuccess *int32 = new(int32)
var authFail *int32 = new(int32)
var certSuccess *int32 = new(int32)
var certFail *int32 = new(int32)

type vaultLogin struct {
	RequestID     string      `json:"request_id"`
	LeaseID       string      `json:"lease_id"`
	Renewable     bool        `json:"renewable"`
	LeaseDuration int         `json:"lease_duration"`
	Data          interface{} `json:"data"`
	WrapInfo      interface{} `json:"wrap_info"`
	Warnings      interface{} `json:"warnings"`
	Auth          struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		Metadata      struct {
			Username string `json:"username"`
		} `json:"metadata"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
		EntityID      string `json:"entity_id"`
		TokenType     string `json:"token_type"`
		Orphan        bool   `json:"orphan"`
	} `json:"auth"`
}

type authObject struct {
	Addr      string `json:"vault_add"`
	Namespace string `json:"vault_namespace"`
	Path      string `json:"auth_path"`
	Role      string `json:"auth_role"`
	JwtToken  string `json:"jwt_token"`
	Insecure  bool   `json:"insecure"`
}

type certConfig struct {
	EnginePath string `json:"engine_path"`
	EngineRole string `json:"engine_role"`
	CertDomain string `json:"cert_domain"`
	Insecure   bool   `json:"insecure"`
}

func (auth *authObject) jwtLogin(debug bool) (string, error) {

	payload := map[string]string{
		"role": auth.Role,
		"jwt":  auth.JwtToken,
	}

	json_data, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("error marshalling payload for jwt login: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
	}

	if auth.Insecure {
		http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	req, err := http.NewRequest("POST", auth.Addr+"/v1/auth/"+auth.Path+"/login", bytes.NewReader(json_data))
	if err != nil {
		log.Fatalf("error building jwt authentication request: %v", err)
	}
	if auth.Namespace != "" {
		req.Header.Add("X-VAULT-NAMESPACE", auth.Namespace)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		atomic.AddInt32(authFail, 1)
		return "", err
	}

	if debug && resp.StatusCode != 200 {
		fmt.Printf("%d\n", resp.StatusCode)
	}

	var result vaultLogin
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		if debug {
			fmt.Printf("error unmarshalling vaultLogin response: %v\n", err)
		}
		atomic.AddInt32(authFail, 1)
		return "", err
	}

	resp.Body.Close()
	atomic.AddInt32(authSuccess, 1)
	return result.Auth.ClientToken, nil
}

func (cert *certConfig) certRequest(token string, addr string, namespace string, debug bool) map[string]interface{} {

	config := vault.DefaultConfig()
	config.Address = addr

	if cert.Insecure {
		config.ConfigureTLS(&vault.TLSConfig{
			Insecure: true,
		})
	}

	client, err := vault.NewClient(config)
	if err != nil {
		log.Fatalf("unable to initialize Vault client: %v", err)
	}

	if namespace != "" {
		client.SetNamespace(namespace)
	}
	client.SetToken(token)

	path := cert.EnginePath + "/issue/" + cert.EngineRole
	data := map[string]interface{}{
		"common_name": fmt.Sprintf("pkiBench.%s", cert.CertDomain),
		"ttl":         "90s",
	}

	resp, err := client.Logical().Write(path, data)
	if err != nil {
		if debug {
			fmt.Printf("error making certificate request: %v\n", err)
		}
		atomic.AddInt32(certFail, 1)
		return nil
	} else {
		atomic.AddInt32(certSuccess, 1)
	}

	return resp.Data
}

func testRun(vaultAuth authObject, vaultCert certConfig, debug bool) {
	fmt.Printf("Running in test mode! Set -notest to disable\n")
	token, err := vaultAuth.jwtLogin(debug)
	if token == "" || err != nil {
		log.Fatalf("error authenticating with Vault -- token is empty!")
	}

	fmt.Printf("Token: %s\n", token)
	data := vaultCert.certRequest(token, vaultAuth.Addr, vaultAuth.Namespace, debug)
	cert := data["certificate"].(string)
	block, _ := pem.Decode([]byte(cert))
	if block == nil {
		log.Printf("failed to parse certificate PEM")
		os.Exit(1)
	}
	certParsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("failed to parse certificate: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Subject: %v\nIssuer: %v\nSerial: %v\n", certParsed.Subject, certParsed.Issuer, certParsed.SerialNumber)
	os.Exit(0)
}

func main() {

	var (
		vaultAddr      string
		authPath       string
		authRole       string
		jwtToken       string
		vaultNamespace string
		enginePath     string
		engineRole     string
		certDomain     string
		seconds        int64
		threads        int
		reuseToken     bool
		strictTimeout  bool
		notest         bool
		insecureTls    bool
		debug          bool
		wg             sync.WaitGroup
		vaultAuth      authObject
		vaultCert      certConfig
		err            error
		i              int
	)

	flag.StringVar(&vaultAddr, "vaultAddr", "", "Vault server address")
	flag.StringVar(&vaultNamespace, "vaultNamespace", "", "Vault Namespace")
	flag.StringVar(&authPath, "authPath", "", "Path to Vault Auth Method")
	flag.StringVar(&authRole, "authRole", "", "Vault Auth Method Role")
	flag.StringVar(&jwtToken, "jwtToken", "", "JWT Token string")

	flag.StringVar(&enginePath, "enginePath", "", "Path to Vault PKI Secrets Engine")
	flag.StringVar(&engineRole, "engineRole", "", "Path to PKI Engine Role")
	flag.StringVar(&certDomain, "certDomain", "", "Domain name to issue certificates")
	flag.Int64Var(&seconds, "seconds", 1, "Duration of time in seconds to loop and create certificates")
	flag.IntVar(&threads, "threads", 1, "Number of concurrent clients to run")
	flag.BoolVar(&reuseToken, "reuseToken", false, "Set to avoid authentication on each iteration")
	flag.BoolVar(&strictTimeout, "strictTimeout", false, "Set to drop all open requests at timeout without waiting for the response")
	flag.BoolVar(&notest, "notest", false, "If unset, run once and return the token and certificate for verification")
	flag.BoolVar(&insecureTls, "insecureTls", false, "If set, certificate validation will be skipped")
	flag.BoolVar(&debug, "debug", false, "If set, verbose output will be enabled")
	flag.Parse()

	required := []string{"vaultAddr", "vaultNamespace", "authPath", "authRole", "jwtToken", "enginePath", "engineRole", "certDomain"}
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range required {
		if !seen[req] {
			fmt.Fprintf(os.Stderr, "Missing required argument: -%s\n", req)
			flag.Usage()
			os.Exit(2)
		}
	}

	vaultAuth.Addr = vaultAddr
	vaultAuth.Namespace = vaultNamespace
	vaultAuth.Path = authPath
	vaultAuth.Role = authRole
	vaultAuth.JwtToken = jwtToken
	vaultAuth.Insecure = insecureTls
	vaultCert.EnginePath = enginePath
	vaultCert.EngineRole = engineRole
	vaultCert.CertDomain = certDomain
	vaultCert.Insecure = insecureTls

	// parse JWT token and make sure it doesn't error
	_, _, err = new(jwt.Parser).ParseUnverified(vaultAuth.JwtToken, jwt.MapClaims{})
	if err != nil {
		log.Fatalf("unable to parse JWT token: %v", err)
	}

	// Get initial token
	initialToken, err := vaultAuth.jwtLogin(debug)
	if err != nil {
		log.Fatalf("error authenticating with Vault: %v", err)
	}
	fmt.Printf("Threads: %d\nDuration: %d seconds\n", threads, seconds)

	if !notest {
		testRun(vaultAuth, vaultCert, debug)
	}

	duration := time.Duration(seconds) * time.Second
	timeout := time.NewTimer(duration)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer timeout.Stop()
	defer ticker.Stop()

	// worker function
	do := func(wg *sync.WaitGroup, initialToken string, reuseToken bool, debug bool) {
		token := initialToken
		wg.Add(1)
		defer wg.Done()
		if !reuseToken {
			token, _ = vaultAuth.jwtLogin(debug)
		}
		if token != "" {
			vaultCert.certRequest(token, vaultAuth.Addr, vaultAuth.Namespace, debug)
		}
	}

	fmt.Printf("%s\n", time.Now().Local())

	// loop until timeout
	guard := make(chan struct{}, threads)
loop:
	for timeout := time.After(duration); ; {
		select {
		case <-timeout:
			break loop
		default:
			guard <- struct{}{}
			go func(n int) {
				do(&wg, initialToken, reuseToken, debug)
				<-guard
			}(i)
		}
		i++
	}

	fmt.Printf("Timeout reached\nIterations: %d\n", i)
	if !strictTimeout {
		wg.Wait()
	}

	rate := *certSuccess / int32(seconds)
	authSuccessRate := float32(float32(*authSuccess)/float32(*authSuccess+*authFail)) * 100
	certSuccessRate := float32(float32(*certSuccess)/float32(*certSuccess+*certFail)) * 100
	fmt.Printf("authSuccess: %v\nauthFail: %v\ncertSuccess: %v\ncertFail: %v\ncertRate: %v certs/sec\nauthSuccessRatio: %v\ncertSuccessRatio: %v\n", *authSuccess, *authFail, *certSuccess, *certFail, rate, authSuccessRate, certSuccessRate)
}

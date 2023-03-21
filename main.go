package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/akamensky/argparse"
	"gopkg.in/ini.v1"
)

const version = "v0.1.0"

type gitpin struct {
	domain string
	file   string
}

func failOnError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getServerCertificate(domain string) *x509.Certificate {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", domain+":443", conf)
	failOnError(err)
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	return certs[0]
}

func generateFingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fingerprint := base64.StdEncoding.EncodeToString(digest[:])
	return "sha256//" + fingerprint
}

func getServerFingerprint(domain string) string {
	cert := getServerCertificate(domain)
	return generateFingerprint(cert)
}

func printServerCertificate(domain string) {
	cert := getServerCertificate(domain)
	fmt.Println("CN:", cert.Subject.CommonName)
	fmt.Println("Alternative subject names:", cert.DNSNames)
	fmt.Println("NotBefore", cert.NotBefore)
	fmt.Println("NotAfter", cert.NotAfter)
	fmt.Println("PublicKeyAlgorithm:", cert.PublicKeyAlgorithm)
	fmt.Println("Fingerprint:", generateFingerprint(cert))
}

func parseGitConfig(configFile string) []gitpin {
	pins := []gitpin{}
	cfg, err := ini.Load(configFile)
	failOnError(err)

	for _, section := range cfg.Sections() {
		parts := strings.Split(section.Name(), " ")
		if strings.Compare(parts[0], "includeIf") != 0 {
			continue
		}
		if !strings.Contains(parts[1], "hasconfig:remote.*.url:") {
			continue
		}
		indexBegin := strings.Index(parts[1], "https://")
		domain := parts[1][indexBegin+len("https://"):]
		if strings.Contains(domain, "/") {
			domain = domain[:strings.Index(domain, "/")]
		}
		s, err := cfg.GetSection(section.Name())
		failOnError(err)
		if !s.HasKey("path") {
			failOnError(errors.New("Section '" + section.Name() + "' has no key 'path'"))
		}
		gp := gitpin{domain: domain, file: s.Key("path").Value()}
		pins = append(pins, gp)
	}
	return pins
}

func checkPins(configFile string) {
	pins := parseGitConfig(configFile)
	for _, pin := range pins {
		fmt.Print("Checking pin for ", pin.domain, " ")
		cfg, err := ini.Load(pin.file)
		failOnError(err)
		s, err := cfg.GetSection("http")
		failOnError(err)
		pinnedPubkey := s.Key("pinnedPubkey")
		fingerprint := getServerFingerprint(pin.domain)
		if strings.Compare(pinnedPubkey.Value(), fingerprint) == 0 {
			fmt.Println("\033[32mOK\033[0m")
		} else {
			fmt.Println("\033[31mFAIL\033[0m")
			fmt.Println("Stored fingerprint:", pinnedPubkey.Value())
			fmt.Println("Current fingerprint:", fingerprint)
		}
	}
}

func updatePins(configFile string) {
	pins := parseGitConfig(configFile)
	for _, pin := range pins {
		fmt.Println("Updating pin for", pin.domain)
		cfg, err := ini.Load(pin.file)
		failOnError(err)
		fingerprint := getServerFingerprint(pin.domain)
		cfg.Section("http").Key("pinnedPubkey").SetValue(fingerprint)
		err = cfg.SaveTo(pin.file)
		failOnError(err)
	}
}

func createPinFile(configFile, domain string) {
	fingerprint := getServerFingerprint(domain)
	cfg := ini.Empty()
	section, err := cfg.NewSection("http")
	failOnError(err)
	_, err = section.NewKey("pinnedPubkey", fingerprint)
	failOnError(err)

	file := path.Join(configFile+".d", domain+".inc")
	fmt.Println("Writing pin file for " + domain + " to " + file)
	err = cfg.SaveTo(file)
	failOnError(err)
}

func addPin(configFile, domain string) {
	createPinFile(configFile, domain)

	cfg, err := ini.Load(configFile)
	failOnError(err)
	section, err := cfg.NewSection(`includeIf "hasconfig:remote.*.url:https://` + domain + `/**"`)
	failOnError(err)
	section.NewKey("path", filepath.Join(configFile+".d", domain+".inc"))
	err = cfg.SaveTo(configFile)
	failOnError(err)
}

func deletePin(configFile, domain string) {
	cfg, err := ini.Load(configFile)
	failOnError(err)
	for _, section := range cfg.Sections() {
		searchSection := `includeIf "hasconfig:remote.*.url:https://` + domain + `/**"`
		if strings.Compare(section.Name(), searchSection) == 0 {
			fmt.Println("Removing " + domain + " in " + configFile)
			cfg.DeleteSection(section.Name())
			break
		}
	}
	err = cfg.SaveTo(configFile)
	failOnError(err)
	configFileInclude := filepath.Join(configFile+".d", domain+".inc")
	fmt.Println("Removing " + configFileInclude)
	err = os.Remove(configFileInclude)
	failOnError(err)
}

func getConfigFileLocation(system bool) string {
	var config string
	if system {
		config = "/etc/gitconfig"
	} else {
		config = filepath.Join(os.Getenv("HOME"), ".gitconfig")
	}

	path := config + ".d"
	if _, err := os.Stat(path); errors.Is(err, fs.ErrNotExist) {
		err := os.Mkdir(path, os.ModePerm)
		failOnError(err)
	}
	return config
}

func main() {
	parser := argparse.NewParser(os.Args[0], "add ssl pinning to git")
	useSystem := parser.Flag("", "system", &argparse.Options{Help: "Use /etc/gitconfig instead of ~/.gitconfig"})
	showCertDomain := parser.String("s", "show-cert", &argparse.Options{Help: "Show certificate of <domain>"})
	actionAddDomain := parser.String("a", "add", &argparse.Options{Help: "Add fingerprint for <domain>"})
	actionCheck := parser.Flag("c", "check", &argparse.Options{Help: "Check if fingerprints match"})
	actionUpdate := parser.Flag("u", "update", &argparse.Options{Help: "Update fingerprints"})
	actionDeleteDomain := parser.String("d", "delete", &argparse.Options{Help: "Delete fingerprint for <domain>"})
	actionVersion := parser.Flag("v", "version", &argparse.Options{Help: "Show version"})

	err := parser.Parse(os.Args)

	if err != nil || len(os.Args) == 1 {
		fmt.Println(parser.Usage(err))
		os.Exit(1)
	}

	configFile := getConfigFileLocation(*useSystem)

	if len(*showCertDomain) != 0 {
		printServerCertificate(*showCertDomain)
	} else if *actionCheck {
		checkPins(configFile)
	} else if *actionUpdate {
		updatePins(configFile)
	} else if len(*actionAddDomain) != 0 {
		addPin(configFile, *actionAddDomain)
	} else if len(*actionDeleteDomain) != 0 {
		deletePin(configFile, *actionDeleteDomain)
	} else if *actionVersion {
		fmt.Println(os.Args[0] + " " + version)
	}

}

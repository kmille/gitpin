package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"gopkg.in/ini.v1"
)

type gitpin struct {
	domain string
	file   string
}

func fail_on_error(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func get_server_certificate(domain string) *x509.Certificate {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}
	conn, err := tls.Dial("tcp", domain+":443", conf)
	fail_on_error(err)
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	return certs[0]
}

func generate_fingerprint(cert *x509.Certificate) string {
	digest := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	fingerprint := base64.StdEncoding.EncodeToString(digest[:])
	return "sha256//" + fingerprint
}

func get_server_fingerprint(domain string) string {
	cert := get_server_certificate(domain)
	return generate_fingerprint(cert)
}

func print_server_certificate(domain string) {
	cert := get_server_certificate(domain)
	fmt.Println("CN:", cert.Subject.CommonName)
	fmt.Println("Alternative subject names:", cert.DNSNames)
	fmt.Println("NotBefore", cert.NotBefore)
	fmt.Println("NotAfter", cert.NotAfter)
	fmt.Println("PublicKeyAlgorithm:", cert.PublicKeyAlgorithm)
	fmt.Println("Fingerprint:", generate_fingerprint(cert))
}

func parseGitConfig() []gitpin {

	pins := []gitpin{}
	cfg, err := ini.Load("/etc/gitconfig")
	fail_on_error(err)
	for _, section := range cfg.Sections() {
		parts := strings.Split(section.Name(), " ")
		if strings.Compare(parts[0], "includeIf") != 0 {
			continue
		}
		if !strings.Contains(parts[1], "hasconfig:remote.*.url:") {
			continue
		}
		index_begin := strings.Index(parts[1], "https://")
		domain := parts[1][index_begin+len("https://"):]
		if strings.Contains(domain, "/") {
			domain = domain[:strings.Index(domain, "/")]
		}
		s, err := cfg.GetSection(section.Name())
		fail_on_error(err)
		if !s.HasKey("path") {
			fail_on_error(errors.New("Section '" + section.Name() + "' has no key 'path'"))
		}
		gp := gitpin{domain: domain, file: s.Key("path").Value()}
		pins = append(pins, gp)
	}
	return pins
}

func checkPins() {
	pins := parseGitConfig()
	for _, pin := range pins {
		fmt.Println("Checking pin for", pin.domain)
		cfg, err := ini.Load(pin.file)
		fail_on_error(err)
		s, err := cfg.GetSection("http")
		fail_on_error(err)
		pinnedPubkey := s.Key("pinnedPubkey")
		fingerprint := get_server_fingerprint(pin.domain)
		if strings.Compare(pinnedPubkey.Value(), fingerprint) != 0 {
			fmt.Println("Fingerprint does not match for domain", pin.domain)
			fmt.Println("Stored fingerprint:", pinnedPubkey.Value())
			fmt.Println("Current fingerprint:", fingerprint)
		}
	}
}

func updatePins() {
	pins := parseGitConfig()
	for _, pin := range pins {
		fmt.Println("Updating pin for", pin.domain)
		cfg, err := ini.Load(pin.file)
		fail_on_error(err)
		fingerprint := get_server_fingerprint(pin.domain)
		cfg.Section("http").Key("pinnedPubkey").SetValue(fingerprint)
		err = cfg.SaveTo(pin.file)
		fail_on_error(err)
	}
}

func createPinFile(domain string) {
	fingerprint := get_server_fingerprint(domain)
	file := path.Join("/etc/gitconfig"+".d", domain+".inc")
	cfg := ini.Empty()
	section, err := cfg.NewSection("http")
	fail_on_error(err)
	_, err = section.NewKey("pinnedPubkey", fingerprint)
	fail_on_error(err)
	fmt.Println("Writing pin to", file)
	err = cfg.SaveTo(file)
	fail_on_error(err)
}

func addPin(domain string) {
	createPinFile(domain)

	cfg, err := ini.Load("/etc/gitconfig")
	fail_on_error(err)
	section, err := cfg.NewSection(`includeIf "hasconfig:remote.*.url:https://` + domain + `/**"`)
	fail_on_error(err)
	section.NewKey("path", "/etc/gitconfig.d/"+domain+".inc")
	err = cfg.SaveTo("/etc/gitconfig")
	fail_on_error(err)

}

func main() {
	//domain := "www.google.com:443"
	//domain := os.Args[1]
	//print_server_certificate(domain)
	//parseGitConfig()

	//addPin("heise.de")
	//checkPins()
	updatePins()
}

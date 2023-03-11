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
	"path/filepath"
	"strings"

	"github.com/akamensky/argparse"
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

func parseGitConfig(config_file string) []gitpin {

	pins := []gitpin{}
	cfg, err := ini.Load(config_file)
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

func checkPins(config_file string) {
	pins := parseGitConfig(config_file)
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

func updatePins(config_file string) {
	pins := parseGitConfig(config_file)
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

func get_config_file_location(system bool) string {
	if system {
		return "/etc/gitconfig"
	} else {
		return filepath.Join(os.Getenv("HOME"), ".gitconfig")
	}
}

func main() {
	parser := argparse.NewParser("gitpin", "add ssl pinning to git")
	system := parser.Flag("", "system", &argparse.Options{Help: "use /etc/gitconfig instead of ~/.gitconfig"})
	show_cert := parser.String("s", "show-cert", &argparse.Options{Help: "Show certificate of <domain>"})
	action_check := parser.Flag("c", "check", &argparse.Options{Help: "Check if fingerprints match"})
	action_update := parser.Flag("u", "update", &argparse.Options{Help: "Update fingerprints"})
	action_add := parser.String("a", "add", &argparse.Options{Help: "add fingerprint for <domain>"})
	action_version := parser.Flag("v", "version", &argparse.Options{Help: "Show version"})

	err := parser.Parse(os.Args)

	if err != nil || len(os.Args) == 1 {
		fmt.Println(parser.Usage(err))
		os.Exit(1)
	}

	config_file := get_config_file_location(*system)

	if len(*show_cert) != 0 {
		print_server_certificate(*show_cert)
	} else if *action_check {
		checkPins(config_file)
	} else if *action_update {
		updatePins(config_file)
	} else if len(*action_add) != 0 {
		addPin(*action_add)
	} else if *action_version {
		fmt.Println("0.1")
	}

}

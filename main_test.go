package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/idna"

	"github.com/natesales/q/cli"
	"github.com/natesales/q/transport"
)

func run(args ...string) (*bytes.Buffer, error) {
	opts := newOpts()
	var out bytes.Buffer
	err := driver(&opts, append([]string{"+nocolor"}, args...), &out)
	return &out, err
}

func TestMainQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* TXT "v=spf1 -all"`), out.String())
}

func TestMainVersion(t *testing.T) {
	out, err := run("-V")
	assert.Nil(t, err)
	assert.Contains(t, out.String(), "https://github.com/natesales/q version dev (unknown unknown)")
}

// TODO
//func TestMainODoHQuery(t *testing.T) {
//	out, err := run(
//		"--all",
//		"-q", "example.com",
//		"-s", "https://odoh.cloudflare-dns.com",
//		"--odoh-proxy", "https://odoh.crypto.sx",
//	)
//	assert.Nil(t, err)
//	assert.Regexp(t, regexp.MustCompile(`example.com. .* TXT "v=spf1 -all"`), out.String())
//}

func TestMainRawFormat(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--format=raw",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), "v=spf1 -all")
	assert.Containsf(t, out.String(), "hera.ns.cloudflare.com", out.String())
}

func TestMainJSONFormat(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--format=json",
	)
	assert.Nil(t, err)
	o := strings.ReplaceAll(out.String(), `\\"`, `"`)
	assert.Contains(t, o, `"preference":0,"mx":"."`)
	assert.Contains(t, o, "hera.ns.cloudflare.com")
	assert.Contains(t, o, `"txt":["v=spf1 -all"`)
}

func TestMainIDNAQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "www.饭太硬.com",
		"-t", "A",
	)
	assert.Nil(t, err)
	ascii, err := idna.Lookup.ToASCII("www.饭太硬.com")
	assert.Nil(t, err)
	re := regexp.MustCompile(regexp.QuoteMeta(ascii + "."))
	assert.Regexp(t, re, out.String())
}

func TestMainInvalidOutputFormat(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"--format=invalid",
	)
	if !(err != nil && strings.Contains(err.Error(), "invalid output format")) {
		t.Errorf("invalid output format should throw an error")
	}
}

func TestMainParseTypes(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"-t", "AAAA",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
	assert.Regexp(t, regexp.MustCompile(`example.com. .* AAAA .*`), out.String())
}

func TestMainInvalidTypes(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-t", "INVALID",
	)
	if !(err != nil && strings.Contains(err.Error(), "INVALID is not a valid RR type")) {
		t.Errorf("expected invalid type error, got %+v", err)
	}
}

func TestMainInvalidODoHUpstream(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-s", "tls://odoh.cloudflare-dns.com",
		"--odoh-proxy", "https://odoh.crypto.sx",
	)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH target must use HTTPS")
}

func TestMainInvalidODoHProxy(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-s", "https://odoh.cloudflare-dns.com",
		"--odoh-proxy", "tls://odoh1.surfdomeinen.nl",
	)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "ODoH proxy must use HTTPS")
}

func TestMainReverseQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-x",
		"-q", "1.1.1.1",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`1.1.1.1.in-addr.arpa. .* PTR one.one.one.one`), out.String())
}

func TestMainInferredQname(t *testing.T) {
	out, err := run(
		"--all",
		"example.com",
		"A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInferredServer(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"@8.8.8.8",
		"-t", "A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidReverseQuery(t *testing.T) {
	_, err := run(
		"--all",
		"-x",
		"example.com",
	)
	if !(err != nil && strings.Contains(err.Error(), "unrecognized address: example.com")) {
		t.Errorf("expected address error, got %+v", err)
	}
}

func TestMainInvalidUpstream(t *testing.T) {
	_, err := run(
		"--all",
		"-s", "127.127.127.127:1",
		"--timeout", "2s",
		"example.com",
	)

	expectedErrors := []string{"connection refused", "i/o timeout", "timeout after"}
	foundErr := false
	for _, expectedError := range expectedErrors {
		if strings.Contains(err.Error(), expectedError) {
			foundErr = true
			break
		}
	}
	assert.Truef(t, foundErr, "expected connection error, got: %+v", err)
}

func TestMainDNSSECArg(t *testing.T) {
	out, err := run(
		"--all",
		"example.com",
		"+dnssec",
		"@9.9.9.9",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* RRSIG .*`), out.String())
}

func TestMainPad(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--pad",
		"--format=json",
	)
	assert.Nil(t, err)
	o := strings.ReplaceAll(out.String(), `\\"`, `"`)
	assert.Contains(t, o, `"truncated":false`)
}

func TestMainChaosClass(t *testing.T) {
	out, err := run(
		"--all",
		"id.server",
		"CH",
		"TXT",
		"@9.9.9.9",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`id.server. .* TXT "res.*"`), out.String())
}

func TestMainParsePlusFlags(t *testing.T) {
	opts := newOpts()
	cli.ParsePlusFlags(&opts, []string{"+dnssec", "+nord"})
	assert.True(t, opts.DNSSEC)
	assert.False(t, opts.RecursionDesired)
}

func TestMainTCPQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-t", "A",
		"-q", "example.com",
		"@tcp://1.1.1.1",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTLSQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@tls://1.1.1.1",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainHTTPSQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@https://dns.quad9.net",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainQUICQuery(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"@quic://dns.adguard.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainDNSCryptStampQuery(t *testing.T) {
	out, err := run(
		"-q", "example.com",
		"-t", "A",
		"@sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainDNSCryptManualQuery(t *testing.T) {
	out, err := run(
		"-q", "example.com",
		"-t", "A",
		"@dnscrypt://94.140.14.14:5443",
		"--dnscrypt-key", "d12b47f252dcf2c2bbf8991086eaf79ce4495d8b16c8a0c4322e52ca3f390873",
		"--dnscrypt-provider", "2.dnscrypt.default.ns1.adguard.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTCPFallbackOnAuthoritative(t *testing.T) {
	out, err := run(
		"--all",
		"@ns47.domaincontrol.com",
		"TXT",
		"chordline.com",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`chordline.com\. .* TXT .*`), out.String())
}

func TestMainInvalidServerURL(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"@bad::server::url",
		"--format=json",
	)
	assert.NotNil(t, err)
	assert.NotRegexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainInvalidTransportScheme(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"@invalid://example.com",
		"--format=json",
	)
	assert.NotNil(t, err)
	assert.NotRegexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainTLS12(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"--tls-min-version=1.1",
		"--tls-max-version=1.2",
		"@tls://dns.quad9.net",
		"-t", "A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`example.com. .* A .*`), out.String())
}

func TestMainNSID(t *testing.T) {
	out, err := run(
		"--all",
		"@9.9.9.9",
		"+nsid",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`NSID: .*`), out.String())
}

func TestMainECSv4(t *testing.T) {
	out, err := run(
		"--all",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "192.0.2.0/24",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), `'subnet':'192.0.2.0/24/0'`)
}

func TestMainECSv6(t *testing.T) {
	out, err := run(
		"--all",
		"@script-ns.packetframe.com",
		"TXT",
		"query.script.packetframe.com",
		"--subnet", "2001:db8::/48",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), `'subnet':'[2001:db8::]/48/0'`)
}

func TestMainHTTPUserAgent(t *testing.T) {
	out, err := run(
		"--all",
		"@https://dns.quad9.net",
		"--http-user-agent", "Example/1.0",
		"-t", "NS",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`. .* NS a.root-servers.net.`), out.String())
}

func TestMainParseServer(t *testing.T) {
	for _, tc := range []struct {
		Server       string
		Type         transport.Type
		ExpectedHost string
	}{
		{ // IPv4 plain with no port
			Server:       "1.1.1.1",
			Type:         transport.TypePlain,
			ExpectedHost: "1.1.1.1:53",
		},
		{ // IPv4 plain with explicit port
			Server:       "1.1.1.1:5353",
			Type:         transport.TypePlain,
			ExpectedHost: "1.1.1.1:5353",
		},
		{ // IPv6 plain with no port
			Server:       "2a09::",
			Type:         transport.TypePlain,
			ExpectedHost: "[2a09::]:53",
		},
		{ // IPv6 plain with explicit port
			Server:       "[2a09::]:5353",
			Type:         transport.TypePlain,
			ExpectedHost: "[2a09::]:5353",
		},
		{ // TLS with no port
			Server:       "tls://dns.quad9.net",
			Type:         transport.TypeTLS,
			ExpectedHost: "dns.quad9.net:853",
		},
		{ // TLS with explicit port
			Server:       "tls://dns.quad9.net:8530",
			Type:         transport.TypeTLS,
			ExpectedHost: "dns.quad9.net:8530",
		},
		{ // HTTPS with no endpoint
			Server:       "https://dns.quad9.net",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://dns.quad9.net:443/dns-query",
		},
		{ // HTTPS with IPv4 address
			Server:       "https://1.1.1.1",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://1.1.1.1:443/dns-query",
		},
		{ // TCP with no port
			Server:       "tcp://dns.quad9.net",
			Type:         transport.TypeTCP,
			ExpectedHost: "dns.quad9.net:53",
		},
		{ // HTTPS with IPv6 address
			Server:       "https://2a09::",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://[2a09::]:443/dns-query",
		},
		{ // HTTPS with explicit endpoint
			Server:       "https://dns.quad9.net/other-dns-endpoint",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://dns.quad9.net:443/other-dns-endpoint",
		},
		{ // QUIC with no port
			Server:       "quic://dns.adguard.com",
			Type:         transport.TypeQUIC,
			ExpectedHost: "dns.adguard.com:853",
		},
		{ // QUIC with explicit port
			Server:       "quic://dns.adguard.com:8530",
			Type:         transport.TypeQUIC,
			ExpectedHost: "dns.adguard.com:8530",
		},
		{ // IPv6 plain with scope ID but without port
			Server:       "fe80::1%en0",
			Type:         transport.TypePlain,
			ExpectedHost: "[fe80::1%en0]:53",
		},
		{ // IPv6 with scope ID and explicit port
			Server:       "plain://[fe80::1%en0]:53",
			Type:         transport.TypePlain,
			ExpectedHost: "[fe80::1%en0]:53",
		},
		{ // DNS Stamp
			Server:       "sdns://AgcAAAAAAAAAAAAHOS45LjkuOQA",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://9.9.9.9:443/dns-query",
		},
		{ // URL encoded path (https://github.com/natesales/q/issues/66)
			Server:       "https://localhost/1%3A89%3D%3D%3A64fx",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://localhost:443/1%3A89%3D%3D%3A64fx",
		},
		{ // Colons in URL path (https://github.com/natesales/q/issues/66)
			Server:       "https://localhost/1:89==:64fx",
			Type:         transport.TypeHTTP,
			ExpectedHost: "https://localhost:443/1:89==:64fx",
		},
		{ // Plain IPv6 address
			Server:       "2001:db8:11:8340:dea6:32ff:fe5b:a19e",
			Type:         transport.TypePlain,
			ExpectedHost: "[2001:db8:11:8340:dea6:32ff:fe5b:a19e]:53",
		},
	} {
		t.Run(tc.Server, func(t *testing.T) {
			server, transportType, err := parseServer(tc.Server)
			assert.Nil(t, err)
			assert.Equal(t, tc.ExpectedHost, server)
			assert.Equal(t, tc.Type, transportType)
		})
	}
}

func TestMainRecAXFR(t *testing.T) {
	out, err := run(
		"--all",
		"+recaxfr",
		"@nsztm1.digi.ninja", "zonetransfer.me",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), `AXFR zonetransfer.me.`)
	assert.Contains(t, out.String(), `AXFR internal.zonetransfer.me.`)

	// Remove zonetransfer files
	files, err := filepath.Glob("zonetransfer.me*")
	assert.Nil(t, err)
	for _, f := range files {
		assert.Nil(t, os.RemoveAll(f))
	}
}

func TestMainShowAll(t *testing.T) {
	out, err := run(
		"@9.9.9.9",
		"--all",
		"+all",
		"example.com",
		"A",
	)
	assert.Nil(t, err)
	assert.Contains(t, out.String(), "example.com.")
	assert.Contains(t, out.String(), "Question:")
	assert.Contains(t, out.String(), "Answer:")
	assert.Contains(t, out.String(), "Stats:")
}

func TestMainResolveIPs(t *testing.T) {
	out, err := run(
		"core1.fmt2.he.net",
		"A", "AAAA",
		"-R",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`core1.fmt2.he.net. .* A .* \(core1.fmt2.he.net.\)`), out.String())
}

func TestMainQueryDomainWithRRType(t *testing.T) {
	out, err := run(
		"NS.network",
		"A",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`(?i)ns.network. .* A .*`), out.String())
}

func TestMainQueryTypeFlag(t *testing.T) {
	out, err := run(
		"-t", "65",
		"cloudflare.com",
		"-v",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`cloudflare.com. .* HTTPS 1 .*`), out.String())
}

func TestMainDnsstampDoH(t *testing.T) {
	out, err := run(
		"@sdns://AgcAAAAAAAAADjEwNC4xNi4yNDguMjQ5ABJjbG91ZGZsYXJlLWRucy5jb20A", // cloudflare-dns.com
		"--all",
	)

	assert.Nil(t, err)
	assert.Contains(t, out.String(), "from https://cloudflare-dns.com:443/dns-query")
}

func TestMainDnsstampDoHPath(t *testing.T) {
	_, err := run(
		"@sdns://AgcAAAAAAAAADjEwNC4xNi4yNDguMjQ5ABJjbG91ZGZsYXJlLWRucy5jb20FL3Rlc3Q", // cloudflare-dns.com/test
		"--all",
	)

	// use err here because the query will result in a 404
	assert.Contains(t, err.Error(), "from https://cloudflare-dns.com:443/test")
}

func TestMainDnsstampInvalid(t *testing.T) {
	_, err := run(
		"@sdns://invalid",
		"--all",
	)

	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "converting DNS stamp to URL: illegal base64 data")
}

func TestMainTypeNotation(t *testing.T) {
	// Test invalid TYPE notation
	_, err := run(
		"--all",
		"-q", "example.com",
		"-t", "TYPEinvalid",
	)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "TYPEinvalid is not a valid RR type")

	// Test that TYPE65 is equivalent to HTTPS
	outType65, err := run(
		"--all",
		"-q", "cloudflare.com",
		"-t", "TYPE65",
	)
	assert.Nil(t, err)
	assert.Regexp(t, regexp.MustCompile(`cloudflare.com. .* HTTPS .*`), outType65.String())
}

func TestIDNAUnderscoreASCII(t *testing.T) {
	// Ensure ASCII names with underscores are not mangled by IDNA processing
	out, err := run(
		"--all",
		"-q", "_acme-challenge.example.com",
		"-t", "TXT",
	)
	assert.Nil(t, err)
	// Expect the question or answer to include the literal underscore name
	re := regexp.MustCompile(regexp.QuoteMeta("_acme-challenge.example.com."))
	assert.Regexp(t, re, out.String())
}

func TestMainEDE_Raw(t *testing.T) {
	out, err := run(
		"--all",
		"-f=raw",
		"A",
		"ede-6.extended-dns-errors.com",
		"+ede",
		"@1.1.1.1",
	)
	assert.Nil(t, err)
	s := out.String()
	assert.Contains(t, s, "EDE: 6 (DNSSEC Bogus)")
	assert.Contains(t, s, "This EDE was intentionally inserted by dnsdist")
}

func TestMainEDE_Pretty(t *testing.T) {
	out, err := run(
		"--all",
		"A",
		"ede-6.extended-dns-errors.com",
		"+ede",
		"@1.1.1.1",
	)
	assert.Nil(t, err)
	s := out.String()
	assert.Contains(t, s, "EDE:")
	assert.Contains(t, s, "6 (DNSSEC Bogus)")
	assert.Contains(t, s, "This EDE was intentionally inserted by dnsdist")
}

func TestMainMultipleServersSkipFailures(t *testing.T) {
	out, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"-s", "127.127.127.127:1", // expected to fail
		"-s", "8.8.8.8", // expected to succeed
	)
	assert.Nil(t, err)
	s := out.String()
	assert.Regexp(t, regexp.MustCompile(`example\.com\. .* A .*`), s)
	// When multiple servers are used, the server suffix is appended to answers
	assert.Truef(t, strings.Contains(s, "(8.8.8.8:53)") || strings.Contains(s, "from 8.8.8.8:53"), "expected output to include successful server 8.8.8.8:53, got: %s", s)
}

func TestMainMultipleServersAllFail(t *testing.T) {
	_, err := run(
		"--all",
		"-q", "example.com",
		"-t", "A",
		"-s", "127.127.127.127:1",
		"-s", "127.127.127.127:2",
		"--timeout", "1s",
	)
	assert.NotNil(t, err)

	timedOut := strings.Contains(err.Error(), "timeout after 2s")
	erroredOut := strings.Contains(err.Error(), "all servers failed")
	assert.True(t, timedOut || erroredOut)
}

func TestDaemonQuery(t *testing.T) {
	srv := httptest.NewServer(daemonMux(daemonBase(t)))
	defer srv.Close()

	res, err := http.Get(srv.URL + "/query?name=example.com&type=A&server=9.9.9.9&timeout=5s")
	assert.Nil(t, err)
	body, _ := io.ReadAll(res.Body)
	assert.Equal(t, http.StatusOK, res.StatusCode, string(body))
	assert.Equal(t, "application/json", res.Header.Get("Content-Type"))
	assert.Contains(t, string(body), `"replies"`)
	assert.Contains(t, string(body), `"server":"9.9.9.9:53"`)

	res, err = http.Get(srv.URL + "/query?type=A")
	assert.Nil(t, err)
	assert.Equal(t, http.StatusBadRequest, res.StatusCode)

	res, err = http.Get(srv.URL + "/query?name=example.com&server=" + silentUDP(t).LocalAddr().String() + "&timeout=1s")
	assert.Nil(t, err)
	body, _ = io.ReadAll(res.Body)
	assert.Equal(t, http.StatusBadGateway, res.StatusCode)
	assert.Contains(t, string(body), "timeout")
}

// silentUDP opens a loopback socket that never answers. An unroutable address
// does not work as a silent server: some networks answer DNS for any destination.
func silentUDP(t *testing.T) net.PacketConn {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.Nil(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// localDNS starts a loopback DNS server that answers every query with an empty reply.
func localDNS(t *testing.T) string {
	return serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(new(dns.Msg).SetReply(r))
	})
}

// loopbackDNS starts a resolver that answers every A question with 127.0.0.1
// and anything else with an empty reply.
func loopbackDNS(t *testing.T) string {
	return serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		if q := r.Question[0]; q.Qtype == dns.TypeA {
			m.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.IPv4(127, 0, 0, 1),
			}}
		}
		_ = w.WriteMsg(m)
	})
}

func serveDNS(t *testing.T, handler dns.HandlerFunc) string {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.Nil(t, err)
	srv := &dns.Server{PacketConn: conn, Handler: handler}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return conn.LocalAddr().String()
}

// keepResolver restores net.DefaultResolver, which -b replaces, when the test ends.
func keepResolver(t *testing.T) {
	resolver := net.DefaultResolver
	t.Cleanup(func() { net.DefaultResolver = resolver })
}

// daemonBase is what `q -D` parses: the flag defaults, applied once.
func daemonBase(t *testing.T) cli.Flags {
	opts := newOpts()
	_, err := configure(&opts, []string{"-D", "127.0.0.1:0"})
	assert.NoError(t, err)
	return opts
}

func daemonGet(base cli.Flags, query url.Values) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	daemonMux(base).ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/query?"+query.Encode(), nil))
	return w
}

func TestDaemonQueryOpts(t *testing.T) {
	base := daemonBase(t)
	base.Server = []string{"8.8.8.8"}
	base.DNSSEC = true
	opts, err := queryOpts(base, url.Values{"name": {"example.com"}, "type": {"TXT,MX", "NS"}, "server": {"@1.1.1.1", "9.9.9.9"}, "timeout": {"3s"}})
	assert.Nil(t, err)
	assert.Equal(t, "example.com", opts.Name)
	assert.Equal(t, []string{"TXT", "MX", "NS"}, opts.Types)
	assert.Equal(t, []string{"1.1.1.1", "9.9.9.9"}, opts.Server)
	assert.Equal(t, "json", opts.Format)
	assert.Equal(t, 3*time.Second, opts.Timeout)
	assert.True(t, opts.DNSSEC)
	assert.Equal(t, []string{"8.8.8.8"}, base.Server)

	// A request without a server or types keeps the daemon's
	opts, err = queryOpts(base, url.Values{"name": {"example.com"}})
	assert.Nil(t, err)
	assert.Equal(t, []string{"8.8.8.8"}, opts.Server)
	assert.Empty(t, opts.Types)
	assert.Equal(t, 10*time.Second, opts.Timeout)

	_, err = queryOpts(base, url.Values{"name": {"-h"}})
	assert.NotNil(t, err)

	// name falls back to the startup --qname and is required without one
	_, err = queryOpts(base, url.Values{})
	assert.NotNil(t, err)
	base.Name = "default.test"
	opts, err = queryOpts(base, url.Values{})
	assert.Nil(t, err)
	assert.Equal(t, "default.test", opts.Name)
	_, err = queryOpts(base, url.Values{"name": {"example.com"}, "timeout": {"soon"}})
	assert.NotNil(t, err)

	// A type is an RR type, never a CLI option in either boolean notation
	for _, rrType := range []string{"-V", "+recaxfr", "+not-a-type", "recaxfr=true", "bogus"} {
		_, err = queryOpts(base, url.Values{"name": {"example.com"}, "type": {rrType}})
		assert.NotNil(t, err, rrType)
	}
}

// The upstream is asked for exactly the name and type of the request, also
// when a value looks like a CLI option, an RR type or a class.
func TestDaemonQueryStaysLiteral(t *testing.T) {
	server := localDNS(t)
	for _, tc := range []struct {
		name, rrType string
		qtype        uint16
	}{
		{"example.com", "65", dns.TypeHTTPS},
		{"example.com", "TYPE65", dns.TypeHTTPS},
		{"mx", "A", dns.TypeA},
		{"ch", "A", dns.TypeA},
		{"+abcd", "A", dns.TypeA},
		{"true", "A", dns.TypeA},
	} {
		w := daemonGet(daemonBase(t), url.Values{"name": {tc.name}, "type": {tc.rrType}, "server": {server}, "timeout": {"2s"}})
		assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Contains(t, w.Body.String(), `"question":[{"name":"`+tc.name+`.","qtype":`+strconv.Itoa(int(tc.qtype))+`,"qclass":1}]`)
	}
}

// A lookup that fails is a 502, it never stops the process.
func TestDaemonDNSCryptFailure(t *testing.T) {
	// DNSCrypt stamp for 127.0.0.1:1, where nothing listens
	stamp := "sdns://AQAAAAAAAAAACzEyNy4wLjAuMToxINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzFDIuZG5zY3J5cHQtY2VydC50ZXN0"
	w := daemonGet(daemonBase(t), url.Values{"name": {"example.com"}, "type": {"A"}, "server": {stamp}, "timeout": {"1s"}})
	assert.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
}

func TestDaemonTimeoutCancelsUpstream(t *testing.T) {
	var reached, active atomic.Int32
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		reached.Add(1)
		active.Add(1)
		defer active.Add(-1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer upstream.Close()
	defer close(release)

	w := daemonGet(daemonBase(t), url.Values{"name": {"example.com"}, "type": {"A"}, "server": {upstream.URL}, "timeout": {"100ms"}})
	assert.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	assert.Eventually(t, func() bool { return reached.Load() == 1 && active.Load() == 0 }, 2*time.Second, 10*time.Millisecond,
		"upstream request is still open after the lookup timed out")
}

func TestMainTLSTimeoutClosesConnection(t *testing.T) {
	certs := httptest.NewTLSServer(nil)
	defer certs.Close()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: certs.TLS.Certificates})
	assert.Nil(t, err)
	defer listener.Close()

	// Accept the query and never answer it
	hungUp := make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
		close(hungUp)
	}()

	_, err = run("-q", "example.com", "-t", "A", "-s", "tls://"+listener.Addr().String(), "--timeout", "200ms", "--tls-insecure-skip-verify")
	assert.NotNil(t, err)
	select {
	case <-hungUp:
	case <-time.After(2 * time.Second):
		t.Error("upstream connection is still open after the lookup timed out")
	}
}

func TestDaemonDoHKeepsDefaultTransport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer upstream.Close()

	// The first request through the default transport initializes it
	res, err := http.Get(upstream.URL)
	assert.Nil(t, err)
	_ = res.Body.Close()
	before := http.DefaultTransport.(*http.Transport).TLSClientConfig

	w := daemonGet(daemonBase(t), url.Values{"name": {"example.com"}, "type": {"A"}, "server": {upstream.URL}, "timeout": {"2s"}})
	assert.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	assert.Same(t, before, http.DefaultTransport.(*http.Transport).TLSClientConfig)
}

func TestDaemonRemoveStaleSocket(t *testing.T) {
	// Not t.TempDir: its path is too long for a Unix socket on macOS
	dir, err := os.MkdirTemp("", "q")
	assert.Nil(t, err)
	defer os.RemoveAll(dir)

	file := filepath.Join(dir, "notes")
	assert.Nil(t, os.WriteFile(file, []byte("keep me"), 0600))
	assert.NotNil(t, removeStaleSocket(file))
	content, err := os.ReadFile(file)
	assert.Nil(t, err)
	assert.Equal(t, "keep me", string(content))

	live := filepath.Join(dir, "live.sock")
	listener, err := net.Listen("unix", live)
	assert.Nil(t, err)
	defer listener.Close()
	assert.NotNil(t, removeStaleSocket(live))
	assert.FileExists(t, live)

	stale := filepath.Join(dir, "stale.sock")
	left, err := net.Listen("unix", stale)
	assert.Nil(t, err)
	left.(*net.UnixListener).SetUnlinkOnClose(false)
	assert.Nil(t, left.Close())
	assert.Nil(t, removeStaleSocket(stale))
	assert.NoFileExists(t, stale)

	assert.Nil(t, removeStaleSocket(filepath.Join(dir, "missing.sock")))
}

func TestDaemonWaitsForShutdown(t *testing.T) {
	silent := silentUDP(t)
	port, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	addr := port.Addr().String()
	assert.Nil(t, port.Close())

	done := make(chan error, 1)
	go func() { done <- runDaemon(addr, daemonBase(t)) }()
	// One connection per request: Shutdown waits 5 seconds for a spare
	// connection that a client pool opened and never used.
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	assert.Eventually(t, func() bool {
		res, err := client.Get("http://" + addr + "/health")
		if err != nil {
			return false
		}
		return res.Body.Close() == nil
	}, 2*time.Second, 10*time.Millisecond)

	go func() {
		res, err := client.Get("http://" + addr + "/query?name=example.com&type=A&server=" + silent.LocalAddr().String() + "&timeout=1s")
		if err == nil {
			_ = res.Body.Close()
		}
	}()

	// The lookup is in flight once its query reaches the upstream
	assert.Nil(t, silent.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, _, err = silent.ReadFrom(make([]byte, 512))
	assert.Nil(t, err)

	start := time.Now()
	self, err := os.FindProcess(os.Getpid())
	assert.Nil(t, err)
	assert.Nil(t, self.Signal(syscall.SIGTERM))
	assert.Nil(t, <-done)
	assert.GreaterOrEqual(t, time.Since(start), 500*time.Millisecond, "runDaemon returned while a lookup was in flight")
}

func TestDaemonConcurrentQueries(t *testing.T) {
	srv := httptest.NewServer(daemonMux(daemonBase(t)))
	defer srv.Close()

	var wg sync.WaitGroup
	results := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			server := []string{"9.9.9.9", "1.1.1.1"}[i%2]
			rrType := []string{"A", "TXT", "MX", "NS"}[i%4]
			res, err := http.Get(srv.URL + "/query?name=example.com&type=" + rrType + "&server=" + server + "&timeout=5s")
			if err != nil {
				results <- err.Error()
				return
			}
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != http.StatusOK || !strings.Contains(string(body), `"server":"`+server+`:53"`) || !strings.Contains(string(body), `"qtype":`+strconv.Itoa(int(dns.StringToType[rrType]))) {
				results <- string(body)
				return
			}
			results <- ""
		}(i)
	}
	wg.Wait()
	close(results)
	for r := range results {
		assert.Equal(t, "", r)
	}
}

// -D leads the arguments; the one positional is the listen address.
func TestDaemonFlag(t *testing.T) {
	keepResolver(t)
	opts := newOpts()
	rest, err := configure(&opts, []string{"-D", "127.0.0.1:0", "-b", "127.0.0.1:5353", "+noedns"})
	assert.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, "127.0.0.1:0", opts.Daemon)
	assert.Equal(t, "127.0.0.1:5353", opts.BootstrapServer)
	assert.False(t, opts.EDNS)

	// The address binds to the flag in each of go-flags' spellings
	for _, args := range [][]string{
		{"--daemon", "/run/q.sock", "--bootstrap-server=127.0.0.1:5353"}, {"--daemon=/run/q.sock", "+noedns"}, {"-D/run/q.sock"},
	} {
		opts = newOpts()
		_, err = configure(&opts, args)
		assert.NoError(t, err, args)
		assert.Equal(t, "/run/q.sock", opts.Daemon, args)
	}

	// Anywhere else -D is an error, as are a missing address, a positional, an
	// unknown flag, and the flags that cannot serve a lookup.
	for _, args := range [][]string{
		{"-v", "-D", "127.0.0.1:0"}, {"example.com", "--daemon=127.0.0.1:0"}, {"-b", "127.0.0.1:5353", "-D", "127.0.0.1:0"}, {"A", "--daemon", "127.0.0.1:0"},
		{"-D"}, {"-D", "-b", "127.0.0.1:5353"}, {"-D", "127.0.0.1:0", "extra"}, {"-D", "127.0.0.1:0", "--no-such-flag"},
		{"-D", "127.0.0.1:0", "--recaxfr"}, {"-D", "127.0.0.1:0", "--nsid-only"}, {"-D", "127.0.0.1:0", "-N=true"}, {"-D", "127.0.0.1:0", "--subnet=bogus"},
	} {
		opts = newOpts()
		_, err = configure(&opts, args)
		assert.Error(t, err, args)
	}
}

// query gets the positionals go-flags leaves, so a short flag's value is
// neither a name nor a type, and the +[no]flag tokens are neither.
func TestConfigurePositionals(t *testing.T) {
	keepResolver(t)
	opts := newOpts()
	rest, err := configure(&opts, []string{"-b", "127.0.0.1:5353", "+noedns", "A", "example.com", "--timeout", "3s"})
	assert.NoError(t, err)
	assert.Equal(t, []string{"A", "example.com"}, rest)
	assert.Equal(t, "127.0.0.1:5353", opts.BootstrapServer)
	assert.Equal(t, 3*time.Second, opts.Timeout)
	assert.False(t, opts.EDNS)
	assert.Empty(t, opts.Daemon)
}

// A service runs on its own flags: ~/.qrc, the CLI defaults, is not read, and
// cannot turn a lookup into a service.
func TestDaemonIgnoresConfig(t *testing.T) {
	keepResolver(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	config := filepath.Join(home, ".qrc")
	assert.NoError(t, os.WriteFile(config, []byte("-b 127.0.0.1:1\n--timeout 4s\n@1.1.1.1\n"), 0o600))

	opts := newOpts()
	rest, err := configure(&opts, []string{"-D", "127.0.0.1:0", "-b", "127.0.0.1:5353"})
	assert.NoError(t, err)
	assert.Empty(t, rest)
	assert.Equal(t, "127.0.0.1:0", opts.Daemon)
	assert.Equal(t, "127.0.0.1:5353", opts.BootstrapServer)
	assert.Equal(t, 10*time.Second, opts.Timeout)

	opts = newOpts()
	rest, err = configure(&opts, []string{"example.com"})
	assert.NoError(t, err)
	assert.Empty(t, opts.Daemon)
	assert.Equal(t, 4*time.Second, opts.Timeout)
	assert.Equal(t, []string{"@1.1.1.1", "example.com"}, rest)

	assert.NoError(t, os.WriteFile(config, []byte("--daemon=127.0.0.1:0\n"), 0o600))
	opts = newOpts()
	_, err = configure(&opts, []string{"example.com"})
	assert.Error(t, err)
}

// The daemon turns a server hostname into an address through the -b resolver
// given at startup, and the lookup fails when that resolver cannot resolve it.
func TestDaemonBootstrapResolver(t *testing.T) {
	keepResolver(t)
	_, port, err := net.SplitHostPort(localDNS(t))
	assert.NoError(t, err)
	request := url.Values{"name": {"example.com"}, "type": {"A"}, "server": {"ns.test:" + port}, "timeout": {"2s"}}

	opts := newOpts()
	_, err = configure(&opts, []string{"-D", "127.0.0.1:0", "-b", loopbackDNS(t)})
	assert.NoError(t, err)
	assert.Equal(t, "127.0.0.1:0", opts.Daemon)
	w := daemonGet(opts, request)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"replies"`)

	// A refusing resolver fails the lookup at once, so no lookup worker outlives
	// the request and races the cleanup that restores net.DefaultResolver.
	refusing := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(r, dns.RcodeRefused))
	})
	opts = newOpts()
	_, err = configure(&opts, []string{"-D", "127.0.0.1:0", "-b", refusing})
	assert.NoError(t, err)
	w = daemonGet(opts, request)
	assert.Equal(t, http.StatusBadGateway, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "ns.test")
}

// driver starts the service on -D with the flags as the defaults of every
// lookup, and returns once SIGTERM has drained it.
func TestDriverServesDaemon(t *testing.T) {
	upstream := loopbackDNS(t)
	port, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	addr := port.Addr().String()
	assert.Nil(t, port.Close())

	opts := newOpts()
	done := make(chan error, 1)
	go func() { done <- driver(&opts, []string{"-D", addr, "--server", upstream}, io.Discard) }()
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	assert.Eventually(t, func() bool {
		res, err := client.Get("http://" + addr + "/health")
		if err != nil {
			return false
		}
		_ = res.Body.Close()
		return res.StatusCode == http.StatusOK
	}, 5*time.Second, 20*time.Millisecond)

	res, err := client.Get("http://" + addr + "/query?name=example.com&type=A")
	assert.Nil(t, err)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode, string(body))
	assert.Contains(t, string(body), `"server":"`+upstream+`"`)
	assert.Contains(t, string(body), `"replies"`)

	self, err := os.FindProcess(os.Getpid())
	assert.Nil(t, err)
	assert.Nil(t, self.Signal(syscall.SIGTERM))
	assert.Nil(t, <-done)
}

// The NS type asks for the referral sections however it is given.
func TestNSFlagReferral(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := serveDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg).SetReply(r)
		m.Ns = []dns.RR{&dns.NS{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
			Ns:  "ns.example.com.",
		}}
		_ = w.WriteMsg(m)
	})
	for _, args := range [][]string{{"-t", "NS", "example.com"}, {"NS", "example.com"}} {
		opts := newOpts()
		var out bytes.Buffer
		args = append(args, "--server="+server, "--format=raw")
		assert.NoError(t, driver(&opts, args, &out), args)
		assert.Contains(t, out.String(), "ns.example.com.", args)
	}
}

// A server given to -s or --server may carry the @ of the positional form.
func TestSeparatedServerPrefix(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := localDNS(t)
	for _, flag := range []string{"-s", "--server"} {
		opts := newOpts()
		args := []string{flag, "@" + server, "-t", "A", "example.com", "--timeout=1s"}
		assert.NoError(t, driver(&opts, args, io.Discard), args)
		assert.Equal(t, []string{server}, opts.Server, args)
	}
}

// A short flag's value may begin with +: it is the flag's, not a +[no]flag.
func TestLiteralPlusValues(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	server := localDNS(t)
	for _, args := range [][]string{{"-q", "+edns", "--type=A"}, {"-t", "+1", "--qname=example.com"}} {
		opts := newOpts()
		args = append(args, "--server="+server, "--format=json")
		assert.NoError(t, driver(&opts, args, io.Discard), args)
	}
}

// Short boolean names are case-sensitive: -d is DNSSEC, -S the statistics.
func TestShortBooleanCase(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	opts := newOpts()
	_, err := configure(&opts, []string{"-S=true", "-d=false", "example.com"})
	assert.NoError(t, err)
	assert.True(t, opts.ShowStats)
	assert.False(t, opts.DNSSEC)
}

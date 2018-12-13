/* crt.sh: test_websites_monitor - see Baseline Requirements section 2.2
 * Written by Rob Stradling
 * Copyright (C) 2015-2018 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type config struct {
	// Common configuration parameters shared by all processors.
	ConnInfo string
	ConnOpen int
	ConnIdle int
	ConnLife duration
	Interval duration
	Batch int
	Concurrent int
	// Processor-specific config.
	HTTPTimeout duration
}

type Work struct {
	http_client http.Client
	db *sql.DB
}

type WorkItem struct {
	certificate_id sql.NullString
	cert_name string
	der_x509 []byte
	test_website [3]string
	test_website_status [3]string
	test_website_certificate_id [3]sql.NullString
	ocsp_response [3]sql.NullString
}

const VALID int = 0
const EXPIRED int = 1
const REVOKED int = 2

// tomlConfig.DefineCustomFlags() and tomlConfig.PrintCustomFlags()
// Specify command-line flags that are specific to this processor.
func (c *config) DefineCustomFlags() {
	flag.DurationVar(&c.HTTPTimeout.Duration, "httptimeout", c.HTTPTimeout.Duration, "HTTP timeout")
}
func (c *config) PrintCustomFlags() string {
	return fmt.Sprintf("httptimeout:%s", c.HTTPTimeout.Duration)
}

// Work.Init()
// One-time initialization.
func (w *Work) Init(c *config) {
	transport := http.Transport { TLSClientConfig: &tls.Config { InsecureSkipVerify: true } }
	w.http_client = http.Client { Timeout: c.HTTPTimeout.Duration, Transport: &transport }
}

// Work.Begin()
// Per-batch initialization.
func (w *Work) Begin(db *sql.DB) {
}

// Work.End
// Per-batch post-processing.
func (w *Work) End() {
}

// Work.Exit
// One-time program exit code.
func (w *Work) Exit() {
}

// Work.Prepare()
// Prepare the driving SELECT query.
func (w *Work) SelectQuery(batch_size int) string {
	return fmt.Sprintf(`
SELECT cc.CERTIFICATE_ID, cc.CERT_NAME, c.CERTIFICATE, coalesce(cc.TEST_WEBSITE_VALID, ''), coalesce(cc.TEST_WEBSITE_EXPIRED, ''), coalesce(cc.TEST_WEBSITE_REVOKED, '')
	FROM ccadb_certificate cc, certificate c
	WHERE cc.CERT_RECORD_TYPE = 'Root Certificate'
		AND cc.CERTIFICATE_ID = c.ID
		AND NOT cc.TEST_WEBSITES_CHECKED
`)
}

// WorkItem.Parse()
// Parse one SELECTed row to configure one work item.
func (wi *WorkItem) Parse(rs *sql.Rows) error {
	return rs.Scan(&wi.certificate_id, &wi.cert_name, &wi.der_x509, &wi.test_website[VALID], &wi.test_website[EXPIRED], &wi.test_website[REVOKED])
}

// WorkItem.Perform()
// Do the work for one item.
func (wi *WorkItem) Perform(db *sql.DB, w *Work) {
	// Parse the root certificate.
	root_cert, parse_err := x509.ParseCertificate(wi.der_x509)
	roots := x509.NewCertPool()
	if parse_err == nil {
		roots.AddCert(root_cert)
	}

	intermediates := x509.NewCertPool()

	for i := 0; i < 3; i++ {
		if len(wi.test_website[i]) == 0 {
			wi.test_website_status[i] = "Not checked"
			continue
		}

		test_website_url, err := url.Parse(wi.test_website[i])
		if err != nil {
			wi.test_website_status[i] = err.Error()
			continue
		}

		req, err := http.NewRequest("GET", wi.test_website[i], nil)
		if err != nil {
			wi.test_website_status[i] = err.Error()
			continue
		}

		req.Header.Set("User-Agent", "crt.sh")
		resp, err := w.http_client.Do(req)
		if err != nil {
			switch {
				case strings.HasSuffix(err.Error(), ": connect: connection refused"): wi.test_website_status[i] = "Connection refused"
				case err.Error() == "tls: DialWithDialer timed out", strings.HasSuffix(err.Error(), ": i/o timeout"): wi.test_website_status[i] = "Timeout"
				case strings.HasSuffix(err.Error(), ": no route to host"): wi.test_website_status[i] = "No route to host"
				case strings.HasSuffix(err.Error(), ": no such host"): wi.test_website_status[i] = "No such host"
				case strings.HasSuffix(err.Error(), ": server misbehaving"): wi.test_website_status[i] = "Server misbehaving"
				case strings.HasSuffix(err.Error(), ": stopped after 10 redirects"): wi.test_website_status[i] = "Stopped after 10 redirects"
				case strings.HasSuffix(err.Error(), ": tls: internal error"): wi.test_website_status[i] = "TLS internal error"
				case strings.HasSuffix(err.Error(), ": tls: no renegotiation"): wi.test_website_status[i] = "TLS renegotiation error"
				case strings.Contains(err.Error(), "Timeout exceeded"): wi.test_website_status[i] = "Timeout"
				case strings.HasSuffix(err.Error(), ": EOF"): wi.test_website_status[i] = "HTTP: EOF"
				default: wi.test_website_status[i] = err.Error()
			}
			continue
		}
		defer resp.Body.Close()

		if resp.TLS.PeerCertificates == nil {
			wi.test_website_status[i] = "Server sent no certs"
			continue
		}

		chains_to_correct_root := false
		var issuer_cert *x509.Certificate

		for j := len(resp.TLS.PeerCertificates) - 1; j >= 0; j-- {
			if !chains_to_correct_root {
				if bytes.Equal(resp.TLS.PeerCertificates[j].Raw, wi.der_x509) {
					chains_to_correct_root = true	// This cert is root_cert.
				} else if resp.TLS.PeerCertificates[j].CheckSignatureFrom(root_cert) == nil {
					chains_to_correct_root = true	// This cert is verified by root_cert.
				}
			}

			err := db.QueryRow("SELECT import_cert($1)", resp.TLS.PeerCertificates[j].Raw).Scan(&wi.test_website_certificate_id[i])
			if err != nil {
				log.Printf("ERROR: %v", err)
			} else {
				log.Printf("%s", wi.test_website_certificate_id[i].String)
			}

			if (issuer_cert != nil) && (resp.TLS.PeerCertificates[j].CheckSignatureFrom(issuer_cert) != nil) {
				wi.test_website_status[i] = "Invalid chain"
				continue
			}
			issuer_cert = resp.TLS.PeerCertificates[j]
			intermediates.AddCert(issuer_cert)
		}

		if !chains_to_correct_root {
			wi.test_website_status[i] = "Wrong chain"
			continue
		}

		var current_time time.Time
		if i == EXPIRED {
			current_time = resp.TLS.PeerCertificates[0].NotAfter
		}
		opts := x509.VerifyOptions{
			DNSName: strings.Split(test_website_url.Host, ":")[0],
			Intermediates: intermediates,
			Roots: roots,
			CurrentTime: current_time,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		if _, err := resp.TLS.PeerCertificates[0].Verify(opts); err != nil {
			switch {
				case err.Error() == "x509: certificate has expired or is not yet valid":
					if i == EXPIRED {
						wi.test_website_status[i] = "Already invalid at expiry"
					} else {
						wi.test_website_status[i] = "Expired or not yet valid"
						for j := len(resp.TLS.PeerCertificates) - 1; j >= 0; j-- {
							if time.Now().UTC().After(resp.TLS.PeerCertificates[j].NotAfter) {
								wi.test_website_status[i] = "Expired"
								break
							} else if time.Now().UTC().Before(resp.TLS.PeerCertificates[j].NotBefore) {
								wi.test_website_status[i] = "Not yet valid"
								break
							}
						}
					}
				case err.Error() == "x509: certificate signed by unknown authority": wi.test_website_status[i] = "Invalid chain"
				case err.Error() == "x509: unhandled critical extension": wi.test_website_status[i] = "Unhandled critical extension"
				case strings.HasPrefix(err.Error(), "x509: certificate is valid for "): wi.test_website_status[i] = "Name mismatch"
				case strings.HasSuffix(err.Error(), "because it doesn't contain any IP SANs"): wi.test_website_status[i] = "No IP Address SANs"
				default: wi.test_website_status[i] = err.Error()
			}
			continue
		}

		if i == EXPIRED {
			if time.Now().UTC().Before(resp.TLS.PeerCertificates[0].NotBefore) {
				wi.test_website_status[i] = "Not yet valid"
			} else if time.Now().UTC().Before(resp.TLS.PeerCertificates[0].NotAfter) {
				wi.test_website_status[i] = "Not yet expired"
			}
		} else {
			err := db.QueryRow(
`SELECT ocsp_embedded(c.CERTIFICATE, c_issuer.CERTIFICATE)
	FROM certificate c, ca_certificate cac, certificate c_issuer
	WHERE c.ID = $1
		AND c.ISSUER_CA_ID = cac.CA_ID
		AND cac.CERTIFICATE_ID = c_issuer.ID
	LIMIT 1`, wi.test_website_certificate_id[i]).Scan(&wi.ocsp_response[i])
			if err != nil {
				log.Printf("ERROR: %v", err)
				wi.test_website_status[i] = err.Error()
				continue
			} else {
				log.Printf("%s: %s", wi.test_website_certificate_id[i].String, wi.ocsp_response[i].String)
				if ((i == VALID) && !strings.HasPrefix(wi.ocsp_response[i].String, "Good")) || ((i == REVOKED) && !strings.HasPrefix(wi.ocsp_response[i].String, "Revoked")) {
					wi.test_website_status[i] = fmt.Sprintf("OCSP: %s", strings.Split(wi.ocsp_response[i].String, "|")[0])
					switch {
						case strings.Contains(wi.test_website_status[i], "ocsp: error from server:"): wi.test_website_status[i] = strings.Replace(wi.test_website_status[i], "ocsp: error from server: ", "", 1)
						case strings.HasPrefix(wi.test_website_status[i], "OCSP: bad signature on embedded certificate:"): wi.test_website_status[i] = "OCSP: bad certificate signature"
						case strings.HasSuffix(wi.test_website_status[i], ": no such host"): wi.test_website_status[i] = "OCSP: No such host"
						case strings.HasPrefix(wi.test_website_status[i], "OCSP: OCSP"): wi.test_website_status[i] = strings.Replace(wi.test_website_status[i], "OCSP: OCSP", "OCSP:", 1)
					}
				}
			}
		}

		if resp.StatusCode != 200 {
			wi.test_website_status[i] = fmt.Sprintf("HTTP: %d", resp.StatusCode)
		} else if resp_body, err := ioutil.ReadAll(resp.Body); err != nil {
			wi.test_website_status[i] = "HTTP: Response read error"
		} else if !strings.HasPrefix(http.DetectContentType(resp_body), "text/html") {
			wi.test_website_status[i] = "Not HTML"
		} else {
			wi.test_website_status[i] = "OK"
		}
	}
}

// Work.UpdateStatement()
// Prepare the UPDATE statement to be run after processing each work item (chunk).
func (w *Work) UpdateStatement() string {
	return `
UPDATE ccadb_certificate
	SET TEST_WEBSITE_VALID_STATUS = $1,
		TEST_WEBSITE_EXPIRED_STATUS = $2,
		TEST_WEBSITE_REVOKED_STATUS = $3,
		TEST_WEBSITE_VALID_CERTIFICATE_ID = $4,
		TEST_WEBSITE_EXPIRED_CERTIFICATE_ID = $5,
		TEST_WEBSITE_REVOKED_CERTIFICATE_ID = $6,
		TEST_WEBSITES_CHECKED = 't'
	WHERE CERTIFICATE_ID = $7
`
}

// WorkItem.Update()
// Update the DB with the results of the work for this item (chunk).
func (wi *WorkItem) Update(update_statement *sql.Stmt) (sql.Result, error) {
	return update_statement.Exec(wi.test_website_status[VALID], wi.test_website_status[EXPIRED], wi.test_website_status[REVOKED], wi.test_website_certificate_id[VALID], wi.test_website_certificate_id[EXPIRED], wi.test_website_certificate_id[REVOKED], wi.certificate_id)
}

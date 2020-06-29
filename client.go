// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2020 Octabase Blockchain Labs.

// Package zamane is a client library to get signed timestamps from the timestamp server
// operated by KamuSM. It also provides extra functionality to verify timestamps and query
// the amount of credit remaining.
package zamane

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/octabase/go-rfc3161"
	"github.com/phayes/cryptoid"
)

const (
	// DefaultServerURL is the address of the timestamp server operated in
	// production by KamuSM.
	DefaultServerURL = "http://zd.kamusm.gov.tr"

	clientUA        = "go-zamane/1"
	maxResponseSize = 1 << 16
)

// it is defined in http://kamusm.bilgem.tubitak.gov.tr/depo/nesne_belirtec_listesi
var oidKamuSMZDPrincipal1 = asn1.ObjectIdentifier{2, 16, 792, 1, 2, 1, 1, 5, 7, 3, 1}

// ClientOption is implemented by Client options. They can be used to customize
// the client behavior. See functions prefixed by With... for available options.
type ClientOption func(*Client) error

// HTTPDoer is an interface for the one method of http.Client that is used by Client
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client provides an interface to access functionalities providing by the KamuSM's
// timestamp server.
type Client struct {
	customerID int
	password   string
	client     HTTPDoer
	serverURL  string
	rnd        io.Reader
}

// NewClient creates a Client instance with the credentials issued by KamuSM to be
// used for authentication. It can be customized with options e.g., to use a proxy.
func NewClient(customerID, password string, options ...ClientOption) (*Client, error) {
	opts := []ClientOption{
		WithServerURL(DefaultServerURL),
		WithHTTPClient(http.DefaultClient),
		WithRandomSource(rand.Reader),
	}

	opts = append(opts, options...)

	cID, err := strconv.ParseInt(customerID, 10, 64)
	if err != nil {
		return nil, err
	}

	c := &Client{
		customerID: int(cID),
		password:   password,
	}

	// apply options given by the user
	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// RemainingCredit returns the available amount of credit remaining for the authenticated user
// on the KamuSM's timestamp server. Note that the spend of credits is processed asynchronously
// by the server with a delay. Therefore, after spending the credits, it may be necessary to
// wait a bit to check the remaining credits.
//
// RemainingCredit also uses the system time to authenticate to the server. It means the system
// date and time must be synchronized with time servers, i.e., using NTP. KamuSM servers allow
// clock drift up to 10 minutes.
//
// Example usage:
//  client, _ := zamane.NewClient("999999", "12345678")
//  credit, _ := client.RemainingCredit(nil)
//
//  fmt.Printf("Remaining credit: %d\n", credit)
func (c *Client) RemainingCredit(ctx context.Context) (int, error) {
	reqTime := int(time.Now().UnixNano() / int64(time.Millisecond))

	authPayload := sha1.Sum([]byte(strconv.Itoa(c.customerID) + strconv.Itoa(reqTime)))

	token, err := NewAuthToken(c.rnd, c.customerID, c.password, authPayload[:])
	if err != nil {
		return 0, err
	}

	tokenDER, err := token.MarshalASN1()
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("POST", c.serverURL, nil)
	if err != nil {
		return 0, err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("identity", hex.EncodeToString(tokenDER))
	req.Header.Set("credit_req", strconv.Itoa(c.customerID))
	req.Header.Set("credit_req_time", strconv.Itoa(reqTime))

	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}

	defer resp.Body.Close()

	// don't read all the response if it exceeds maxResponseSize
	res := io.LimitReader(resp.Body, maxResponseSize)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := ioutil.ReadAll(res)
		return 0, fmt.Errorf("server error: %s: `%s`", resp.Status, string(raw))
	}

	raw, err := ioutil.ReadAll(res)
	if err != nil {
		return 0, err
	}

	// expected response is a number as a string that indicating the amount of credit remaining
	credit, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, err
	}

	return int(credit), nil
}

// RequestTimestamp makes a request to the server to get signed timestamp for the given
// hash sum and algorithm. If successful, it returns the request and its response.
//
// It is recommended that both be kept next to the digested file or data for future verifications.
// Both can be serialized in ASN.1 encoding, and revert.
//
// RequestTimestamp also verifies the response given by the timestamp server. The signature is verified
// with the certificate in the response, and that certificate is also verified by the KamuSM root certificates.
// It also considers intermediate certificates if the server provides.
//
// Warning: This function doesn't check the certificate revocation list provided by KamuSM. Note that all of the
// root certificates are defined statically in file kamusm_ca.go. It can be checked if they are identical with
// certificates provided by KamuSM site https://sertifikalar.kamusm.gov.tr
//
// Example usage:
//  algo := cryptoid.SHA512
//  digester := algo.Hash.New()
//
//  file, _ := os.Open("file-to-be-timestamped.txt")
//  io.Copy(digester, file)
//
//  client, _ := zamane.NewClient("999999", "12345678")
//
//  tsq, tsr, _ := client.RequestTimestamp(nil, digester.Sum(nil), algo)
//
//  tsqDER, _ := asn1.Marshal(*tsq)
//  tsrDER, _ := asn1.Marshal(*tsr)
//
//  ioutil.WriteFile("file-to-be-timestamped.tsq", tsqDER, 0644)
//  ioutil.WriteFile("file-to-be-timestamped.tsr", tsrDER, 0644)
func (c *Client) RequestTimestamp(ctx context.Context, sum []byte, algo cryptoid.HashAlgorithm) (tsq *rfc3161.TimeStampReq, tsr *rfc3161.TimeStampResp, err error) {
	tsq, err = newTSQ(c.rnd, sum, algo)
	if err != nil {
		return nil, nil, err
	}

	tsqDER, err := asn1.Marshal(*tsq)
	if err != nil {
		return nil, nil, err
	}

	token, err := NewAuthToken(c.rnd, c.customerID, c.password, sum)
	if err != nil {
		return nil, nil, err
	}

	tokenDER, err := token.MarshalASN1()
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", c.serverURL, bytes.NewReader(tsqDER))
	if err != nil {
		return nil, nil, err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	req.Header.Set("Content-Type", "application/timestamp-query")
	req.Header.Set("User-Agent", clientUA)
	req.Header.Set("identity", hex.EncodeToString(tokenDER))

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer resp.Body.Close()

	// don't read all the response if it exceeds maxResponseSize
	res := io.LimitReader(resp.Body, maxResponseSize)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := ioutil.ReadAll(res)
		return nil, nil, fmt.Errorf("zamane server error: %s: `%s`", resp.Status, string(raw))
	}

	raw, err := ioutil.ReadAll(res)
	if err != nil {
		return nil, nil, err
	}

	tsr = &rfc3161.TimeStampResp{}
	if rest, err := asn1.Unmarshal(raw, tsr); err != nil {
		return nil, nil, err

	} else if len(rest) > 0 {
		return nil, nil, errors.New("trailing data after timestamp-response")
	}

	if tsr.Status.Status.IsError() {
		return nil, nil, errors.New(tsr.Status.Error())
	}

	// verify with PKI
	if err = tsr.Verify(tsq, nil); err != nil {
		return nil, nil, err
	}

	return tsq, tsr, nil
}

// WithHTTPClient returns an option to be used the given HTTP client for the requests.
func WithHTTPClient(client HTTPDoer) ClientOption {
	return func(c *Client) error {
		c.client = client

		return nil
	}
}

// WithServerURL returns an option to be used the given timestamp server URL for the requests.
func WithServerURL(serverURL string) ClientOption {
	return func(c *Client) error {
		u, err := url.Parse(serverURL)
		if err != nil {
			return err
		}

		c.serverURL = u.String()

		return nil
	}
}

// WithRandomSource returns an option to be used the given random source for generating random numbers.
// It must be a cryptographically secure random source.
func WithRandomSource(rnd io.Reader) ClientOption {
	return func(c *Client) error {
		c.rnd = rnd

		return nil
	}
}

// AFAIK, only SHA-256 and SHA-512 are supported by KamuSM server.
func newTSQ(rand io.Reader, sum []byte, algo cryptoid.HashAlgorithm) (*rfc3161.TimeStampReq, error) {
	nonce := make([]byte, 160/8)
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, err
	}

	return &rfc3161.TimeStampReq{
		Version:   1,
		CertReq:   true,
		Nonce:     new(big.Int).SetBytes(nonce),
		ReqPolicy: oidKamuSMZDPrincipal1,
		MessageImprint: rfc3161.MessageImprint{
			HashAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: algo.OID,
			},
			HashedMessage: sum,
		},
	}, nil
}

// load KamuSM root certificates to verify the signature's certs and intermediates.
func init() {
	rfc3161.RootCerts = x509.NewCertPool()

	b, _ := pem.Decode([]byte(kamusmsRootCAv6))
	rootCAv6, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	rfc3161.RootCerts.AddCert(rootCAv6)

	b, _ = pem.Decode([]byte(kamusmsRootCAv5))
	rootCAv5, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	rfc3161.RootCerts.AddCert(rootCAv5)

	b, _ = pem.Decode([]byte(kamusmsRootCAv4))
	rootCAv4, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}

	rfc3161.RootCerts.AddCert(rootCAv4)
}

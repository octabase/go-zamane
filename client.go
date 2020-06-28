// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2020 Octabase Blockchain Labs.

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
	"time"

	"github.com/octabase/go-rfc3161"
	"github.com/phayes/cryptoid"
)

// ...
const (
	DefaultServerURL = "http://zd.kamusm.gov.tr"

	clientUA        = "go-zamane/1"
	maxResponseSize = 1 << 16
)

var oidKamuSMZDPrincipal1 = asn1.ObjectIdentifier{2, 16, 792, 1, 2, 1, 1, 5, 7, 3, 1}

// ClientOption ...
type ClientOption func(*Client) error

// Client ...
type Client struct {
	customerID int
	password   string
	client     *http.Client
	serverURL  string
	rnd        io.Reader
}

// NewClient ...
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

	for _, o := range opts {
		if err := o(c); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// RemainingCredit ...
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

	res := io.LimitReader(resp.Body, maxResponseSize)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := ioutil.ReadAll(res)
		return 0, fmt.Errorf("zamane server error: %s: `%s`", resp.Status, string(raw))
	}

	raw, err := ioutil.ReadAll(res)
	if err != nil {
		return 0, err
	}

	credit, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil {
		return 0, err
	}

	return int(credit), nil
}

// RequestTimestamp ...
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

	if err = tsr.Verify(tsq, nil); err != nil {
		return nil, nil, err
	}

	return tsq, tsr, nil
}

// WithHTTPClient ...
func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) error {
		c.client = client

		return nil
	}
}

// WithServerURL ...
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

// WithRandomSource ...
func WithRandomSource(rnd io.Reader) ClientOption {
	return func(c *Client) error {
		c.rnd = rnd

		return nil
	}
}

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

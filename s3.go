package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"
)

// Represents AWS credentials and config.
type Credentials struct {
	Region string
	Bucket string
	AccessKeyID string
	SecretAccessKey string
}

// Represents presigned POST information.
type PresignedPOST struct {
	Key string         `json:"key"`
	Policy string      `json:"policy"`
	Signature string   `json:"signature"`
	Action string      `json:"action"`
	Credential string  `json:"credential"`
	Date string        `json:"date"`
}

// Creates a new presigned POST.
func NewPresignedPOST(key string, c *Credentials) (*PresignedPOST, error) {
	p := NewPolicy(key, c)
	b64Policy := p.Base64()
	signature := createSignature(p.C, p.Date[:8], b64Policy)
	action := fmt.Sprintf("https://%s.s3.amazonaws.com/", p.Bucket)
	post := &PresignedPOST{
		Key: p.Key,
		Policy: b64Policy,
		Signature: signature,
		Action: action,
		Credential: p.Credential,
		Date: p.Date,
	}
	return post, nil
}

// Creates the signature for a string.
func createSignature(c *Credentials, formattedShortTime, stringToSign string) string {
	h1 := makeHmac([]byte("AWS4"+c.SecretAccessKey), []byte(formattedShortTime))
	h2 := makeHmac(h1, []byte(c.Region))
	h3 := makeHmac(h2, []byte("s3"))
	h4 := makeHmac(h3, []byte("aws4_request"))
	signature := makeHmac(h4, []byte(stringToSign))
	return hex.EncodeToString(signature)
}

// Helper to make the HMAC-SHA256.
func makeHmac(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

// Policy template.
const policyDocument = `
{ "expiration": "%s",
  "conditions": [
    {"bucket": "%s"},
    ["starts-with", "$key", "%s"],
    {"acl": "public-read"},
    ["starts-with", "$x-amz-meta-tag", ""],

    {"x-amz-credential": "%s"},
    {"x-amz-algorithm": "AWS4-HMAC-SHA256"},
    {"x-amz-date": "%s" }
  ]
}
`

const (
	expirationFormat = "2006-01-02T15:04:05.000Z"
	timeFormat = "20060102T150405Z"
	shortTimeFormat = "20060102"
)

// Represents a new policy for uploading sounds.
type policy struct {
	Expiration string
	Region string
	Bucket string
	Key string
	Credential string
	Date string
	C *Credentials
}

// Creates a new policy.
func NewPolicy(key string, c *Credentials) *policy {
	// expires in 5 minutes
	t := time.Now().Add(time.Minute * 5)
	formattedShortTime := t.UTC().Format(shortTimeFormat)
	date := t.UTC().Format(timeFormat)
	cred := fmt.Sprintf("%s/%s/%s/s3/aws4_request", c.AccessKeyID, formattedShortTime, c.Region)
	return &policy{
		Expiration: t.UTC().Format(expirationFormat),
		Region: c.Region,
		Bucket: c.Bucket,
		Key: key,
		Credential: cred,
		Date: date,
		C: c,
	}
}

// Returns the policy as a string.
func (p *policy) String() string {
	return fmt.Sprintf(policyDocument,
		p.Expiration,
		p.Bucket,
		p.Key,
		p.Credential,
		p.Date,
	)
}

// Returns the policy as a base64 encoded string.
func (p *policy) Base64() string {
	return base64.StdEncoding.EncodeToString([]byte(p.String()))
}

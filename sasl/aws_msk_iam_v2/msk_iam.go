package aws_msk_iam_v2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	signer "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/segmentio/kafka-go/sasl"
)

const (
	// These constants come from https://github.com/aws/aws-msk-iam-auth#details and
	// https://github.com/aws/aws-msk-iam-auth/blob/main/src/main/java/software/amazon/msk/auth/iam/internals/AWS4SignedPayloadGenerator.java.
	signAction       = "kafka-cluster:Connect"
	signPayload      = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // the hex encoded SHA-256 of an empty string
	signService      = "kafka-cluster"
	signVersion      = "2020_10_22"
	signActionKey    = "action"
	signHostKey      = "host"
	signUserAgentKey = "user-agent"
	signVersionKey   = "version"
	queryActionKey   = "Action"
	queryExpiryKey   = "X-Amz-Expires"
)

var signUserAgent = fmt.Sprintf("kafka-go/sasl/aws_msk_iam_v2/%s", runtime.Version())

// Mechanism implements sasl.Mechanism for the AWS_MSK_IAM mechanism, based on the official java implementation:
// https://github.com/aws/aws-msk-iam-auth
type Mechanism struct {
	// The sigv4.Signer of aws-sdk-go-v2 to use when signing the request. Required.
	Signer *signer.Signer
	// The aws.Credentials of aws-sdk-go-v2. Required.
	Credentials aws.Credentials
	// The region where the msk cluster is hosted, e.g. "us-east-1". Required.
	Region string
	// The time the request is planned for. Optional, defaults to time.Now() at time of authentication.
	SignTime time.Time
	// The duration for which the presigned request is active. Optional, defaults to 5 minutes.
	Expiry time.Duration
}

func (m *Mechanism) Name() string {
	return "AWS_MSK_IAM"
}

func (m *Mechanism) Next(ctx context.Context, challenge []byte) (bool, []byte, error) {
	// After the initial step, the authentication is complete
	// kafka will return error if it rejected the credentials, so we'll only
	// arrive here on success.
	return true, nil, nil
}

// Start produces the authentication values required for AWS_MSK_IAM. It produces the following json as a byte array,
// making use of the aws-sdk to produce the signed output.
// 	{
// 	  "version" : "2020_10_22",
// 	  "host" : "<broker host>",
// 	  "user-agent": "<user agent string from the client>",
// 	  "action": "kafka-cluster:Connect",
// 	  "x-amz-algorithm" : "<algorithm>",
// 	  "x-amz-credential" : "<clientAWSAccessKeyID>/<date in yyyyMMdd format>/<region>/kafka-cluster/aws4_request",
// 	  "x-amz-date" : "<timestamp in yyyyMMdd'T'HHmmss'Z' format>",
// 	  "x-amz-security-token" : "<clientAWSSessionToken if any>",
// 	  "x-amz-signedheaders" : "host",
// 	  "x-amz-expires" : "<expiration in seconds>",
// 	  "x-amz-signature" : "<AWS SigV4 signature computed by the client>"
// 	}
func (m *Mechanism) Start(ctx context.Context) (sess sasl.StateMachine, ir []byte, err error) {
	saslMeta := sasl.MetadataFromContext(ctx)
	if saslMeta == nil {
		return nil, nil, errors.New("missing sasl metadata")
	}

	expiry := m.Expiry
	if expiry == 0 {
		expiry = 5 * time.Minute
	}

	query := url.Values{
		queryActionKey: {signAction},
		queryExpiryKey: {strconv.Itoa(int(expiry / time.Second))},
	}

	signUrl := url.URL{
		Scheme:   "kafka",
		Host:     saslMeta.Host,
		Path:     "/",
		RawQuery: query.Encode(),
	}

	req, err := http.NewRequest("GET", signUrl.String(), nil)
	if err != nil {
		return nil, nil, err
	}

	signTime := m.SignTime
	if signTime.IsZero() {
		signTime = time.Now()
	}

	signedUrl, header, err := m.Signer.PresignHTTP(ctx, m.Credentials, req, signPayload, signService, m.Region, signTime)
	if err != nil {
		return nil, nil, err
	}

	u, err := url.Parse(signedUrl)
	if err != nil {
		return nil, nil, err
	}

	signedMap := map[string]string{
		signVersionKey:   signVersion,
		signHostKey:      u.Host,
		signUserAgentKey: signUserAgent,
		signActionKey:    signAction,
	}
	// The protocol requires lowercase keys.
	for key, vals := range header {
		signedMap[strings.ToLower(key)] = vals[0]
	}

	for key, vals := range u.Query() {
		signedMap[strings.ToLower(key)] = vals[0]
	}

	signedJson, err := json.Marshal(signedMap)
	return m, signedJson, err
}

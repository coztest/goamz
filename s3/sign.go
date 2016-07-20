package s3

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"log"
	"sort"
	"strings"

	"github.com/mitchellh/goamz/aws"
)

var b64 = base64.StdEncoding

var xamzOrder = map[string]int{
	"x-amz-acl":               5,
	"x-amz-copy-source":       6,
	"x-amz-copy-source-range": 7,
}

// this struct for sort map by value
type Pair struct {
	Key   string
	Value int
}

type PairList []Pair

func (p PairList) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p PairList) Len() int           { return len(p) }
func (p PairList) Less(i, j int) bool { return p[i].Value < p[j].Value }

// A function to turn a map into a PairList, then sort and return it.
func sortMap(m map[string]int) []string {
	arr := make([]string, 0, len(m))
	pls := make(PairList, 0, len(m))

	for k, v := range m {
		p := Pair{Key: k, Value: v}
		pls = append(pls, p)
	}
	sort.Sort(pls)
	for _, v := range pls {
		arr = append(arr, v.Key)
	}
	return arr
}

// ----------------------------------------------------------------------------
// S3 signing (http://goo.gl/G1LrK)

var s3ParamsToSign = map[string]bool{
	"acl":                          true,
	"delete":                       true,
	"location":                     true,
	"logging":                      true,
	"notification":                 true,
	"partNumber":                   true,
	"policy":                       true,
	"requestPayment":               true,
	"torrent":                      true,
	"uploadId":                     true,
	"uploads":                      true,
	"versionId":                    true,
	"versioning":                   true,
	"versions":                     true,
	"response-content-type":        true,
	"response-content-language":    true,
	"response-expires":             true,
	"response-cache-control":       true,
	"response-content-disposition": true,
	"response-content-encoding":    true,
}

func sign(auth aws.Auth, method, canonicalPath string, params, headers map[string][]string) {
	var md5, ctype, date, xamz string
	var xamzDate bool
	var sarray []string
	orderMap := make(map[string]int, len(headers))

	// add security token
	if auth.Token != "" {
		headers["x-amz-security-token"] = []string{auth.Token}
	}

	if auth.SecretKey == "" {
		// no auth secret; skip signing, e.g. for public read-only buckets.
		return
	}
	for k, v := range headers {
		k = strings.ToLower(k)
		switch k {
		case "content-md5":
			md5 = v[0]
		case "content-type":
			ctype = v[0]
		case "date":
			if !xamzDate {
				date = v[0]
			}
		default:
			if strings.HasPrefix(k, "x-amz-") {
				vall := strings.Join(v, ",")
				//				sarray = append(sarray, k+":"+vall)
				orderMap[k+":"+vall] = xamzOrder[k]
				sarray = sortMap(orderMap)
				if k == "x-amz-date" {
					xamzDate = true
					date = ""
				}
			}
		}
	}
	if len(sarray) > 0 {
		//		sort.StringSlice(sarray).Sort()
		//		sort.Sort(sort.Reverse(sort.StringSlice(sarray)))
		xamz = strings.Join(sarray, "\n") + "\n"
	}

	expires := false
	if v, ok := params["Expires"]; ok {
		// Query string request authentication alternative.
		expires = true
		date = v[0]
		params["AWSAccessKeyId"] = []string{auth.AccessKey}
	}

	sarray = sarray[0:0]
	for k, v := range params {
		if s3ParamsToSign[k] {
			for _, vi := range v {
				if vi == "" {
					sarray = append(sarray, k)
				} else {
					// "When signing you do not encode these values."
					sarray = append(sarray, k+"="+vi)
				}
			}
		}
	}
	if len(sarray) > 0 {
		sort.StringSlice(sarray).Sort()
		canonicalPath = canonicalPath + "?" + strings.Join(sarray, "&")
	}

	payload := method + "\n" + md5 + "\n" + ctype + "\n" + date + "\n" + xamz + canonicalPath
	hash := hmac.New(sha1.New, []byte(auth.SecretKey))
	hash.Write([]byte(payload))
	signature := make([]byte, b64.EncodedLen(hash.Size()))
	b64.Encode(signature, hash.Sum(nil))

	if expires {
		params["Signature"] = []string{string(signature)}
	} else {
		headers["Authorization"] = []string{"AWS " + auth.AccessKey + ":" + string(signature)}
	}

	if debug {
		log.Printf("Signature payload: %q", payload)
		log.Printf("Signature: %q", signature)
	}
}

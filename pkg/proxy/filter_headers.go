package proxy

import (
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/fagongzi/gateway/pkg/filter"
	"github.com/fagongzi/log"
	_ "github.com/go-sql-driver/mysql"
	"io"
	"strings"
)

type JwtHeader struct {
	Type string `json:"type"`
	Alg  string `json:"alg"`
}

type JwtClaims struct {
	HttpBody string `json:"httpBody"`
	Pubkey   string `json:"pubkey"`
	jwt.StandardClaims
}

// Hop-by-hop headers. These are removed when sent to the backend.
// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // canonicalized version of "TE"
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

// HeadersFilter HeadersFilter
type HeadersFilter struct {
	filter.BaseFilter
}

func newHeadersFilter() filter.Filter {
	return &HeadersFilter{}
}

// Name return name of this filter
func (f HeadersFilter) Name() string {
	return FilterHeader
}

// Pre execute before proxy
func (f HeadersFilter) Pre(c filter.Context) (statusCode int, err error) {

	//check===================================================start
	statusCode, err = validate(c)
	if statusCode != 200 {
		return statusCode, err
	}
	//check====================================================end

	for _, h := range hopHeaders {
		c.GetProxyOuterRequest().Header.Del(h)
	}

	return f.BaseFilter.Pre(c)
}

// Post execute after proxy
func (f HeadersFilter) Post(c filter.Context) (statusCode int, err error) {
	for _, h := range hopHeaders {
		c.GetProxyResponse().Header.Del(h)
	}

	// 需要合并处理的，不做header的复制，由proxy做合并
	if !c.NeedMerge() {
		c.GetOriginRequestCtx().Response.Header.Reset()
		c.GetProxyResponse().Header.CopyTo(&c.GetOriginRequestCtx().Response.Header)
	}

	return f.BaseFilter.Post(c)
}

// validity of the request data
func validate(c filter.Context) (statusCode int, err error) {

	cookie := c.GetProxyOuterRequest().Header.Cookie("Auth")
	// log.Info(string(cookie))
	signature := string(cookie)
	signatureStart := strings.LastIndexAny(signature, ".")
	signatureStart = signatureStart + 1
	log.Infof("signatureStart is: %v", signatureStart)
	signatureEnd := len(signature)
	log.Infof("signatureEnd is: %v", signatureEnd)
	signatureStr := string([]rune(signature)[signatureStart:signatureEnd])
	log.Infof("signatureStr is: %v", signatureStr)

	// gets the stream of request parameters；	request type is application/x-www-form-urlencoded
	c.GetProxyOuterRequest().Body()

	requestBodyStream := c.GetProxyOuterRequest().Body()

	requestBodyString := string(requestBodyStream[:])

	log.Infof("The requestBodyString httpBody String is: %v", requestBodyString)

	var pubkey string

	token, err := jwt.ParseWithClaims(string(cookie), &JwtClaims{},
		func(token *jwt.Token) (interface{}, error) {
			return []byte(pubkey), nil
		})

	if token.Header["alg"] != "secp256k1" {
		log.Infof("JWT alg is wrong")
		return 204, errors.New("JWT alg is wrong")
	}

	b64 := base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
	var jwtHeader JwtHeader
	jwtHeader.Alg = "secp256k1"
	jwtHeader.Type = "JWT"
	jwtHeader_byte, _ := json.Marshal(jwtHeader)
	header_string := b64.EncodeToString(jwtHeader_byte)

	playload_byte, _ := json.Marshal(token.Claims.(*JwtClaims))
	playload_string := b64.EncodeToString(playload_byte)
	jwtMsg := header_string + "." + playload_string

	log.Infof("JWT's Header + . + playload is: %v", jwtMsg)

	msg := ComputeSHA256(jwtMsg)

	log.Infof("JWT's Header + . + playload of ComputeSHA256 is: %v", msg)

	pubkey = finduserbyName(token.Claims.(*JwtClaims).Issuer)

	log.Infof("return pubkey by finduserbyName is: %v", pubkey)

	log.Infof("The requested JWT's nonce is: %v", (token.Claims.(*JwtClaims).Id))

	log.Infof("The requested JWT'httpBody is: %v", (token.Claims.(*JwtClaims).HttpBody))

	if token.Claims.(*JwtClaims).Pubkey != pubkey {
		log.Infof("User pubkey is not exist")
		return 201, errors.New("User pubkey is not exist")
	}

	log.Infof("ComputeSHA256(requestBodyString) is: %v", (ComputeSHA256(requestBodyString)))

	if token.Claims.(*JwtClaims).HttpBody != ComputeSHA256(requestBodyString) {
		log.Infof("User body has been modified")
		return 203, errors.New("User body has been modified")
	}

	log.Infof("JWT's signatureStr is: %v", signatureStr)

	signByte, _ := hex.DecodeString(signatureStr)

	msgByte, _ := hex.DecodeString(msg)

	pubkey2, err := secp256k1.RecoverPubkey(msgByte, signByte)

	log.Infof("RecoverPubkey pubkey2 is: %v", (hex.EncodeToString(pubkey2)))

	log.Infof("DB pubkey is: %v", pubkey)

	if hex.EncodeToString(pubkey2) != pubkey {
		log.Infof("secp256k1 is error or pubkey is error")
		return 205, errors.New("secp256k1 is error or pubkey is error")
	}

	return 200, errors.New("success")

}

//find pubkey by name
func finduserbyName(name string) (pubkey string) {
	db, err := sql.Open("mysql", "root:pass123word01@tcp(172.16.192.91:3308)/gateway?charset=utf8")
	pubkey = ""
	if err != nil {
		log.Info(err)
		return pubkey
	}

	defer db.Close()

	var rows *sql.Rows
	log.Info("The Method finduserbyName Request Name is", name)

	rows, err = db.Query("select id,pubkey from gateway_user where username = ?", name)
	if err != nil {
		log.Info(err)
		return pubkey
	}
	for rows.Next() {
		var id int
		rows.Scan(&id, &pubkey)
		log.Info(id, "\t", pubkey)
		if !strings.EqualFold(pubkey, "") {
			pubkey = pubkey
		}
	}

	log.Infof("pubkey in finduserbyName is: %v", pubkey)

	return pubkey
}

//对字符串进行SHA1哈希
func ComputeSHA1(data string) string {
	t := sha1.New()
	io.WriteString(t, data)
	return fmt.Sprintf("%x", t.Sum(nil))
}

//对字符串进行SHA256哈希
func ComputeSHA256(data string) string {
	hash := sha256.New()
	hash.Write([]byte(data))
	md := hash.Sum(nil)
	mdStr := hex.EncodeToString(md)
	return mdStr
}

package call

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

const (
	QUESTION_TYPE_RANGE         = 6
	FIRM_ID_RANGE               = 0
	PRIVATE_KEY_LENGTH          = 229
	DIGITAL_SIGNATURE_CONNECTOR = "@==@"
)

type requestContext struct {
	questionType     uint32 //问题类型_ 0-随机,1-逻辑推理,2-简单常识,3-简单计算,4-常见诗词,5-常见成语,6-娱乐题型……大于1000-企业定制
	firmId           uint32 //企业ID_ 与生成时数据库主键id一致
	currentTimestamp string //当前时间戳_ 接口调用时生成的时间戳
	digitalSignature string //数字签名_ 上面三个字段通过sha256生成摘要后,再通过私钥加密生成的数字签名
	privateKey       string //私钥_ 字符串类型的私钥,用于生成数字签名
}

func newRequestContext(questionType uint32, firmId uint32, privateKey string) *requestContext {
	return &requestContext{
		questionType:     questionType,
		firmId:           firmId,
		currentTimestamp: strconv.FormatInt(time.Now().UnixNano(), 10),
		privateKey:       privateKey,
	}
}

//参数校验
func (rc *requestContext) checkParams() error {

	if rc.questionType > QUESTION_TYPE_RANGE {
		return errors.New("暂无此问题类型: questionType=" + strconv.Itoa(int(rc.questionType)))
	}

	if rc.firmId > FIRM_ID_RANGE {
		return errors.New("企业ID错误: firmId=" + strconv.Itoa(int(rc.firmId)))
	}

	if len(rc.privateKey) != PRIVATE_KEY_LENGTH {
		return errors.New("私钥错误: privateKey=" + rc.privateKey)
	}

	return nil
}

//生成数字签名
func (rc *requestContext) generateDigitalSignature() error {
	//将字符串私钥转化为ECC私钥
	block, _ := pem.Decode([]byte(rc.privateKey))             //pem解码
	eccPrivateKey, err := x509.ParseECPrivateKey(block.Bytes) //x509解码
	if err != nil {
		return err
	}

	//sha256生成bytes摘要
	msg := fmt.Sprintf("%d%d%v", rc.questionType, rc.firmId, rc.currentTimestamp)
	bytes := sha256.Sum256([]byte(msg))
	//用ECC私钥加密摘要获得数字签名
	r, s, err := ecdsa.Sign(rand.Reader, eccPrivateKey, bytes[:])
	if err != nil {
		return err
	}

	rc.digitalSignature = r.String() + DIGITAL_SIGNATURE_CONNECTOR + s.String()

	return nil
}

//生成get请求的URL
func (rc *requestContext) generateGetURL(baseUrl string) (string, error) {
	params := url.Values{}
	parseURL, err := url.Parse(baseUrl)
	if err != nil {
		return "", err
	}

	params.Set("questionType", strconv.Itoa(int(rc.questionType)))
	params.Set("firmId", strconv.Itoa(int(rc.firmId)))
	params.Set("currentTimestamp", rc.currentTimestamp)
	params.Set("digitalSignature", rc.digitalSignature)
	parseURL.RawQuery = params.Encode()

	return parseURL.String(), nil
}

package call

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	//校验参数相关常量
	QUESTION_TYPE_START = 0
	QUESTION_TYPE_END   = 7
	FIRM_ID_LENGTH      = 18
	PRIVATE_KEY_LENGTH  = 229

	//自定义字符
	SUCCESS                     = 0
	DIGITAL_SIGNATURE_CONNECTOR = "@==@"

	BASE_URL = "https://cmmvplat.com:8888/output"
)

type (
	RequestPreparer interface {
		CheckParams() error
		GenerateDigitalSignature() error
		SendHttp() (*ResponseData, error)
	}

	requestVariable struct {
		questionType     int    //问题类型_ 0-随机,1-简单常识,2-简单计算,3-逻辑推理,4-科学常识,5-常见诗词成语,6-简单历史,7-娱乐题型……大于1000-企业定制
		firmID           string //企业ID
		currentTimestamp string //当前时间戳_ 接口调用时生成的时间戳
		digitalSignature string //数字签名_ 上面三个字段通过sha256生成摘要后,再通过私钥加密生成的数字签名
		privateKey       string //私钥_ 字符串类型的私钥,用于生成数字签名
	}

	//此结构体用于接收http请求返回的数据
	ResponseBody struct {
		Status int          `json:"status"` //状态码_ 0表示成功
		Msg    string       `json:"msg"`    //错误信息_ 请求未成功时msg不为空
		Data   ResponseData `json:"data"`
	}

	//此结构体作为给调用方的返回参数
	ResponseData struct {
		Question      string `json:"question"`
		Answer        string `json:"answer"`
		DisturbAnswer string `json:"disturbAnswer"`          //干扰项
		RemainTimes   int    `json:"remainTimes,default=-1"` //剩余调用次数_ -1表示无限制
	}
)

func NewRequestPrepare(questionType int, firmID string, privateKey string) RequestPreparer {
	return &requestVariable{
		questionType:     questionType,
		firmID:           firmID,
		currentTimestamp: strconv.FormatInt(time.Now().UnixNano(), 10),
		privateKey:       privateKey,
	}
}

//简单参数校验
func (rv *requestVariable) CheckParams() error {

	if rv.questionType < QUESTION_TYPE_START || rv.questionType > QUESTION_TYPE_END {
		return errors.New("暂无此问题类型: questionType=" + strconv.Itoa(rv.questionType))
	}

	if len(rv.firmID) > FIRM_ID_LENGTH {
		return errors.New("企业ID错误: firmID=" + rv.firmID)
	}

	if len(rv.privateKey) != PRIVATE_KEY_LENGTH {
		return errors.New("私钥错误: privateKey=" + rv.privateKey)
	}

	return nil
}

//生成数字签名
func (rv *requestVariable) GenerateDigitalSignature() error {

	//将字符串私钥转化为ECC私钥
	block, _ := pem.Decode([]byte(rv.privateKey))   //pem解码
	ecc, err := x509.ParseECPrivateKey(block.Bytes) //x509解码
	if err != nil {
		return err
	}

	//sha256生成bytes摘要
	msg := fmt.Sprintf("%d%v%v", rv.questionType, rv.firmID, rv.currentTimestamp)
	bytes := sha256.Sum256([]byte(msg))

	//用ECC私钥加密摘要获得数字签名
	r, s, err := ecdsa.Sign(rand.Reader, ecc, bytes[:])
	if err != nil {
		return err
	}

	rbytes, err := r.MarshalText()
	sbytes, err := s.MarshalText()
	if err != nil {
		return err
	}

	rv.digitalSignature = string(rbytes) + DIGITAL_SIGNATURE_CONNECTOR + string(sbytes)

	return nil
}

//发送http请求
func (rv *requestVariable) SendHttp() (*ResponseData, error) {

	//拼装get请求url
	params := url.Values{}
	url, err := url.Parse(BASE_URL)
	if err != nil {
		return nil, err
	}

	params.Set("questionType", strconv.Itoa(rv.questionType))
	params.Set("firmID", rv.firmID)
	params.Set("currentTimestamp", rv.currentTimestamp)
	params.Set("digitalSignature", rv.digitalSignature)
	url.RawQuery = params.Encode()

	//发送get请求
	resp, err := http.Get(url.String())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	//处理响应结果
	if resp.StatusCode/100 != 2 {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		return nil, errors.New(buf.String())
	}

	jsonData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rb ResponseBody
	if err = json.Unmarshal(jsonData, &rb); err != nil {
		return nil, err
	}

	if rb.Status != SUCCESS {
		return nil, errors.New(rb.Msg)
	}

	return &rb.Data, nil
}

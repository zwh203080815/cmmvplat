package call

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
)

const BASE_URL = "http://127.0.0.1:4523/m1/1594305-0-default/output"

type ResponseBody struct {
	Status int          `json:"status"` //0表示成功
	Msg    string       `json:"msg"`    //请求未成功时msg不为空
	Data   ResponseData `json:"data"`
}

type ResponseData struct {
	RemainTimes int    `json:"remainTimes"` //剩余调用次数：-1表示无限制
	Question    string `json:"question"`
	Answer      string `json:"answer"`
}

//此接口仅用于测试
func GetQuestion(questionType uint32, firmId uint32, privateKey string) (*ResponseData, error) {
	//生成requestContext实例
	rc := newRequestContext(questionType, firmId, privateKey)
	//入参校验
	err := rc.checkParams()
	if err != nil {
		return nil, err
	}
	//数字签名
	rc.generateDigitalSignature()
	//生成请求url
	url, err := rc.generateGetURL(BASE_URL)
	if err != nil {
		return nil, err
	}
	//发送get请求
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	//处理响应结果
	jsonData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rb ResponseBody
	if err = json.Unmarshal(jsonData, &rb); err != nil {
		return nil, err
	}

	if rb.Status != 0 {
		return nil, errors.New(rb.Msg)
	}

	return &rb.Data, nil
}

//一般密钥以文件形式保存，此接口需传入密钥文件路径
func GetQuestionByPath(questionType uint32, firmId uint32, privateKeyFilePath string) (*ResponseData, error) {
	//读取私钥文件
	privateKeyFile, err := os.Open(privateKeyFilePath)
	if err != nil {
		return nil, err
	}
	defer privateKeyFile.Close()
	privateKeyInfo, err := privateKeyFile.Stat()
	if err != nil {
		return nil, err
	}
	privateKeyBytes := make([]byte, privateKeyInfo.Size())
	privateKeyFile.Read(privateKeyBytes)

	return GetQuestion(questionType, firmId, string(privateKeyBytes))
}

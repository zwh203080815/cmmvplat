package call

import (
	"os"
)

//此接口仅用于测试
func GetQuestion(questionType int, firmID string, privateKey string) (*ResponseData, error) {

	//生成requestVariable实例
	rp := NewRequestPrepare(questionType, firmID, privateKey)

	//入参校验
	err := rp.CheckParams()
	if err != nil {
		return nil, err
	}

	//数字签名
	if err = rp.GenerateDigitalSignature(); err != nil {
		return nil, err
	}

	//发送请求
	return rp.SendHttp()
}

//此接口需传入密钥文件路径_一般密钥以pem文件形式保存
func GetQuestionByPath(questionType int, firmID string, privateKeyFilePath string) (*ResponseData, error) {

	//读取私钥文件
	file, err := os.Open(privateKeyFilePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	bytes := make([]byte, info.Size())
	file.Read(bytes)

	return GetQuestion(questionType, firmID, string(bytes))
}

package call

import (
	"os"
)

//此接口仅用于测试
func GetItem(questionType int, firmID string, privateKey string) (*ResponseData, error) {

	//生成requestVariable实例
	rp := NewRequestPrepare(questionType, firmID, privateKey)

	//入参校验
	if err := rp.CheckParams(); err != nil {
		return nil, err
	}

	//数字签名_ ECC非对称加密（优于RSA）
	if err := rp.GenerateDigitalSignature(); err != nil {
		return nil, err
	}

	//发送请求
	return rp.SendHttp()
}

//此接口需传入私钥文件路径_ 私钥编码格式为pem
func GetItemByKeyPath(questionType int, firmID string, privateKeyFile string) (*ResponseData, error) {

	//读取私钥文件
	file, err := os.Open(privateKeyFile)
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

	return GetItem(questionType, firmID, string(bytes))
}

package app

import (
	logger "ImaginaryCraftManager/log"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/quic-go/quic-go/http3"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type serverOption struct {
	addr, certName, keyName string
	certMode                string
}

func runHTTPServer(s serverOption) error {
	certFolderPath := ".\\cert"
	if _, err := os.Stat(certFolderPath); os.IsNotExist(err) {
		err = os.MkdirAll(certFolderPath, 0775)
		if err != nil {
			return err
		}
	}

	switch strings.ToLower(s.certMode) {
	case "self":
		if s.certMode != "" || s.keyName != "" {
			// 创建自签名证书
			logger.Debugln("未检测到存在的证书,尝试创建自签名证书")
			err := generateCert(certFolderPath)
			if err != nil {
				return err
			}
		}
	}

	certPath := filepath.Join(certFolderPath, s.certName)
	keyPath := filepath.Join(certFolderPath, s.keyName)

	if http3Enable {
		err := http3.ListenAndServeQUIC(s.addr, certPath, keyPath, nil)
		if err != nil {
			logger.Fatalf("Main: 开启HTTP3时遇到错误: %v", err)
			return err
		}
	}

	// 启动HTTP服务
	if tlsEnable {
		err := http.ListenAndServeTLS(s.addr, certPath, keyPath, nil)
		if err != nil {
			logger.Fatalf("Main: 开启HTTP in TLS时遇到错误: %v", err)
			return err
		}
	} else {
		err := http.ListenAndServe(s.addr, nil)
		if err != nil {
			logger.Fatalf("Main: 开启HTTP服务时遇到错误: %v", err)
			return err
		}
	}
	return nil
}

// generateCert 生成证书
func generateCert(path string) error {
	// 创建一个新的私钥
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Errorf("生成私钥失败: %v\n", err)
		return err
	}

	// 生成证书模板
	notBefore := time.Now()
	notAfter := notBefore.Add(30 * 24 * time.Hour) // 证书有效期为1个月

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		logger.Errorf("生成序列号失败: %v\n", err)
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Organization"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// 使用私钥创建自签名证书
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		logger.Errorf("生成证书失败: %v", err)
		return err
	}

	// 将证书写入文件
	certOut, err := os.Create(filepath.Join(path, "cert.pem"))
	if err != nil {
		logger.Errorf("无法创建证书文件: %v", err)
		return err
	}
	defer certOut.Close()

	if err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		logger.Errorf("写入证书失败: %v", err)
		return err
	}

	// 将私钥写入文件
	keyOut, err := os.Create(filepath.Join(path, "key.pem"))
	if err != nil {
		logger.Errorf("无法创建私钥文件: %v", err)
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		logger.Errorf("无法序列化私钥: %v", err)
		return err
	}

	if err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes}); err != nil {
		logger.Errorf("写入私钥失败: %v", err)
		return err
	}

	logger.Infoln("证书和私钥已成功生成并写入 'cert.pem' 和 'key.pem'")
	return nil
}

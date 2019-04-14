#ifndef _CERTKIT_HEADER_H
#define _CERTKIT_HEADER_H

#ifdef  __cplusplus
extern "C" {
#endif

int szitrus_signature(
	/*[IN]*/  const char* encoded,       //签名的公钥证书
	/*[IN]*/  const char* key,        //与签名证书匹配的私钥
	/*[IN]*/  const char* plaintext,  //签名数据原文
	/*[IN]*/  const char* datatype,   //签名数据原文编码格式  hex|base64|text
	/*[IN]*/  const char* type,        //签名类型  PKCS7#Detach|PKCS7#Attach|PKCS1#Nopadding|PKCS1#Padding
	/*[OUT]*/ char* pbSignedBlob, //输出以base64编码格式的签名值
	/*[OUT]*/ int* pcbSignedBlob        //输出以base64编码格式的签名值长度
);
//返回值  1代表成功 否则失败

int szitrus_verify(
	/*[IN]*/     const char* signature, //base64编码格式的签名值
	/*[IN]*/     const char* type,      //签名类型    
	/*[OUT|IN]*/ char* plaintext,  //签名数据原文  PKCS7#Attach时表示输出
	/*[OUT|IN]*/ int* plaintextlen,  //签名数据原文长度  PKCS7#Attach时表示输出
	/*[IN]*/     const char* datatype,   //签名数据原文编码格式  hex|base64|text
	/*[OUT|IN]*/     char* pbEncodedBlob,    //x.509证书内容base64编码数据   PKCS1#Nopadding|PKCS1#Padding 验签有效/
	    				 //输出cert证书信息  PKCS7#Detach|PKCS7#Attach 验签模式有效
	/*[OUT|IN]*/     int* pcbEncodedBlob    //pbEncodedBlob长度
);
/*Return Value  If the function succeeds, the return value is nonzero (1).If the function fails, the return value is zero (0). 

NOTE:
When NULL is input for pbEncodedBlob/plaintext to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbEncodedBlob/plaintext. Use this size when processing the data.
*/

//产生证书请求，使用标准密钥对,内容为标准的PKCS1

int szitrus_genCSRwithNative(
	/*[IN]*/   const char* dn,   //使用者识别名  CN='',OU='',U='',Street='',email='',
	/*[IN]*/   const char* privatekey,   //私钥数据
	/*[IN]*/   const char* publickey,    //公钥数据
	/*[OUT]*/  char* pbCSRBlob ,    //证书请求
	/*[OUT]*/ int* pcbCSRBlob        //输出以base64编码格式的证书请求长度
);
//Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).

/*NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/ 

//产生证书请求，使用加密密钥对
int szitrus_genCSR(
	/*[IN]*/   const char* key,
	/*[IN]*/   const char* dn,
	/*[OUT]*/  char* pbCSRBlob,
	/*[OUT]*/  int *pcbCSRBlob
);
//Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).

/*NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/ 

int szitrus_genKey(
	/*[IN]*/  const char* type,   //密钥对类型  RSA|ECC|SM2
	/*[IN]*/  const int size,     //密钥对长度  1024|2048|256|4096|ECC-nid(选择一种椭圆曲线)SM2已经确定椭圆曲线参数
	/*[OUT]*/ char* pbkey
);
//Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).

/*NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/ 

//产生密钥对
int szitrus_genKeyPair(
	/*[IN]*/  const char* type,   //密钥对类型  RSA|ECC|SM2
	/*[IN]*/  const int size,     //密钥对长度  1024|2048|256|4096|ECC-nid(选择一种椭圆曲线)SM2已经确定椭圆曲线参数
	/*[OUT]*/ char* pbPrivateKeyBlob,   //输出私钥文件
	/*[OUT]*/ char* pbPublicKeyBlob     //输出公钥文件
);
//Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).

/*NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/ 

//私钥转化格式接口
int szitrus_keyToPKCS8(
	const char* alg,   //需要转的密钥类型
	const char* in,   //需要转的密钥   PKCS1格式
	char* out,
	int* outlen
);
//Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).

/*NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/ 


int szitrus_genPKCS12(
	/*[IN]*/  const char* encoded,  //x.509证书内容base64编码数据
	/*[IN]*/  const char* priKey,    //x.509公钥证书的私钥文件内容
	/*[IN]*/  const char* pwd,    //pfx口令
	/*[OUT]*/ char* pbP12Blob,   //获取p12编码值
	/*[OUT]*/ int* pcbP12Blob  //获取p12编码值长度
);
//Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).

/*NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/ 
int szitrus_getLastError(
	/*[OUT]*/ 	char* error,
	/*[OUT]|[IN]*/	int *length
);
/*Return Value  If the function succeeds, the return value is nonzero (1). If the function fails, the return value is zero (0).
NOTE:
When NULL is input for pbCertBlob to determine the size needed to ensure that the returned data fits in the specified buffer, the second call to the function which populates the buffer with the desired data may not use the whole buffer. After the second call, the actual size of the data returned is contained in pbCertBlob. Use this size when processing the data.
*/


void szitrus_free();


#ifdef  __cplusplus
}
#endif

#endif //_CERTKIT_HEADER_H


<?php

if (is_file(__DIR__ . '/../autoload.php')) {
    require_once __DIR__ . '/../autoload.php';
}

use AlibabaCloud\Dkms\Gcs\OpenApi\Models\Config as AlibabaCloudDkmsGcsOpenApiConfig;
use AlibabaCloud\Dkms\Gcs\Sdk\Client as AlibabaCloudDkmsGcsSdkClient;
use AlibabaCloud\Dkms\Gcs\Sdk\Models\DecryptRequest;
use AlibabaCloud\Dkms\Gcs\Sdk\Models\DecryptResponse;
use AlibabaCloud\Dkms\Gcs\Sdk\Models\GenerateDataKeyPairRequest;
use AlibabaCloud\Dkms\Gcs\Sdk\Models\GenerateDataKeyPairResponse;
use AlibabaCloud\Tea\Utils\Utils;

// 填写您在KMS应用管理获取的ClientKey文件路径
// $clientKeyFile = '<your client key file path>';

// 或者，填写您在KMS应用管理获取的ClientKey文件内容
$clientKeyContent = '<your client key content>';

// 填写您在KMS应用管理创建ClientKey时输入的加密口令
$password = getenv('CLIENT_KEY_PASSWORD');

// 填写您的专属KMS实例服务地址
$endpoint = '<your dkms instance service address>';

// 填写您在KMS创建的对称主密钥Id
$keyId = '<your symmetric cmk id>';

// 填写您的数据密钥对的类型，示例:RSA_2048
$keyPairSpec = 'RSA_2048';

// 填写您待生成的数据密钥对格式，示例:PEM
$keyFormat = 'PEM';

// 专属KMS SDK Client对象
$client = getDkmsGcsSdkClient();
if (is_null($client)) exit(1);

// 使用专属KMS获取数据密钥示例，以数据密钥对格式PEM为例
generateDataKeyPairSignVerifySample();

/**
 * 使用kms实例生成非对称数据密钥对在本地进行签名验签示例
 * @return void
 */
function generateDataKeyPairSignVerifySample()
{
    global $client, $keyFormat, $keyId, $keyPairSpec;

    try {
        // 调用生成非对称的数据密钥对接口
        $generateDataKeyResponse = generateDataKeyPair($client, $keyFormat, $keyId, $keyPairSpec);
        // 用户可以持久化非对称数据密钥对信息
        $keyPairInfo = saveKeyPairInfo($generateDataKeyResponse, $keyFormat);

        // 解密持久化的非对称数据密钥私钥密文
        $decryptResponse = decrypt($client, $keyPairInfo->privateKeyCiphertextBlob, $keyPairInfo->keyId, $keyPairInfo->iv);
        $privateKeyPem = $decryptResponse->plaintext;

        $data = 'test data';
        // 签名
        $signature = sign($data, $privateKeyPem);
        // 验签
        $ok = verify($data, $signature, $keyPairInfo->publicKey);
        if ($ok) {
            var_dump('success!');
        } else {
            var_dump('failed!');
        }
    } catch (\Exception $error) {
        if ($error instanceof \AlibabaCloud\Tea\Exception\TeaError) {
            var_dump($error->getErrorInfo());
        }
        var_dump($error->getMessage());
        var_dump($error->getTraceAsString());
    }
}

/**
 * @param AlibabaCloudDkmsGcsSdkClient $client
 * @param string $keyFormat
 * @param string $keyId
 * @param string $keyPairSpec
 * @return GenerateDataKeyPairResponse
 */
function generateDataKeyPair($client, $keyFormat, $keyId, $keyPairSpec)
{
    $request = new GenerateDataKeyPairRequest([
        'keyFormat' => $keyFormat,
        'keyId' => $keyId,
        'keyPairSpec' => $keyPairSpec
    ]);
    return $client->generateDataKeyPair($request);
}

/**
 * @param AlibabaCloudDkmsGcsSdkClient $client
 * @param $ciphertextBlob
 * @param $keyId
 * @param $iv
 * @return DecryptResponse
 */
function decrypt($client, $ciphertextBlob, $keyId, $iv)
{
    $decryptRequest = new DecryptRequest([
        'keyId' => $keyId,
        'ciphertextBlob' => $ciphertextBlob,
        'iv' => $iv
    ]);
    return $client->decrypt($decryptRequest);
}

/**
 * @param $data
 * @param $private_key
 * @return mixed
 * @throws Exception
 */
function sign($data, $private_key)
{
    $pkey = openssl_get_privatekey(Utils::toString($private_key));
    if (!$pkey) {
        throw new Exception('private key invalid.' . "\n" . Utils::toString($private_key));
    }
    openssl_sign($data, $signature, $pkey, OPENSSL_ALGO_SHA256);
    return $signature;
}

/**
 * @param $data
 * @param $signature
 * @param $public_key
 * @return false|int
 * @throws Exception
 */
function verify($data, $signature, $public_key)
{
    $pkey = openssl_get_publickey(Utils::toString($public_key));
    if (!$pkey) {
        throw new Exception('public key invalid.' . "\n" . Utils::toString($public_key));
    }
    return openssl_verify($data, $signature, $pkey, OPENSSL_ALGO_SHA256);
}

/**
 * @param GenerateDataKeyPairResponse $resp
 * @param string $keyFormat
 * @return KeyPairInfo
 */
function saveKeyPairInfo($resp, $keyFormat)
{
    return new KeyPairInfo([
        'keyFormat' => $keyFormat,
        'keyId' => $resp->keyId,
        'keyPairSpec' => $resp->keyPairSpec,
        'privateKeyCiphertextBlob' => $resp->privateKeyCiphertextBlob,
        'publicKey' => $resp->publicKey,
        'iv' => $resp->iv,
        'algorithm' => $resp->algorithm
    ]);
}

/**
 * 构建专属KMS SDK Client对象
 * @return AlibabaCloudDkmsGcsSdkClient
 */
function getDkmsGcsSdkClient()
{
    global $clientKeyContent, $password, $endpoint;

    // 构建专属KMS SDK Client配置
    $config = new AlibabaCloudDkmsGcsOpenApiConfig();
    $config->protocol = 'https';
    $config->clientKeyContent = $clientKeyContent;
    $config->password = $password;
    $config->endpoint = $endpoint;
    // 验证服务端证书
    $config->caFilePath = 'path/to/caCert.pem';

    // 构建专属KMS SDK Client对象
    return new AlibabaCloudDkmsGcsSdkClient($config);
}

/**
 * 持久化公钥及私钥密文等密钥对信息
 */
class KeyPairInfo
{
    public function __construct($config = [])
    {
        if (!empty($config)) {
            foreach ($config as $k => $v) {
                $this->{$k} = $v;
            }
        }
    }

    /**
     * 用户主密钥
     * @var string
     */
    public $keyId;

    /**
     * 数据密钥对的私钥密文
     * @var int[]
     */
    public $privateKeyCiphertextBlob;

    /**
     * 数据密钥对的公钥明文
     * @var int[]
     */
    public $publicKey;

    /**
     * 加密数据密钥对时使用的初始向量
     * @var int[]
     */
    public $iv;

    /**
     * 生成的数据密钥对格式
     * @var string
     */
    public $keyFormat;

    /**
     * 成的数据密钥对的类型
     * @var string
     */
    public $keyPairSpec;

    /**
     * 加密算法
     * @var string
     */
    public $algorithm;
}

<?php

if (is_file(__DIR__ . '/../autoload.php')) {
    require_once __DIR__ . '/../autoload.php';
}

use AlibabaCloud\Dkms\Gcs\OpenApi\Models\Config as AlibabaCloudDkmsGcsOpenApiConfig;
use AlibabaCloud\Dkms\Gcs\OpenApi\Util\Models\RuntimeOptions;
use AlibabaCloud\Dkms\Gcs\Sdk\Client as AlibabaCloudDkmsGcsSdkClient;
use AlibabaCloud\Dkms\Gcs\Sdk\Models\AdvanceDecryptRequest;
use AlibabaCloud\Dkms\Gcs\Sdk\Models\AdvanceEncryptRequest;
use AlibabaCloud\Tea\Utils\Utils as AlibabaCloudTeaUtils;

// 填写您在KMS应用管理获取的ClientKey文件路径
$clientKeyFile = '<your client key file path>';

// 填写您在KMS应用管理创建ClientKey时输入的加密口令
$password = getenv('CLIENT_KEY_PASSWORD');

// 填写您的专属KMS实例服务地址
$endpoint = '<your dkms instance service address>';

// 填写您在KMS创建的主密钥Id
$keyId = '<your cmk id>';

// 待加密明文
$plaintext = 'encrypt and decrypt sample';

// 专属KMS SDK Client对象
$client = getDkmsGcsSdkClient();
if (is_null($client)) exit(1);

//使用加密服务实例进行高级加解密示例
advanceEncryptDecryptSample();

/**
 * 使用加密服务实例进行高级加解密示例
 * @return void
 */
function advanceEncryptDecryptSample()
{
    global $client, $keyId, $plaintext;

    $cipherCtx = advanceEncryptSample($client, $keyId, $plaintext);
    if ($cipherCtx !== null) {
        $decryptResult = AlibabaCloudTeaUtils::toString(advanceDecryptSample($client, $cipherCtx));
        if ($plaintext !== $decryptResult) {
            echo 'decrypt result not match the plaintext' . PHP_EOL;
        } else {
            echo 'advanceEncryptDecryptSample success' . PHP_EOL;
        }
    }
}

/**
 * 加密示例
 * @param AlibabaCloudDkmsGcsSdkClient $client
 * @param string $keyId
 * @param string $plaintext
 * @return AdvanceEncryptContext
 */
function advanceEncryptSample($client, $keyId, $plaintext)
{
    // 构建加密请求
    $encryptRequest = new AdvanceEncryptRequest();
    $encryptRequest->keyId = $keyId;
    $encryptRequest->plaintext = AlibabaCloudTeaUtils::toBytes($plaintext);
    $runtimeOptions = new RuntimeOptions();
    // 忽略服务端证书
    //$runtimeOptions->ignoreSSL = true;

    try {
        // 调用加密接口进行加密
        $encryptResponse = $client->advanceEncryptWithOptions($encryptRequest, $runtimeOptions);
        // 数据密文
        $cipher = $encryptResponse->ciphertextBlob;
        var_dump($encryptResponse->toMap());
        return new AdvanceEncryptContext([
            'ciphertextBlob' => $cipher
        ]);
    } catch (\Exception $error) {
        if ($error instanceof \AlibabaCloud\Tea\Exception\TeaError) {
            var_dump($error->getErrorInfo());
        }
        var_dump($error->getMessage());
        var_dump($error->getTraceAsString());
    }
    return null;
}

/**
 * 解密示例
 * @param AlibabaCloudDkmsGcsSdkClient $client
 * @param AdvanceEncryptContext $ctx
 * @return int[]|null
 */
function advanceDecryptSample($client, $ctx)
{
    // 构建解密请求对象
    $decryptRequest = new AdvanceDecryptRequest();
    $decryptRequest->ciphertextBlob = $ctx->ciphertextBlob;
    $runtimeOptions = new RuntimeOptions();
    // 忽略证书
    //$runtimeOptions->ignoreSSL = true;

    try {
        // 调用解密接口进行解密
        $decryptResponse = $client->advanceDecryptWithOptions($decryptRequest, $runtimeOptions);
        var_dump($decryptResponse->toMap());
        return $decryptResponse->plaintext;
    } catch (Exception $error) {
        if ($error instanceof \AlibabaCloud\Tea\Exception\TeaError) {
            var_dump($error->getErrorInfo());
        }
        var_dump($error->getMessage());
        var_dump($error->getTraceAsString());
    }
    return null;
}

/**
 * 构建专属KMS SDK Client对象
 * @return AlibabaCloudDkmsGcsSdkClient
 */
function getDkmsGcsSdkClient()
{
    global $clientKeyFile, $password, $endpoint;

    // 构建专属KMS SDK Client配置
    $config = new AlibabaCloudDkmsGcsOpenApiConfig();
    $config->protocol = 'https';
    $config->clientKeyFile = $clientKeyFile;
    $config->password = $password;
    $config->endpoint = $endpoint;
    // 验证服务端证书
    $config->caFilePath = 'path/to/caCert.pem';

    // 构建专属KMS SDK Client对象
    return new AlibabaCloudDkmsGcsSdkClient($config);
}

// The advance encrypt context may be stored
class AdvanceEncryptContext
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
     * @var int[]
     */
    public $ciphertextBlob;
}

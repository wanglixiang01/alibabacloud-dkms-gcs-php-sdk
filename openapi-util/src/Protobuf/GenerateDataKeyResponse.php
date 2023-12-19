<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: api.proto

namespace AlibabaCloud\Dkms\Gcs\OpenApi\Util\Protobuf;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>api.GenerateDataKeyResponse</code>
 */
class GenerateDataKeyResponse extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>string KeyId = 1;</code>
     */
    protected $KeyId = '';
    /**
     * Generated from protobuf field <code>bytes Iv = 2;</code>
     */
    protected $Iv = '';
    /**
     * Generated from protobuf field <code>bytes Plaintext = 3;</code>
     */
    protected $Plaintext = '';
    /**
     * Generated from protobuf field <code>bytes CiphertextBlob = 4;</code>
     */
    protected $CiphertextBlob = '';
    /**
     * Generated from protobuf field <code>string RequestId = 5;</code>
     */
    protected $RequestId = '';
    /**
     * Generated from protobuf field <code>string Algorithm = 6;</code>
     */
    protected $Algorithm = '';

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type string $KeyId
     *     @type string $Iv
     *     @type string $Plaintext
     *     @type string $CiphertextBlob
     *     @type string $RequestId
     *     @type string $Algorithm
     * }
     */
    public function __construct($data = NULL) {
        \AlibabaCloud\Dkms\Gcs\OpenApi\Util\Protobuf\GPBMetadata\Api::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>string KeyId = 1;</code>
     * @return string
     */
    public function getKeyId()
    {
        return $this->KeyId;
    }

    /**
     * Generated from protobuf field <code>string KeyId = 1;</code>
     * @param string $var
     * @return $this
     */
    public function setKeyId($var)
    {
        GPBUtil::checkString($var, True);
        $this->KeyId = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes Iv = 2;</code>
     * @return string
     */
    public function getIv()
    {
        return $this->Iv;
    }

    /**
     * Generated from protobuf field <code>bytes Iv = 2;</code>
     * @param string $var
     * @return $this
     */
    public function setIv($var)
    {
        GPBUtil::checkString($var, False);
        $this->Iv = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes Plaintext = 3;</code>
     * @return string
     */
    public function getPlaintext()
    {
        return $this->Plaintext;
    }

    /**
     * Generated from protobuf field <code>bytes Plaintext = 3;</code>
     * @param string $var
     * @return $this
     */
    public function setPlaintext($var)
    {
        GPBUtil::checkString($var, False);
        $this->Plaintext = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>bytes CiphertextBlob = 4;</code>
     * @return string
     */
    public function getCiphertextBlob()
    {
        return $this->CiphertextBlob;
    }

    /**
     * Generated from protobuf field <code>bytes CiphertextBlob = 4;</code>
     * @param string $var
     * @return $this
     */
    public function setCiphertextBlob($var)
    {
        GPBUtil::checkString($var, False);
        $this->CiphertextBlob = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>string RequestId = 5;</code>
     * @return string
     */
    public function getRequestId()
    {
        return $this->RequestId;
    }

    /**
     * Generated from protobuf field <code>string RequestId = 5;</code>
     * @param string $var
     * @return $this
     */
    public function setRequestId($var)
    {
        GPBUtil::checkString($var, True);
        $this->RequestId = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>string Algorithm = 6;</code>
     * @return string
     */
    public function getAlgorithm()
    {
        return $this->Algorithm;
    }

    /**
     * Generated from protobuf field <code>string Algorithm = 6;</code>
     * @param string $var
     * @return $this
     */
    public function setAlgorithm($var)
    {
        GPBUtil::checkString($var, True);
        $this->Algorithm = $var;

        return $this;
    }

}


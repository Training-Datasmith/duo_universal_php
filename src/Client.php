<?php

declare (strict_types=1);
/**
 * This contains the Client class for the Universal flow
 *
 * This SDK allows a web developer to quickly add Duo's interactive,
 * self-service, two-factor authentication to any Python web login form.
 *
 * PHP version 7
 *
 * @category Duo
 * @package  DuoUniversal
 * @author   Duo Security <support@duosecurity.com>
 * @license  https://opensource.org/licenses/BSD-3-Clause
 * @link     https://duo.com/docs/duoweb-v4
 * @file
 */
namespace Duo\Duo_Universal;

use Firebase\JWT\Before_Valid_Exception;
use Firebase\JWT\Expired_Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\Signature_Invalid_Exception;
use UnexpectedValueException;
/**
 * This class contains the client for the Universal flow.
 */
class Client
{
    public const MAX_STATE_LENGTH = 1024;
    public const MIN_STATE_LENGTH = 22;
    public const JTI_LENGTH = 36;
    public const DEFAULT_STATE_LENGTH = 36;
    public const CLIENT_ID_LENGTH = 20;
    public const CLIENT_SECRET_LENGTH = 40;
    public const HS512_MIN_KEY_LENGTH = 64;
    public const JWT_EXPIRATION = 300;
    public const JWT_LEEWAY = 60;
    public const SUCCESS_STATUS_CODE = 200;
    public const USER_AGENT = 'duo_universal_php/1.1.2';
    public const SIG_ALGORITHM = 'HS512';
    public const GRANT_TYPE = 'authorization_code';
    public const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
    public const HEALTH_CHECK_ENDPOINT = '/oauth/v1/health_check';
    public const TOKEN_ENDPOINT = '/oauth/v1/token';
    public const AUTHORIZE_ENDPOINT = '/oauth/v1/authorize';
    public const USERNAME_ERROR = 'The username is invalid.';
    public const NONCE_ERROR = 'The nonce is invalid.';
    public const JWT_DECODE_ERROR = 'Error decoding JWT';
    public const INVALID_CLIENT_ID_ERROR = 'The Client ID is invalid';
    public const INVALID_CLIENT_SECRET_ERROR = 'The Client Secret is invalid';
    public const DUO_STATE_ERROR = 'State must be at least ' . self::MIN_STATE_LENGTH . ' characters long and no longer than ' . self::MAX_STATE_LENGTH . ' characters';
    public const FAILED_CONNECTION = 'Unable to connect to Duo';
    public const MALFORMED_RESPONSE = 'Result missing expected data.';
    public const DUO_CERTS = __DIR__ . '/ca_certs.pem';
    /**
     * @var string
     */
    public $client_id;
    /**
     * @var string
     */
    public $api_host;
    /**
     * @var string|null
     */
    public $http_proxy;
    /**
     * @var string
     */
    public $redirect_url;
    /**
     * @var bool
     */
    public $use_duo_code_attribute;
    private string $client_secret;
    private $user_agent_extension;
    /**
     * Retrieves exception message for DuoException from HTTPS result message.
     *
     * @param array $result The result from the HTTPS request
     *
     * @return string The exception message taken from the message or MALFORMED_RESPONSE
     */
    private function get_exception_from_result(array $result): string
    {
        if (isset($result['message']) && isset($result['message_detail'])) {
            return $result['message'] . ': ' . $result['message_detail'];
        }
        if (isset($result['error']) && isset($result['error_description'])) {
            return $result['error'] . ': ' . $result['error_description'];
        }
        return self::MALFORMED_RESPONSE;
    }
    /**
     * Make HTTPS calls to Duo.
     *
     * @param string      $endpoint   The endpoint we are trying to hit
     * @param array       $request    Information to send to Duo
     * @param string|null $user_agent (Optional) A user-agent string
     *
     * @return array of strings
     * @throws DuoException For failure to connect to Duo
     */
    protected function make_https_call(string $endpoint, array $request, ?string $user_agent = null): array
    {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://' . $this->api_host . $endpoint);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $request);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_CAINFO, self::DUO_CERTS);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        if ($user_agent !== null) {
            curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
        }
        if (!is_null($this->http_proxy)) {
            curl_setopt($ch, CURLOPT_PROXYTYPE, CURLPROXY_HTTP);
            curl_setopt($ch, CURLOPT_PROXY, $this->http_proxy);
        }
        $result = curl_exec($ch);
        /* Throw an error if the result doesn't exist or if our request returned a 5XX status */
        if (!$result) {
            throw new Duo_Exception(self::FAILED_CONNECTION);
        }
        if (self::SUCCESS_STATUS_CODE !== curl_getinfo($ch, CURLINFO_HTTP_CODE)) {
            throw new Duo_Exception($this->get_exception_from_result(json_decode($result, true)));
        }
        return json_decode($result, true);
    }
    /**
     * Pads the client secret to meet minimum key length requirements for HS512.
     * HMAC-SHA512 in php-jwt v7+ requires 64-byte keys. Padding with null bytes
     * doesn't affect HMAC output because HMAC internally pads to block size.
     *
     * @return string The padded client secret
     */
    private function get_padded_secret(): string
    {
        return str_pad($this->client_secret, self::HS512_MIN_KEY_LENGTH, "\x00");
    }
    private function create_jwt_payload(string $audience): string
    {
        $date = new \DateTime();
        $current_date = $date->get_timestamp();
        $payload = ['iss' => $this->client_id, 'sub' => $this->client_id, 'aud' => $audience, 'jti' => $this->generate_random_string(self::JTI_LENGTH), 'iat' => $current_date, 'exp' => $current_date + self::JWT_EXPIRATION];
        return JWT::encode($payload, $this->get_padded_secret(), self::SIG_ALGORITHM);
    }
    /**
     * Generates a random hex string.
     *
     * @param int $state_length The length of the hex string
     *
     * @return string A hexadecimal string
     * @throws DuoException    For lengths that are shorter than MIN_STATE_LENGTH or longer than MAX_STATE_LENGTH
     */
    private function generate_random_string(int $state_length): string
    {
        if ($state_length > self::MAX_STATE_LENGTH || $state_length < self::MIN_STATE_LENGTH) {
            throw new Duo_Exception(self::DUO_STATE_ERROR);
        }
        $ALPHANUMERICS = array_merge(range('A', 'Z'), range('a', 'z'), range(0, 9));
        $state = '';
        for ($i = 0; $i < $state_length; ++$i) {
            $state = $state . $ALPHANUMERICS[random_int(0, count($ALPHANUMERICS) - 1)];
        }
        return $state;
    }
    /**
     * Constructor for Client class.
     *
     * @param string $client_id               The Client ID found in the admin panel
     * @param string $client_secret           The Client Secret found in the admin panel
     * @param string $api_host                The api-host found in the admin panel
     * @param string $redirect_url            The URL to redirect back to after the prompt
     * @param bool   $use_duo_code_attribute  (Optional: default true) Flag to use `duo_code` instead of `code` for returned authorization parameter
     * @param string|null $http_proxy         (Optional) HTTP proxy to tunnel requests through
     *
     * @throws DuoException For invalid Client ID or Client Secret
     */
    public function __construct(string $client_id, string $client_secret, string $api_host, string $redirect_url, bool $use_duo_code_attribute = true, ?string $http_proxy = null)
    {
        if (strlen($client_id) !== self::CLIENT_ID_LENGTH) {
            throw new Duo_Exception(self::INVALID_CLIENT_ID_ERROR);
        }
        if (strlen($client_secret) !== self::CLIENT_SECRET_LENGTH) {
            throw new Duo_Exception(self::INVALID_CLIENT_SECRET_ERROR);
        }
        $this->client_id = $client_id;
        $this->client_secret = $client_secret;
        $this->api_host = $api_host;
        $this->redirect_url = $redirect_url;
        $this->use_duo_code_attribute = $use_duo_code_attribute;
        $this->http_proxy = $http_proxy;
        $this->user_agent_extension = null;
    }
    /**
     * Append custom information to the user agent string.
     *
     * @param string $user_agent_extension Custom user agent information
     */
    public function append_to_user_agent(string $user_agent_extension): void
    {
        $this->user_agent_extension = trim($user_agent_extension);
    }
    /**
     * Build the complete user agent string.
     *
     * @return string The complete user agent string
     */
    private function build_user_agent(): string
    {
        $base_user_agent = self::USER_AGENT . ' php/' . phpversion() . ' ' . php_uname();
        if (!empty($this->user_agent_extension)) {
            return $base_user_agent . ' ' . $this->user_agent_extension;
        }
        return $base_user_agent;
    }
    /**
     * Generate a random hex string with a length of DEFAULT_STATE_LENGTH.
     */
    public function generate_state(): string
    {
        return $this->generate_random_string(self::DEFAULT_STATE_LENGTH);
    }
    /**
     * Makes a call to HEALTH_CHECK_ENDPOINT to see if Duo is available.
     *
     * @return array The result of the health check
     * @throws DuoException For failure to connect to Duo or failed health check
     */
    public function health_check(): array
    {
        $audience = 'https://' . $this->api_host . self::HEALTH_CHECK_ENDPOINT;
        $jwt = $this->create_jwt_payload($audience);
        $request = ['client_id' => $this->client_id, 'client_assertion' => $jwt];
        $result = $this->make_https_call(self::HEALTH_CHECK_ENDPOINT, $request);
        if (!isset($result['stat']) || $result['stat'] !== 'OK') {
            throw new Duo_Exception($this->get_exception_from_result($result));
        }
        return $result;
    }
    /**
     * Generate URI to redirect to for the Duo prompt.
     *
     * @param string $username The username of the user trying to auth
     * @param string $state    Randomly generated character string of at least 22
     *                         chars returned to the integration by Duo after 2FA
     *
     * @return string The URI used to redirect to the Duo prompt
     * @throws DuoException For invalid inputs
     */
    public function create_auth_url(string $username, string $state): string
    {
        if (strlen($state) < self::MIN_STATE_LENGTH || strlen($state) > self::MAX_STATE_LENGTH) {
            throw new Duo_Exception(self::DUO_STATE_ERROR);
        }
        $date = new \DateTime();
        $current_date = $date->get_timestamp();
        $payload = ['scope' => 'openid', 'redirect_uri' => $this->redirect_url, 'client_id' => $this->client_id, 'iss' => $this->client_id, 'aud' => 'https://' . $this->api_host, 'exp' => $current_date + self::JWT_EXPIRATION, 'state' => $state, 'response_type' => 'code', 'duo_uname' => $username, 'use_duo_code_attribute' => $this->use_duo_code_attribute];
        $jwt = JWT::encode($payload, $this->get_padded_secret(), self::SIG_ALGORITHM);
        $all_args = ['response_type' => 'code', 'client_id' => $this->client_id, 'scope' => 'openid', 'redirect_uri' => $this->redirect_url, 'request' => $jwt];
        $arguments = http_build_query($all_args);
        return 'https://' . $this->api_host . self::AUTHORIZE_ENDPOINT . '?' . $arguments;
    }
    /**
     * Exchange a code returned by Duo for a token that contains information about the authorization.
     *
     * @param string $duoCode  The code returned by Duo as a URL parameter after a successful authentication
     * @param string $username The username of the user trying to authenticate with Duo
     * @param string|null $nonce (Optional) Random 36B string used to associate a session with an ID token
     *
     * @return array of strings that contains information about the authentication
     *
     * @throws DuoException For malformed response from Duo, problems decoding the JWT,
     *                      the wrong username, and the wrong nonce
     */
    public function exchange_authorization_code_for2fa_result(string $duo_code, string $username, ?string $nonce = null): array
    {
        $token_endpoint = 'https://' . $this->api_host . self::TOKEN_ENDPOINT;
        $useragent = $this->build_user_agent();
        $jwt = $this->create_jwt_payload($token_endpoint);
        $request = ['grant_type' => self::GRANT_TYPE, 'code' => $duo_code, 'redirect_uri' => $this->redirect_url, 'client_id' => $this->client_id, 'client_assertion_type' => self::CLIENT_ASSERTION_TYPE, 'client_assertion' => $jwt];
        $result = $this->make_https_call(self::TOKEN_ENDPOINT, $request, $useragent);
        /* Verify that we are receiving the expected response from Duo */
        $required_keys = ['id_token', 'access_token', 'expires_in', 'token_type'];
        foreach ($required_keys as $key) {
            if (!isset($result[$key])) {
                throw new Duo_Exception(self::MALFORMED_RESPONSE);
            }
        }
        if ($result['token_type'] !== 'Bearer') {
            throw new Duo_Exception(self::MALFORMED_RESPONSE);
        }
        try {
            JWT::$leeway = self::JWT_LEEWAY;
            $jwt_key = new Key($this->get_padded_secret(), self::SIG_ALGORITHM);
            $token_obj = JWT::decode($result['id_token'], @$jwt_key);
            /* JWT::decode returns a PHP object, this will turn the object into a multidimensional array */
            $token = json_decode(json_encode($token_obj), true);
        } catch (Signature_Invalid_Exception|Before_Valid_Exception|Expired_Exception|UnexpectedValueException $e) {
            throw new Duo_Exception(self::JWT_DECODE_ERROR);
        }
        $required_token_key = ['exp', 'iat', 'iss', 'aud'];
        foreach ($required_token_key as $key) {
            if (!isset($token[$key])) {
                throw new Duo_Exception(self::MALFORMED_RESPONSE);
            }
        }
        /* Verify we have all expected fields in our token */
        if ($token['iss'] !== $token_endpoint || $token['aud'] !== $this->client_id) {
            throw new Duo_Exception(self::MALFORMED_RESPONSE);
        }
        if (!isset($token['preferred_username']) || $token['preferred_username'] !== $username) {
            throw new Duo_Exception(self::USERNAME_ERROR);
        }
        if (is_string($nonce) && (!isset($token['nonce']) || $token['nonce'] !== $nonce)) {
            throw new Duo_Exception(self::NONCE_ERROR);
        }
        return $token;
    }
}
<?php
/**
 * Created by Jak Gibb
 * Date: 20/07/2018
 * Time: 18:05
 *
 * Class to initiate a connection to IBM ISIM via REST API
 * Steps to authenticate:
 * 1. Perform a GET request to https://isimserver:port/itim/restlogin/login.jsp to obtain a JSESSIONID
 * 2. Perform a POST request to https://isimserver:port/itim/j_security_check passing ISIM credentials via j_username & j_password
 * 3. Perform a GET request to https://isimserver:port/itim/rest/systemusers/me which pulls details of the current logged in user along
 *    with the required CSRF token needed to perform PUT/POST/DELETE requests
 *
 * Class ISIMAuth
 */
namespace ISIM\Connection;

use Httpful\Mime;
use Httpful\Request;
use ISIM\Exception\AuthenticationFailedException;
use ISIM\Exception\InvalidConfigurationException;
use Exception;

/**
 * Class ISIMAuth
 */
class ISIMAuth {
    /**
     * @var
     */
    private $baseURI;

    /**
     * @var
     */
    private $jsiPath;

    /**
     * @var
     */
    private $restBase;

    /**
     * @var
     */
    private $authPath;

    /**
     * @var
     */
    private $csrfPath;

    /**
     * @var array
     */
    private $token = [];

    /**
     * @var
     */
    private $username;

    /**
     * @var
     */
    private $password;

    /**
     * @var
     */
    private $serverURI;

    /**
     * ISIMAuth constructor.
     * Extracts and validates the authentication and URI details from the passed in config array.
     * @param array $config  Config containing authentication and URL details
     * @throws InvalidConfigurationException
     */
    public function __construct(array $config) {

        foreach ($config as $key => $value) {
            $this->$key = $value;
        }

        try {
            $this->validateConfig();
        } catch (Exception $e) {
            throw new InvalidConfigurationException($e->getMessage());
        }
    }

    /**
     * Check the obtained values from the configuration file are valid
     * @throws InvalidConfigurationException
     */
    private function validateConfig() {
        if (filter_var($this->baseURI, FILTER_VALIDATE_URL) === FALSE || (filter_var($this->restBase, FILTER_VALIDATE_URL) === FALSE))
            throw new InvalidConfigurationException("Invalid base address in configuration file");
        if (is_null($this->username) || is_null($this->password))
            throw new InvalidConfigurationException("Credentials not set in configuration file");
        if (is_null($this->jsiPath) || is_null($this->authPath) || is_null($this->csrfPath))
            throw new InvalidConfigurationException("Path not set in configuration file");
    }


    public function connect(){
        if(!$this->checkSessionValid()) {
            $this->retrieveJSessionCookie();
            $this->retrieveLTPA2Cookie();
            $this->retrieveCSRFToken();
        }
    }

    /**
     * Executes a GET request to https://isimserver:port/itim/restlogin/login.jsp
     * to obtain the JSESSIONID cookie
     * @throws AuthenticationFailedException
     * @throws \Httpful\Exception\ConnectionErrorException
     */
    private function retrieveJSessionCookie() {
        try {
            $jsessionResponse = Request::get($this->baseURI . $this->jsiPath)
                ->send();
        } catch (Exception $e) {
            throw new AuthenticationFailedException("HTTP request failed to obtain JSession cookie");
        }
        $this->verifyJSession($jsessionResponse->headers['Set-Cookie']);
        $this->token['jsession'] = $jsessionResponse->headers['Set-Cookie'];
    }

    /**
     * Executes a form POST request to https://isimserver:port/itim/j_security_check
     * with the ISIM username/password in the body which returns the LTPA2 cookie
     * @throws AuthenticationFailedException
     * @throws \Httpful\Exception\ConnectionErrorException
     */
    private function retrieveLTPA2Cookie() {
        try {
            $ltpa2Response = Request::post($this->baseURI . $this->authPath)
                ->body([
                    'j_username' => $this->username,
                    'j_password' => $this->password
                ],
                    Mime::FORM)
                ->send();
        } catch (Exception $e) {
            throw new AuthenticationFailedException("HTTP request failed to retrieve LTPA2 cookie");
        }
        $this->verifyLTPA2($ltpa2Response->headers['Set-Cookie']);
        $this->token['ltpa2'] = $ltpa2Response->headers['Set-Cookie'];
    }

    /**
     * Executes a GET post to https://isimserver:port/itim/rest/systemusers/me
     * passing the JSESSIONID and LTPA2 cookies in the header
     * to obtain the CSRF token request for PUT/DELETE/POST requests
     * @throws AuthenticationFailedException
     * @throws \Httpful\Exception\ConnectionErrorException
     */
    private function retrieveCSRFToken() {
        try {
            $csrfResponse = Request::get($this->baseURI . $this->csrfPath)
                ->addHeader('Cookie', $this->token['ltpa2'] . ";" . $this->token['jsession'])
                ->send();
        } catch (Exception $e) {
            throw new AuthenticationFailedException("HTTP request failed to retrieve CSRF token");
        }
        $this->verifyCSRF($csrfResponse->headers['CSRFToken']);
        $this->token['csrf'] = $csrfResponse->headers['CSRFToken'];
    }

    /**
     * Check if the returned cookie contains a JSESSIONID
     *
     * @param $token
     *
     * @throws AuthenticationFailedException
     */
    private function verifyJSession($token) {
        if (strpos($token, 'JSESSION') === 0) {
            return;
        }
        throw new AuthenticationFailedException("Invalid JSession Token Received");
    }

    /**
     * Check if the returned cookie contains a LTPA2 token
     *
     * @param $token
     *
     * @throws AuthenticationFailedException
     */
    private function verifyLTPA2($token) {
        if (strpos($token, 'LtpaToken2') === 0) {
            return;
        }
        throw new AuthenticationFailedException("Invalid LTPA2 Token Received - Check credentials");
    }

    /**
     * Check if the returned CSRF is valid (should be 32 characters)
     *
     * @param $token
     *
     * @throws AuthenticationFailedException
     */
    private function verifyCSRF($token) {
        if (strlen($token) != 32) {
            throw new AuthenticationFailedException("Invalid CSRF Token Received");
        }
    }

    /**
     * Checks if any previous connection attempt is still valid by executing a GET request to systemusers/me.
     * The CSRF token will change upon initiating the check, so it is required to be re-set in the token array.
     * @return bool
     * @throws AuthenticationFailedException
     * @throws \Httpful\Exception\ConnectionErrorException
     */
    public function checkSessionValid(){
        if(!empty($this->token['csrf']) && !empty($this->token['ltpa2']) && !empty($this->token['jsession'])){
            try {
                $response = Request::get($this->baseURI . $this->csrfPath)
                    ->addHeader('Cookie', $this->token['ltpa2'] . ";" . $this->token['jsession'])
                    ->send();
                if($response->code == "200"){
                    $this->token['csrf'] = $response->headers['CSRFToken'];
                    return TRUE;
                }
            } catch (Exception $e) {
                throw new AuthenticationFailedException("HTTP request failed to retrieve CSRF token");
            }
        }else{
            return FALSE;
        }
    }

    /**
     * @return mixed
     */
    public function getBaseURI() {
        return $this->baseURI;
    }

    /**
     * @return mixed
     */
    public function getRestBase() {
        return $this->restBase;
    }

    /**
     * @return array
     */
    public function getToken() {
        return $this->token;
    }

    public function getServerURI(){
        return $this->serverURI;
    }
}
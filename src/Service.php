<?php
namespace Opine\User;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Opine\User\Model as UserModel;
use Opine\Interfaces\Container;

class Service {
    private $root;
    private $containerService;
    private $model;
    private $jwt;
    private $activities;
    private $tokenSession;
    private $qualifications = [];

    public function __construct (string $root, Container $containerService, UserModel $model, Array $jwt, Array $activities)
    {
        $this->root = $root;
        $this->containerService = $containerService;
        $this->model = $model;
        $this->jwt = $jwt;
        $this->activities = $activities;
    }

    public function decodeJWT (string $token) : Array
    {
        $jwt = new Parser();
        $signer = new Sha256();
        $token = $jwt->parse($token);
        if (!$token->verify($signer, $this->jwt['signature'])) {
            return [];
        }
        $token->getHeaders();
        $token->getClaims();

        return [
            'id'    => $token->getClaim('id'),
            'email' => $token->getClaim('email'),
            'roles' => $token->getClaim('roles')
        ];
    }

    public function encodeJWT (int $id, string $email, array $roles) : string
    {
        $jwt = new Builder();
        $signer = new Sha256();

        return (string)$jwt->
            setIssuer($this->jwt['issuedBy'])->
            setAudience($this->jwt['canOnlyBeUsedBy'])->
            setId($this->jwt['identifiedBy'], true)->
            setIssuedAt(time())->
            setNotBefore(time())->
            setExpiration(time() + $this->jwt['expiresAt'])->
            set('id', $id)->
            set('email', $email)->
            set('roles', $roles)->
            sign($signer, $this->jwt['signature'])->
            getToken();
    }

    public function getRoles ($userId) : array
    {
        return $this->model->getRoles($userId);
    }

    public function getUser ($userId) : array
    {
        return $this->model->getUser($userId);
    }

    public function checkActivity (string $activity) {
        $authorized = false;
        $redirect = '/';
        if (isset($this->activities['redirects'][$activity])) {
            $redirect = $this->activities['redirects'][$activity];
        }
        if (empty($this->tokenSession)) {
            return ['authorized' => false, 'redirect' => $redirect, 'cause' => 'not logged in'];
        }
        if (!isset($this->activities['activities'][$activity])) {
            return ['authorized' => false, 'redirect' => $redirect, 'cause' => 'unknown activity'];
        }
        $activityRoles = $this->activities['activities'][$activity];
        $userRoles = $this->tokenSession['roles'];

        // always authorize super admin
        if (in_array('SUPER_ADMIN', $userRoles)) {
            $authorized = true;
        }

        // loop through all activity roles and qualifiers
        foreach ($activityRoles as $activityRole => $qualifiers) {
            if (!in_array($activityRole, $userRoles)) {
                continue;
            }
            if (empty($qualifiers)) {
                $authorized = true;
                continue;
            }
            foreach ($qualifiers as $qualifier) {
                list($service, $action) = explode('@', $qualifier, 2);
                $service = $this->containerService->get($service);
                $qualifierResult = call_user_func_array([$service, $action], $this->tokenSession);
                if ($qualifierResult['authorized'] === true) {
                    $authorized = true;
                    if (!isset($qualifierResult['payload']) || empty($qualifierResult['payload'])) {
                        continue;
                    }
                    $this->qualifications = array_merge($this->qualifications, $qualifierResult['payload']);
                }
            }
        }
        return ['authorized' => $authorized, 'redirect' => $redirect, 'qualifications' => $this->qualifications];
    }

    public function login (string $email, string $password) {
        return $this->model->login($email, $password, $this->jwt['signature']);
    }

    public function addUser (string $firstName, string $lastName, string $email, string $password) {
        return $this->model->addUser($firstName, $lastName, $email, $password);
    }

    public function setTokenSession ($tokenSession) {
        $this->tokenSession = $tokenSession;
    }

    public function getTokenSession () {
        return $this->tokenSession;
    }

    public function getQualifications () {
        return $this->qualifications;
    }
}

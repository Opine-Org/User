<?php
namespace Opine\User;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Opine\User\Model as UserModel;
use Opine\Interfaces\Container;
use Exception;

class Service {
    private $root;
    private $containerService;
    private $model;
    private $jwt;
    private $activities;
    private $tokenSession = [];
    private $userQualifications = [];

    public function __construct (string $root, Container $containerService, UserModel $model, array $jwt, array $activities)
    {
        $this->root = $root;
        $this->containerService = $containerService;
        $this->model = $model;
        $this->jwt = $jwt;
        $this->activities = $activities;
    }

    public function decodeJWT (string $token) : array
    {
        $jwt = new Parser();
        $signer = new Sha256();
        try {
            $token = $jwt->parse($token);
        } catch (Exception $e) {
            return [];
        }
        if (!$token->verify($signer, $this->jwt['signature'])) {
            return [];
        }
        $token->getHeaders();
        $token->getClaims();

        // convert to array
        $session = json_decode(json_encode($token->getClaim('session')), true);

        return $session;
    }

    public function encodeJWT (array $session) : string
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
            set('session', $session)->
            sign($signer, $this->jwt['signature'])->
            getToken();
    }

    public function getRoles () : array
    {
        return $this->model->getRoles();
    }

    public function getUserRoles (int $userId) : array
    {
        return $this->model->getUserRoles($userId);
    }

    public function getUser (int $userId) : array
    {
        return $this->model->getUser($userId);
    }

    public function getUserByEmail (string $email) : array
    {
        return $this->model->getUser($userId);
    }

    public function checkActivity (string $activity) : array
    {
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
        if (is_object($this->tokenSession['roles'])) {
            $userRoles = array_values(get_object_vars($this->tokenSession['roles']));
        } else {
            $userRoles = array_values($this->tokenSession['roles']);
        }

        // always authorize super admin
        if (in_array('SUPER_ADMIN', $userRoles)) {
            $authorized = true;
        }

        // loop through all activity roles and qualifiers
        foreach ($activityRoles as $activityRole) {

            // some roles are just a string, others container an array of qualifiers
            if (!is_array($activityRole)) {
                $qualifiers = [];
            } else {
                foreach ($activityRole as $key => $value) {
                    $activityRole = $key;
                    $qualifiers = $value;
                    break;
                }
            }

            // see if the user's role is one of the activity roles
            if (!in_array($activityRole, $userRoles)) {
                continue;
            }

            // if there are not qualifiers, the user must be authorized
            if (empty($qualifiers)) {
                $authorized = true;
                continue;
            }

            // if there are qualifiers, each one needs to be checked
            // the user will gain access if ANY qualifier matches
            foreach ($qualifiers as $qualifier) {
                list($service, $action) = explode('@', $qualifier, 2);
                $service = $this->containerService->get($service);
                $qualifierResult = call_user_func_array([$service, $action], $this->tokenSession);
                if ($qualifierResult['authorized'] === true) {
                    $authorized = true;
                    if (!isset($qualifierResult['payload']) || empty($qualifierResult['payload'])) {
                        continue;
                    }
                    $this->userQualifications = array_merge($this->userQualifications, $qualifierResult['payload']);
                }
            }
        }
        return ['authorized' => $authorized, 'redirect' => $redirect, 'qualifications' => $this->userQualifications];
    }

    public function login (string $email, string $password) : array {
        return $this->model->login($email, $password);
    }

    public function addUser (string $firstName, string $lastName, string $email, string $password) : int
    {
        return $this->model->addUser($firstName, $lastName, $email, $password);
    }

    public function setTokenSession (array $tokenSession)
    {
        $this->tokenSession = $tokenSession;
    }

    public function getTokenSession () : array
    {
        return $this->tokenSession;
    }

    public function getQualifications () : array
    {
        return $this->userQualifications;
    }
}

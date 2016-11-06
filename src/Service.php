<?php
namespace Opine\User;
use Lcobucci\JWT\Configuration;
use Opine\User\Model as UserModel;

class Service {
    private $root;
    private $model;
    private $jwt;
    private $activities;

    public function __construct (string $root, UserModel $model, Array $jwt, Array $activities)
    {
        $this->root = $root;
        $this->model = $model;
        $this->jwt = $jwt;
        $this->activities = $activities;
    }

    public function decodeJWT (string $token) : Array
    {
        $config = new Configuration();
        $token = $config->getParser()->parse((string) $token);
        if (!$token->verify($signer, $this->jwt['signature'])) {
            return false;
        }
        $token->getHeaders();
        $token->getClaims();

        return [
            'id'    => $token->getClaim('id'),
            'email' => $token->getClaim('email'),
            'roles' => $token->getClaim('roles')
        ];
    }

    public function encodeJWT ($id, string $email, array $roles) : string
    {
        $jwt = new Configuration();
        $signer = $config->getSigner();

        $token = $jwt->createBuilder()->
            issuedBy($this->jwt['issuedBy'])->
            canOnlyBeUsedBy($this->jwt['canOnlyBeUsedBy'])->
            identifiedBy($this->jwt['identifiedBy'], true)->
            issuedAt(time())->
            canOnlyBeUsedAfter(time())->
            expiresAt(time() + $this->jwt['expiresAt'])->
            with('id', $id)->
            with('email', $email)->
            with('roles', $roles)->
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

    public function checkActivity () {

    }
}

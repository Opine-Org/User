<?php
namespace Opine\User;
use Lcobucci\JWT\Configuration;
use Model;

class Service {
    private $root;
    private $configService;

    public function __construct ($root, $configService)
    {
        $this->root = $root;
        $this->configService = $configService;
    }

    public function decodeJWT (string $token) : Array
    {
        $config = new Configuration();
        $token = $config->getParser()->parse((string) $token);
        $token->getHeaders(); // Retrieves the token header
        $token->getClaims();

        return [
            'id'    => $token->getClaim('id'),
            'email' => $token->getClaim('email'),
            'roles' => $token->getClaim('roles')
        ];
    }

    public function encodeJWT ($id, string $email, array $roles) : string
    {
        $config = new Configuration();

        $token = $config->createBuilder()->
            issuedBy('http://example.com')->
            canOnlyBeUsedBy('http://example.org')->
            identifiedBy('4f1g23a12aa', true)->
            issuedAt(time())->canOnlyBeUsedAfter(time() + 60)->
            expiresAt(time() + 3600)->
            with('id', $id)->
            with('email', $email)->
            with('roles', $roles)->
            getToken();

        return (string)$token;
    }

    public function getRoles ($userId) : array
    {
        $roles = Model::getRoles($userId);
    }

    public function checkActivity (string $activity, array $userRoles, array $activityRoles) {

    }
}

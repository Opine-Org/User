<?php
namespace Opine\User;
use PDO;

class Model {
    private $root;
    private $db;

    public function __construct (string $root, PDO $db)
    {
        $this->root = $root;
        $this->db = $db;
    }

    public function getRoles (integer $userId) : Array
    {
        $result = $this->db->prepare('
            SELECT
                id,
                name
            FROM
                authorization_roles
            WHERE
                user_id = :userId
        ');
        $result->execute(['userId' => $userId]);
        return $result->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getUser (integer $userId)
    {
        $result = $this->db->prepare('
            SELECT
                id,
                email,
                first_name,
                last_name
            FROM
                users
            WHERE
                user_id = :userId
        ');
        $result->execute(['userId' => $userId]);
        return $result->fetch(PDO::FETCH_ASSOC);
    }

    public function checkUser (string $email) : bool
    {

    }

    public function addUser (array $values) : integer
    {
        $result = $this->db->prepare(


        );
    }

    public function login (string $email, string $password, string $salt) : bool
    {

    }
}

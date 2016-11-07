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

    private function checkUser (string $email) : bool
    {
        $email = trim(strtolower($email));
        $result = $this->db->prepare('
            SELECT
                count(*) AS count
            FROM
                users
            WHERE
                email = :email
        ');
        $result->execute(['email' => $email]);
        $count = $result->fetch(PDO::FETCH_ASSOC)['count'];
        if ($count == 0) {
            return true;
        }
        return false;
    }

    public function addUser ($firstName, $lastName, $email, $password)
    {
        if (!$this->checkUser($email)) {
            return false;
        };
        $email = trim(strtolower($email));
        $statement = $this->db->prepare('
            INSERT INTO users
            (first_name, last_name, email, password)
            VALUES
            (:firstName, :lastName, :email, :password)
        ');
        $result = $statement->execute([
            'firstName' => $firstName,
            'lastName' => $lastName,
            'email' => $email,
            'password' => $password
        ]);
        var_dump($result);
        exit();
    }

    public function login (string $email, string $password, string $salt) : bool
    {

    }
}

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

    public function getRoles () : Array
    {
        $result = $this->db->prepare('
            SELECT
                id,
                name
            FROM
                authorization_roles
            ORDER BY
                name
        ');
        $result->execute();
        return $result->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getUserRoles (int $userId) : Array
    {
        $result = $this->db->prepare('
            SELECT
                R.id,
                R.name
            FROM
                authorization_roles R,
                authorization_user_roles U
            WHERE
                U.role_id = R.id AND
                U.user_id = :userId
        ');
        $result->execute(['userId' => $userId]);
        $records = $result->fetchAll(PDO::FETCH_ASSOC);
        if (empty($records)) {
            return [];
        }
        $output = [];
        foreach ($records as $record) {
            $output[$record['id']] = $record['name'];
        }
        return $output;
    }

    public function getUser (int $userId)
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

    public function addUser (string $firstName, string $lastName, string $email, string $password) : int
    {
        if (!$this->checkUser($email)) {
            return 0;
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
            'password' => password_hash($password, PASSWORD_DEFAULT)
        ]);
        $userId = $this->db->lastInsertId('users_id_seq');
        $this->makeSuperAdmin($userId);
        return $userId;
    }

    private function makeSuperAdmin ($userId) : bool
    {
        // if this is the first user to register, make them a SUPER_ADMIN
        // see if there were any entries before this one
        $result = $this->db->prepare('
            SELECT id FROM users WHERE id < :id LIMIT 1
        ');
        $result->execute([
            'id' => $userId
        ]);

        // if any records are found, then return
        $record = $result->fetch(PDO::FETCH_ASSOC);
        if (!empty($record)) {
            return false;
        }

        // get the super admin role id
        $result = $this->db->prepare('
            SELECT id FROM authorization_roles WHERE name = \'SUPER_ADMIN\'
        ');
        $result->execute();
        $record = $result->fetch(PDO::FETCH_ASSOC);

        // if the role does not already exist, create it
        if (empty($record)) {
            $result = $this->db->prepare('
                INSERT INTO authorization_roles (name) VALUES (\'SUPER_ADMIN\')
            ');
            $result->execute();
            $roleId = $this->db->lastInsertId('authorization_roles_id_seq');
        } else {
            $roleId = $record['id'];
        }

        // insert the SUPER_ADMIN role for this user
        $result = $this->db->prepare('
            INSERT INTO authorization_user_roles (user_id, role_id) VALUES (:userId, :roleId)
        ');
        $result->execute([
            'userId' => $userId,
            'roleId' => $roleId
        ]);

        return true;
    }

    public function login (string $email, string $password) : array
    {
        $email = trim(strtolower($email));
        $query = $this->db->prepare('
            SELECT
                id,
                first_name,
                last_name,
                email,
                password
            FROM
                users
            WHERE
                email = :email
        ');
        $query->execute([
            'email' => $email
        ]);
        $record = $query->fetch(PDO::FETCH_ASSOC);
        if (empty($record)) {
            return [];
        }
        if (password_verify($password, $record['password'])) {
            unset($record['password']);
            return $record;
        }
        return [];
    }
}

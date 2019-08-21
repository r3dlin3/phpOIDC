<?php
/**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

require_once('doctrine2_bootstrap.php');

require_once('PasswordHash.php');


function db_check_credential($username, $password) : bool {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $em = $qb->getEntityManager();
    $account = db_get_account($username);

    if($account && $account) {

        if(strstr($account->getCryptedPassword(), ':') !== false) {
            return validate_password($password, $account->getCryptedPassword());
        } else { // check and migrate sha1 password to pbkdf2
            if(sha1($password) == $account->getCryptedPassword()) {
                $account->setCryptedPassword(create_hash($password));
                $em->flush();
                return true;
            }
        }
    }
    return false;
}


function db_check_credential_array($username, $password) : bool {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $em = $qb->getEntityManager();
    $account = db_get_account($username);

    if($account && $account) {

        if(strstr($account['crypted_password'], ':') !== false) {
            return validate_password($password, $account['crypted_password']);
        } else { // check and migrate sha1 password to pbkdf2
            if(sha1($password) == $account['crypted_password']) {
                $account['crypted_password'] = create_hash($password);
                $em->flush();
                return true;
            }
        }
    }
    return false;
}

function db_get_user($username) : ?Account {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('a')
        ->from('Account', 'a')
        ->where('a.login = :login')
        ->setParameter('login', $username);
    $result = $qb->getQuery()->getResult();
    return ($result && count($result)) ? $result[0] : null;
}


/////////////////////////////////////////////////////////////////

//    function db_get_user_objects($username, $object, $sort_field) {
//
//        $q = Doctrine_Query::create()
//                ->select('o.*')
//                ->from("$object o")
//                ->innerJoin('o.Account a')
//                ->where('a.login = ?', array($username))
//                ->orderBy("o.{$sort_field} ASC");
//    //    printf("%s\n", $q->getSqlQuery());
//        return $q->execute();
//    }


//    function db_get_user_object($username, $object, $object_field, $object_value) {
//
//        $q = Doctrine_Query::create()
//                ->select('o.*')
//                ->from("$object o")
//                ->innerJoin('o.Account a')
//                ->where("a.login = ? and o.{$object_field} = ?", array($username, $object_value));
//    //    printf("%s\n", $q->getSqlQuery());
//        $res = $q->execute();
//        return ($res && $res->count() == 1) ? $res->getFirst() : false;
//    }

//    function db_delete_user_object($username, $object, $object_field, $object_value) {
//        $q = Doctrine_Query::create()
//                ->select('o.*')
//                ->from("$object o")
//                ->innerJoin('o.Account a')
//                ->where("a.login = ? and o.{$object_field} = ?", array($username, $object_value));
//    //    printf("%s\n", $q->getSqlQuery());
//        $res = $q->execute();
//        if($res && $res->count() == 1)
//            $res[0]->delete();
//        return true;
//    }


//    function db_save_user_object($username, $object, $object_field, $object_value, $object_values) {
//        if(!is_array($object_values) || !$object_field || !$object_value)
//            return false;
//        $q = Doctrine_Query::create()
//                ->select('o.*')
//                ->from("$object o")
//                ->innerJoin('o.Account a')
//                ->where("a.login = ? and o.{$object_field} = ?", array($username, $object_value));
//        $res = $q->execute();
//        $object =  ($res && $res->count() == 1) ? $res[0] : new $object();
//        if(!$object->exists()) {
//            // Set Account
//            $user = db_get_user($username);
//            if($user)
//                $object['account_id'] = $user['id'];
//            else
//                return false;
//            $object[$object_field] = $object_value;
//        }
//        $object->merge($object_values);
//        $object->save();
//        return true;
//    }



////////////////////////////////////////////////////////
function db_find_token($token) : ?Token {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('t')
        ->from('Token', 't')
        ->where('t.token = :token')
        ->setParameter('token', $token);
    $result = $qb->getQuery()->getResult();
    return ($result && count($result)) ? $result[0] : null;

}

function db_find_token_type($token, $token_type) : ?Token {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('t')
        ->from('Token', 't')
        ->where('t.token = :token and t.token_type = :token_type')
        ->setParameters(new \Doctrine\Common\Collections\ArrayCollection(array(
            new \Doctrine\ORM\Query\Parameter('token', $token),
            new \Doctrine\ORM\Query\Parameter('token_type', $token_type)
        )));
    $result = $qb->getQuery()->getResult();
    if($result && count($result))
        return $result[0];
    else
        return null;
}


function db_find_auth_code($token) : ?Token {
    return db_find_token_type($token, 0);
}

function db_find_access_token($token) : ?Token {
    return db_find_token_type($token, 1);
}

function db_find_refresh_token($token) : ?Token  {
    return db_find_token_type($token, 2);
}


function db_save_token($token, $token_type, $user, $client, $issued, $expiration, $data=NULL, $details=NULL) : void {
    if(is_array($data));
        unset($data['name']);
    $account = db_get_user($user);
    if($account) {
        $dbToken = new Token();
        $dbToken->setToken($token);
        $dbToken->setTokenType($token_type);
        $dbToken->setClient($client);
        $dbToken->setIssuedAt($issued);
        $dbToken->setExpirationAt($expiration);
        $dbToken->setDetails($details);
        $dbToken->setInfo(json_encode($data));
        $account->addToken($dbToken);
        $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
        $em = $qb->getEntityManager();
        $em->persist($dbToken);
        $em->flush();
    }
}

function db_get_user_tokens($username) : ?\Doctrine\Common\Collections\Collection {
    $user = db_get_user($username);
    if($user) {
        return $user->getTokens();
    } else
        return null;
}

function db_get_user_token($username, $token) {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('t')
        ->from('Token', 't')
        ->innerJoin('t.account', 'a')
        ->where('a.login = :login and t.token = :token')
        ->setParameters(new \Doctrine\Common\Collections\ArrayCollection(array(
            new \Doctrine\ORM\Query\Parameter('token', $token),
            new \Doctrine\ORM\Query\Parameter('login', $username)
        )));
    $result = $qb->getQuery()->getResult();
    if($result && count($result))
        return $result[0];
    else
        return null;
}

function db_delete_user_token($username, $token_name) : void {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $token = db_get_user_token($username, $token_name);
    if($token) {
        $qb->getEntityManager()->remove($token);
        $qb->getEntityManager()->flush();
    }
}

function db_save_user_token($username, $token_name, $token_fields) : bool {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $em = $qb->getEntityManager();
    $user = db_get_user($username);
    if($user) {
        $token = db_get_user_token($username, $token_name);
        if(!$token) {
            $token = new Token();
            $token->setToken($token_name);
            $user->addToken($token);
            $em->persist($token);
        }
        foreach ($token_fields as $key => $val) {
            $token[$key] = $val;
        }
        $token->setToken($token_name);
        $em->flush();
        return true;
    }
    return false;
}


////////////////////////////////////////////////////////////////////////////
function db_get_user_trusted_clients($username) : ?\Doctrine\Common\Collections\Collection
{
    $user = db_get_user($username);
    if($user) {
        return $user->getTrustedClients();
    } else
        return null;
}

function db_get_user_trusted_client($username, $client_id) : ?Client {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('c')
        ->from('Client', 'c')
        ->innerJoin('c.accounts', 'a')
        ->where('a.login = :login and c.client_id = :client_id')
        ->setParameters(new \Doctrine\Common\Collections\ArrayCollection(array(
            new \Doctrine\ORM\Query\Parameter('client_id', $client_id),
            new \Doctrine\ORM\Query\Parameter('login', $username)
        )));
    $result = $qb->getQuery()->getResult();
    if($result && count($result))
        return $result[0];
    else
        return null;
}


function db_delete_user_trusted_client($username, $client) : void {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $trusted_client = db_get_user_trusted_client($username, $client);
    if($trusted_client) {
        $qb->getEntityManager()->remove($trusted_client);
        $qb->getEntityManager()->flush();
    }
}

function db_save_user_trusted_client($username, $client_id) : void {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $trusted_client = db_get_user_trusted_client($username, $client_id);
    if(!$trusted_client) {
        $account = db_get_user($username);
        $client = db_get_client($client_id);
        if($account && $client) {
            $account->addTrustedClient($client);
            $qb->getEntityManager()->flush();
        }
    }
}

/////////////////////////////////////////////////////////////////

function db_get_accounts() : array {
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('a')
//        ->from('Account', 'a')
//        ->orderBy('a.login', 'ASC');
//    $result = $qb->getQuery()->getResult();
//    return $result;

    return db_get_objects('Account', 'login');
}

function db_get_account($username) : ?Account {
    return db_get_user($username);
}


function db_save_account($username, $account_values) {
    if(!is_array($account_values) || !$username)
        return false;
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $em = $qb->getEntityManager();
    $account = db_get_account($username);
    if($account) {
        foreach ($account_values as $key => $val) {
            $account[$key] = $val;
        }
        $account->setLogin($username);
        $em->flush();
        return true;
    }
    return false;
}


///////////////////////////////////////////////////



function db_get_objects($object, $sort_field) : array {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('o')
        ->from($object, 'o')
        ->orderBy("o.{$sort_field}", 'ASC');
    return $qb->getQuery()->getResult();
}

function db_get_object($object, $object_field, $object_value) {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('o')
        ->from($object, 'o')
        ->where("o.{$object_field} = :value")
        ->setParameter('value',  $object_value);
    $result = $qb->getQuery()->getResult();
    return ($result && count($result)) ? $result[0] : null;
}


function db_delete_object($object, $object_field, $object_value) : bool {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $em = $qb->getEntityManager();

    $qb->select('o')
        ->from($object, 'o')
        ->where("o.{$object_field} = :value")
        ->setParameter('value',  $object_value);
    $result = $qb->getQuery()->getResult();
    if($result && count($result) == 1) {
        $em->remove($result[0]);
        $em->flush();
        return true;
    }
    return false;
}


function db_save_object( $object, $object_field, $object_value, $object_values) {
    if(!is_array($object_values) || !$object_field || !$object_value)
        return false;

    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $em = $qb->getEntityManager();
    $qb->select('o')
        ->from($object, 'o')
        ->where("o.{$object_field} = :value")
        ->setParameter('value',  $object_value);
    $result = $qb->getQuery()->getResult();

    $dbObject = null;
    if($result && count($result) == 1) {
        $dbObject = $result[0];
    } else {
        $dbObject = new $object();
        $em->persist($dbObject);
    }
    foreach ($object_values as $key => $value) {
        $dbObject[$key] = $value;
    }
    $dbObject[$object_field] = $object_value;
    $em->flush();
    return true;
}





function db_get_providers() : array
{
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('p')
//        ->from('Provider', 'p')
//        ->orderBy('p.name', 'ASC');
//    return $qb->getQuery()->getResult();
    return db_get_objects('Provider', 'name');
}


function db_get_provider($name) : ?Provider {
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('p')
//        ->from('Provider', 'p')
//        ->where('p.name = :name')
//        ->setParameter('name', $name);
//    $result = $qb->getQuery()->getResult();
//    return ($result && count($result)) ? $result[0] : null;
    return db_get_object('Provider', 'name', $name);
}

function db_get_provider_by_url($url) : ?Provider {
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('p')
//        ->from('Provider', 'p')
//        ->where('p.url = :url')
//        ->setParameter('url', $url);
//    $result = $qb->getQuery()->getResult();
//    return ($result && count($result)) ? $result[0] : null;
    return db_get_object('Provider', 'url', $url);
}


function db_get_provider_by_issuer($issuer) : ?Provider {
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('p')
//        ->from('Provider', 'p')
//        ->where('p.issuer = :issuer')
//        ->setParameter('issuer', $issuer);
//    $result = $qb->getQuery()->getResult();
//    return ($result && count($result)) ? $result[0] : null;
    return db_get_object('Provider', 'issuer', $issuer);
}

function db_get_provider_by_key_id($key_id) : ?Provider {
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('p')
//        ->from('Provider', 'p')
//        ->where('p.key_id = :key_id')
//        ->setParameter('key_id', $key_id);
//    $result = $qb->getQuery()->getResult();
//    return ($result && count($result)) ? $result[0] : null;
    return db_get_object('Provider', 'key_id', $key_id);
}


function db_delete_provider($name) : bool {
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $provider = db_get_provider($name);
//    if($provider) {
//        $qb->getEntityManager()->remove($provider);
//        $qb->getEntityManager()->flush();
//    }
    return db_delete_object('Provider', 'name', $name);
}


function db_save_provider($name, $provider_values) : bool {
//    if(!is_array($provider_values) || !$name)
//        return false;
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $em = $qb->getEntityManager();
//    $qb->select('p')
//        ->from('Provider', 'p')
//        ->where('p.name = :name')
//        ->setParameter('name', $name);
//    $result = $qb->getQuery()->getResult();
//    $provider = null;
//    if($result && count($result)) {
//        $provider = $result[0];
//    } else {
//        $provider = new Provider();
//        $provider->setName($name);
//        $em->persist($provider);
//    }
//    foreach ($provider_values as $key => $val) {
//        $provider[$key] = $val;
//    }
//    $provider->setName($name);
//    $em->flush();
//    return true;

    return db_save_object('Provider', 'name', $name, $provider_values);
}


function db_get_clients() : array {
    $object = 'Client';
    $object_field = 'client_id';
    return db_get_objects($object, $object_field);
}


function db_get_client($client) : ?Client{
//    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
//    $qb->select('c')
//        ->from('Client', 'c')
//        ->where('c.client_id = :client_id')
//        ->setParameter('client_id', $client);
//    $result = $qb->getQuery()->getResult();
//    return ($result && count($result)) ? $result[0] : null;
    $object = 'Client';
    $object_field = 'client_id';
    $object_value = $client;
    return db_get_object($object, $object_field, $object_value);

}

function db_get_client_by_registration_token($registration_token) : ?Client{

    $object = 'Client';
    $object_field = 'registration_access_token';
    $object_value = $registration_token;
    return db_get_object($object, $object_field, $object_value);
}

function db_get_client_by_registration_uri_path($registration_client_uri_path) : ?Client{

    $object = 'Client';
    $object_field = 'registration_client_uri_path';
    $object_value = $registration_client_uri_path;
    return db_get_object($object, $object_field, $object_value);
}


function db_save_client($name, $client_values) : bool {
    $object = 'Client';
    $object_field = 'client_id';
    $object_value = $name;
    $object_values = $client_values;
    return db_save_object($object, $object_field, $object_value, $object_values);
}


function db_delete_client($name) : bool {
    return db_delete_object('Client', 'client_id', $name);
}

function db_check_client_credential($client_id, $client_secret) : bool {
    $qb = DbEntity::getInstance()->getEntityManager()->createQueryBuilder();
    $qb->select('o')
        ->from('Client', 'o')
        ->where("o.client_id = :client_id and o.client_secret = :client_secret")
        ->setParameters(new \Doctrine\Common\Collections\ArrayCollection(array(
            new \Doctrine\ORM\Query\Parameter('client_id', $client_id),
            new \Doctrine\ORM\Query\Parameter('client_secret', $client_secret)
        )));
    $result = $qb->getQuery()->getResult();
    return ($result && count($result) == 1) ? true : false;
}


function db_get_request_file($fileid) : ?RequestFile {
    $object = 'RequestFile';
    $object_field = 'fileid';
    $object_value = $fileid;
    return db_get_object($object, $object_field, $object_value);
}

function db_save_request_file($fileid, $request_file_values) : bool {
    $object = 'RequestFile';
    $object_field = 'fileid';
    $object_value = $fileid;
    $object_values = $request_file_values;
    return db_save_object($object, $object_field, $object_value, $object_values);
}


function db_delete_entity($entity) : void {
    if($entity) {
        $em = DbEntity::getInstance()->getEntityManager();
        $em->remove($entity);
        $em->flush();
    }
}
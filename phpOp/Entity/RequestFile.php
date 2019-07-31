<?php
require_once "BaseEntity.php";

use Doctrine\ORM\Mapping as ORM;


/**
 * @ORM\Entity
 * @ORM\Table(name="request_file", uniqueConstraints={@ORM\UniqueConstraint(name="index_request_files_on_fileid", columns={"fileid"})})
 * */
Class RequestFile extends BaseEntity implements JsonSerializable, ArrayAccess
{
    /** @ORM\Id
     *  @ORM\Column(type="integer")
     *  @ORM\GeneratedValue
     **/
    private $id;

    /** @ORM\Column(type="string",length=255) **/
    private $fileid;

    /** @ORM\Column(type="text") **/
    private $request;

    /** @ORM\Column(type="boolean") **/
    private $type;

    /** @ORM\Column(type="text") **/
    private $jwt;

    private static $tableFields = array(
        'id',
        'fileid',
        'request',
        'type',
        'jwt'
    );

    public function offsetExists($offset)
    {
        return in_array($offset, self::$tableFields);
    }

    public function offsetSet($offset, $value)
    {
        $method = $this->getSetterName(self::$tableFields, $offset);
        if($method)
            $this->{$method}($value);
    }

    public function offsetGet($offset)
    {
        $method = $this->getGetterName(self::$tableFields, $offset);
        if($method)
            return $this->{$method}();
        else
            return null;
    }

    public function offsetUnset($offset)
    {
    }


    /**
     * @return mixed
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return mixed
     */
    public function getFileid()
    {
        return $this->fileid;
    }

    /**
     * @param mixed $fileid
     */
    public function setFileid($fileid)
    {
        $this->fileid = $fileid;
    }

    /**
     * @return mixed
     */
    public function getRequest()
    {
        return $this->request;
    }

    /**
     * @param mixed $request
     */
    public function setRequest($request)
    {
        $this->request = $request;
    }

    /**
     * @return mixed
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @param mixed $type
     */
    public function setType($type)
    {
        $this->type = $type;
    }

    /**
     * @return mixed
     */
    public function getJwt()
    {
        return $this->jwt;
    }

    /**
     * @param mixed $jwt
     */
    public function setJwt($jwt)
    {
        $this->jwt = $jwt;
    }

    public function jsonSerialize()
    {
        $json = array();
        $vars1 = get_object_vars($this);
        foreach ($vars1 as $key => $value) {
            if(!($value instanceof Doctrine\ORM\PersistentCollection) && !($value instanceof BaseEntity)) {
                $json[$key] = $value;

            }
        }

        return $json;
    }


}
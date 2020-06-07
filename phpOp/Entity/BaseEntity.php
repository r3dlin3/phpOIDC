<?php


use Doctrine\ORM\Mapping as ORM;

/**
 * @ORM\HasLifecycleCallbacks
 */
abstract class BaseEntity
{
    private function getCamelCaseName($name) {
        return implode('', array_map(function($arg) {return ucfirst($arg);}, explode('_', $name)));
    }

    protected function  getSetterName($validNames, $offset ) : ?string {
        if(in_array($offset, $validNames)) {
            $method = 'set' . $this->getCamelCaseName($offset);
            return $method;
        } else
            return null;
    }

    protected function  getGetterName($validNames, $offset) : ?string {
        if(in_array($offset, $validNames)) {
            $method = 'get' . $this->getCamelCaseName($offset);
            return $method;
        } else
            return null;
    }

    public abstract function jsonSerialize() : array ;

    public function toArray() : array {
        return $this->jsonSerialize();
    }

    /**
     * @var datetime $created
     *
     * @ORM\Column(type="datetime")
     */
    protected $created_at;

    /**
     * @var datetime $updated
     * 
     * @ORM\Column(type="datetime", nullable = true)
     */
    protected $updated_at;

    /**
     * Gets triggered only on insert
     * @ORM\PrePersist
     */
    public function onPrePersist()
    {
        $this->updated_at = $this->created_at = new \DateTime("now");
    }

    /**
     * Gets triggered every time on update
     * @ORM\PreUpdate
     */
    public function onPreUpdate()
    {
        $this->updated_at = new \DateTime("now");
    }

    public function getUpdatedAt()
    {
        return $this->updated_at;
    }

    public function getCreatedAt()
    {
        return $this->created_at;
    }
}
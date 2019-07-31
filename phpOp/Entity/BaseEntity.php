<?php




class BaseEntity
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

}
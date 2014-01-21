<?php
/**
 * base64url
 *
 * This is a library to do the url safe base64 encode/decode. 
 * License: GPL v.3
 *
 * @author Nat Sakimura (http://www.sakimura.org/)
 * @version 0.5
 * @create 2010-05-09
**/

/**
 * base64url encoding.
 * @param  String $input    Data to be encoded. 
 * @param  Int    $nopad    Whether "=" pad the output or not. 
 * @param  Int    $wrap     Whether to wrap the result. 
 * @return base64url encoded $input. 
 */
function base64url_encode($input,$nopad=1,$wrap=0)
{
    $data  = base64_encode($input);

    if($nopad) {
	$data = str_replace("=","",$data);
    }
    $data = strtr($data, '+/=', '-_,');
    if ($wrap) {
        $datalb = ""; 
        while (strlen($data) > 64) { 
            $datalb .= substr($data, 0, 64) . "\n"; 
            $data = substr($data,64); 
        } 
        $datalb .= $data; 
        return $datalb; 
    } else {
        return $data;
    }
}

/**
 * base64url encoding.
 * @param  String $input    Data to be Base64url decoded.
 * @return Decoded data
 */
function base64url_decode($input)
{
    return base64_decode(strtr($input, '-_,', '+/='));
}
?>

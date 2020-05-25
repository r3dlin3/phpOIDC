<?php 
include_once(__DIR__ . '/../check_admin.php');
check_admin();

$id = (int) $_GET['id'];
$result = db_delete_client_by_id($id);
echo $result ? "Row deleted.<br /> " : "Nothing deleted.<br /> ";
?> 

<a href='index.php?action=list'>Back To Listing</a>
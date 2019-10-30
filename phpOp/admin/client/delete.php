<?php 
$id = (int) $_GET['id'];
$result = db_delete_client_by_id($id);
echo $result ? "Row deleted.<br /> " : "Nothing deleted.<br /> ";
?> 

<a href='index.php?action=list'>Back To Listing</a>
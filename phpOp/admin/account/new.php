<?php
require_once __DIR__ . '/../../PasswordHash.php';

if (isset($_POST['submitted'])) {

    $_POST['crypted_password'] = create_hash($_POST['crypted_password']);

    db_create_account($_POST['login'], $_POST);
    echo "Added row.<br />";
    echo "<a href='index.php?action=list'>Back To Listing</a>";
} 
?>

<form action='' method='POST'>
<div class='table1'>
<table border='1'>
<tr>
<td><b>Field</b></td>
<td><b>Value</b></td>
</tr>    

<tr><td>Name:</td><td><input type='text' name='name'/> </td></tr>
<tr><td>Enabled:</td><td><input type='text' name='enabled'/> </td></tr>
<tr><td>Login:</td><td><input type='text' name='login'/> </td></tr>
<tr><td>Password:</td><td><input type='text' name='crypted_password'/> </td></tr>
<tr><td>Name Ja Kana Jp:</td><td><input type='text' name='name_ja_kana_jp'/> </td></tr>
<tr><td>Name Ja Hani Jp:</td><td><input type='text' name='name_ja_hani_jp'/> </td></tr>
<tr><td>Given Name:</td><td><input type='text' name='given_name'/> </td></tr>
<tr><td>Given Name Ja Kana Jp:</td><td><input type='text' name='given_name_ja_kana_jp'/> </td></tr>
<tr><td>Given Name Ja Hani Jp:</td><td><input type='text' name='given_name_ja_hani_jp'/> </td></tr>
<tr><td>Family Name:</td><td><input type='text' name='family_name'/> </td></tr>
<tr><td>Family Name Ja Kana Jp:</td><td><input type='text' name='family_name_ja_kana_jp'/> </td></tr>
<tr><td>Family Name Ja Hani Jp:</td><td><input type='text' name='family_name_ja_hani_jp'/> </td></tr>
<tr><td>Middle Name:</td><td><input type='text' name='middle_name'/> </td></tr>
<tr><td>Middle Name Ja Kana Jp:</td><td><input type='text' name='middle_name_ja_kana_jp'/> </td></tr>
<tr><td>Middle Name Ja Hani Jp:</td><td><input type='text' name='middle_name_ja_hani_jp'/> </td></tr>
<tr><td>Nickname:</td><td><input type='text' name='nickname'/> </td></tr>
<tr><td>Preferred Username:</td><td><input type='text' name='preferred_username'/> </td></tr>
<tr><td>Profile:</td><td><input type='text' name='profile'/> </td></tr>
<tr><td>Picture:</td><td><input type='text' name='picture'/> </td></tr>
<tr><td>Website:</td><td><input type='text' name='website'/> </td></tr>
<tr><td>Email:</td><td><input type='text' name='email'/> </td></tr>
<tr><td>Email Verified:</td><td><input type='text' name='email_verified'/> </td></tr>
<tr><td>Gender:</td><td><input type='text' name='gender'/> </td></tr>
<tr><td>Birthdate:</td><td><input type='text' name='birthdate'/> </td></tr>
<tr><td>Zoneinfo:</td><td><input type='text' name='zoneinfo'/> </td></tr>
<tr><td>Locale:</td><td><input type='text' name='locale'/> </td></tr>
<tr><td>Phone Number:</td><td><input type='text' name='phone_number'/> </td></tr>
<tr><td>Phone Number Verified:</td><td><input type='text' name='phone_number_verified'/> </td></tr>
<tr><td>Address:</td><td><input type='text' name='address'/> </td></tr>
<tr><td>Updated At:</td><td><input type='text' name='updated_at'/> </td></tr>
</table>
</div>
    <br/><br/>
    <p><input type='submit' value='Add Row' /><input type='hidden' value='1' name='submitted' />

</form> 

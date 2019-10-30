<?php
if (isset($_POST['submitted'])) {
    db_save_provider($_POST['name'], $_POST);
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

<tr><td>Key Id:</td><td><input type='text' name='key_id'/> </td></tr>
<tr><td>Name:</td><td><textarea name='name'></textarea> </td></tr>
<tr><td>Url:</td><td><input type='text' name='url'/> </td></tr>
<tr><td>Issuer:</td><td><input type='text' name='issuer'/> </td></tr>
<tr><td>Client Id:</td><td><input type='text' name='client_id'/> </td></tr>
<tr><td>Client Secret:</td><td><input type='text' name='client_secret'/> </td></tr>
<tr><td>Client Id Issued At:</td><td><input type='text' name='client_id_issued_at'/> </td></tr>
<tr><td>Client Secret Expires At:</td><td><input type='text' name='client_secret_expires_at'/> </td></tr>
<tr><td>Registration Access Token:</td><td><input type='text' name='registration_access_token'/> </td></tr>
<tr><td>Registration Client Uri:</td><td><input type='text' name='registration_client_uri'/> </td></tr>
<tr><td>Authorization Endpoint:</td><td><input type='text' name='authorization_endpoint'/> </td></tr>
<tr><td>Token Endpoint:</td><td><input type='text' name='token_endpoint'/> </td></tr>
<tr><td>Userinfo Endpoint:</td><td><input type='text' name='userinfo_endpoint'/> </td></tr>
<tr><td>Check Id Endpoint:</td><td><input type='text' name='check_id_endpoint'/> </td></tr>
<tr><td>Check Session Iframe:</td><td><input type='text' name='check_session_iframe'/> </td></tr>
<tr><td>End Session Endpoint:</td><td><input type='text' name='end_session_endpoint'/> </td></tr>
<tr><td>Jwks Uri:</td><td><input type='text' name='jwks_uri'/> </td></tr>
<tr><td>Jwk Encryption Uri:</td><td><input type='text' name='jwk_encryption_uri'/> </td></tr>
<tr><td>X509 Uri:</td><td><input type='text' name='x509_uri'/> </td></tr>
<tr><td>X509 Encryption Uri:</td><td><input type='text' name='x509_encryption_uri'/> </td></tr>
<tr><td>Registration Endpoint:</td><td><input type='text' name='registration_endpoint'/> </td></tr>
<tr><td>Scopes Supported:</td><td><textarea name='scopes_supported'></textarea> </td></tr>
<tr><td>Response Types Supported:</td><td><textarea name='response_types_supported'></textarea> </td></tr>
<tr><td>Grant Types Supported:</td><td><input type='text' name='grant_types_supported'/> </td></tr>
<tr><td>Acr Values Supported:</td><td><textarea name='acr_values_supported'></textarea> </td></tr>
<tr><td>Subject Types Supported:</td><td><input type='text' name='subject_types_supported'/> </td></tr>
<tr><td>Userinfo Signing Alg Values Supported:</td><td><input type='text' name='userinfo_signing_alg_values_supported'/> </td></tr>
<tr><td>Userinfo Encryption Alg Values Supported:</td><td><input type='text' name='userinfo_encryption_alg_values_supported'/> </td></tr>
<tr><td>Userinfo Encryption Enc Values Supported:</td><td><input type='text' name='userinfo_encryption_enc_values_supported'/> </td></tr>
<tr><td>Id Token Signing Alg Values Supported:</td><td><input type='text' name='id_token_signing_alg_values_supported'/> </td></tr>
<tr><td>Id Token Encryption Alg Values Supported:</td><td><input type='text' name='id_token_encryption_alg_values_supported'/> </td></tr>
<tr><td>Id Token Encryption Enc Values Supported:</td><td><input type='text' name='id_token_encryption_enc_values_supported'/> </td></tr>
<tr><td>Request Object Signing Alg Values Supported:</td><td><input type='text' name='request_object_signing_alg_values_supported'/> </td></tr>
<tr><td>Request Object Encryption Alg Values Supported:</td><td><input type='text' name='request_object_encryption_alg_values_supported'/> </td></tr>
<tr><td>Request Object Encryption Enc Values Supported:</td><td><input type='text' name='request_object_encryption_enc_values_supported'/> </td></tr>
<tr><td>Token Endpoint Auth Methods Supported:</td><td><input type='text' name='token_endpoint_auth_methods_supported'/> </td></tr>
<tr><td>Token Endpoint Auth Signing Alg Values Supported:</td><td><input type='text' name='token_endpoint_auth_signing_alg_values_supported'/> </td></tr>
<tr><td>Display Values Supported:</td><td><input type='text' name='display_values_supported'/> </td></tr>
<tr><td>Claim Types Supported:</td><td><input type='text' name='claim_types_supported'/> </td></tr>
<tr><td>Claims Supported:</td><td><textarea name='claims_supported'></textarea> </td></tr>
<tr><td>Service Documentation:</td><td><input type='text' name='service_documentation'/> </td></tr>
<tr><td>Claims Locales Supported:</td><td><input type='text' name='claims_locales_supported'/> </td></tr>
<tr><td>Ui Locales Supported:</td><td><input type='text' name='ui_locales_supported'/> </td></tr>
<tr><td>Require Request Uri Registration:</td><td><input type='text' name='require_request_uri_registration'/> </td></tr>
<tr><td>Op Policy Uri:</td><td><input type='text' name='op_policy_uri'/> </td></tr>
<tr><td>Op Tos Uri:</td><td><input type='text' name='op_tos_uri'/> </td></tr>
<tr><td>Claims Parameter Supported:</td><td><input type='text' name='claims_parameter_supported'/> </td></tr>
<tr><td>Request Parameter Supported:</td><td><input type='text' name='request_parameter_supported'/> </td></tr>
<tr><td>Request Uri Parameter Supported:</td><td><input type='text' name='request_uri_parameter_supported'/>


</table>
</div>
    <br/><br/>
    <p><input type='submit' value='Add Row' /><input type='hidden' value='1' name='submitted' />

</form>
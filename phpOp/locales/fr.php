<?php

use eftec\bladeone\BladeOne;

BladeOne::$dictionary=array(
"TitleLogin" =>
"Authentification",
'or' => 'ou',

"%s OP Login" =>
"%s OP Login",


'bitbucket' => 'Bitbucket',
'facebook' => 'Facebook',
'github' => 'GitHub',
'gitlab' => 'Gitlab',
'google' => 'Google',
'linkedin' => 'LinkedIn',
'twitter' => 'Twitter',

'Sign in with %s' => 'Continuer avec %s',


"Authentication error" =>
"Erreur d’authentification",

"E-Mail Address" =>
"Adresse email",

"Email is invalid" =>
"Adresse e-mail non valide",

"Password" =>
"Mot de passe",

"Forgot Password?" =>
"Mot de passe oublié ?",

"Password is required" =>
"Le mot de passe est requis",

"Remember Me" =>
"Se souvenir de moi",

"Login" =>
"Se connecter",

"Don't have an account?" =>
"Pas encore de compte ?",

"Create an account" =>
"Créer un compte",

"Policy" =>
"Politique",

"Terms of use" =>
"Conditions d’utilisation",

"Copyright &copy; 2020 &mdash; Your Company" =>
"Copyright &copy; 2020 &mdash; Your Company",

"TitleConsent" =>
"Consentement",

"%s Authorization OP" =>
"%s Authorization OP",

"This application wants to access the following information:" =>
"Cette application souhaite accéder aux informations suivantes :",

"%s has provided a <a href=\"%s\">policy</a> and <a href=\"%s\" class=\"card-link\">terms of use</a>." =>
"%s a fourni une <a href=\"%s\">politique</a> et <a href=\"%s\" class=\"card-link\">des conditions d’utilisation</a>.",

"%s has provided a <a href=\"%s\">policy</a>." =>
"%s a fourni une <a href=\"%s\">politique</a>.",

"%s has provided  <a href=\"%s\" class=\"card-link\">terms of use</a>." =>
"%s a fourni <a href=\"%s\" class=\"card-link\">des conditions d’utilisation</a>.",

"%s has not provided any policy nor terms of use." =>
"%s n'a fourni de politique ni de conditions d’utilisation.",

"Trust this site this time only" =>
"Faire confiance à ce site une seule fois",

"Trust this site always" =>
"Toujours faire confiance à ce site",

"Deny" =>
"Refuser",

"Accept" =>
"Accepter",

"label-openid" =>
"Jeton d'identité",

"label-profile" =>
"Profil",

"label-email" =>
"Adresse e-mail",

"label-address" =>
"Adresse postale",

"label-phone" =>
"Téléphone",

"label-offline_access" =>
"Accès hors ligne",

"desc-openid" =>
"Le jeton d'identification est un jeton de sécurité qui contient des revendications concernant l'authentification d'un utilisateur final, y compris le nom d'utilisateur.",

"desc-profile" =>
"Cette valeur d'étendue demande l'accès aux revendications de profil par défaut de l'utilisateur final, qui sont: nom, nom de famille, prénom, deuxième nom, surnom, nom d'utilisateur préféré, profil, image, site Web, sexe, date de naissance, fuseau horaire, paramètres régionaux et date de mise à jour.",

"desc-email" =>
"Cette valeur d'étendue demande l'accès aux e-mails de l'utilisateur.",

"desc-address" =>
"Cette valeur d'étendue demande l'accès à l'adresse postale.",

"desc-phone" =>
"Cette valeur d'étendue demande l'accès aux numéros de téléphone.",

"desc-offline_access" =>
"Cette valeur d'étendue demande qu'un jeton d'actualisation OAuth 2.0 soit émis qui puisse être utilisé pour obtenir un jeton d'accès qui accorde l'accès aux ressources de l'utilisateur même lorsque l'utilisateur final n'est pas présent (non connecté).",

"TitleError" => "Erreur",

"Error" => "Erreur",

# register.blade.php
"Already have an account?" => "Vous avez déjà un compte ?",
"Register" => "S'inscrire",
"TitleRegister" => "Enregistrement",

"email" => "Adresse email",
"given_name" => "Prénom",
"family_name" => "Nom",
"password" => "Mot de passe",

"A valid e-mail address is required." => "Une adresse e-mail est requise.",
'A complex password is required.' => 'Un mot de passe complexe est requis.',
'A family name is required.' => 'Un nom de famille est requis.',
'A given name is required.' => 'Un prénom est requis.',

# register_success.blade.php
'Authenticate yourself to continue.' => 'Authentifiez-vous pour continuer.',
'TitleRegisterSuccess' => 'Compte créé',
'You are now registered.' => 'Vous êtes maintenant enregistré.',
#Error
'Functionality is disabled' => 'Fonctionnalité désactivée',
"Registration is disabled." => "L'enregistrement est désactivé.",
"Password reset is disabled." => "La réinitialisation de mot de passe est désactivée.",

# forgotpassword.blade.php

'Back to <a href="%s">Login</a>' => 'Retour à la page <a href="%s">d\'authentification</a>',
'By clicking "Reset Password" we will send a password reset link' => 'Après avoir cliqué sur "Réinitialiser le mot de passe", vous recevrez un e-mail.',
'E-mail address is invalid' => 'Adresse e-mail invalide',
'E-mail sent.' => 'E-mail envoyé.',
'Forgot Password' => 'Mot de pass oublié',
'Make sure your password is strong and easy to remember' => 'Assurez-vous que le mot de passe est suffisamment fort et facile à se souvenir.',
'New Password' => 'Nouveau mot de passe',
'Password reset for %s' => 'Réinitialisation du mot de passe pour %s',
'Password saved.' => 'Mot de passe sauvegardé.',
'Reset Password' => 'Réinitialiser le mot de passe',
'TitleForgotPassword' => 'Mot de passe oublié',
'TitlePasswordReset' => 'Réinitialisation du mot de passe',
'TitlePasswordResetMailSentSuccess' => 'E-mail envoyé',
'TitlePasswordResetSuccess' => 'Mot de passe réinitialisé avec succès',
'You will receive an e-mail to reset your password. Check your mails, especially in the spam folder.' => 'Vous allez recevoir un e-mail pour réinitialiser votre mot de passe. Vérifier vos mails, notamment dans les e-mails indésirables.',
);
/*
DROP DATABASE IF EXISTS `abop_db`;
CREATE DATABASE `abop_db`;
GRANT ALL PRIVILEGES on abop_db.* to abop@'localhost' identified by 'abop';

USE phpoidc_01;
*/


--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `account`;
CREATE TABLE `account` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `enabled` tinyint(1) DEFAULT '1',
  `login` varchar(255) NOT NULL,
  `crypted_password` varchar(255) NOT NULL,
  `name` varchar(255) DEFAULT NULL,
  `name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `given_name` varchar(255) DEFAULT NULL,
  `given_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `given_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `family_name` varchar(255) DEFAULT NULL,
  `family_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `family_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `middle_name` varchar(255) DEFAULT NULL,
  `middle_name_ja_kana_jp` varchar(255) DEFAULT NULL,
  `middle_name_ja_hani_jp` varchar(255) DEFAULT NULL,
  `nickname` varchar(255) DEFAULT NULL,
  `preferred_username` varchar(255) DEFAULT NULL,
  `profile` varchar(255) DEFAULT NULL,
  `picture` varchar(255) DEFAULT NULL,
  `website` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  `email_verified` tinyint(1) DEFAULT '0',
  `gender` varchar(255) DEFAULT NULL,
  `birthdate` varchar(255) DEFAULT NULL,
  `zoneinfo` varchar(255) DEFAULT NULL,
  `locale` varchar(255) DEFAULT NULL,
  `phone_number` varchar(255) DEFAULT NULL,
  `phone_number_verified` tinyint(1) DEFAULT '0',
  `address` varchar(255) DEFAULT NULL,
  `updated_at` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`, `login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Dumping data for table `accounts`
--

-- LOCK TABLES `accounts` WRITE;
-- !40000 ALTER TABLE `accounts` DISABLE KEYS */;
-- INSERT INTO `accounts` VALUES (1,1,'alice','b6263bb14858294c08e4bdfceba90363e10d72b4'),(2,1,'bob','cc8684eed2b6544e89242558df73a7208c9391b4');
-- !40000 ALTER TABLE `accounts` ENABLE KEYS */;
-- UNLOCK TABLES;


--
-- Table structure for table `clients`
--

DROP TABLE IF EXISTS `client`;
CREATE TABLE `client` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `client_id_issued_at` int(11) NULL,
  `client_id` varchar(255) NOT NULL,
  `client_secret` varchar(255) DEFAULT NULL,
  `client_secret_expires_at` int(11) DEFAULT NULL,
  `registration_access_token` varchar(255) DEFAULT NULL,
  `registration_client_uri_path` varchar(255) DEFAULT NULL,
  `contacts` text,
  `application_type` varchar(255) DEFAULT NULL,
  `client_name` varchar(255) DEFAULT NULL,
  `logo_uri` varchar(255) DEFAULT NULL,
  `tos_uri` varchar(255) DEFAULT NULL,
  `redirect_uris` text,
  `post_logout_redirect_uris` text,
  `token_endpoint_auth_method` varchar(255) DEFAULT NULL,
  `policy_uri` varchar(255) DEFAULT NULL,
  `jwks_uri` varchar(255) DEFAULT NULL,
  `jwk_encryption_uri` varchar(255) DEFAULT NULL,
  `x509_uri` varchar(255) DEFAULT NULL,
  `x509_encryption_uri` varchar(255) DEFAULT NULL,
  `sector_identifier_uri` varchar(255) DEFAULT NULL,
  `subject_type` varchar(255) DEFAULT NULL,
  `request_object_signing_alg` varchar(255) DEFAULT NULL,
  `userinfo_signed_response_alg` varchar(255) DEFAULT NULL,
  `userinfo_encrypted_response_alg` varchar(255) DEFAULT NULL,
  `userinfo_encrypted_response_enc` varchar(255) DEFAULT NULL,
  `id_token_signed_response_alg` varchar(255) DEFAULT NULL,
  `id_token_encrypted_response_alg` varchar(255) DEFAULT NULL,
  `id_token_encrypted_response_enc` varchar(255) DEFAULT NULL,
  `default_max_age` int(11) DEFAULT NULL,
  `require_auth_time` tinyint(1) DEFAULT NULL,
  `default_acr_values` varchar(255) DEFAULT NULL,
  `initiate_login_uri` varchar(255) DEFAULT NULL,
  `post_logout_redirect_uri` varchar(255) DEFAULT NULL,
  `request_uris` text DEFAULT NULL,
  `grant_types` varchar(255) DEFAULT NULL,
  `response_types` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;



--
-- Dumping data for table `personas`
--

-- LOCK TABLES `personas` WRITE;
-- /*!40000 ALTER TABLE `personas` DISABLE KEYS */;
-- INSERT INTO `personas` VALUES (1,1,'Default','Alice Yamada','ãƒ¤ãƒžãƒ€ã‚¢ãƒªã‚µ','å±±ç”°äºœç†ç´—','Alice','ã‚¢ãƒªã‚µ','äºœç†ç´—','Yamada','ãƒ¤ãƒžãƒ€','å±±ç”°','','','','Standard Alice','=Alice1','http://www.wonderland.com/alice','https://mgi1.gotdns.com:8443/abop/profiles/smiling_woman.jpg','http://www.wonderland.com','alice@wonderland.com',1,'female','2000-01-01','some zone','some locale','1-81-234-234234234','123 wonderland way','2010-12-10 14:00:00'),(2,1,'Shopping','Shopping Alice Yamada','ãƒ¤ãƒžãƒ€ã‚¢ãƒªã‚µ','å±±ç”°äºœç†ç´—','Alice','ã‚¢ãƒªã‚µ','äºœç†ç´—','Yamada','ãƒ¤ãƒžãƒ€','å±±ç”°','','','','Shopping Alice',NULL,'http://www.wonderland.com/alice','https://mgi1.gotdns.com:8443/abop/profiles/smiling_woman.jpg','http://www.wonderland.com','alice@wonderland.com',1,'female','2000-01-01','some zone','some locale','1-81-234-234234234','123 wonderland way','2010-12-10 14:00:00'),(3,1,'Browsing','Alice Yamada','ãƒ¤ãƒžãƒ€ã‚¢ãƒªã‚µ','å±±ç”°äºœç†ç´—','Alice','ã‚¢ãƒªã‚µ','äºœç†ç´—','Yamada','ãƒ¤ãƒžãƒ€','å±±ç”°','','','','Browsing Alice','BAlice','http://www.wonderland.com/alice','https://mgi1.gotdns.com:8443/abop/profiles/smiling_woman.jpg','http://www.wonderland.com','alice@wonderland.com',1,'female','2000-01-01','some zone','some locale','1-81-234-234234234','123 wonderland way','2010-12-10 14:00:00'),(4,2,'Default','Bob Ikeda','ã‚¤ã‚±ãƒ€ãƒœãƒ–','æ± ç”°ä¿å¤«','Bob','ãƒœãƒ–','ä¿å¤«','Ikeda','ã‚¤ã‚±ãƒ€','æ± ç”°','',NULL,NULL,'Standard Bob','','http://www.underland.com/bob','http://www.costumzee.com/users/Barbaro-2770-full.gif','http://www.underland.com','bob@underland.com',1,'male','1980-11-11','some zone','some locale','1-81-234-234234234','456 underland ct.','2010-12-10 14:00:00'),(5,2,'Shopping','Bob Ikeda','ã‚¤ã‚±ãƒ€ãƒœãƒ–','æ± ç”°ä¿å¤«','Bob','ãƒœãƒ–','ä¿å¤«','Ikeda','ã‚¤ã‚±ãƒ€','æ± ç”°',NULL,NULL,NULL,'Shopping Bob',NULL,'http://www.underland.com/bob','http://www.costumzee.com/users/Barbaro-2770-full.gif','http://www.underland.com','bob@underland.com',1,'male','1980-11-11','some zone','some locale','1-81-234-234234234','456 underland ct.','2010-12-10 14:00:00'),(6,1,'test','','','','','','','','','','','','','',NULL,'','','','',0,'','1980-11-11','','','','','0000-00-00 00:00:00');
-- /*!40000 ALTER TABLE `personas` ENABLE KEYS */;
-- UNLOCK TABLES;

--
-- Table structure for table `providers`
--

DROP TABLE IF EXISTS `provider`;
CREATE TABLE `provider` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` text NOT NULL,
  `url` varchar(255) NOT NULL,
  `issuer` varchar(255) NOT NULL,
  `client_id` varchar(255) NOT NULL,
  `client_secret` varchar(255) NOT NULL,
  `client_id_issued_at` int(11) DEFAULT NULL,
  `client_secret_expires_at` int(11) DEFAULT NULL,
  `registration_access_token` varchar(255) DEFAULT NULL,
  `registration_client_uri` varchar(255) DEFAULT NULL,
  `authorization_endpoint` varchar(255) DEFAULT NULL,
  `token_endpoint` varchar(255) DEFAULT NULL,
  `userinfo_endpoint` varchar(255) DEFAULT NULL,
  `check_id_endpoint` varchar(255) DEFAULT NULL,
  `check_session_iframe` varchar(255) DEFAULT NULL,
  `end_session_endpoint` varchar(255) DEFAULT NULL,
  `jwks_uri` varchar(255) DEFAULT NULL,
  `jwk_encryption_uri` varchar(255) DEFAULT NULL,
  `x509_uri` varchar(255) DEFAULT NULL,
  `x509_encryption_uri` varchar(255) DEFAULT NULL,
  `registration_endpoint` varchar(255) DEFAULT NULL,
  `scopes_supported` text,
  `response_types_supported` text,
  `grant_types_supported` varchar(255) DEFAULT NULL,
  `acr_values_supported` text,
  `subject_types_supported` varchar(255) DEFAULT NULL,
  `userinfo_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `userinfo_encryption_alg_values_supported` varchar(255) DEFAULT NULL,
  `userinfo_encryption_enc_values_supported` varchar(255) DEFAULT NULL,
  `id_token_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `id_token_encryption_alg_values_supported` varchar(255) DEFAULT NULL,
  `id_token_encryption_enc_values_supported` varchar(255) DEFAULT NULL,
  `request_object_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `request_object_encryption_alg_values_supported` varchar(255) DEFAULT NULL,
  `request_object_encryption_enc_values_supported` varchar(255) DEFAULT NULL,
  `token_endpoint_auth_methods_supported` varchar(255) DEFAULT NULL,
  `token_endpoint_auth_signing_alg_values_supported` varchar(255) DEFAULT NULL,
  `display_values_supported` varchar(255) DEFAULT NULL,
  `claim_types_supported` varchar(255) DEFAULT NULL,
  `claims_supported` text DEFAULT NULL,
  `service_documentation` varchar(255) DEFAULT NULL,
  `claims_locales_supported` varchar(255) DEFAULT NULL,
  `ui_locales_supported` varchar(255) DEFAULT NULL,
  `require_request_uri_registration` tinyint(1) DEFAULT NULL,
  `op_policy_uri` varchar(255) DEFAULT NULL,
  `op_tos_uri` varchar(255) DEFAULT NULL,
  `claims_parameter_supported` tinyint(1) DEFAULT NULL,
  `request_parameter_supported` tinyint(1) DEFAULT NULL,
  `request_uri_parameter_supported` tinyint(1) DEFAULT NULL,

  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;




--
-- Table structure for table `request_files`
--

DROP TABLE IF EXISTS `request_file`;
CREATE TABLE `request_file` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `fileid` varchar(255) NOT NULL,
  `request` text,
  `type` tinyint(1) DEFAULT NULL,
  `jwt` text,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_request_files_on_fileid` (`fileid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `sites`
--

DROP TABLE IF EXISTS `user_trusted_client`;
CREATE TABLE `user_trusted_client` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `client_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `trustedclients_account_id_accounts_id` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE ,
  CONSTRAINT `trustedclients_client_id_clients_id` FOREIGN KEY (`client_id`) REFERENCES `client` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


--
-- Table structure for table `tokens`
--

DROP TABLE IF EXISTS `token`;

CREATE TABLE `token` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `account_id` int(11) NOT NULL,
  `token` text NOT NULL,
  `token_type` tinyint(4) DEFAULT '1',
  `client` varchar(255) NOT NULL,
  `details` text,
  `issued_at` datetime NOT NULL,
  `expiration_at` datetime NOT NULL,
  `info` text,
  PRIMARY KEY (`id`),
  KEY `account_id_idx` (`account_id`),
  CONSTRAINT `tokens_account_id_accounts_id` FOREIGN KEY (`account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8;


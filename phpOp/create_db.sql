 /**
 * Copyright 2013 Nomura Research Institute, Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
DROP DATABASE IF EXISTS `phpoidc`;
CREATE DATABASE `phpoidc`;
USE phpoidc;

-- 
-- Table structure for table `accounts`
-- 
DROP TABLE IF EXISTS `account`;

CREATE TABLE `account`
  (
     `id`                          INT(11) NOT NULL auto_increment,
     `enabled`                     TINYINT(1) DEFAULT '1',
     `login`                       VARCHAR(255) NOT NULL,
     `crypted_password`            VARCHAR(255) NOT NULL,
     `name`                        VARCHAR(255) DEFAULT NULL,
     `name_ja_kana_jp`             VARCHAR(255) DEFAULT NULL,
     `name_ja_hani_jp`             VARCHAR(255) DEFAULT NULL,
     `given_name`                  VARCHAR(255) DEFAULT NULL,
     `given_name_ja_kana_jp`       VARCHAR(255) DEFAULT NULL,
     `given_name_ja_hani_jp`       VARCHAR(255) DEFAULT NULL,
     `family_name`                 VARCHAR(255) DEFAULT NULL,
     `family_name_ja_kana_jp`      VARCHAR(255) DEFAULT NULL,
     `family_name_ja_hani_jp`      VARCHAR(255) DEFAULT NULL,
     `middle_name`                 VARCHAR(255) DEFAULT NULL,
     `middle_name_ja_kana_jp`      VARCHAR(255) DEFAULT NULL,
     `middle_name_ja_hani_jp`      VARCHAR(255) DEFAULT NULL,
     `nickname`                    VARCHAR(255) DEFAULT NULL,
     `preferred_username`          VARCHAR(255) DEFAULT NULL,
     `profile`                     VARCHAR(255) DEFAULT NULL,
     `picture`                     VARCHAR(255) DEFAULT NULL,
     `website`                     VARCHAR(255) DEFAULT NULL,
     `email`                       VARCHAR(255) DEFAULT NULL,
     `email_verified`              TINYINT(1) DEFAULT '0',
     `gender`                      VARCHAR(255) DEFAULT NULL,
     `birthdate`                   VARCHAR(255) DEFAULT NULL,
     `zoneinfo`                    VARCHAR(255) DEFAULT NULL,
     `locale`                      VARCHAR(255) DEFAULT NULL,
     `phone_number`                VARCHAR(255) DEFAULT NULL,
     `phone_number_verified`       TINYINT(1) DEFAULT '0',
     `address`                     VARCHAR(255) DEFAULT NULL,
     `reset_password_code`         VARCHAR(80) DEFAULT NULL,
     `reset_password_code_timeout` DATETIME DEFAULT NULL,
     `created_at` DATETIME NOT NULL,
     `updated_at` DATETIME DEFAULT NULL, 
     UNIQUE INDEX uniq_login (login),
     PRIMARY KEY (`id`)
  )
engine=innodb
COLLATE `utf8_unicode_ci`
DEFAULT charset=utf8;

-- 
-- Table structure for table `clients`
-- 
DROP TABLE IF EXISTS `client`;

CREATE TABLE `client`
  (
     `id`                              INT(11) NOT NULL auto_increment,
     `client_id_issued_at`             INT(11) NULL,
     `client_id`                       VARCHAR(255) NOT NULL,
     `client_secret`                   VARCHAR(255) DEFAULT NULL,
     `client_secret_expires_at`        INT(11) DEFAULT NULL,
     `registration_access_token`       VARCHAR(255) DEFAULT NULL,
     `registration_client_uri_path`    VARCHAR(255) DEFAULT NULL,
     `contacts`                        TEXT,
     `application_type`                VARCHAR(255) DEFAULT NULL,
     `client_name`                     VARCHAR(255) DEFAULT NULL,
     `logo_uri`                        VARCHAR(255) DEFAULT NULL,
     `tos_uri`                         VARCHAR(255) DEFAULT NULL,
     `redirect_uris`                   TEXT,
     `post_logout_redirect_uris`       TEXT,
     `token_endpoint_auth_method`      VARCHAR(255) DEFAULT NULL,
     `token_endpoint_auth_signing_alg` VARCHAR(255) DEFAULT NULL,
     `policy_uri`                      VARCHAR(255) DEFAULT NULL,
     `jwks_uri`                        VARCHAR(255) DEFAULT NULL,
     `jwks`                            TEXT,
     `jwk_encryption_uri`              VARCHAR(255) DEFAULT NULL,
     `x509_uri`                        VARCHAR(255) DEFAULT NULL,
     `x509_encryption_uri`             VARCHAR(255) DEFAULT NULL,
     `sector_identifier_uri`           VARCHAR(255) DEFAULT NULL,
     `subject_type`                    VARCHAR(255) DEFAULT NULL,
     `request_object_signing_alg`      VARCHAR(255) DEFAULT NULL,
     `userinfo_signed_response_alg`    VARCHAR(255) DEFAULT NULL,
     `userinfo_encrypted_response_alg` VARCHAR(255) DEFAULT NULL,
     `userinfo_encrypted_response_enc` VARCHAR(255) DEFAULT NULL,
     `id_token_signed_response_alg`    VARCHAR(255) DEFAULT NULL,
     `id_token_encrypted_response_alg` VARCHAR(255) DEFAULT NULL,
     `id_token_encrypted_response_enc` VARCHAR(255) DEFAULT NULL,
     `default_max_age`                 INT(11) DEFAULT NULL,
     `require_auth_time`               TINYINT(1) DEFAULT NULL,
     `default_acr_values`              VARCHAR(255) DEFAULT NULL,
     `initiate_login_uri`              VARCHAR(255) DEFAULT NULL,
     `post_logout_redirect_uri`        VARCHAR(255) DEFAULT NULL,
     `request_uris`                    TEXT DEFAULT NULL,
     `grant_types`                     VARCHAR(255) DEFAULT NULL,
     `response_types`                  VARCHAR(255) DEFAULT NULL,
     `trusted`                         TINYINT(1) NOT NULL,
     `created_at`                      DATETIME NOT NULL,
     `updated_at`                      DATETIME DEFAULT NULL, 
     PRIMARY KEY (`id`)
  )
engine=innodb
COLLATE `utf8_unicode_ci`
DEFAULT charset=utf8;

-- 
-- Table structure for table `providers`
-- 
DROP TABLE IF EXISTS `provider`;

CREATE TABLE `provider`
  (
     `id`                                               INT(11) NOT NULL
     auto_increment,
     `key_id`                                           VARCHAR(16) UNIQUE,
     `name`                                             TEXT NOT NULL,
     `url`                                              VARCHAR(255) NOT NULL,
     `issuer`                                           VARCHAR(255) NOT NULL,
     `client_id`                                        VARCHAR(255) NOT NULL,
     `client_secret`                                    VARCHAR(255) NOT NULL,
     `client_id_issued_at`                              INT(11) DEFAULT NULL,
     `client_secret_expires_at`                         INT(11) DEFAULT NULL,
     `registration_access_token`                        VARCHAR(255) DEFAULT
     NULL,
     `registration_client_uri`                          VARCHAR(255) DEFAULT
     NULL,
     `authorization_endpoint`                           VARCHAR(255) DEFAULT
     NULL,
     `token_endpoint`                                   VARCHAR(255) DEFAULT
     NULL,
     `userinfo_endpoint`                                VARCHAR(255) DEFAULT
     NULL,
     `check_id_endpoint`                                VARCHAR(255) DEFAULT
     NULL,
     `check_session_iframe`                             VARCHAR(255) DEFAULT
     NULL,
     `end_session_endpoint`                             VARCHAR(255) DEFAULT
     NULL,
     `jwks_uri`                                         VARCHAR(255) DEFAULT
     NULL,
     `jwk_encryption_uri`                               VARCHAR(255) DEFAULT
     NULL,
     `x509_uri`                                         VARCHAR(255) DEFAULT
     NULL,
     `x509_encryption_uri`                              VARCHAR(255) DEFAULT
     NULL,
     `registration_endpoint`                            VARCHAR(255) DEFAULT
     NULL,
     `scopes_supported`                                 TEXT,
     `response_types_supported`                         TEXT,
     `grant_types_supported`                            VARCHAR(255) DEFAULT
     NULL,
     `acr_values_supported`                             TEXT,
     `subject_types_supported`                          VARCHAR(255) DEFAULT
     NULL,
     `userinfo_signing_alg_values_supported`            VARCHAR(255) DEFAULT
     NULL,
     `userinfo_encryption_alg_values_supported`         VARCHAR(255) DEFAULT
     NULL,
     `userinfo_encryption_enc_values_supported`         VARCHAR(255) DEFAULT
     NULL,
     `id_token_signing_alg_values_supported`            VARCHAR(255) DEFAULT
     NULL,
     `id_token_encryption_alg_values_supported`         VARCHAR(255) DEFAULT
     NULL,
     `id_token_encryption_enc_values_supported`         VARCHAR(255) DEFAULT
     NULL,
     `request_object_signing_alg_values_supported`      VARCHAR(255) DEFAULT
     NULL,
     `request_object_encryption_alg_values_supported`   VARCHAR(255) DEFAULT
     NULL,
     `request_object_encryption_enc_values_supported`   VARCHAR(255) DEFAULT
     NULL,
     `token_endpoint_auth_methods_supported`            VARCHAR(255) DEFAULT
     NULL,
     `token_endpoint_auth_signing_alg_values_supported` VARCHAR(255) DEFAULT
     NULL,
     `display_values_supported`                         VARCHAR(255) DEFAULT
     NULL,
     `claim_types_supported`                            VARCHAR(255) DEFAULT
     NULL,
     `claims_supported`                                 TEXT DEFAULT NULL,
     `service_documentation`                            VARCHAR(255) DEFAULT
     NULL,
     `claims_locales_supported`                         VARCHAR(255) DEFAULT
     NULL,
     `ui_locales_supported`                             VARCHAR(255) DEFAULT
     NULL,
     `require_request_uri_registration`                 TINYINT(1) DEFAULT NULL,
     `op_policy_uri`                                    VARCHAR(255) DEFAULT
     NULL,
     `op_tos_uri`                                       VARCHAR(255) DEFAULT
     NULL,
     `claims_parameter_supported`                       TINYINT(1) DEFAULT NULL,
     `request_parameter_supported`                      TINYINT(1) DEFAULT NULL,
     `request_uri_parameter_supported`                  TINYINT(1) DEFAULT NULL,
     PRIMARY KEY (`id`)
  )
engine=innodb
COLLATE `utf8_unicode_ci`
DEFAULT charset=utf8;

-- 
-- Table structure for table `request_files`
-- 
DROP TABLE IF EXISTS `request_file`;

CREATE TABLE `request_file`
  (
     `id`      INT(11) NOT NULL auto_increment,
     `fileid`  VARCHAR(255) NOT NULL,
     `request` TEXT,
     `type`    TINYINT(1) DEFAULT NULL,
     `jwt`     TEXT,
     PRIMARY KEY (`id`),
     UNIQUE KEY `index_request_files_on_fileid` (`fileid`)
  )
engine=innodb
COLLATE `utf8_unicode_ci`
DEFAULT charset=utf8;

-- 
-- Table structure for table `sites`
-- 
DROP TABLE IF EXISTS `user_trusted_client`;

CREATE TABLE `user_trusted_client`
  (
     `id`         INT(11) NOT NULL auto_increment,
     `account_id` INT(11) NOT NULL,
     `client_id`  INT(11) NOT NULL,
     PRIMARY KEY (`id`),
     CONSTRAINT `trustedclients_account_id_accounts_id` FOREIGN KEY (
     `account_id`) REFERENCES `account` (`id`) ON DELETE CASCADE,
     CONSTRAINT `trustedclients_client_id_clients_id` FOREIGN KEY (`client_id`)
     REFERENCES `client` (`id`) ON DELETE CASCADE
  )
engine=innodb
DEFAULT charset=utf8;

-- 
-- Table structure for table `tokens`
-- 
DROP TABLE IF EXISTS `token`;

CREATE TABLE `token`
  (
     `id`            INT(11) NOT NULL auto_increment,
     `account_id`    INT(11) NOT NULL,
     `token`         TEXT NOT NULL,
     `token_type`    TINYINT(4) DEFAULT '1',
     `client`        VARCHAR(255) NOT NULL,
     `details`       TEXT,
     `issued_at`     DATETIME NOT NULL,
     `expiration_at` DATETIME NOT NULL,
     `info`          TEXT,
     `created_at`    DATETIME NOT NULL,
     `updated_at`    DATETIME DEFAULT NULL, 
     PRIMARY KEY (`id`),
     KEY `account_id_idx` (`account_id`),
     CONSTRAINT `tokens_account_id_accounts_id` FOREIGN KEY (`account_id`)
     REFERENCES `account` (`id`) ON DELETE CASCADE
  )
engine=innodb
DEFAULT charset=utf8;

-- 
-- Insert values into account table
-- 
INSERT INTO `account`
            (`id`,
             `enabled`,
             `login`,
             `crypted_password`,
             `name`,
             `name_ja_kana_jp`,
             `name_ja_hani_jp`,
             `given_name`,
             `given_name_ja_kana_jp`,
             `given_name_ja_hani_jp`,
             `family_name`,
             `family_name_ja_kana_jp`,
             `family_name_ja_hani_jp`,
             `middle_name`,
             `middle_name_ja_kana_jp`,
             `middle_name_ja_hani_jp`,
             `nickname`,
             `preferred_username`,
             `profile`,
             `picture`,
             `website`,
             `email`,
             `email_verified`,
             `gender`,
             `birthdate`,
             `zoneinfo`,
             `locale`,
             `phone_number`,
             `phone_number_verified`,
             `address`,
             `updated_at`,
             `created_at`)
VALUES      ( 0,
              1,
              'alice',
              'b6263bb14858294c08e4bdfceba90363e10d72b4',
              'Alice Yamada',
              'ヤマダアリサ',
              '山田亜理紗',
              'Alice',
              'アリサ',
              '亜理紗',
              'Yamada',
              'ヤマダ',
              '山田',
              NULL,
              NULL,
              NULL,
              'Standard Alice Nickname',
              'AlicePreferred',
              'http://www.wonderland.com/alice',
              'smiling_woman.jpg',
              'http://www.wonderland.com',
              'alice@wonderland.com',
              1,
              'female',
              '2000-08-08',
              'America/Los Angeles',
              'en',
              '1-81-234-234234234',
              1,
              '123 wonderland way',
              Now(),
              Now() ),
            (0,
             1,
             'bob',
             'cc8684eed2b6544e89242558df73a7208c9391b4',
             'Bob Ikeda',
             'イケダボブ',
             '池田保夫',
             'Bob',
             'ボブ',
             '保夫',
             'Ikeda',
             'イケダ',
             '池田',
             NULL,
             NULL,
             NULL,
             'BobNick',
             'BobPreferred',
             'http://www.underland.com/bob',
             'smiling_woman.jpg',
             'http://www.underland.com',
             'bob@underland.com',
             1,
             'male',
             '2111-11-11',
             'France/Paris',
             'fr',
             '1-81-234-234234234',
             1,
             '456 underland ct.',
             Now(),
             Now() );  
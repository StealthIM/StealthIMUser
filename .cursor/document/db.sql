-- 以上表位于 SqlDatabases=Users 中
CREATE TABLE IF NOT EXISTS `user_auth` (
    `uid` INT(32) NOT NULL PRIMARY KEY AUTO_INCREMENT,
    `username` VARCHAR(64) NOT NULL UNIQUE,
    `nickname` VARCHAR(64) NOT NULL,
    `password` VARCHAR(128) NOT NULL,
    `salt` VARCHAR(128) NOT NULL,
    `login_level` SMALLINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS `user_info` (
    `uid` INT(32) NOT NULL PRIMARY KEY,
    `create_time` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `vip` SMALLINT NOT NULL DEFAULT 0,
    `email` VARCHAR(128),
    `phone_number` VARCHAR(64)
);
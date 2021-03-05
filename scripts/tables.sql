CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `email` varchar(255) NOT NULL,
  `password` text,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_email` (`email`)
);


CREATE TABLE `tokens` (
  `id` int NOT NULL AUTO_INCREMENT,
  `accessToken` text NOT NULL,
  `refreshToken` text NOT NULL,
  `isBlocked` tinyint(1) NOT NULL DEFAULT '0',
  `userId` int DEFAULT NULL,
  `inserted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`userId`),
  CONSTRAINT `tokens_ibfk_1` FOREIGN KEY (`userId`) REFERENCES `users` (`id`)
);


CREATE TABLE `files` (
  `id` int NOT NULL AUTO_INCREMENT,
  `fileName` text NOT NULL,
  `extension` text,
  `mimeType` text NOT NULL,
  `sizeInBytes` int DEFAULT NULL,
  `inserted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `location` text NOT NULL,
  PRIMARY KEY (`id`)
);
);
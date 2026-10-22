-- MySQL dump 10.13  Distrib 8.0.46, for Win64 (x86_64)
--
-- Host: mysql-bfdf0f9-jihyan0710-df10.a.aivencloud.com    Database: defaultdb
-- ------------------------------------------------------
-- Server version	8.4.11

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `ai_incidents`
--

DROP TABLE IF EXISTS `ai_incidents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ai_incidents` (
  `id` int NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL,
  `risk_score` double NOT NULL,
  `message` varchar(255) NOT NULL,
  `status` varchar(20) NOT NULL DEFAULT 'open',
  `process_name` varchar(255) DEFAULT NULL,
  `pid` int DEFAULT NULL,
  `proc_create_time` double DEFAULT NULL,
  `features` json DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_inc_status` (`status`,`device_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ai_incidents`
--

LOCK TABLES `ai_incidents` WRITE;
/*!40000 ALTER TABLE `ai_incidents` DISABLE KEYS */;
/*!40000 ALTER TABLE `ai_incidents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `alert_devices`
--

DROP TABLE IF EXISTS `alert_devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `alert_devices` (
  `alert_id` int NOT NULL,
  `device_id` int NOT NULL,
  PRIMARY KEY (`alert_id`,`device_id`),
  KEY `idx_alert_devices_device` (`device_id`),
  CONSTRAINT `fk_alert_devices_alert` FOREIGN KEY (`alert_id`) REFERENCES `alerts` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_alert_devices_device` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alert_devices`
--

LOCK TABLES `alert_devices` WRITE;
/*!40000 ALTER TABLE `alert_devices` DISABLE KEYS */;
/*!40000 ALTER TABLE `alert_devices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `alerts`
--

DROP TABLE IF EXISTS `alerts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `alerts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `lv` varchar(10) NOT NULL DEFAULT 'info',
  `title` varchar(200) NOT NULL,
  `msg` text NOT NULL,
  `cause` varchar(500) NOT NULL DEFAULT '',
  `action` varchar(500) NOT NULL DEFAULT '',
  `timestamp` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_alerts_ts` (`timestamp` DESC),
  KEY `idx_alerts_lv_ts` (`lv`,`timestamp` DESC),
  CONSTRAINT `ck_alerts_lv` CHECK ((`lv` in (_utf8mb4'ok',_utf8mb4'warn',_utf8mb4'crit',_utf8mb4'info')))
) ENGINE=InnoDB AUTO_INCREMENT=56 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `alerts`
--

LOCK TABLES `alerts` WRITE;
/*!40000 ALTER TABLE `alerts` DISABLE KEYS */;
INSERT INTO `alerts` VALUES (1,'crit','[CRITICAL] 장애 위험 감지','Distribution SW 트래픽 급증','분산 스위치 구간 트래픽 증가','상위 링크 대역폭 확인','2026-10-05 21:12:04.000'),(2,'warn','Dist-SW-01 CPU 고부하','CPU 82%','패킷 처리량 증가','트래픽 분산 확인','2026-10-05 21:12:04.000'),(3,'info','AI 엔진 정상 기동','이상 감지 모델 로드됨','시스템 시작','모니터링 계속','2026-10-05 21:12:04.000'),(4,'crit','[TEST] 신규 경고','테스트 알림','테스트','확인','2026-10-05 21:22:41.000'),(5,'crit','🤖 AI 이상 감지','의심 프로세스 System Idle Process(PID 0) 감지! 차단하시겠습니까?','위험도 72.1% · 주요 요인: 트래픽','승인/차단 또는 오탐/재학습을 선택하세요','2026-10-09 10:56:14.596'),(6,'info','♻ 오탐 재학습','위험도 72.1% → 2.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:33.093'),(7,'info','♻ 오탐 재학습','위험도 72.1% → 2.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:33.146'),(8,'info','♻ 오탐 재학습','위험도 2.3% → 1.0%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:40.349'),(9,'info','♻ 오탐 재학습','위험도 2.3% → 1.0%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:40.421'),(10,'info','♻ 오탐 재학습','위험도 1.0% → 1.0%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:47.414'),(11,'info','♻ 오탐 재학습','위험도 1.0% → 1.0%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:47.496'),(12,'info','♻ 오탐 재학습','위험도 1.0% → 0.9%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:53.468'),(13,'info','♻ 오탐 재학습','위험도 1.0% → 0.9%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:12:53.554'),(14,'info','♻ 오탐 재학습','위험도 0.9% → 0.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:01.148'),(15,'info','♻ 오탐 재학습','위험도 0.9% → 0.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:01.303'),(16,'info','♻ 오탐 재학습','위험도 0.7% → 0.6%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:05.203'),(17,'info','♻ 오탐 재학습','위험도 0.7% → 0.6%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:05.491'),(18,'info','♻ 오탐 재학습','위험도 0.6% → 0.6%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:12.494'),(19,'info','♻ 오탐 재학습','위험도 0.6% → 0.6%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:12.603'),(20,'info','♻ 오탐 재학습','위험도 0.6% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:17.446'),(21,'info','♻ 오탐 재학습','위험도 0.6% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:17.625'),(22,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:21.467'),(23,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:21.529'),(24,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:26.536'),(25,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:26.693'),(26,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:31.059'),(27,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:31.709'),(28,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:37.680'),(29,'info','♻ 오탐 재학습','위험도 0.4% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:37.734'),(30,'info','♻ 오탐 재학습','위험도 0.4% → 0.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:40.158'),(31,'info','♻ 오탐 재학습','위험도 0.3% → 0.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:45.539'),(32,'info','♻ 오탐 재학습','위험도 0.3% → 0.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:45.660'),(33,'info','♻ 오탐 재학습','위험도 0.3% → 0.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:48.364'),(34,'info','♻ 오탐 재학습','위험도 0.4% → 0.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:55.003'),(35,'info','♻ 오탐 재학습','위험도 0.4% → 0.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-09 11:13:55.150'),(36,'crit','✖ 지환의 ipad 오프라인','지환의 ipad(172.28.4.132) 응답이 없습니다','핑 3회 연속 실패','전원과 Wi-Fi 연결을 확인하세요','2026-10-09 11:59:14.996'),(37,'crit','🤖 AI 이상 감지','장비 #85: CPU 이상 징후 감지','위험도 70.7% · 주요 요인: CPU','승인/차단 또는 오탐/재학습을 선택하세요','2026-10-19 15:36:32.067'),(38,'info','♻ 오탐 재학습','위험도 70.7% → 10.1%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:40:52.953'),(39,'info','♻ 오탐 재학습','위험도 70.7% → 10.1%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:40:53.037'),(40,'info','♻ 오탐 재학습','위험도 10.1% → 6.9%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:40:56.772'),(41,'info','♻ 오탐 재학습','위험도 6.9% → 5.5%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:41:02.907'),(42,'info','♻ 오탐 재학습','위험도 5.5% → 4.3%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:41:07.389'),(43,'info','♻ 오탐 재학습','위험도 4.3% → 3.6%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:41:11.023'),(44,'info','♻ 오탐 재학습','위험도 3.6% → 3.1%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:41:14.518'),(45,'info','♻ 오탐 재학습','위험도 3.1% → 3.0%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:41:19.010'),(46,'crit','🤖 AI 이상 감지','장비 #85: 패킷 손실 이상 징후 감지','위험도 77.5% · 주요 요인: 패킷 손실','승인/차단 또는 오탐/재학습을 선택하세요','2026-10-19 15:45:44.395'),(47,'info','♻ 오탐 재학습','위험도 77.5% → 23.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:47.934'),(48,'info','♻ 오탐 재학습','위험도 77.5% → 15.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:49.098'),(49,'info','♻ 오탐 재학습','위험도 42.3% → 11.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:49.804'),(50,'info','♻ 오탐 재학습','위험도 23.7% → 11.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:49.919'),(51,'info','♻ 오탐 재학습','위험도 11.7% → 7.4%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:51.234'),(52,'info','♻ 오탐 재학습','위험도 7.4% → 5.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:54.336'),(53,'info','♻ 오탐 재학습','위험도 7.4% → 5.7%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:54.416'),(54,'info','♻ 오탐 재학습','위험도 5.7% → 5.1%','관리자가 오탐으로 판정','정상 기준선에 반영됨','2026-10-19 15:47:56.141'),(55,'info','기기 등록','테스트 환경 (118.221.161.6) 등록','관리자 승인','','2026-10-21 13:19:07.423');
/*!40000 ALTER TABLE `alerts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `devices`
--

DROP TABLE IF EXISTS `devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `devices` (
  `id` int NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `type` varchar(20) NOT NULL DEFAULT 'server',
  `owner_id` int DEFAULT NULL,
  `x` double DEFAULT NULL,
  `y` double DEFAULT NULL,
  `vlan_id` int NOT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `status` varchar(20) DEFAULT 'registered',
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_devices_ip` (`ip`),
  KEY `idx_devices_vlan` (`vlan_id`),
  KEY `idx_devices_owner` (`owner_id`),
  CONSTRAINT `fk_devices_owner` FOREIGN KEY (`owner_id`) REFERENCES `users` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  CONSTRAINT `fk_devices_vlan` FOREIGN KEY (`vlan_id`) REFERENCES `vlans` (`id`) ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT `ck_devices_type` CHECK ((`type` in (_utf8mb4'server',_utf8mb4'router',_utf8mb4'firewall',_utf8mb4'switch',_utf8mb4'pc',_utf8mb4'printer',_utf8mb4'access-point',_utf8mb4'app',_utf8mb4'mobile'))),
  CONSTRAINT `ck_devices_x` CHECK (((`x` is null) or (`x` between -(50) and 150))),
  CONSTRAINT `ck_devices_xy` CHECK (((`x` is null) = (`y` is null))),
  CONSTRAINT `ck_devices_y` CHECK (((`y` is null) or (`y` between -(50) and 150)))
) ENGINE=InnoDB AUTO_INCREMENT=129 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `devices`
--

LOCK TABLES `devices` WRITE;
/*!40000 ALTER TABLE `devices` DISABLE KEYS */;
INSERT INTO `devices` VALUES (128,'테스트 환경','118.221.161.6','mobile',5,49.3,27.6,1,'2026-10-21 13:19:07.421','registered');
/*!40000 ALTER TABLE `devices` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `endpoint_events`
--

DROP TABLE IF EXISTS `endpoint_events`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `endpoint_events` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `action` varchar(20) NOT NULL,
  `process_name` varchar(255) NOT NULL,
  `pid` int DEFAULT NULL,
  `reason` varchar(500) NOT NULL DEFAULT '',
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_endpoint_events_created` (`created_at` DESC)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `endpoint_events`
--

LOCK TABLES `endpoint_events` WRITE;
/*!40000 ALTER TABLE `endpoint_events` DISABLE KEYS */;
INSERT INTO `endpoint_events` VALUES (1,'block','unknown_tool.exe',4321,'미인증 실행파일 감지','2026-09-29 13:36:40.739'),(2,'allow','chrome.exe',1024,'서명된 프로세스','2026-09-29 13:36:40.739'),(3,'blocked','python.exe',8964,'Suspicious process detected: python.exe','2026-10-01 22:31:51.971');
/*!40000 ALTER TABLE `endpoint_events` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `links`
--

DROP TABLE IF EXISTS `links`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `links` (
  `source_id` int NOT NULL,
  `target_id` int NOT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`source_id`,`target_id`),
  KEY `idx_links_target` (`target_id`),
  CONSTRAINT `fk_links_source` FOREIGN KEY (`source_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `fk_links_target` FOREIGN KEY (`target_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `links`
--

LOCK TABLES `links` WRITE;
/*!40000 ALTER TABLE `links` DISABLE KEYS */;
/*!40000 ALTER TABLE `links` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ping_logs`
--

DROP TABLE IF EXISTS `ping_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `ping_logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL,
  `ok` tinyint(1) NOT NULL,
  `rtt_ms` double DEFAULT NULL,
  `created_at` timestamp(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_ping_dev` (`device_id`,`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6476 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ping_logs`
--

LOCK TABLES `ping_logs` WRITE;
/*!40000 ALTER TABLE `ping_logs` DISABLE KEYS */;
INSERT INTO `ping_logs` VALUES (5233,89,0,NULL,'2026-10-09 02:17:26.087');
/*!40000 ALTER TABLE `ping_logs` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `telemetry`
--

DROP TABLE IF EXISTS `telemetry`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `telemetry` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `device_id` int NOT NULL,
  `cpu_usage` double NOT NULL,
  `ram_usage` double NOT NULL,
  `traffic_in_mbps` double NOT NULL DEFAULT '0',
  `packet_loss` double NOT NULL DEFAULT '0',
  `timestamp` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `idx_telemetry_ts` (`timestamp` DESC),
  KEY `idx_telemetry_device_ts` (`device_id`,`timestamp` DESC),
  CONSTRAINT `fk_telemetry_device` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `ck_telemetry_cpu` CHECK ((`cpu_usage` between 0 and 100)),
  CONSTRAINT `ck_telemetry_in` CHECK ((`traffic_in_mbps` >= 0)),
  CONSTRAINT `ck_telemetry_loss` CHECK ((`packet_loss` between 0 and 100)),
  CONSTRAINT `ck_telemetry_ram` CHECK ((`ram_usage` between 0 and 100))
) ENGINE=InnoDB AUTO_INCREMENT=13330 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `telemetry`
--

LOCK TABLES `telemetry` WRITE;
/*!40000 ALTER TABLE `telemetry` DISABLE KEYS */;
/*!40000 ALTER TABLE `telemetry` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_vlans`
--

DROP TABLE IF EXISTS `user_vlans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_vlans` (
  `id` int NOT NULL AUTO_INCREMENT,
  `user_id` int NOT NULL,
  `vlan_id` int NOT NULL,
  `access_level` varchar(20) DEFAULT 'view',
  `created_at` datetime(3) DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_user_vlans` (`user_id`,`vlan_id`),
  KEY `vlan_id` (`vlan_id`),
  CONSTRAINT `user_vlans_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_vlans_ibfk_2` FOREIGN KEY (`vlan_id`) REFERENCES `vlans` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_vlans`
--

LOCK TABLES `user_vlans` WRITE;
/*!40000 ALTER TABLE `user_vlans` DISABLE KEYS */;
INSERT INTO `user_vlans` VALUES (6,5,3,'admin','2026-10-06 14:04:52.570'),(7,5,2,'admin','2026-10-06 14:04:52.570'),(8,5,1,'admin','2026-10-06 14:04:52.570'),(37,6,2,'view','2026-10-06 14:29:07.199'),(38,7,1,'view','2026-10-06 14:29:07.199'),(39,8,1,'view','2026-10-06 14:29:07.199'),(40,9,3,'view','2026-10-06 14:29:07.199'),(41,10,2,'view','2026-10-06 14:29:07.199'),(42,11,3,'view','2026-10-06 14:29:07.199'),(43,12,3,'view','2026-10-06 14:29:07.199'),(44,13,1,'view','2026-10-06 14:29:07.199');
/*!40000 ALTER TABLE `user_vlans` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(255) NOT NULL,
  `role` varchar(10) NOT NULL DEFAULT 'user',
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_users_username` (`username`),
  CONSTRAINT `ck_users_role` CHECK ((`role` in (_utf8mb4'admin',_utf8mb4'user')))
) ENGINE=InnoDB AUTO_INCREMENT=14 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (5,'이지환','$2b$12$7GecLUYbGxoNO0wMIJgvnehLUl26Upo1Yn9pPE9K9Je5HjTfH373q','admin','2026-10-06 13:28:28.000'),(6,'김태현','$2b$12$jTMEhkJOLdrXPeRBnT1cKOHBPr1yPF3xkUFwJ.4npgQ6DLWwsu3T2','user','2026-10-06 13:28:28.000'),(7,'장우진','$2b$12$ttBcf3ZwdWhrc.6D7VAB9uSffe7Y1u0llmB7YstRXZs1uHTMslAIO','user','2026-10-06 13:28:28.000'),(8,'양이수','$2b$12$M8YvS0XK.CywxzwGET2asOCWJhxIl4iCpeLOdfVcIKBUqR8Z4uwT6','user','2026-10-06 13:28:28.000'),(9,'구본학','$2b$12$boK0E12imSpqa60tNuRKLOk2hJYfNS3wsCfTsNhQ8Dio1dJQRfqNG','user','2026-10-06 13:28:28.000'),(10,'박동연','$2b$12$5dnHtVdshNe7DIMZ2ESaYeILskb1HWAogmP6HOk5qp5pbB2zEQL0i','user','2026-10-06 13:28:28.000'),(11,'김민석','$2b$12$miL5985YvF0hehII4KGvh.dAK/KBhCJsTSP.Sa4hI7/8O5JmT4sU6','user','2026-10-06 13:28:28.000'),(12,'최민규','$2b$12$.ogKmrNFL6aaeKm/3bqhKeVapdMqopLK2BbNS/21qfJvPE9kFikxC','user','2026-10-06 13:28:28.000'),(13,'김범수','$2b$12$TkSkie7D4GeIwVMWh3FXDOiCdR/zwFjq6Rv6e13/X3ZVAyxv0Easm','user','2026-10-06 13:28:28.000');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Temporary view structure for view `v_latest_telemetry`
--

DROP TABLE IF EXISTS `v_latest_telemetry`;
/*!50001 DROP VIEW IF EXISTS `v_latest_telemetry`*/;
SET @saved_cs_client     = @@character_set_client;
/*!50503 SET character_set_client = utf8mb4 */;
/*!50001 CREATE VIEW `v_latest_telemetry` AS SELECT 
 1 AS `device_id`,
 1 AS `cpu_usage`,
 1 AS `ram_usage`,
 1 AS `traffic_in_mbps`,
 1 AS `packet_loss`,
 1 AS `timestamp`*/;
SET character_set_client = @saved_cs_client;

--
-- Table structure for table `vlans`
--

DROP TABLE IF EXISTS `vlans`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `vlans` (
  `id` int NOT NULL AUTO_INCREMENT,
  `code` varchar(20) NOT NULL,
  `name` varchar(100) NOT NULL,
  `cidr` varchar(50) DEFAULT NULL,
  `color` char(7) NOT NULL DEFAULT '#a78bfa',
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `ux_vlans_code` (`code`),
  UNIQUE KEY `ux_vlans_name` (`name`),
  CONSTRAINT `ck_vlans_color` CHECK ((left(`color`,1) = _utf8mb4'#'))
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `vlans`
--

LOCK TABLES `vlans` WRITE;
/*!40000 ALTER TABLE `vlans` DISABLE KEYS */;
INSERT INTO `vlans` VALUES (1,'100','Backbone (백본)','192.168.1.0/24','#22d3ee','2026-10-03 22:30:24.916'),(2,'101','VLAN1 (Dev)','10.0.0.0/24','#a78bfa','2026-10-03 22:30:24.916'),(3,'102','VLAN2 (Biz)','192.168.1.0/25','#fb923c','2026-10-03 22:30:24.916');
/*!40000 ALTER TABLE `vlans` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Final view structure for view `v_latest_telemetry`
--

/*!50001 DROP VIEW IF EXISTS `v_latest_telemetry`*/;
/*!50001 SET @saved_cs_client          = @@character_set_client */;
/*!50001 SET @saved_cs_results         = @@character_set_results */;
/*!50001 SET @saved_col_connection     = @@collation_connection */;
/*!50001 SET character_set_client      = utf8mb4 */;
/*!50001 SET character_set_results     = utf8mb4 */;
/*!50001 SET collation_connection      = utf8mb4_0900_ai_ci */;
/*!50001 CREATE ALGORITHM=UNDEFINED */
/*!50013 DEFINER=`avnadmin`@`%` SQL SECURITY DEFINER */
/*!50001 VIEW `v_latest_telemetry` AS select `t`.`device_id` AS `device_id`,`t`.`cpu_usage` AS `cpu_usage`,`t`.`ram_usage` AS `ram_usage`,`t`.`traffic_in_mbps` AS `traffic_in_mbps`,`t`.`packet_loss` AS `packet_loss`,`t`.`timestamp` AS `timestamp` from (`devices` `d` join `telemetry` `t` on((`t`.`id` = (select `t2`.`id` from `telemetry` `t2` where (`t2`.`device_id` = `d`.`id`) order by `t2`.`timestamp` desc,`t2`.`id` desc limit 1)))) */;
/*!50001 SET character_set_client      = @saved_cs_client */;
/*!50001 SET character_set_results     = @saved_cs_results */;
/*!50001 SET collation_connection      = @saved_col_connection */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-10-22 18:37:42

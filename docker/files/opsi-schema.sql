-- MySQL dump 10.17  Distrib 10.3.25-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: opsi
-- ------------------------------------------------------
-- Server version	10.3.25-MariaDB-0+deb10u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `AUDIT_SOFTWARE_TO_LICENSE_POOL`
--

DROP TABLE IF EXISTS `AUDIT_SOFTWARE_TO_LICENSE_POOL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `AUDIT_SOFTWARE_TO_LICENSE_POOL` (
  `licensePoolId` varchar(100) NOT NULL,
  `name` varchar(100) NOT NULL,
  `version` varchar(100) NOT NULL,
  `subVersion` varchar(100) NOT NULL,
  `language` varchar(10) NOT NULL,
  `architecture` varchar(3) NOT NULL,
  PRIMARY KEY (`name`,`version`,`subVersion`,`language`,`architecture`),
  KEY `licensePoolId` (`licensePoolId`),
  CONSTRAINT `AUDIT_SOFTWARE_TO_LICENSE_POOL_ibfk_1` FOREIGN KEY (`licensePoolId`) REFERENCES `LICENSE_POOL` (`licensePoolId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `CONFIG`
--

DROP TABLE IF EXISTS `CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CONFIG` (
  `configId` varchar(200) NOT NULL,
  `type` varchar(30) NOT NULL,
  `description` varchar(256) DEFAULT NULL,
  `multiValue` tinyint(1) NOT NULL,
  `editable` tinyint(1) NOT NULL,
  PRIMARY KEY (`configId`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `CONFIG_STATE`
--

DROP TABLE IF EXISTS `CONFIG_STATE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CONFIG_STATE` (
  `config_state_id` int(11) NOT NULL AUTO_INCREMENT,
  `configId` varchar(200) NOT NULL,
  `objectId` varchar(255) NOT NULL,
  `values` text DEFAULT NULL,
  PRIMARY KEY (`config_state_id`),
  KEY `configId` (`configId`),
  KEY `objectId` (`objectId`)
) ENGINE=InnoDB AUTO_INCREMENT=719823 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `CONFIG_STATE_LOG`
--

DROP TABLE IF EXISTS `CONFIG_STATE_LOG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CONFIG_STATE_LOG` (
  `config_state_id` int(11) NOT NULL AUTO_INCREMENT,
  `configId` varchar(200) NOT NULL,
  `objectId` varchar(255) NOT NULL,
  `svalues` text DEFAULT NULL,
  `svaluesplain` text DEFAULT NULL,
  `action` varchar(255) DEFAULT NULL,
  `Created` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`config_state_id`),
  KEY `index_config_state_configId` (`configId`),
  KEY `index_config_state_objectId` (`objectId`)
) ENGINE=InnoDB AUTO_INCREMENT=10393 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `CONFIG_VALUE`
--

DROP TABLE IF EXISTS `CONFIG_VALUE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `CONFIG_VALUE` (
  `config_value_id` int(11) NOT NULL AUTO_INCREMENT,
  `configId` varchar(200) NOT NULL,
  `value` text DEFAULT NULL,
  `isDefault` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`config_value_id`),
  KEY `configId` (`configId`),
  CONSTRAINT `CONFIG_VALUE_ibfk_1` FOREIGN KEY (`configId`) REFERENCES `CONFIG` (`configId`)
) ENGINE=InnoDB AUTO_INCREMENT=1877871 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `GROUP`
--

DROP TABLE IF EXISTS `GROUP`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `GROUP` (
  `type` varchar(30) NOT NULL,
  `groupId` varchar(255) NOT NULL,
  `parentGroupId` varchar(255) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `notes` varchar(500) DEFAULT NULL,
  PRIMARY KEY (`type`,`groupId`),
  KEY `parentGroupId` (`parentGroupId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_1394_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_1394_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_1394_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=505 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_AUDIO_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_AUDIO_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_AUDIO_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=8072 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_BASE_BOARD`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_BASE_BOARD`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_BASE_BOARD` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=41726 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_BIOS`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_BIOS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_BIOS` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `version` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=40819 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_CACHE_MEMORY`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_CACHE_MEMORY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_CACHE_MEMORY` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=87043 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_CHASSIS`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_CHASSIS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_CHASSIS` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `installDate` varchar(40) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=70499 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_COMPUTER_SYSTEM`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_COMPUTER_SYSTEM`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_COMPUTER_SYSTEM` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `totalPhysicalMemory` bigint(20) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `systemType` varchar(50) DEFAULT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `dellexpresscode` varchar(50) DEFAULT NULL,
  `sku` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=71353 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_DISK_PARTITION`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_DISK_PARTITION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_DISK_PARTITION` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `index` int(11) DEFAULT NULL,
  `driveLetter` varchar(2) DEFAULT NULL,
  `freeSpace` bigint(20) DEFAULT NULL,
  `startingOffset` bigint(20) DEFAULT NULL,
  `filesystem` varchar(50) DEFAULT NULL,
  `size` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=128970 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_FLOPPY_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_FLOPPY_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_FLOPPY_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=465 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_FLOPPY_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_FLOPPY_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_FLOPPY_DRIVE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `size` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=94 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_HARDDISK_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_HARDDISK_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_HARDDISK_DRIVE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `partitions` tinyint(4) DEFAULT NULL,
  `size` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=45927 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_HDAUDIO_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_HDAUDIO_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_HDAUDIO_DEVICE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=9213 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_IDE_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_IDE_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_IDE_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=40768 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_KEYBOARD`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_KEYBOARD`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_KEYBOARD` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=920 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_MEMORY_BANK`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_MEMORY_BANK`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_MEMORY_BANK` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `location` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=40808 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_MEMORY_MODULE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_MEMORY_MODULE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_MEMORY_MODULE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `tag` varchar(100) DEFAULT NULL,
  `deviceLocator` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=42828 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_MONITOR`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_MONITOR`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_MONITOR` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `screenHeight` int(11) DEFAULT NULL,
  `screenWidth` int(11) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1089 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_NETWORK_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_NETWORK_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_NETWORK_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `macAddress` varchar(20) DEFAULT NULL,
  `ipAddress` varchar(60) DEFAULT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `ipEnabled` varchar(60) DEFAULT NULL,
  `netConnectionStatus` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=144837 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_OPTICAL_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_OPTICAL_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_OPTICAL_DRIVE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `driveLetter` varchar(2) DEFAULT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `size` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=27984 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_PCI_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_PCI_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_PCI_DEVICE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `busId` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1413253 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_PCMCIA_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_PCMCIA_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_PCMCIA_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_POINTING_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_POINTING_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_POINTING_DEVICE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1459 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_PORT_CONNECTOR`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_PORT_CONNECTOR`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_PORT_CONNECTOR` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `internalConnectorType` varchar(60) DEFAULT NULL,
  `name` varchar(60) DEFAULT NULL,
  `externalConnectorType` varchar(60) DEFAULT NULL,
  `internalDesignator` varchar(60) DEFAULT NULL,
  `externalDesignator` varchar(60) DEFAULT NULL,
  `connectorType` varchar(60) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=190375 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_PRINTER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_PRINTER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_PRINTER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `driverName` varchar(100) DEFAULT NULL,
  `port` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1922 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_PROCESSOR`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_PROCESSOR`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_PROCESSOR` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `socketDesignation` varchar(100) DEFAULT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `voltage` double DEFAULT NULL,
  `extClock` bigint(20) DEFAULT NULL,
  `currentClockSpeed` bigint(20) DEFAULT NULL,
  `NumberOfCores` tinyint(4) DEFAULT NULL,
  `NumberOfLogicalCores` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=1335767 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_SCSI_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_SCSI_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_SCSI_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=35533 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_SYSTEM_SLOT`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_SYSTEM_SLOT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_SYSTEM_SLOT` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `status` varchar(20) DEFAULT NULL,
  `maxDataWidth` int(11) DEFAULT NULL,
  `currentUsage` varchar(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=195314 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_TAPE_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_TAPE_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_TAPE_DRIVE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  `size` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_USB_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_USB_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_USB_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=26853 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_USB_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_USB_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_USB_DEVICE` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=29251 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_CONFIG_VIDEO_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_CONFIG_VIDEO_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_CONFIG_VIDEO_CONTROLLER` (
  `config_id` int(11) NOT NULL AUTO_INCREMENT,
  `hostId` varchar(255) NOT NULL,
  `hardware_id` int(11) NOT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `serialNumber` varchar(50) DEFAULT NULL,
  PRIMARY KEY (`config_id`)
) ENGINE=InnoDB AUTO_INCREMENT=43536 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_1394_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_1394_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_1394_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=51 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_AUDIO_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_AUDIO_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_AUDIO_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=317 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_BASE_BOARD`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_BASE_BOARD`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_BASE_BOARD` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `product` varchar(100) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=270 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_BIOS`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_BIOS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_BIOS` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=130 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_CACHE_MEMORY`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_CACHE_MEMORY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_CACHE_MEMORY` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `installedSize` int(11) DEFAULT NULL,
  `name` varchar(50) DEFAULT NULL,
  `level` varchar(10) DEFAULT NULL,
  `maxSize` int(11) DEFAULT NULL,
  `location` varchar(10) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=318 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_CHASSIS`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_CHASSIS`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_CHASSIS` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `chassisType` varchar(40) DEFAULT NULL,
  `name` varchar(64) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=50 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_COMPUTER_SYSTEM`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_COMPUTER_SYSTEM`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_COMPUTER_SYSTEM` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=289 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_DISK_PARTITION`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_DISK_PARTITION`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_DISK_PARTITION` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=321 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_FLOPPY_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_FLOPPY_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_FLOPPY_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_FLOPPY_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_FLOPPY_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_FLOPPY_DRIVE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_HARDDISK_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_HARDDISK_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_HARDDISK_DRIVE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `sectors` bigint(20) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `heads` int(11) DEFAULT NULL,
  `cylinders` int(11) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=618 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_HDAUDIO_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_HDAUDIO_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_HDAUDIO_DEVICE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `address` varchar(10) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=299 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_IDE_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_IDE_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_IDE_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=368 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_KEYBOARD`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_KEYBOARD`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_KEYBOARD` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `numberOfFunctionKeys` int(11) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=37 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_MEMORY_BANK`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_MEMORY_BANK`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_MEMORY_BANK` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `slots` tinyint(4) DEFAULT NULL,
  `maxCapacity` bigint(20) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=173 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_MEMORY_MODULE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_MEMORY_MODULE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_MEMORY_MODULE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `formFactor` varchar(10) DEFAULT NULL,
  `capacity` bigint(20) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `memoryType` varchar(20) DEFAULT NULL,
  `dataWidth` int(11) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `speed` bigint(20) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=586 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_MONITOR`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_MONITOR`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_MONITOR` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=31 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_NETWORK_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_NETWORK_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_NETWORK_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `maxSpeed` bigint(20) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `autoSense` varchar(20) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `adapterType` varchar(40) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=890 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_OPTICAL_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_OPTICAL_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_OPTICAL_DRIVE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=273 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_PCI_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_PCI_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_PCI_DEVICE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5638 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_PCMCIA_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_PCMCIA_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_PCMCIA_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_POINTING_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_POINTING_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_POINTING_DEVICE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `numberOfButtons` tinyint(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=73 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_PORT_CONNECTOR`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_PORT_CONNECTOR`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_PORT_CONNECTOR` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=9 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_PRINTER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_PRINTER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_PRINTER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `verticalResolution` int(11) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `paperSizesSupported` varchar(200) DEFAULT NULL,
  `capabilities` varchar(200) DEFAULT NULL,
  `horizontalResolution` int(11) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=221 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_PROCESSOR`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_PROCESSOR`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_PROCESSOR` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `family` varchar(50) DEFAULT NULL,
  `addressWidth` int(11) DEFAULT NULL,
  `maxClockSpeed` bigint(20) DEFAULT NULL,
  `architecture` varchar(50) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=539 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_SCSI_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_SCSI_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_SCSI_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=79 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_SYSTEM_SLOT`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_SYSTEM_SLOT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_SYSTEM_SLOT` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(50) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=380 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_TAPE_DRIVE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_TAPE_DRIVE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_TAPE_DRIVE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_USB_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_USB_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_USB_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=982 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_USB_DEVICE`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_USB_DEVICE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_USB_DEVICE` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `status` varchar(200) DEFAULT NULL,
  `vendorId` varchar(4) DEFAULT NULL,
  `interfaceSubClass` varchar(500) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `interfaceClass` varchar(500) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `usbRelease` varchar(8) DEFAULT NULL,
  `interfaceProtocol` varchar(200) DEFAULT NULL,
  `maxPower` int(11) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=578 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HARDWARE_DEVICE_VIDEO_CONTROLLER`
--

DROP TABLE IF EXISTS `HARDWARE_DEVICE_VIDEO_CONTROLLER`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HARDWARE_DEVICE_VIDEO_CONTROLLER` (
  `hardware_id` int(11) NOT NULL AUTO_INCREMENT,
  `vendorId` varchar(4) DEFAULT NULL,
  `vendor` varchar(50) DEFAULT NULL,
  `name` varchar(100) DEFAULT NULL,
  `videoProcessor` varchar(20) DEFAULT NULL,
  `subsystemDeviceId` varchar(4) DEFAULT NULL,
  `subsystemVendorId` varchar(4) DEFAULT NULL,
  `deviceType` varchar(10) DEFAULT NULL,
  `deviceId` varchar(4) DEFAULT NULL,
  `model` varchar(100) DEFAULT NULL,
  `revision` varchar(8) DEFAULT NULL,
  `adapterRAM` bigint(20) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  PRIMARY KEY (`hardware_id`)
) ENGINE=InnoDB AUTO_INCREMENT=479 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `HOST`
--

DROP TABLE IF EXISTS `HOST`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `HOST` (
  `hostId` varchar(255) NOT NULL,
  `type` varchar(30) DEFAULT NULL,
  `description` varchar(100) DEFAULT NULL,
  `notes` varchar(500) DEFAULT NULL,
  `hardwareAddress` varchar(17) DEFAULT NULL,
  `ipAddress` varchar(15) DEFAULT NULL,
  `inventoryNumber` varchar(64) NOT NULL,
  `created` timestamp NOT NULL DEFAULT current_timestamp(),
  `lastSeen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `opsiHostKey` varchar(32) DEFAULT NULL,
  `oneTimePassword` varchar(32) DEFAULT NULL,
  `maxBandwidth` int(11) DEFAULT NULL,
  `depotLocalUrl` varchar(128) DEFAULT NULL,
  `depotRemoteUrl` varchar(255) DEFAULT NULL,
  `depotWebdavUrl` varchar(255) DEFAULT NULL,
  `repositoryLocalUrl` varchar(128) DEFAULT NULL,
  `repositoryRemoteUrl` varchar(255) DEFAULT NULL,
  `networkAddress` varchar(31) DEFAULT NULL,
  `isMasterDepot` tinyint(1) DEFAULT NULL,
  `masterDepotId` varchar(255) DEFAULT NULL,
  `workbenchLocalUrl` varchar(128) DEFAULT NULL,
  `workbenchRemoteUrl` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`hostId`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `LICENSE_CONTRACT`
--

DROP TABLE IF EXISTS `LICENSE_CONTRACT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `LICENSE_CONTRACT` (
  `licenseContractId` varchar(100) NOT NULL,
  `partner` varchar(100) DEFAULT NULL,
  `conclusionDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `notificationDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `expirationDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `notes` varchar(1000) DEFAULT NULL,
  `type` varchar(30) NOT NULL,
  `description` varchar(100) NOT NULL,
  PRIMARY KEY (`licenseContractId`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `LICENSE_ON_CLIENT`
--

DROP TABLE IF EXISTS `LICENSE_ON_CLIENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `LICENSE_ON_CLIENT` (
  `license_on_client_id` int(11) NOT NULL AUTO_INCREMENT,
  `softwareLicenseId` varchar(100) NOT NULL,
  `licensePoolId` varchar(100) NOT NULL,
  `clientId` varchar(255) DEFAULT NULL,
  `licenseKey` varchar(1024) DEFAULT NULL,
  `notes` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`license_on_client_id`),
  KEY `softwareLicenseId` (`softwareLicenseId`,`licensePoolId`),
  KEY `clientId` (`clientId`),
  CONSTRAINT `LICENSE_ON_CLIENT_ibfk_1` FOREIGN KEY (`softwareLicenseId`, `licensePoolId`) REFERENCES `SOFTWARE_LICENSE_TO_LICENSE_POOL` (`softwareLicenseId`, `licensePoolId`)
) ENGINE=InnoDB AUTO_INCREMENT=3318 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `LICENSE_POOL`
--

DROP TABLE IF EXISTS `LICENSE_POOL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `LICENSE_POOL` (
  `licensePoolId` varchar(100) NOT NULL,
  `description` varchar(200) DEFAULT NULL,
  `type` varchar(30) NOT NULL,
  PRIMARY KEY (`licensePoolId`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `LOG_CONFIG`
--

DROP TABLE IF EXISTS `LOG_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `LOG_CONFIG` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `configId` varchar(200) NOT NULL,
  `type` varchar(30) NOT NULL,
  `description` varchar(256) DEFAULT NULL,
  `multiValue` tinyint(1) NOT NULL,
  `editable` tinyint(1) NOT NULL,
  `action` varchar(255) DEFAULT NULL,
  `Created` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `index_config_type` (`type`)
) ENGINE=InnoDB AUTO_INCREMENT=40542 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `LOG_CONFIG_VALUE`
--

DROP TABLE IF EXISTS `LOG_CONFIG_VALUE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `LOG_CONFIG_VALUE` (
  `config_value_id` int(11) NOT NULL AUTO_INCREMENT,
  `configId` varchar(200) NOT NULL,
  `value` text DEFAULT NULL,
  `isDefault` tinyint(1) DEFAULT NULL,
  `action` varchar(255) DEFAULT NULL,
  `Created` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`config_value_id`),
  KEY `configId` (`configId`)
) ENGINE=InnoDB AUTO_INCREMENT=166473 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `OBJECT_TO_GROUP`
--

DROP TABLE IF EXISTS `OBJECT_TO_GROUP`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `OBJECT_TO_GROUP` (
  `object_to_group_id` int(11) NOT NULL AUTO_INCREMENT,
  `groupType` varchar(30) NOT NULL,
  `groupId` varchar(255) NOT NULL,
  `objectId` varchar(255) NOT NULL,
  PRIMARY KEY (`object_to_group_id`),
  KEY `groupType` (`groupType`,`groupId`),
  KEY `objectId` (`objectId`),
  CONSTRAINT `OBJECT_TO_GROUP_ibfk_1` FOREIGN KEY (`groupType`, `groupId`) REFERENCES `GROUP` (`type`, `groupId`)
) ENGINE=InnoDB AUTO_INCREMENT=7355 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `OPSI_SCHEMA`
--

DROP TABLE IF EXISTS `OPSI_SCHEMA`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `OPSI_SCHEMA` (
  `version` int(11) NOT NULL,
  `updateStarted` timestamp NOT NULL DEFAULT current_timestamp(),
  `updateEnded` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT`
--

DROP TABLE IF EXISTS `PRODUCT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT` (
  `productId` varchar(255) NOT NULL DEFAULT '',
  `productVersion` varchar(32) NOT NULL,
  `packageVersion` varchar(16) NOT NULL,
  `type` varchar(32) NOT NULL,
  `name` varchar(128) NOT NULL,
  `licenseRequired` varchar(50) DEFAULT NULL,
  `setupScript` varchar(50) DEFAULT NULL,
  `uninstallScript` varchar(50) DEFAULT NULL,
  `updateScript` varchar(50) DEFAULT NULL,
  `alwaysScript` varchar(50) DEFAULT NULL,
  `onceScript` varchar(50) DEFAULT NULL,
  `customScript` varchar(50) DEFAULT NULL,
  `userLoginScript` varchar(50) DEFAULT NULL,
  `priority` int(11) DEFAULT NULL,
  `description` text DEFAULT NULL,
  `advice` text DEFAULT NULL,
  `pxeConfigTemplate` varchar(50) DEFAULT NULL,
  `changelog` text DEFAULT NULL,
  PRIMARY KEY (`productId`,`productVersion`,`packageVersion`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_DEPENDENCY`
--

DROP TABLE IF EXISTS `PRODUCT_DEPENDENCY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_DEPENDENCY` (
  `productId` varchar(255) NOT NULL DEFAULT '',
  `productVersion` varchar(32) NOT NULL,
  `packageVersion` varchar(16) NOT NULL,
  `productAction` varchar(16) NOT NULL,
  `requiredProductId` varchar(255) NOT NULL DEFAULT '',
  `requiredProductVersion` varchar(32) DEFAULT NULL,
  `requiredPackageVersion` varchar(16) DEFAULT NULL,
  `requiredAction` varchar(16) DEFAULT NULL,
  `requiredInstallationStatus` varchar(16) DEFAULT NULL,
  `requirementType` varchar(16) DEFAULT NULL,
  PRIMARY KEY (`productId`,`productVersion`,`packageVersion`,`productAction`,`requiredProductId`),
  CONSTRAINT `PRODUCT_DEPENDENCY_ibfk_1` FOREIGN KEY (`productId`, `productVersion`, `packageVersion`) REFERENCES `PRODUCT` (`productId`, `productVersion`, `packageVersion`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_ID_TO_LICENSE_POOL`
--

DROP TABLE IF EXISTS `PRODUCT_ID_TO_LICENSE_POOL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_ID_TO_LICENSE_POOL` (
  `licensePoolId` varchar(100) NOT NULL,
  `productId` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`licensePoolId`,`productId`),
  CONSTRAINT `PRODUCT_ID_TO_LICENSE_POOL_ibfk_1` FOREIGN KEY (`licensePoolId`) REFERENCES `LICENSE_POOL` (`licensePoolId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_ON_CLIENT`
--

DROP TABLE IF EXISTS `PRODUCT_ON_CLIENT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_ON_CLIENT` (
  `productId` varchar(255) NOT NULL DEFAULT '',
  `clientId` varchar(255) NOT NULL,
  `productType` varchar(16) NOT NULL,
  `targetConfiguration` varchar(16) DEFAULT NULL,
  `installationStatus` varchar(16) DEFAULT NULL,
  `actionRequest` varchar(16) DEFAULT NULL,
  `actionProgress` varchar(255) DEFAULT NULL,
  `actionResult` varchar(16) DEFAULT NULL,
  `lastAction` varchar(16) DEFAULT NULL,
  `productVersion` varchar(32) DEFAULT NULL,
  `packageVersion` varchar(16) DEFAULT NULL,
  `modificationTime` timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`productId`,`clientId`),
  KEY `clientId` (`clientId`),
  CONSTRAINT `PRODUCT_ON_CLIENT_ibfk_1` FOREIGN KEY (`clientId`) REFERENCES `HOST` (`hostId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_ON_DEPOT`
--

DROP TABLE IF EXISTS `PRODUCT_ON_DEPOT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_ON_DEPOT` (
  `productId` varchar(255) NOT NULL DEFAULT '',
  `productVersion` varchar(32) NOT NULL,
  `packageVersion` varchar(16) NOT NULL,
  `depotId` varchar(255) NOT NULL,
  `productType` varchar(16) NOT NULL,
  `locked` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`productId`,`depotId`),
  KEY `productId` (`productId`,`productVersion`,`packageVersion`),
  KEY `depotId` (`depotId`),
  KEY `productType` (`productType`),
  CONSTRAINT `PRODUCT_ON_DEPOT_ibfk_1` FOREIGN KEY (`productId`, `productVersion`, `packageVersion`) REFERENCES `PRODUCT` (`productId`, `productVersion`, `packageVersion`),
  CONSTRAINT `PRODUCT_ON_DEPOT_ibfk_2` FOREIGN KEY (`depotId`) REFERENCES `HOST` (`hostId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_PROPERTY`
--

DROP TABLE IF EXISTS `PRODUCT_PROPERTY`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_PROPERTY` (
  `productId` varchar(255) NOT NULL DEFAULT '',
  `productVersion` varchar(32) NOT NULL,
  `packageVersion` varchar(16) NOT NULL,
  `propertyId` varchar(200) NOT NULL,
  `type` varchar(30) NOT NULL,
  `description` text DEFAULT NULL,
  `multiValue` tinyint(1) NOT NULL,
  `editable` tinyint(1) NOT NULL,
  PRIMARY KEY (`productId`,`productVersion`,`packageVersion`,`propertyId`),
  KEY `type` (`type`),
  CONSTRAINT `PRODUCT_PROPERTY_ibfk_1` FOREIGN KEY (`productId`, `productVersion`, `packageVersion`) REFERENCES `PRODUCT` (`productId`, `productVersion`, `packageVersion`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_PROPERTY_STATE`
--

DROP TABLE IF EXISTS `PRODUCT_PROPERTY_STATE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_PROPERTY_STATE` (
  `product_property_state_id` int(11) NOT NULL AUTO_INCREMENT,
  `productId` varchar(255) DEFAULT NULL,
  `propertyId` varchar(200) NOT NULL,
  `objectId` varchar(255) NOT NULL,
  `values` text DEFAULT NULL,
  PRIMARY KEY (`product_property_state_id`),
  KEY `objectId` (`objectId`)
) ENGINE=InnoDB AUTO_INCREMENT=411543 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `PRODUCT_PROPERTY_VALUE`
--

DROP TABLE IF EXISTS `PRODUCT_PROPERTY_VALUE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `PRODUCT_PROPERTY_VALUE` (
  `product_property_id` int(11) NOT NULL AUTO_INCREMENT,
  `productId` varchar(255) DEFAULT NULL,
  `productVersion` varchar(32) NOT NULL,
  `packageVersion` varchar(16) NOT NULL,
  `propertyId` varchar(200) NOT NULL,
  `value` text DEFAULT NULL,
  `isDefault` tinyint(1) DEFAULT NULL,
  PRIMARY KEY (`product_property_id`),
  KEY `productId` (`productId`,`productVersion`,`packageVersion`,`propertyId`),
  KEY `index_product_property_value` (`productId`,`propertyId`,`productVersion`,`packageVersion`),
  CONSTRAINT `PRODUCT_PROPERTY_VALUE_ibfk_1` FOREIGN KEY (`productId`, `productVersion`, `packageVersion`, `propertyId`) REFERENCES `PRODUCT_PROPERTY` (`productId`, `productVersion`, `packageVersion`, `propertyId`)
) ENGINE=InnoDB AUTO_INCREMENT=1542573 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SOFTWARE`
--

DROP TABLE IF EXISTS `SOFTWARE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SOFTWARE` (
  `name` varchar(100) NOT NULL,
  `version` varchar(100) NOT NULL,
  `subVersion` varchar(100) NOT NULL,
  `language` varchar(10) NOT NULL,
  `architecture` varchar(3) NOT NULL,
  `windowsSoftwareId` varchar(100) DEFAULT NULL,
  `windowsDisplayName` varchar(100) DEFAULT NULL,
  `windowsDisplayVersion` varchar(100) DEFAULT NULL,
  `type` varchar(30) NOT NULL,
  `installSize` bigint(20) DEFAULT NULL,
  PRIMARY KEY (`name`,`version`,`subVersion`,`language`,`architecture`),
  KEY `windowsSoftwareId` (`windowsSoftwareId`),
  KEY `type` (`type`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SOFTWARE_CONFIG`
--

DROP TABLE IF EXISTS `SOFTWARE_CONFIG`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SOFTWARE_CONFIG` (
  `config_id` bigint(20) NOT NULL AUTO_INCREMENT,
  `clientId` varchar(255) NOT NULL,
  `name` varchar(100) NOT NULL,
  `version` varchar(100) NOT NULL,
  `subVersion` varchar(100) NOT NULL,
  `language` varchar(10) NOT NULL,
  `architecture` varchar(3) NOT NULL,
  `uninstallString` varchar(200) DEFAULT NULL,
  `binaryName` varchar(100) DEFAULT NULL,
  `firstseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `lastseen` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `state` tinyint(4) NOT NULL,
  `usageFrequency` int(11) NOT NULL DEFAULT -1,
  `lastUsed` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `licenseKey` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`config_id`),
  KEY `clientId` (`clientId`),
  KEY `name` (`name`,`version`,`subVersion`,`language`,`architecture`)
) ENGINE=InnoDB AUTO_INCREMENT=984581 DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SOFTWARE_LICENSE`
--

DROP TABLE IF EXISTS `SOFTWARE_LICENSE`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SOFTWARE_LICENSE` (
  `softwareLicenseId` varchar(100) NOT NULL,
  `licenseContractId` varchar(100) NOT NULL,
  `boundToHost` varchar(255) DEFAULT NULL,
  `maxInstallations` int(11) DEFAULT NULL,
  `expirationDate` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `type` varchar(30) NOT NULL,
  PRIMARY KEY (`softwareLicenseId`),
  KEY `licenseContractId` (`licenseContractId`),
  KEY `type` (`type`),
  KEY `boundToHost` (`boundToHost`),
  CONSTRAINT `SOFTWARE_LICENSE_ibfk_1` FOREIGN KEY (`licenseContractId`) REFERENCES `LICENSE_CONTRACT` (`licenseContractId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `SOFTWARE_LICENSE_TO_LICENSE_POOL`
--

DROP TABLE IF EXISTS `SOFTWARE_LICENSE_TO_LICENSE_POOL`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SOFTWARE_LICENSE_TO_LICENSE_POOL` (
  `softwareLicenseId` varchar(100) NOT NULL,
  `licensePoolId` varchar(100) NOT NULL,
  `licenseKey` varchar(1024) DEFAULT NULL,
  PRIMARY KEY (`softwareLicenseId`,`licensePoolId`),
  KEY `licensePoolId` (`licensePoolId`),
  CONSTRAINT `SOFTWARE_LICENSE_TO_LICENSE_POOL_ibfk_1` FOREIGN KEY (`softwareLicenseId`) REFERENCES `SOFTWARE_LICENSE` (`softwareLicenseId`),
  CONSTRAINT `SOFTWARE_LICENSE_TO_LICENSE_POOL_ibfk_2` FOREIGN KEY (`licensePoolId`) REFERENCES `LICENSE_POOL` (`licensePoolId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `WINDOWS_SOFTWARE_ID_TO_PRODUCT`
--

DROP TABLE IF EXISTS `WINDOWS_SOFTWARE_ID_TO_PRODUCT`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `WINDOWS_SOFTWARE_ID_TO_PRODUCT` (
  `windowsSoftwareId` varchar(100) NOT NULL,
  `productId` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`windowsSoftwareId`,`productId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-12-07  7:44:54

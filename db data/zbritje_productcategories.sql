-- MySQL dump 10.13  Distrib 8.0.42, for Win64 (x86_64)
--
-- Host: localhost    Database: zbritje
-- ------------------------------------------------------
-- Server version	8.0.42

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Dumping data for table `productcategories`
--

LOCK TABLES `productcategories` WRITE;
/*!40000 ALTER TABLE `productcategories` DISABLE KEYS */;
INSERT INTO `productcategories` VALUES (1,100,'Fruits (Fruta)',86),(2,101,'Vegetables (Perime)',84),(3,102,'Herbs (Erëza të Freskëta)',80),(4,103,'Red Meat (Mish i Kuq)',65),(5,104,'Poultry (Shpendë)',69),(6,105,'Processed Meats (Mishra të Përpunuar)',59),(7,106,'Fresh Fish (Peshk i Freskët)',38),(8,107,'Frozen Fish & Seafood (Peshk dhe Fruta Deti të Ngrira)',70),(9,108,'Canned Fish (Peshk i Konservuar)',65),(10,109,'Milk (Qumësht)',86),(11,110,'Yogurt (Kos / Jogurt)',85),(12,111,'Cheese (Djathë)',84),(13,112,'Cream (Ajkë / Krem Qumështi)',83),(14,113,'Butter (Gjalpë)',82),(15,114,'Margarine & Spreads (Margarinë dhe Produkte për Lyerje)',64),(16,115,'Eggs (Vezë)',87),(17,116,'Bread (Bukë)',71),(18,117,'Pastries & Croissants (Pasta dhe Kroasante)',71),(19,118,'Cakes & Sweet Baked Goods (Kekë dhe Ëmbëlsira Furre)',71),(20,119,'Flour (Miell)',47),(21,120,'Rice (Oriz)',65),(22,121,'Pasta & Noodles (Makarona dhe Fide)',65),(23,122,'Grains & Cereals (Drithëra)',66),(24,123,'Sugar & Sweeteners (Sheqer dhe Ëmbëltues)',47),(25,124,'Salt & Spices (Kripë dhe Erëza)',47),(26,125,'Cooking Oils (Vajra Gatimi)',64),(27,126,'Vinegar (Uthull)',64),(28,127,'Canned Goods (Konserva)',65),(29,128,'Sauces & Condiments (Salca dhe Kondimente)',64),(30,129,'Spreads (Produkte për Lyerje)',64),(31,130,'Chips & Crisps (Çipsa dhe Patatina)',79),(32,131,'Pretzels & Salty Snacks (Shkopinj të Kripur dhe Rosto të Tjera)',76),(33,132,'Nuts & Seeds (Fruta të Thata dhe Fara)',75),(34,133,'Chocolate (Çokollatë)',53),(35,134,'Biscuits & Cookies (Biskota dhe Keksa)',76),(36,135,'Candies & Gums (Karamele dhe Çamçakëz)',43),(37,136,'Frozen Vegetables & Fruits (Perime dhe Fruta të Ngrira)',70),(38,137,'Frozen Potato Products (Produkte Patatesh të Ngrira)',70),(39,138,'Frozen Ready Meals & Pizza (Gatime të Gata dhe Pica të Ngrira)',70),(40,139,'Frozen Meat & Fish (Mish dhe Peshk i Ngrirë)',70),(41,140,'Ice Cream (Akullore)',70),(42,141,'Baby Food (Ushqim për Foshnje)',7),(43,142,'Baby Formula (Qumësht Formule)',7),(44,143,'Water (Ujë)',53),(45,144,'Still Water (Ujë Natyral / pa Gaz)',53),(46,145,'Sparkling Water (Ujë Mineral / me Gaz)',53),(47,146,'Flavored Water (Ujë me Shije)',53),(48,147,'Fruit Juices (Lëngje Frutash)',53),(49,148,'Nectars (Nektare)',53),(50,149,'Smoothies (Smoothie)',53),(51,150,'Colas (Kola)',53),(52,151,'Other Carbonated Drinks (Pije të Tjera të Gazuara)',53),(53,152,'Coffee (Kafe)',53),(54,153,'Tea (Çaj)',53),(55,154,'Energy Drinks (Pije Energjike)',53),(56,155,'Alcoholic Beverages (Pije Alkoolike)',29),(57,156,'Beer (Birrë)',29),(58,157,'Wine (Verë)',29),(59,158,'Spirits (Pije Spirtuore)',29),(60,159,'Laundry Detergents (Detergjentë Rrobash)',59),(61,160,'Fabric Softeners (Zbutës Rrobash)',59),(62,161,'Dishwashing Products (Produkte për Larjen e Enëve)',59),(63,162,'Surface Cleaners (Pastrues Sipërfaqesh)',59),(64,163,'Toilet Cleaners (Pastrues WC)',59),(65,164,'Garbage Bags (Thasë Mbeturinash)',59),(66,165,'Soaps & Shower Gels (Sapunë dhe Xhel Dushi)',50),(67,166,'Shampoos & Conditioners (Shampon dhe Balsam Flokësh)',50),(68,167,'Oral Care (Kujdesi Oral)',50),(69,168,'Deodorants & Antiperspirants (Deodorantë)',50),(70,169,'Skin Care (Kujdesi i Lëkurës)',50),(71,170,'Feminine Hygiene (Higjiena Femërore)',50),(72,171,'Paper Products (Produkte Letre)',59),(73,172,'Baby Diapers & Wipes (Pelena dhe Letra të Lagura për Foshnje)',7),(74,173,'Other',1);
/*!40000 ALTER TABLE `productcategories` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-08-07 20:26:34

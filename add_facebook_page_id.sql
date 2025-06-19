-- Simple migration to add facebookPageId column and update existing stores
-- Run this on your remote database

-- Add the facebookPageId column to the stores table
ALTER TABLE `stores` 
ADD COLUMN `facebookPageId` varchar(100) DEFAULT NULL;

-- Update existing stores with facebookPageId values
-- Only update if the store exists and matches the name

UPDATE `stores` SET `facebookPageId` = '100064857035989' WHERE `storeName` = 'Viva Fresh';
UPDATE `stores` SET `facebookPageId` = '100064737098662' WHERE `storeName` = 'Maxi';
UPDATE `stores` SET `facebookPageId` = '100066760141131' WHERE `storeName` = 'Spar';
UPDATE `stores` SET `facebookPageId` = '100064548255987' WHERE `storeName` = 'Meridian';
UPDATE `stores` SET `facebookPageId` = '100064921530426' WHERE `storeName` = 'ETC';
UPDATE `stores` SET `facebookPageId` = '100064778858305' WHERE `storeName` = 'KAM Market';
UPDATE `stores` SET `facebookPageId` = '100064921530426' WHERE `storeName` = 'Interex';
UPDATE `stores` SET `facebookPageId` = '100075613553853' WHERE `storeName` = 'Horeca';

-- Check the results
SELECT storeId, storeName, facebookPageId FROM `stores` WHERE facebookPageId IS NOT NULL;

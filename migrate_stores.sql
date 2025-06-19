-- Migration script to add missing columns to stores table
-- Run this on your remote database

-- Step 1: Add the missing columns to the stores table
ALTER TABLE `stores` 

ADD COLUMN `facebookPageId` varchar(100) DEFAULT NULL;

-- Step 2: Update existing records with the data from your local database
-- Make sure these store IDs match your remote database

-- Update store data with Facebook information
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/vivafresh.rks/photos', `facebookPageId` = '100064857035989' WHERE `storeId` = 1 AND `storeName` = 'Viva Fresh';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/maxisupermarketprishtine/photos', `facebookPageId` = '100064737098662' WHERE `storeId` = 2 AND `storeName` = 'Maxi';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/SPARinKosova/photos', `facebookPageId` = '100066760141131' WHERE `storeId` = 3 AND `storeName` = 'Spar';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/RrjetiMeridianExpress/photos', `facebookPageId` = '100064548255987' WHERE `storeId` = 4 AND `storeName` = 'Meridian';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/etcks/photos', `facebookPageId` = '100064921530426' WHERE `storeId` = 5 AND `storeName` = 'ETC';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/kamkosova/photos', `facebookPageId` = '100064778858305' WHERE `storeId` = 6 AND `storeName` = 'KAM Market';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/InterexKs/photos', `facebookPageId` = '100064921530426' WHERE `storeId` = 7 AND `storeName` = 'Interex';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/Horecacenter.ks/photos', `facebookPageId` = '100075613553853' WHERE `storeId` = 8 AND `storeName` = 'Horeca';

-- Update additional stores with Facebook information
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/superviva.ks/photos', `facebookPageId` = '100064683519808' WHERE `storeId` = 16 AND `storeName` = 'Super Viva';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/AlbiMarket/photos', `facebookPageId` = '100057620493108' WHERE `storeId` = 17 AND `storeName` = 'Albi Market';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/ABICENTER1/photos', `facebookPageId` = '100064777866111' WHERE `storeId` = 18 AND `storeName` = 'Abi Center';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/ViprosMarket/photos', `facebookPageId` = '100063792752922' WHERE `storeId` = 19 AND `storeName` = 'Vipros';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/eliabmarket/photos', `facebookPageId` = NULL WHERE `storeId` = 20 AND `storeName` = 'ELI-AB';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/QendraTregtareArjeta/photos', `facebookPageId` = NULL WHERE `storeId` = 21 AND `storeName` = 'QTA';
UPDATE `stores` SET `facebookUrl` = NULL, `facebookPageId` = NULL WHERE `storeId` = 22 AND `storeName` = 'Nora Center';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/profile.php?id=100040544017359/photos', `facebookPageId` = '100040544017359' WHERE `storeId` = 23 AND `storeName` = 'Express Store';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/emonacenter/photos', `facebookPageId` = '100064321496376' WHERE `storeId` = 24 AND `storeName` = 'Emona Center';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/durmart.ks/photos', `facebookPageId` = '100064829852774' WHERE `storeId` = 25 AND `storeName` = 'Durmart';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/kipperkosova/photos', `facebookPageId` = '100083286734007' WHERE `storeId` = 26 AND `storeName` = 'Kipper Market';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/iffis.ks/photos', `facebookPageId` = '100090295401370' WHERE `storeId` = 27 AND `storeName` = 'Iffis Market';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/plusmarketks/photos', `facebookPageId` = '100064814673759' WHERE `storeId` = 28 AND `storeName` = 'Plus Market';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/mediterangroup/photos', `facebookPageId` = '100064649165384' WHERE `storeId` = 29 AND `storeName` = 'Mediteran Group';
UPDATE `stores` SET `facebookUrl` = 'https://www.facebook.com/marketnora.official/photos', `facebookPageId` = '100064725036970' WHERE `storeId` = 30 AND `storeName` = 'Market Nora';

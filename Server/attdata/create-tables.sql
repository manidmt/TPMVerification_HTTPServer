DROP TABLE IF EXISTS attestationdata;
CREATE TABLE attestationdata (
  id		INT AUTO_INCREMENT NOT NULL,
  pcr         VARCHAR(512) NOT NULL,
  transactionid      VARCHAR(512) NOT NULL,
  timerequest	BIGINT NOT NULL,
  uniqueid      VARCHAR(1024) NOT NULL,
  
  PRIMARY KEY (`id`)
);

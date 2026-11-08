CREATE TABLE offers (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    origin      CHAR(3)       NOT NULL,
    destination CHAR(3)       NOT NULL,
    carrier     VARCHAR(40)   NOT NULL,
    price       DECIMAL(10,2) NOT NULL,
    departure   DATE          NOT NULL
);

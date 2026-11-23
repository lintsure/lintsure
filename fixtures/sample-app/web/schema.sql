-- Planted: a stored card security code and a sensitive category.
CREATE TABLE customers (
  id SERIAL PRIMARY KEY,
  cvv VARCHAR(4),
  religion TEXT
);

---
title: SQL
layout: post
date: 2025-05-05
description: "SQL is a standard language for managing and manipulating databases."
permalink: /theory/misc/sql
---

# SQL 
SQL (Structured Query Language) is a standard language for managing and manipulating databases. It is used to perform tasks such as querying data, updating records, and creating and modifying database structures.

## Basic SQL Commands
- **SELECT**: Retrieve data from a database.
- **ORDER BY**: Sort the result set in ascending or descending order.
- **GROUP BY**: Group rows that have the same values in specified columns into summary rows.
- **DESCRIBE**: Show the structure of a table, including column names and data types.
- **INSERT**: Add new records to a table.
- **UPDATE**: Modify existing records in a table.
- **DELETE**: Remove records from a table.
- **CREATE**: Create a new table or database.
- **ALTER**: Modify the structure of an existing table.
- **DROP**: Delete a table or database.
- **JOIN**: Combine rows from two or more tables based on a related column.
- **WHERE**: Filter records based on specific conditions.
- **HAVING**: Filter records after grouping.
- **DISTINCT**: Select only unique values.
- **LIMIT**: Specify the maximum number of records to return.
- **INDEX**: Create an index on a table to improve query performance.
- **TRANSACTION**: A sequence of operations performed as a single logical unit of work.
- **COMMIT**: Save changes made during a transaction.
- **ROLLBACK**: Undo changes made during a transaction.
- **VIEW**: A virtual table based on the result of a SELECT query.
- **SUBQUERY**: A query nested inside another query.
- **UNION**: Combine the result sets of two or more SELECT statements.

## Simple SQL Queries Examples
```sql
-- Select all columns from the "employees" table
SELECT * FROM employees;
-- Select specific columns from the "employees" table
SELECT first_name, last_name FROM employees;
-- Insert a new record into the "employees" table
INSERT INTO employees (first_name, last_name, age) VALUES ('John', 'Doe', 30);
-- Update a record in the "employees" table for the employee with name `John Doe`
UPDATE employees SET age = 31 WHERE first_name = 'John' AND last_name = 'Doe';
-- Delete a record from the "employees" table for the employee with name `John Doe`
DELETE FROM employees WHERE first_name = 'John' AND last_name = 'Doe';
-- Use UNION to combine results from two SELECT statements
SELECT first_name FROM employees
UNION
SELECT first_name FROM managers;
-- Use JOIN to combine rows from two tables based on a related column
SELECT employees.first_name, departments.department_name
FROM employees
JOIN departments ON employees.department_id = departments.id;
-- Use WHERE to filter records based on specific conditions
SELECT * FROM employees WHERE age > 30;
-- Use ORDER BY to sort the result set in ascending order
SELECT * FROM employees ORDER BY last_name ASC;
-- Use GROUP BY to group rows that have the same values in specified columns
SELECT department_id, COUNT(*) AS employee_count
FROM employees
GROUP BY department_id;
```

## SQL Injection
SQL injection is a code injection technique that exploits a security vulnerability in an application's software by manipulating SQL queries. It allows attackers to interfere with the queries that an application makes to its database, potentially allowing them to view, modify, or delete data.

To prevent SQL injection, developers should use prepared statements and parameterized queries, which separate SQL code from data input. This ensures that user input is treated as data rather than executable code.

### Example of SQL Injection
```sql
-- Vulnerable SQL query
SELECT * FROM users WHERE username = '$username' AND password = '$password';
-- If $username is 'admin' OR '1'='1', the query becomes:
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '$password';
-- This would return all users in the database, bypassing authentication.
```

## SQL Injection CheatSheet

A very good piece of payloads for SQLi is the [`PayloadAllTheThings`](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) repository. It contains a lot of payloads for different types of SQL injection attacks.

### Personal Cheatsheet
- Todo


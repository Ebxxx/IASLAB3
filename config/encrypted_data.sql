CREATE TABLE personal_data1 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    name TEXT NOT NULL,
    phone_number TEXT NOT NULL,
    address TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1;

CREATE TABLE personal_data2 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email TEXT NOT NULL,
    date_of_birth TEXT NOT NULL,
    social_security_number TEXT NOT NULL,
    occupation TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1;

CREATE TABLE personal_data3 (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    credit_card_number TEXT NOT NULL,
    expiration_date TEXT NOT NULL,
    cvv TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB AUTO_INCREMENT=1;


CREATE TABLE payroll_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_name VARCHAR(50) NOT NULL UNIQUE,
    base_salary TEXT NOT NULL,
    bonus TEXT NOT NULL,
    tax_rate TEXT NOT NULL,
    encrypted_total TEXT,
    encryption_method VARCHAR(50) DEFAULT 'homomorphic'
) ENGINE=InnoDB AUTO_INCREMENT=1;




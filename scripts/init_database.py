#!/usr/bin/env python3

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import redis
from typing import Optional

def check_redis_connection() -> bool:
    """Check if Redis server is running and accessible."""
    try:
        r = redis.Redis(host='localhost', port=6379, db=0)
        r.ping()
        return True
    except redis.ConnectionError:
        return False

def check_postgres_connection() -> bool:
    """Check if PostgreSQL server is running and accessible."""
    try:
        print("Attempting to connect to PostgreSQL...")
        print("Connection parameters:")
        print("  Host: localhost")
        print("  Port: 5432")
        print("  User: postgres")
        print("  Database: postgres")
        
        conn = psycopg2.connect(
            dbname='postgres',
            user='postgres',
            password='kali',  # Default password in Kali Linux
            host='localhost',
            port=5432
        )
        print("Successfully connected to PostgreSQL!")
        conn.close()
        return True
    except psycopg2.OperationalError as e:
        print(f"\nPostgreSQL connection error details:")
        print(f"Error message: {str(e)}")
        print("\nPlease check:")
        print("1. PostgreSQL service is running")
        print("2. PostgreSQL is listening on port 5432")
        print("3. User 'postgres' exists and has correct permissions")
        print("4. Password for user 'postgres' is correct")
        return False
    except Exception as e:
        print(f"\nUnexpected error while connecting to PostgreSQL:")
        print(f"Error type: {type(e).__name__}")
        print(f"Error message: {str(e)}")
        return False

def create_postgres_database() -> bool:
    """Create the security_audit database if it doesn't exist."""
    try:
        # Connect to default database
        conn = psycopg2.connect(
            dbname='postgres',
            user='postgres',
            password='kali',
            host='localhost',
            port=5432
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        with conn.cursor() as cur:
            # First, update the collation version of template1
            print("Updating collation version of template1 database...")
            try:
                cur.execute('ALTER DATABASE template1 REFRESH COLLATION VERSION')
                print("Successfully updated template1 collation version")
            except Exception as e:
                print(f"Warning: Could not update template1 collation version: {str(e)}")
                print("Continuing with database creation...")
            
            # Check if database exists
            cur.execute("SELECT 1 FROM pg_database WHERE datname = 'security_audit'")
            if not cur.fetchone():
                # Create database
                print("Creating security_audit database...")
                cur.execute('CREATE DATABASE security_audit')
                print("Created security_audit database")
                
                # Update collation version of the new database
                try:
                    cur.execute('ALTER DATABASE security_audit REFRESH COLLATION VERSION')
                    print("Successfully updated security_audit collation version")
                except Exception as e:
                    print(f"Warning: Could not update security_audit collation version: {str(e)}")
            else:
                print("security_audit database already exists")
                # Update collation version of existing database
                try:
                    cur.execute('ALTER DATABASE security_audit REFRESH COLLATION VERSION')
                    print("Successfully updated security_audit collation version")
                except Exception as e:
                    print(f"Warning: Could not update security_audit collation version: {str(e)}")
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error creating database: {str(e)}")
        return False

def init_redis() -> bool:
    """Initialize Redis with default configuration."""
    try:
        r = redis.Redis(host='localhost', port=6379, db=0)
        
        # Clear any existing data
        r.flushdb()
        
        # Set some default configuration
        r.config_set('maxmemory', '512mb')
        r.config_set('maxmemory-policy', 'allkeys-lru')
        
        print("Redis initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing Redis: {str(e)}")
        return False

def init_postgres() -> bool:
    """Initialize PostgreSQL database schema."""
    try:
        conn = psycopg2.connect(
            dbname='security_audit',
            user='postgres',
            password='kali',  # Default password in Kali Linux
            host='localhost',
            port=5432
        )
        
        # Read and execute schema.sql
        schema_path = os.path.join(os.path.dirname(__file__), '..', 'database', 'schema.sql')
        with open(schema_path, 'r') as f:
            schema_sql = f.read()
        
        with conn.cursor() as cur:
            cur.execute(schema_sql)
        
        conn.commit()
        print("PostgreSQL schema initialized successfully")
        return True
    except Exception as e:
        print(f"Error initializing PostgreSQL schema: {str(e)}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    print("Initializing databases for Security Audit Automation...")
    
    # Check Redis connection
    if not check_redis_connection():
        print("Error: Cannot connect to Redis server. Please ensure Redis is running.")
        sys.exit(1)
    
    # Check PostgreSQL connection
    if not check_postgres_connection():
        print("Error: Cannot connect to PostgreSQL server. Please ensure PostgreSQL is running.")
        sys.exit(1)
    
    # Create PostgreSQL database
    if not create_postgres_database():
        print("Failed to create PostgreSQL database")
        sys.exit(1)
    
    # Initialize Redis
    if not init_redis():
        print("Failed to initialize Redis")
        sys.exit(1)
    
    # Initialize PostgreSQL schema
    if not init_postgres():
        print("Failed to initialize PostgreSQL schema")
        sys.exit(1)
    
    print("\nDatabase initialization completed successfully!")
    print("Redis and PostgreSQL are ready to use.")

if __name__ == "__main__":
    main() 
# Simple Server

This is a simple REST API server written in Go that performs CRUD operations on a database.

## Requirements
- Go (>= 1.23)
- PostgreSQL (v16)

## Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/xtasysensei/simple-server-auth.git

cd simple-server-auth
```

### 2. Install Dependencies
```bash
go mod tidy
```

### 3. Set Up PostgreSQL
Install PostgreSQL

- Linux (Debian-based):
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
```
- macOS:
```bash
brew install postgresql
```

Start PostgreSQL
- Linux:
```bash
sudo systemctl start postgresql
```
- macOS:
```bash
brew services start postgresql
```
Create a Database and User
```bash
sudo -i -u postgres
psql
CREATE DATABASE <your_db_name>;
CREATE USER <your_user> WITH ENCRYPTED PASSWORD 'yourpassword';
GRANT ALL PRIVILEGES ON DATABASE <your_db_name> TO <your_user>;
\q
exit
```

### 4. Configure Environment Variables
Edit the `.env` file in the root directory of the project with the following content, replacing the placeholders with your actual PostgreSQL credentials:
```bash
DB_HOST=localhost
DB_PORT=5432
DB_USER=<your_user>
DB_PASSWORD='yourpassword'
DB_NAME=<your_db_name>
```

### 5. Run the Server
```bash
# The server will run on localhost:8000 by default
go run main.go
```
## Usage
After running the server, it will be available at `http://localhost:8000`.
## Docker
If yoyu have docker installed , you can run `docker compose up -d` in the root directory to get the server and potgresql containers running.
## Contributing
Feel free to fork this project, create a feature branch, and submit pull requests.


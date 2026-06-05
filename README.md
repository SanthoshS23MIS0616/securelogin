# Secure Login System

A high-level Java Spring Boot cybersecurity internship project that demonstrates secure user registration, secure login, session handling, optional two-factor authentication, and account activity monitoring through a polished web interface.

## Project Highlights

- User registration and login with bcrypt password hashing.
- Strong input validation for name, email, password, and 2FA codes.
- SQL injection protection through Spring Data JPA repositories and parameterized queries.
- Secure session management with logout and session ID migration after login.
- Optional TOTP-based two-factor authentication using authenticator apps.
- Account lockout after repeated failed login or 2FA attempts.
- Login activity audit table with status, reason, IP address, and time.
- Security score/passport dashboard for a useful account-protection overview.
- Professional responsive UI with green, violet, pink, slight yellow, and white styling.

## Technology Stack

- Java 21
- Spring Boot 3.3.5
- Spring Security
- Spring Data JPA
- Thymeleaf
- H2 database for local demo
- PostgreSQL support for deployment
- Maven
- Docker

## Project Structure

```text
src/main/java/com/intern/securelogin
├── config          Security configuration
├── controller      Web page controllers
├── dto             Validated form objects
├── entity          User and login audit entities
├── repository      JPA repositories
└── service         Login, 2FA, audit, and account logic

src/main/resources
├── templates       Thymeleaf pages
├── static          CSS, JavaScript, and image assets
└── application*.properties
```

## Run Locally

```powershell
cd "C:\Users\santhosh\OneDrive\Desktop\intern\fullstack\secure login"
mvn spring-boot:run "-Dspring-boot.run.arguments=--server.port=8090"
```

Or run the packaged jar:

```powershell
java -jar dist\secure-login-1.0.0-boot.jar --server.port=8090
```

Open:

```text
http://localhost:8090
```

## H2 Database Console

The local database is in-memory H2. It is available only while the app is running.

Open:

```text
http://localhost:8090/h2-console
```

Use:

```text
JDBC URL: jdbc:h2:mem:secure-login-db
User Name: sa
Password: leave empty
```

Important tables:

```text
APP_USERS
LOGIN_EVENTS
```

Passwords are stored only as bcrypt hashes in `PASSWORD_HASH`. The original password cannot be viewed or recovered.

## Test and Build

```powershell
mvn test
mvn package
```

The runnable jar is created at:

```text
dist/secure-login-1.0.0-boot.jar
```

## Deployment Recommendation

The easiest hosting option for this Java project is Render using Docker.

1. Push this project to GitHub.
2. Create a PostgreSQL database on Render.
3. Create a new Render Web Service from the GitHub repository.
4. Select Docker as the runtime.
5. Add these environment variables:

```text
SPRING_PROFILES_ACTIVE=prod
JDBC_DATABASE_URL=jdbc:postgresql://YOUR_RENDER_DB_HOST:5432/YOUR_DATABASE
JDBC_DATABASE_USERNAME=YOUR_DATABASE_USER
JDBC_DATABASE_PASSWORD=YOUR_DATABASE_PASSWORD
```

Render will build the project using the included `Dockerfile`.

## Security Notes

- Plain-text passwords are never stored.
- bcrypt strength is configured through Spring Security's `BCryptPasswordEncoder`.
- Failed login attempts are tracked and can temporarily lock an account.
- Authenticated sessions can be ended through logout.
- TOTP 2FA can be enabled from the Security page.
- Database access uses JPA repositories instead of raw SQL string concatenation.

## Author

Santhosh S - Software Engineer

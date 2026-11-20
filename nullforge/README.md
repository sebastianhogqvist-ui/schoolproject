internal : https://github.com/xd3d9/roblox-internal

# რობლოქსის ექსტერნალი
სანამ დავიწყებდე მსურს განვაცხადო რომ ეს ექსტერნალი სრული კრახია, ვეცადე აიმბოტის მსგავსი რამის გაკეთებას მაგრამ მერე მივხვდი რომ უაზრობა იქნებოდა და გადავედი ინტერნალის დაწერაზე. ექსტერნალზე მივხვდი რომ აზრი არ ქონდა იმისდა მიუხედავად რომ შემეძლო მოდულსკრიპტზე გადამეწერა ჩემი ლუას კოდი და კომუნიკაციის ხიდი შემექმნა, მე როგორც სიძნელის და ინტერნალის მოყვარული პიროვნება პირდაპირ გადავრბაგდი იქეთ, რომელსაც შეგიძლია გაეცნოთ ჩემს მეორე რეპოზე. ვინც იწყებთ რობლოქსის ექსპლოიტის დაწერას გირჩევთ რომ ინტერნალი დაწეროთ თქვენით თავიდან ბოლომდე ან გამოიყენოთ ჩემი პროექტი რომელიც Execution-ს შვება მაგრამ Identity და Capabilities ვერ აყენებს. (მე პირადად გირჩევთ თქვენით გააკეთოთ თორემ ადრე თუ გვიან უფრო გაიჭედებით.)

![image](https://github.com/user-attachments/assets/a29223e1-aaef-4b62-a040-7368538a4446)

---

## Server-Side: License Server (`server/`)

FastAPI-based license management server with:

- **Database**: SQLite + SQLAlchemy ORM + Alembic migrations
- **Authentication**: JWT-based session tokens (HS256)
- **Licensing**: HWID-bound licenses with activation/validation workflows
- **Admin Panel**: Web interface for license management
- **Security**: Rate limiting, maintenance mode toggle, CORS configuration

### Run Server

```bash
cd server
cp .env.example .env
python -m app.cli migrate --revision head
python -m server.main
```

Server runs on `http://127.0.0.1:8080` by default.

---

## Client-Side: License Core Library (`um/license/`)

Portable C++20 library for license validation:

- **HWID Generation**: Cross-platform hardware identification
- **JWT Parsing**: Header/payload parsing with signature verification
- **Offline Policy**: Grace period and cached validation support
- **Utilities**: Base64URL encoding, RFC3339 timestamp handling

### Windows Integration (`um/license_win.hpp`)

Platform-specific stub using:
- **WinHTTP** for network requests
- **BCrypt** for cryptographic operations

---

## Keysystem UI (Beta)

Browser-based loader at `loader/nullforge-loader.html`:

- Currently a static shell — wiring to server API in progress
- Open `loader/nullforge-loader.html` in a browser
- Set server URL to `http://127.0.0.1:8080`

---

## Build Instructions

### Server
```bash
cd server
pip install -r requirements.txt
```

### Client (Windows)
1. Open `KernelBridge.sln` in Visual Studio 2022
2. Build the `um` project (x64 configuration)

# 🚀 KChat - Advanced Real-Time Messaging API
### Developed by **Mohammed Walid**

![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
![Socket.io](https://img.shields.io/badge/Socket.io-010101?style=for-the-badge&logo=socket.io&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-black?style=for-the-badge&logo=JSON%20web%20tokens)

A sophisticated and secure Backend engine for real-time messaging applications, leveraging advanced encryption technologies and high-performance real-time communication.

## ✨ Key Features

- **💬 Real-Time Communication:**
    - Bi-directional communication via **Socket.io**.
    - Support for private chats, groups, and channels.
    - Instant notifications for messages, friend requests, and user status (Online/Offline).

- **🔐 Privacy & Encryption:**
    - **End-to-End Encryption (E2EE):** Message encryption using AES-256-GCM and RSA.
    - **Zero-Knowledge Architecture:** Ensuring privacy of content stored in the database.

- **🛡️ Security First:**
    - **Authentication:** Access & Refresh Token system with automatic rotation.
    - **2FA Support:** Two-factor authentication via Google Authenticator and QR codes.
    - **Replay Attack Protection:** Validation of request timestamps.
    - **Data Sanitization:** Protection against NoSQL Injection and XSS.

- **🚀 Performance & Scalability:**
    - **Redis Caching:** Session management and user status for fast response times.
    - **Image Processing:** Image compression and processing via the **Sharp** library to reduce storage footprint.
    - **Rate Limiting:** Protection against DDoS and Brute-force attacks.

## 🛠️ Tech Stack

- **Runtime:** Node.js
- **Framework:** Express.js
- **Database:** MongoDB (Mongoose ODM)
- **Real-time Engine:** Socket.io
- **In-Memory Cache:** Redis
- **Security:** Helmet, Bcrypt, Speakeasy, JWT
- **Media:** Multer & Sharp

## 🚀 Getting Started

### Prerequisites
- Node.js (v16+)
- MongoDB & Redis Server

### Installation

1. **Clone the repository:**
    ```bash
    git clone [https://github.com/MohammedWalid22/real-time-chatapp-server.git](https://github.com/MohammedWalid22/real-time-chatapp-server.git)
    cd real-time-chatapp-server
    ```

2. **Install dependencies:**
    ```bash
    npm install
    ```

3. **Environment Variables:**
    Create a `.env` file and add the required credentials (PORT, MONGO_URI, JWT_SECRETS, GMAIL_USER, etc.).

4. **Run the Server:**
    ```bash
    # Development Mode
    npm run dev
    
    # Production Mode
    npm start
    ```

## 📡 API Endpoints Documentation

### 🔐 Authentication & Security

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Register a new user | No |
| `POST` | `/api/auth/login` | Login and receive tokens | No |
| `POST` | `/api/auth/refresh` | Refresh access token | No |
| `POST` | `/api/auth/logout` | Revoke token and logout | Yes |
| `POST` | `/api/auth/2fa/setup` | Generate 2FA secret and QR code | Yes |
| `POST` | `/api/auth/2fa/verify` | Verify OTP code and enable 2FA | Yes |
| `POST` | `/api/auth/2fa/disable` | Disable 2FA | Yes |
| `GET` | `/api/auth/verify-email/:token` | Verify email via link | No |
| `POST` | `/api/auth/resend-verification` | Resend verification email | No |
| `POST` | `/api/auth/forgot-password` | Send password reset email | No |
| `PATCH` | `/api/auth/reset-password/:token`| Reset password via token | No |

### 👥 User Management

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/users/me` | Get current user profile | Yes |
| `PATCH` | `/api/users/me` | Update profile information | Yes |
| `DELETE`| `/api/users/me` | Deactivate/Delete account | Yes |
| `PATCH` | `/api/users/password` | Update account password | Yes |
| `POST` | `/api/users/avatar` | Upload/Update avatar image | Yes |
| `GET` | `/api/users/search` | Search for users by username | Yes |
| `GET` | `/api/users/:id` | Get another user's profile | Yes |

### 🤝 Friends & Relationships

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/friends/request` | Send a friend request | Yes |
| `GET` | `/api/friends/requests/incoming`| Get pending incoming requests | Yes |
| `GET` | `/api/friends/requests/sent` | Get pending sent requests | Yes |
| `POST` | `/api/friends/accept` | Accept a friend request | Yes |
| `POST` | `/api/friends/reject` | Reject a friend request | Yes |
| `POST` | `/api/friends/cancel` | Cancel a sent friend request | Yes |
| `DELETE`| `/api/friends/:userId` | Remove a friend | Yes |
| `GET` | `/api/friends/` | Get friends list | Yes |

### 💬 Messaging & Rooms

| Method | Endpoint | Description | Auth Required |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/rooms/` | Get all user rooms (chats) | Yes |
| `POST` | `/api/rooms/private` | Create/Get 1-on-1 chat room | Yes |
| `POST` | `/api/rooms/group` | Create a new group chat | Yes |
| `GET` | `/api/rooms/:id` | Get room details | Yes |
| `PATCH` | `/api/rooms/:id` | Update room settings/name | Yes |
| `DELETE`| `/api/rooms/:id` | Delete a room | Yes |
| `POST` | `/api/rooms/:id/members` | Add member to group | Yes |
| `DELETE`| `/api/rooms/:id/members/:userId`| Remove member from group | Yes |
| `POST` | `/api/rooms/:id/join` | Join a room | Yes |
| `POST` | `/api/rooms/:id/leave` | Leave a room | Yes |
| `GET` | `/api/messages/room/:roomId` | Get messages for a room | Yes |
| `POST` | `/api/messages/` | Send a new message | Yes |
| `PATCH` | `/api/messages/:id` | Edit a message | Yes |
| `DELETE`| `/api/messages/:id` | Delete a message | Yes |
| `POST` | `/api/messages/:id/react` | Add reaction to message | Yes |
| `POST` | `/api/messages/:id/read` | Mark message as read | Yes |
| `GET` | `/api/messages/search` | Search messages in a room | Yes |

## 🛡️ Security Implementation Details

1. **Replay Attack Prevention:** Every request is validated via the `x-request-timestamp` header to ensure no request is replayed by an attacker.
2. **Session Security:** Refresh Tokens are stored in the database, linked to the IP address and device type for enhanced security.
3. **Email Verification:** The system supports account activation via email links or OTP codes to guarantee user identity.

## 👨‍💻 Author

**Mohammed Walid**
Backend Developer (Node.js)

LinkedIn: [Mohammed Waleed](https://www.linkedin.com/in/mohammed-waleed-2033872a7)
GitHub: [MohammedWalid22](https://github.com/MohammedWalid22)

---

## ⭐️ Support
If you find this project helpful, don't forget to give it a **Star**!

## 📄 License
Licensed under the MIT License - Copyright © 2026 **Mohammed Walid**.

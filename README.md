# PassFort
---

# 🔐 PassFort – Secure, Smart, Simple Password Manager

**PassFort** is a modern, open-source password manager built with **Flask** and **SQLite**, featuring **AES-256 encryption**, **2FA (TOTP)**, and **Google OAuth** login. It delivers a sleek and secure experience with a responsive, dark/light mode user interface — all designed for simplicity and security.

> 💡 Project built with the guidance and help of **ChatGPT-4o-mini** as a code agent.
> 🎨 UI design and concept contributed by **Krishsavaliya** and **RavalPrem**.

[![GitHub Repo](https://img.shields.io/badge/Repo-Visit-green)](https://github.com/error-raga-008/PassFort)

---

## 🚀 Features

* 🔐 **Secure Authentication**

  * Email/password login with salted hashing
  * Google OAuth2 login via Authlib
  * TOTP-based 2FA (QR code + verification)

* 🧠 **Password Intelligence**

  * Random password generator with custom rules
  * Password strength estimator (zxcvbn-style)

* 📦 **Encrypted Vault**

  * AES-256 encryption with a user-defined safety key
  * Stored as `final_decimal` (displayed) + hidden `original_decimal`
  * Safety key & wrong-key alerts via email

* 🖥️ **Clean User Interface**

  * Dark/light mode toggle with Poppins font
  * Responsive sidebar dashboard
  * Detail panels with copy, decrypt, “Get Key” via email, and error modals

* 🛠️ **Admin/Dev-Friendly**

  * Modular Python code with comments
  * HTML/Jinja templates
  * Uses `.env` for secret configuration

---

## 🧰 Tech Stack

**Backend:**

* Flask
* SQLite + SQLAlchemy
* Python `cryptography` (AES-256 encryption)
* `pyotp`, `qrcode` (2FA)
* Authlib (Google OAuth)
* SMTP (email alerts)

**Frontend:**

* HTML5, CSS3, JavaScript
* Poppins font
* Dark/Light mode support

---

## 📦 Prerequisites

Make sure Python 3.8+ is installed. You'll also need the following Python packages:

```bash
pip install -r requirements.txt
```

### ✅ `.env` Configuration

Create a `.env` file in your project root with:

```env
SECRET_KEY=your_flask_secret_key
SQLALCHEMY_DATABASE_URI=sqlite:///passfort.db
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_email_app_password
MAIL_USE_TLS=True
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
ENCRYPTION_KEY=your_static_encryption_key_for_aes
```

---

## 🔧 Installation

1. **Clone the repo:**

```bash
git clone https://github.com/error-raga-008/PassFort.git
cd PassFort
```

2. **Create virtual environment:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**

```bash
pip install -r requirements.txt
```

4. **Initialize the database:**

```bash
flask db init
flask db migrate
flask db upgrade
```

---

## ▶️ Running the App

### Development

```bash
flask run
```

App will run at `http://127.0.0.1:5000`

### Production (Optional)

Consider using **Gunicorn** + **Nginx**, or **Docker** for deployment.

---

## 📸 UI Overview

### 1. **Signup/Login Page**

* Email/password or Google sign-in
* TOTP setup after initial login

### 2. **Dashboard**

* Sidebar navigation
* View password entries
* Add new password entry

### 3. **Password Entry Detail**

* View with "Show Password" option (requires key)
* "Get Key" via email button
* Open website and copy credentials
* Wrong key triggers email alert

### 4. **Generator & Strength Checker**

* Customize generated passwords
* Strength feedback with estimated crack time

---

## 📁 Folder Structure

```bash
PassFort/
├── app/
│   ├── __init__.py
│   ├── models.py
│   ├── routes/
│   │   ├── auth.py
│   │   ├── dashboard.py
│   │   ├── passwords.py
│   ├── utils/
│   │   ├── encryption.py
│   │   ├── email_utils.py
│   │   └── password_tools.py
│   ├── templates/
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── icons/
├── .env
├── requirements.txt
├── run.py
├── README.md
```

---

## 🤝 Contributing

1. Fork this repo
2. Create your feature branch (`git checkout -b feature/xyz`)
3. Commit your changes (`git commit -m 'Add XYZ feature'`)
4. Push to branch (`git push origin feature/xyz`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License**.
Feel free to use, modify, and share with proper credit.

---

**Crafted with ❤️ using Flask, AES-256, and ChatGPT-4o-mini**
👨‍💻 UI Concept & Design: **Krishsavaliya**, **RavalPrem**
🔗 [GitHub Repository »](https://github.com/error-raga-008/PassFort)

---

# Hệ thống quản lý thời gian học tập cho sinh viên

Node.js + Express + MySQL. Đăng ký / đăng nhập thật, dữ liệu mỗi tài khoản lưu trong MySQL.

## Cách chạy
1. Mở Laragon → **Start All**.
2. Mở Cmder, gõ từng dòng:
   ```
   cd F:\laragon\www\studymanage
   copy .env.example .env
   npm install
   npm start
   ```
   (`copy` và `npm install` chỉ cần chạy lần đầu)
3. Mở http://localhost:3000 (không mở qua `localhost/studymanage/public`).

Lần sau chỉ cần `cd F:\laragon\www\studymanage` rồi `npm start`. Muốn dừng: Ctrl + C.

## Các file chính
- `server.js`: máy chủ, đăng ký / đăng nhập và lưu dữ liệu vào MySQL
- `public/StudyManage.html`, `public/styles.css`, `public/app.js`: giao diện
- `.env`: cấu hình MySQL (Laragon mặc định: root, mật khẩu trống)

# Login dengan verifikasi OTP email

## Cara menjalankan
1. Pasang Node.js 18 atau lebih baru.
2. Di folder ini jalankan: `npm install`
3. Salin `.env.example` menjadi `.env`, lalu isi data SMTP.
   - Gmail: aktifkan verifikasi 2 langkah, lalu buat "App password" di pengaturan akun Google.
   - Atau pakai SMTP dari Brevo, SendGrid, Resend, dll.
4. Jalankan: `npm start`
5. Buka `http://localhost:3000` (jangan buka file HTML langsung, harus lewat alamat ini).

## Catatan
- Akun disimpan di `data/users.json` (untuk uji coba). Untuk produksi pakai database.
- Password dan kode OTP disimpan sebagai hash (bcrypt).
- Sesi login (cookie/JWT) belum ada: lihat TODO di `/api/login`.
- Pakai HTTPS saat dipasang di server sungguhan.
- Font MADE Evolve Sans di halaman berlisensi "Personal Use".

import os
import hmac
import hashlib
from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = Flask(__name__)

# 1. PEPPER: Khóa bí mật lấy từ biến môi trường (Lưu ngoài Database)
# Nếu không tìm thấy biến môi trường, dùng một chuỗi mặc định để test
PEPPER = os.environ.get("APP_PEPPER", "BiMatHeThongKhongLuuTrongDB_2026!")

# 2. COST TUNING: Cấu hình Argon2id (Chuẩn OWASP 2024+)
# time_cost=3 (số vòng băm), memory_cost=65536 (dùng 64MB RAM cho mỗi lần băm)
ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4
)

# Cơ sở dữ liệu giả lập trong bộ nhớ (Dùng Dictionary)
# Trong thực tế phần này sẽ lưu vào database như MySQL/PostgreSQL
user_db = {}

def apply_pepper(password: str) -> str:
    """Hàm trộn Pepper vào mật khẩu bằng HMAC-SHA256"""
    return hmac.new(PEPPER.encode(), password.encode(), hashlib.sha256).hexdigest()

@app.route('/register', methods=['POST'])
def register():
    """API Đăng ký tài khoản"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Vui lòng nhập đầy đủ username và password"}), 400

    if username in user_db:
        return jsonify({"message": "Tài khoản đã tồn tại!"}), 400

    # Bước A: Trộn Pepper vào mật khẩu
    peppered_password = apply_pepper(password)
    
    # Bước B: Thực hiện Băm mật khẩu (Argon2id tự động tạo và nhúng Salt ngẫu nhiên vào chuỗi hash)
    hashed_password = ph.hash(peppered_password)

    # Lưu thông tin vào Database giả lập
    user_db[username] = {
        "hash": hashed_password,
        "failed_attempts": 0 # Đếm số lần đăng nhập sai
    }

    return jsonify({
        "message": "Đăng ký thành công!",
        "stored_hash_demo": hashed_password # Trả về chuỗi hash để bạn quan sát
    }), 201

@app.route('/login', methods=['POST'])
def login():
    """API Đăng nhập an toàn"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # THIẾT KẾ AN TOÀN 1: Thông báo chung chung để tránh phân biệt "Sai User" hay "Sai Password"
    generic_error = {"message": "Tên đăng nhập hoặc mật khẩu không chính xác."}

    user = user_db.get(username)
    if not user:
        return jsonify(generic_error), 401

    # THIẾT KẾ AN TOÀN 2: Lockout / Rate limiting đơn giản
    if user["failed_attempts"] >= 5:
        return jsonify({"message": "Tài khoản tạm thời bị khóa do nhập sai quá 5 lần!"}), 429

    # Bước A: Trộn Pepper
    peppered_password = apply_pepper(password)

    # Bước B: Xác thực Hash bằng thuật toán Argon2id
    try:
        ph.verify(user["hash"], peppered_password)
        # Nếu đúng, reset số lần thử sai
        user["failed_attempts"] = 0
        return jsonify({"message": "Đăng nhập thành công!"}), 200
    except VerifyMismatchError:
        # Nếu sai, tăng số lần thử sai
        user["failed_attempts"] += 1
        return jsonify(generic_error), 401

if __name__ == '__main__':
    # Lấy cổng PORT do Render tự động cấp, nếu chạy ở máy local thì mặc định là 5000
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)

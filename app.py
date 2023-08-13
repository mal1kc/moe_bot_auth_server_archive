from moe_gthr_auth_server import create

if __name__ == "__main__":
    app = create()
    app.run(debug=True)

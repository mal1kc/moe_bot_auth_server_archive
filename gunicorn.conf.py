# import multiprocessing

bind = ":8080"
# workers = multiprocessing.cpu_count()
workers = 1
wsgi_app = "moe_bot_auth_server:create_app()"
threads = 8
timeout = 1  # seconds

import multiprocessing

bind = ":8080"
workers = multiprocessing.cpu_count() // 2
# workers = 1
wsgi_app = "moe_bot_auth_server:create_app()"
threads = 3
# threads = 1
timeout = 90  # seconds
loglevel = "debug"

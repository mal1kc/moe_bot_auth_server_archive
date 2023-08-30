import time


def took_time_decorator_ns(func):
    def wrapper(*args, **kwargs):
        start = time.time_ns()
        result = func(*args, **kwargs)
        end = time.time_ns()
        print(f"Function {func.__name__} took {end - start} ns")
        return result

    return wrapper

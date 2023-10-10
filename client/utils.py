import logging
import random
import time

from data import pContentEnum, sample_admin_data

logging.basicConfig(level=logging.INFO)

LOGGER = logging.getLogger("client.utils")


def took_time_decorator_ns(func):
    def wrapper(*args, **kwargs):
        start = time.time_ns()
        result = func(*args, **kwargs)
        end = time.time_ns()
        LOGGER.debug(f"Function {func.__name__} took {end - start} ns")
        return result

    return wrapper


def generate_random_sized_random_int_list(
    max_int=8, min_int=1, max_size: int = 4, min_size: int = 1, unique: bool = True
):
    size_list = random.randint(a=min_size, b=max_size)
    result = []
    while len(result) < size_list:
        random_int = random.randint(a=min_int, b=max_int)
        if random_int not in result or not unique:
            result.append(random_int)
    return result


def generate_random_sized_random_package_content_list(max_size: int = 4):
    size_list = random.randint(a=1, b=max_size)
    result = []
    while len(result) < size_list:
        p_content = random.choice(list(pContentEnum))
        if p_content not in result:
            result.append(p_content)
    return result


default_headers = {
    # "Content-Type": "application/json",
    # "Accept": "application/json",
}

admin_header_kwargs = {"auth": tuple(sample_admin_data.values()), **default_headers}

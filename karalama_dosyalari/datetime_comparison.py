import datetime
import random


def main():
    now_date = datetime.datetime.now()

    start_date = datetime.date(2021, 1, 1)
    end_date = datetime.date(2400, 12, 31)

    start_time = datetime.time(0, 0, 0)
    end_time = datetime.time(23, 59, 59)

    random_date = datetime.datetime.combine(
        datetime.date.fromordinal(random.randint(start_date.toordinal(), end_date.toordinal())),
        datetime.time(
            random.randint(start_time.hour, end_time.hour),
            random.randint(start_time.minute, end_time.minute),
            random.randint(start_time.second, end_time.second),
        ),
    )

    print(f"-> {now_date=} \n-> {random_date=}")

    print(f"{(now_date < random_date)=}")


if __name__ == "__main__":
    main()

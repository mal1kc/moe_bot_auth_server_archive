# ruff: noqa: E501
from pprint import pprint
from random import randint
from string import ascii_letters

from sqlalchemy import String, create_engine
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, sessionmaker

engine = create_engine("sqlite:///gecici.db", echo=True)

Base = declarative_base()


class PackageIcerik(Base):
    __tablename__ = "package_content"
    p_icerikId: Mapped[int] = mapped_column(primary_key=True)
    p_icerikAdi: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)

    def __repr__(self):
        return "<PackageIcerik(p_icerikId='%s', p_icerikAdi='%s')>" % (
            self.p_icerikId,
            self.p_icerikAdi,
        )


def main():
    "35 tane  rastgele package icerigi olusturuluyor ve bunlarin hepsi veritabanina ekleniyor"
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    for i in range(35):
        session.add(
            PackageIcerik(
                p_icerikId=i,
                p_icerikAdi="".join([ascii_letters[randint(0, 51)] for _ in range(256)]),
            )
        )
    session.commit()
    " veritabanindaki package icerikleri listeleniyor"
    pprint(session.query(PackageIcerik).all())
    session.close()


if __name__ == "__main__":
    main()

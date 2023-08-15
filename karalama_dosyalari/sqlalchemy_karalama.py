from pprint import pprint
from random import randint
from string import ascii_letters

from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, sessionmaker

engine = create_engine("sqlite:///gecici.db", echo=True)

Base = declarative_base()


class PaketIcerik(Base):
    __tablename__ = "paket_icerik"
    p_icerikId: Mapped[int] = mapped_column(primary_key=True)
    p_icerikAdi: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)

    def __repr__(self):
        return "<PaketIcerik(p_icerikId='%s', p_icerikAdi='%s')>" % (
            self.p_icerikId,
            self.p_icerikAdi,
        )


def main():
    "35 tane  rastgele paket icerigi olusturuluyor ve bunlarin hepsi veritabanina ekleniyor"
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    for i in range(35):
        session.add(
            PaketIcerik(
                p_icerikId=i,
                p_icerikAdi="".join([ascii_letters[randint(0, 51)] for i in range(256)]),
            )
        )
    session.commit()
    " veritabanindaki paket icerikleri listeleniyor"
    pprint(session.query(PaketIcerik).all())
    session.close()
    # pprint(PaketIcerik.__table__)
    # pprint(PaketIcerik.__dict__)
    # pprint(PaketIcerik.__dict__.keys())


if __name__ == "__main__":
    main()

from __future__ import annotations

from pprint import pprint
from random import randint
from typing import List, Set

from sqlalchemy import ForeignKey, create_engine

# from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import (
    Mapped,
    declarative_base,
    mapped_column,
    relationship,
    sessionmaker,
)

Base = declarative_base()


class Parent(Base):
    __tablename__ = "parent_table"

    id: Mapped[int] = mapped_column(primary_key=True)
    child_id: Mapped[int | None] = mapped_column(ForeignKey("child_table.id"))
    child: Mapped[Set[Child]] = relationship("Child", back_populates="parents")

    def __repr__(self):
        return f"<Parent(id={self.id}, child_id={self.child_id}, child={self.child})>"


class Child(Base):
    __tablename__ = "child_table"

    id: Mapped[int] = mapped_column(primary_key=True)
    parents: Mapped[List[Parent]] = relationship(back_populates="child")

    def __repr__(self):
        return f"<Child(id={self.id}, parents={self.parents})>"


def main():
    engine = create_engine("sqlite:///karalama.db", echo=True)
    engine.connect()
    engine.clear_compiled_cache()
    # remove all tables
    Base.metadata.drop_all(engine)
    # create all tables
    Base.metadata.create_all(engine)
    session = sessionmaker(engine)()
    for i in range(10):
        session.add(Child(id=i))
    session.commit()
    for i in range(10):
        session.add(Parent(id=i, child_id=randint(0, 9)))
    session.commit()
    childs = session.query(Child).all()
    parents = session.query(Parent).all()
    print("-" * 50)
    pprint(childs)
    print("-" * 50)
    pprint(parents)
    for parent in parents:
        for j in range(10):
            if randint(0, 1):
                p = session.query(Parent).filter(Parent.id == parent.id).first()
                if p is not None:
                    print(p)
                    # p.child.add(choice(childs))
    session.commit()

    parents = session.query(Parent).all()
    childs = session.query(Child).all()
    print("-" * 50)
    pprint(childs)
    print("-" * 50)
    print("-" * 50)
    # print out all parents which have child more than 1
    # pprint([parent for parent in parents if len(parent.child)>1])
    session.close()


if __name__ == "__main__":
    main()

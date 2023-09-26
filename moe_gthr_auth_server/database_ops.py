from __future__ import annotations

from datetime import datetime, timedelta
from logging import getLogger
from typing import Any, Callable, List
from werkzeug.datastructures import ImmutableMultiDict
from flask import current_app
from flask_sqlalchemy import SQLAlchemy
from schema import And, Optional, Or, Schema, SchemaError, Use
from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import (
    Mapped,
    declarative_base,
    mapped_column,
    relationship,
    scoped_session,
)
from sqlalchemy.orm.decl_api import DeclarativeMeta

from .enums import DBOperationResult, loginError, pContentEnum
from .cryption import make_password_hash

Base: DeclarativeMeta = declarative_base()
db = SQLAlchemy(model_class=Base)
DB_LOGGER = getLogger("sqlalchemy_db")

# DEVLOG -> serilize datetime as utc_timestamp


pcontent_packages_conn_table = db.Table(
    "pcontent_packages_conn_table",
    db.Column("id", db.Integer, primary_key=True, autoincrement=True),
    db.Column("package_content_id", db.Integer, db.ForeignKey("package_contents.id")),
    db.Column("package_id", db.Integer, db.ForeignKey("packages.id")),
)


class PackageContent(Base):
    __tablename__ = "package_contents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    content_value: Mapped[str] = mapped_column(
        Enum(*[e for e in pContentEnum]), nullable=False
    )
    package_id: Mapped[int | None] = mapped_column(ForeignKey("packages.id"), nullable=True)
    packages: Mapped[List[Package]] = relationship(
        "Package", secondary=pcontent_packages_conn_table, back_populates="package_contents"
    )

    def __repr__(self):
        return "<{clsname} ({id} {name} {content_value} {packages})>".format(
            clsname=self.__class__.__name__,
            id=self.id,
            name=self.name,
            content_value=self.content_value,
            packages=self.packages,
        )

    def __json__(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "content_value": self.content_value,
        }

    @staticmethod
    def from_json(data: dict) -> PackageContent:
        PackageContent.validate(data=data)
        ret_package_content = {
            "name": data["name"],
            "content_value": data["content_value"],
        }
        if "id" in data.keys():
            ret_package_content["id"] = data["id"]
        return PackageContent(**ret_package_content)

    @staticmethod
    def from_req_form(immutable_data: ImmutableMultiDict) -> PackageContent:
        mutable_data: dict = immutable_data.to_dict()
        for key, value in mutable_data.items():
            if value is None or value == "":
                mutable_data.pop(key)
        return PackageContent.from_json(mutable_data)  # maybe nned to change

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(
                    int,
                    Use(
                        lambda x: x
                        in [p_content.id for p_content in PackageContent.query.all()],
                        error="not_valid_id",
                    ),
                ),
                "name": And(str, len, error="not_valid_name"),
                "content_value": And(
                    str, Use(pContentEnum), error="not_valid_content_value"
                ),
                Optional("packages"): And(
                    list,
                    Use(lambda x: [Package.from_json(package_data) for package_data in x]),
                    error="not_valid_packages",
                ),
                Optional("package_id"): And(
                    Or(int, None), Use(_package_id_check), error="not_valid_package_id"
                ),
            },
            error="not_valid_data",
        )
        schema.validate(data)


class Package(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)

    days: Mapped[int] = mapped_column(nullable=False, default=30)  # 1,30,90,365 gibi
    detail: Mapped[str] = mapped_column(
        String(256), nullable=False, default="package_detail"
    )

    package_contents: Mapped[List[PackageContent]] = relationship(
        "PackageContent", back_populates="packages", secondary=pcontent_packages_conn_table
    )

    def __repr__(self):
        return "<{clsname} ({id} {name} {days} {detail})>".format(
            clsname=self.__class__.__name__,
            id=self.id,
            name=self.name,
            days=self.days,
            detail=self.detail,
        )

    def __json__(self) -> dict[str, Any]:
        if self.package_contents is not None and len(self.package_contents) > 0:
            return {
                "id": self.id,
                "name": self.name,
                "days": self.days,
                "detail": self.detail,
                "package_contents": [
                    package_content.__json__() for package_content in self.package_contents
                ],
            }
        return {
            "id": self.id,
            "name": self.name,
            "days": self.days,
            "detail": self.detail,
            "package_contents": None,
        }

    @staticmethod
    def from_json(data: dict) -> Package:
        Package.validate(data=data)
        ret_package = {
            "name": data["name"],
            "days": data["days"],
            "detail": data["detail"],
        }

        if "id" in data.keys():
            ret_package["id"] = data["id"]
        if "package_contents" in data.keys():
            ret_package["package_contents"] = []
            if isinstance(data["package_contents"], list):
                for package_content in data["package_contents"]:
                    DB_LOGGER.debug("package_content:  %s", package_content)
                    if isinstance(package_content, int):
                        db_package_content = get_package_content_by_id(package_content)
                        DB_LOGGER.debug("db_package_content : %s", db_package_content)
                        if db_package_content is None:
                            raise SchemaError("package_content_not_found")
                        ret_package["package_contents"].append(db_package_content)
                    elif isinstance(package_content, dict):
                        pc_content = PackageContent.from_json(package_content)
                        DB_LOGGER.debug("pc_content : %s", pc_content)
                        ret_package["package_contents"].append(pc_content)
                    else:
                        raise SchemaError("not_valid_package_contents")
        return Package(**ret_package)

    @staticmethod
    def from_req_form(immutable_data: ImmutableMultiDict) -> Package:
        mutable_data: dict = immutable_data.to_dict()
        for key, value in mutable_data.items():
            if value is None or value == "":
                mutable_data.pop(key)
        return Package.from_json(mutable_data)  # maybe nned to change

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(
                    int,
                    Use(lambda x: x in [package.id for package in Package.query.all()]),
                    error="not_valid_id",
                ),
                "name": And(str, Use(lambda x: len(x) > 3), error="not_valid_name"),
                "days": And(
                    int, Use(lambda x: (1 >= x) and (x < 366)), error="not_valid_days"
                ),  # 1,30,90,365 gibi
                "detail": And(str, len, error="not_valid_detail"),
                Optional("package_contents"): Use(
                    _package_contents_validate, error="not_valid_package_contents"
                ),
            },
            error="not_valid_data",
        )
        schema.validate(data)


class U_Package(Base):
    __tablename__ = "user_packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    start_date: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    base_package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"), nullable=False)
    base_package: Mapped[Package] = relationship(
        "Package", uselist=False, backref="user_packages"
    )

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    def __repr__(self) -> str:
        return "<{clsname} ({id} {base_package} {start_date} {end_date} {user})>".format(
            clsname=self.__class__.__name__,
            id=self.id,
            base_package=self.base_package,
            start_date=self.start_date,
            end_date=self.end_date,
            user=self.user,
        )

    def __json__(self, user_incld=True) -> dict[str, Any]:
        return (
            {
                "id": self.id,
                "base_package": self.base_package.__json__(),
                "start_date": utc_timestamp(self.start_date),
                "end_date": utc_timestamp(self.end_date),
                "user": self.user.__json__(package_incld=False),
            }
            if user_incld
            else {
                "id": self.id,
                "base_package": self.base_package.__json__(),
                "start_date": utc_timestamp(self.start_date),
                "end_date": utc_timestamp(self.end_date),
            }
        )

    @staticmethod
    def from_json(data: dict) -> U_Package:
        U_Package.validate(data=data)
        base_package = get_package_by_id(data["base_package"])
        ret_u_package = {
            "base_package": base_package,
            "start_date": utc_timestamp(data["start_date"], return_type=datetime),
        }
        if base_package is None:
            raise SchemaError("base_package_not_found")
        if base_package.days is None:
            raise SchemaError("base_package.days_not_found")
        base_package_days = base_package.days
        ret_u_package["base_package"] = base_package
        if "id" in data.keys():
            ret_u_package["id"] = data["id"]
        if "end_date" in data.keys():
            ret_u_package["end_date"] = utc_timestamp(
                data["end_date"], return_type=datetime
            )
        else:
            ret_u_package["end_date"] = utc_timestamp(
                data["start_date"], return_type=datetime
            ) + timedelta(
                days=base_package_days
            )  # type: ignore

        if "user_id" in data.keys():
            if "user" in data.keys():
                if data["user"] != data["user_id"]:
                    raise SchemaError("user_id_and_user_both_found")
            if isinstance(data["user_id"], int):
                ret_u_package["user_id"] = data["user_id"]
            else:
                raise SchemaError("user_not_found")
        elif "user" in data.keys():
            if isinstance(data["user"], int):
                ret_u_package["user_id"] = data["user"]
            else:
                raise SchemaError("user_not_found")
        else:
            raise SchemaError("user_not_found")
        DB_LOGGER.debug("ret_u_package: %s" % ret_u_package)
        return U_Package(**ret_u_package)

    @staticmethod
    def from_req_form(immutable_data: ImmutableMultiDict) -> U_Package:
        mutable_data: dict = immutable_data.to_dict()
        for key, value in mutable_data.items():
            if value is None or value == "":
                mutable_data.pop(key)
        return U_Package.from_json(mutable_data)  # maybe nned to change

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(
                    int,
                    Use(
                        lambda x: x in [u_package.id for u_package in U_Package.query.all()]
                    ),
                    error="not_valid_id",
                ),
                "base_package": And(int, Use(_package_id_check), error="not_valid_package"),
                "start_date": And(int, error="not_valid_start_date"),
                Optional("end_date"): And(
                    int,
                    Use(
                        lambda x: (
                            x > data["start_date"] and x < utc_timestamp(datetime.utcnow())
                        )
                    ),
                    error="not_valid_end_date",
                ),
                Optional("user"): And(int, Use(_user_id_check), error="not_valid_user"),
                Optional("user_id"): And(int, Use(_user_id_check), error="not_valid_user"),
            },
            error="not_valid_data",
        )
        schema.validate(data)

    def is_expired(self) -> bool:
        return self.end_date < datetime.utcnow()


class U_Session(Base):
    __slots__ = ["u_package", "u_accessible_sessions"]
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    start_date: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=datetime.utcnow
    )
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    ip: Mapped[str] = mapped_column(String(256), nullable=False)
    access: Mapped[bool] = mapped_column(nullable=False, default=True)

    def __repr__(self) -> str:
        return "<{clsname} ({id} {user_id} {start_date} {end_date} {ip} {access})>".format(
            clsname=self.__class__.__name__,
            id=self.id,
            user_id=self.user_id,
            start_date=self.start_date,
            end_date=self.end_date,
            ip=self.ip,
            access=self.access,
        )

    def __json__(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "start_date": utc_timestamp(self.start_date),
            "end_date": utc_timestamp(self.end_date),
            "ip": self.ip,
            "access": self.access,
        }

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(
                    int,
                    Use(
                        lambda x: x in [u_session.id for u_session in U_Session.query.all()]
                    ),
                    error="not_valid_id",
                ),
                "user_id": And(int, Use(_user_id_check), error="not_valid_user"),
                "start_date": And(
                    int,
                    Use(lambda x: x < utc_timestamp(datetime.utcnow())),
                    error="not_valid_start_date",
                ),
                "end_date": And(
                    int, Use(lambda x: (x > data["start_date"])), error="not_valid_end_date"
                ),
                "ip": And(str, len, error="not_valid_ip"),
                "accesible": And(bool, error="not_valid_accesible"),
            },
            error="not_valid_data",
        )
        schema.validate(data)

    def extend_session(self) -> None:
        self.end_date = datetime.utcnow() + timedelta(
            minutes=current_app.config["USER_SESSION_TIMEOUT"]
        )
        self.access = True
        db.session.commit()

    def is_expired(self) -> bool:
        return self.end_date < datetime.utcnow()


class User(Base):
    """
    # tr: Kullanici
    db model for users
    """

    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)

    password_hash: Mapped[str] = mapped_column(String(256), unique=False, nullable=False)

    discord_id: Mapped[str] = mapped_column(String(18), nullable=True)

    # delete u_package when user deleted
    package: Mapped[U_Package] = relationship(
        "U_Package", cascade="all, delete-orphan", backref="user"
    )
    # delete all u_sessions when user deleted
    sessions: Mapped[List[U_Session]] = relationship(
        "U_Session",
        backref="user",
        cascade="all, delete-orphan",
        order_by="asc(U_Session.end_date)",  # first most oldest session
        lazy="dynamic",
    )

    def __repr__(self) -> str:
        return "<{clsname} ({id} {name} {password_hash} {discord_id})>".format(
            clsname=self.__class__.__name__,
            id=self.id,
            name=self.name,
            password_hash=self.password_hash,
            discord_id=self.discord_id,
        )

    def __json__(self, package_incld=True) -> dict[str, Any]:
        ret_package = {
            "id": self.id,
            "name": self.name,
            "password_hash": self.password_hash,
            "discord_id": self.discord_id,
        }
        if self.package is not None:
            if package_incld:
                ret_package["package"] = self.package.__json__(user_incld=False)
        if self.sessions is not None:
            ret_package["sessions"] = [u_session.__json__() for u_session in self.sessions]
        return ret_package

    @staticmethod
    def from_json(data: dict) -> User:
        User.validate(data=data)
        ret_user = {
            "name": data["name"],
            "password_hash": data["password_hash"],
        }
        if "discord_id" in data.keys():
            ret_user["discord_id"] = data["discord_id"]
        if "package" in data.keys():
            ret_user["package"] = data["package"]
        if "id" in data.keys():
            ret_user["id"] = data["id"]
        return User(**ret_user)

    @staticmethod
    def from_req_form(
        immutable_data: ImmutableMultiDict, org_user: User | None = None
    ) -> User:
        DB_LOGGER.debug("org_user: %s" % org_user)
        DB_LOGGER.debug("immutable_data: %s" % immutable_data)
        mutable_data: dict = immutable_data.to_dict()
        data_before_pop = immutable_data.to_dict()
        mutable_data = {
            key: value
            for key, value in mutable_data.items()
            if key
            in [
                "id",
                "name",
                "password",
                "discord_id",
                "base_package",
                "package",
            ]
        }
        for key, value in data_before_pop.items():
            if value is None or value == "":
                DB_LOGGER.debug("key: %s, value: %s" % (key, value))
                mutable_data.pop(key)
        del data_before_pop
        if "password" in mutable_data.keys():
            password_hash = make_password_hash(mutable_data["password"])
            mutable_data["password_hash"] = password_hash
            mutable_data.pop("password")
        elif "id" in mutable_data.keys() or org_user is not None:
            user = org_user if org_user is not None else get_user_by_id(mutable_data["id"])
            if user is None:
                raise SchemaError("user_not_found")
            mutable_data["password_hash"] = user.password_hash
        else:
            raise SchemaError("password_or_id_not_found")
        if "base_package" in mutable_data.keys():
            base_package = get_package_by_id(mutable_data["base_package"])
            if base_package is None:
                raise SchemaError("base_package_not_found")
            new_u_package = U_Package(
                base_package_id=mutable_data["base_package"],
                start_date=datetime.utcnow(),
                end_date=datetime.utcnow() + timedelta(days=base_package.days),
                user_id=org_user.id if org_user is not None else mutable_data["id"],
            )
            add_u_package(new_u_package)
            mutable_data["package"] = new_u_package
            mutable_data.pop("base_package")
        return User(**mutable_data)

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(int, Use(_user_id_check), error="not_valid_id"),
                "name": And(str, len, error="not_valid_name"),
                "password_hash": And(str, len, error="not_valid_password_hash"),
                Optional("discord_id"): And(str, len, error="not_valid_discord_id"),
                Optional("package"): Or(
                    And(Or(int, None), Use(_package_id_check), error="not_valid_package"),
                    U_Package,
                ),
            },
            error="not_valid_data",
        )

        schema.validate(data)

    @staticmethod
    def validate_login_data(data: dict) -> None:
        schema = Schema(
            {
                "name": And(str, len),
                "password_hash": And(str, len),
            },
            error="not_valid_data",
        )
        schema.validate(data)

    def open_session(self, inamedr: str) -> loginError | bool:
        # self.sessions.sort(key=lambda x: x.end_date)
        self.u_accessible_sessions = list(filter(lambda x: x.access, self.sessions))
        u_package: U_Package = self.package
        if u_package is not None:
            if u_package.is_expired():
                delete_model(u_package, db.session)
                return loginError.user_package_expired
            p_contents = u_package.base_package.package_contents
            extra_user_quota = list(
                filter(lambda x: x.content_value == pContentEnum.extra_user, p_contents)
            )
            max_sessions = 1 + len(extra_user_quota) if extra_user_quota is not None else 0
            same_ip_expired_session = self._eleminate_expired_accessible_sessions(inamedr)

            if len(self.u_accessible_sessions) > max_sessions:
                return loginError.max_online_user
            if same_ip_expired_session is not None:
                same_ip_expired_session.extend_session()
                DB_LOGGER.info(
                    "user oturum uzatildi: id:%s, name:%s, ip:%s"
                    % (self.id, self.name, inamedr)
                )
                return True
            self._add_new_session(inamedr)
            db.session.commit()
            DB_LOGGER.info(
                "user oturum acildi: id:%s, name:%s, ip:%s" % (self.id, self.name, inamedr)
            )
            return True
        return loginError.user_not_have_package

    def _add_new_session(self, inamedr: str) -> None:
        """
        en: add new session to user (accessable)
        tr: kullanıcıya yeni oturum ekle (erişilebilir)
        :param inamedr: client ip
        """
        if self.u_accessible_sessions is None:
            self.u_accessible_sessions = []
        new_session = U_Session(
            user_id=self.id,
            start_date=datetime.utcnow(),
            end_date=datetime.utcnow()
            + timedelta(minutes=current_app.config["USER_SESSION_TIMEOUT"]),
            ip=inamedr,
        )
        self.sessions.append(new_session)
        self.u_accessible_sessions.append(new_session)
        db.session.commit()

    def _eleminate_expired_accessible_sessions(self, inamedr: str) -> None | U_Session:
        """
        en :eleminate expired sessions and return last session with same ip
        tr: acik oturumlar listesini gunceller \
            if ayni ip adresinden birden fazla oturum varsa en yeni olanı döndürür
        :param inamedr: client ip
        :return: None | U_Session
        """
        expired_sessions = filter_list(lambda x: x.is_expired(), self.u_accessible_sessions)
        DB_LOGGER.debug("expired_sessions: %s" % expired_sessions)
        same_ip_expired_sessions = filter_list(lambda x: x.ip == inamedr, expired_sessions)
        DB_LOGGER.debug("same_ip_expired_sessions: %s" % same_ip_expired_sessions)
        other_ip_expired_sessions = filter_list(lambda x: x.ip != inamedr, expired_sessions)
        DB_LOGGER.debug("other_ip_expired_sessions: %s" % other_ip_expired_sessions)
        self._disable_multiple_sessions_acess(other_ip_expired_sessions)

        if len(same_ip_expired_sessions) > 1:
            same_ip_expired_sessions.sort(key=lambda x: x.end_date)

            newest_same_ip_session = same_ip_expired_sessions[-1]
            same_ip_expired_sessions.remove(newest_same_ip_session)
            self._disable_multiple_sessions_acess(same_ip_expired_sessions)
            if not (
                newest_same_ip_session.end_date
                + timedelta(minutes=current_app.config["USER_OLDEST_SESSION_TIMEOUT"])
                < datetime.utcnow()
            ):
                self._disable_session_access(newest_same_ip_session)
                return newest_same_ip_session
            return None
        return None

    def _disable_session_access(self, oturum: U_Session) -> None:
        oturum.access = False
        DB_LOGGER.info("user oturum kapatildi: k_ad:%s  oturum:%s" % (self.id, oturum))
        self.u_accessible_sessions.remove(oturum)
        # self.sessions.append(oturum)
        db.session.commit()

    def _disable_multiple_sessions_acess(self, oturumlar: List[U_Session]) -> None:
        DB_LOGGER.debug("disable_multiple_sessions_acess: %s" % oturumlar)
        if oturumlar is not None:
            for oturum in oturumlar:
                self._disable_session_access(oturum)
        db.session.commit()

    def tum_oturumlari_kapat(self) -> None:
        if self.sessions is not None:
            for oturum in self.sessions:
                self._disable_session_access(oturum)
        db.session.commit()


class Admin(Base):
    __tablename__ = "admins"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), unique=False, nullable=False)

    def __repr__(self) -> str:
        return "<{clsname} ({id} {name} {password_hash})>".format(
            clsname=self.__class__.__name__,
            id=self.id,
            name=self.name,
            password_hash=self.password_hash,
        )

    def __json__(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "password_hash": self.password_hash,
        }

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                "name": And(str, len, error="not_valid_name"),
                "password_hash": And(str, len, error="not_valid_password_hash"),
            },
            error="not_valid_data",
        )
        schema.validate(data)


def utc_timestamp(dt: datetime | int, return_type: type | None = None) -> int | datetime:
    """
    toggle datetime to int timestamp
    toggle int timestampt to datetime
    :param: dt
    :param: return_type -> datetime | int | None (default None)

    note: i lose some presition but is it need to be that precise
    """
    DB_LOGGER.debug(f"dt: {dt},return_type: {return_type}")
    if return_type is None:
        if isinstance(dt, datetime):
            return int(dt.timestamp())
        if isinstance(dt, int):
            return datetime.utcfromtimestamp(float(dt))
    else:
        new_dt = utc_timestamp(dt, return_type=None)
        DB_LOGGER.debug(f"new_dt: {new_dt}")
        for _ in range(2):
            if isinstance(new_dt, return_type):
                return new_dt
            new_dt = utc_timestamp(new_dt, return_type=None)
    raise RuntimeError("dt needs to be int or datetime.datetime object")


def add_db_model(
    model: U_Package | U_Session | User | Admin | Package | PackageContent,
    session: scoped_session = db.session,
) -> DBOperationResult:
    try:
        DB_LOGGER.info("adding model to database %s" % model)
        if not isinstance(model, U_Package) or isinstance(model, U_Session):
            if len(model.name) < 3:
                return DBOperationResult.model_name_too_short
            if len(model.name) > 256:
                return DBOperationResult.model_name_too_long
        with session.begin_nested():
            DB_LOGGER.debug("session.is_active: %s" % session.is_active)
            session.add(model)
            DB_LOGGER.debug("session.add(model) done")
            session.commit()
            return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while adding model to database %s" % e)
        session.rollback()
        if "UNIQUE constraint failed" in str(e):
            DB_LOGGER.error("model already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_db_all_models(
    models: List[U_Package | U_Session | User | Admin | Package | PackageContent],
    session: scoped_session = db.session,
) -> DBOperationResult:
    try:
        with session.begin_nested():
            session.add_all(models)
            session.commit()
            return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while adding model to database %s" % e)
        session.rollback()
        if "UNIQUE constraint failed" in str(e):
            DB_LOGGER.error("model already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_user(user: User, session: scoped_session = db.session) -> DBOperationResult:
    if len(user.password_hash) < 16:  # AESBlockSize 16
        return DBOperationResult.model_passhash_too_short
    if user.package is not None:
        if add_u_package(user.package, session) != DBOperationResult.success:
            return DBOperationResult.model_not_created
    if is_exits := session.query(User).filter_by(name=user.name).first():
        DB_LOGGER.info("user already exists %s" % is_exits)
        return DBOperationResult.model_already_exists
    return add_db_model(user, session)


def add_admin(admin: Admin, session: scoped_session = db.session) -> DBOperationResult:
    if len(admin.password_hash) < 16:
        return DBOperationResult.model_passhash_too_short
    if is_exits := session.query(Admin).filter_by(name=admin.name).first():
        DB_LOGGER.info("admin already exists %s" % is_exits)
        return DBOperationResult.model_already_exists
    return add_db_model(admin, session)


def add_package(
    package: Package, session: scoped_session = db.session, disable_recursive=False
) -> DBOperationResult:
    DB_LOGGER.info("adding package to database")
    DB_LOGGER.debug("package: %s" % package)
    DB_LOGGER.debug("session: %s" % session)
    DB_LOGGER.debug("disable_recursive: %s" % disable_recursive)
    if hasattr(package, "package_contents") and not disable_recursive:
        # TODO: this part probably never runs cause -> Package.from_json()
        for package_content in package.package_contents:
            if package_content is None:
                continue
            if isinstance(package_content, PackageContent):
                package_content_exist = (
                    session.query(PackageContent)
                    .filter(
                        PackageContent.name == package_content.name,
                        PackageContent.content_value == package_content.content_value,
                    )
                    .first()
                )
                if package_content_exist is None:
                    if (
                        add_package_content(
                            package_content, session, disable_recursive=True
                        )
                        != DBOperationResult.success
                    ):
                        return DBOperationResult.model_not_created
            elif isinstance(package_content, int):
                package_content_exist = (
                    session.query(PackageContent).filter_by(id=package_content).first()
                )
                if package_content_exist is None:
                    return DBOperationResult.model_not_created
    return add_db_model(package, session)


def add_package_content(
    package_content: PackageContent,
    session: scoped_session = db.session,
    disable_recursive=False,
) -> DBOperationResult:
    if hasattr(package_content, "packages") and not disable_recursive:
        # TODO: maybe change this to add_db_all_models
        for package in package_content.packages:
            if isinstance(package, Package):
                package_exist = session.query(Package).filter_by(name=package.name).first()
                if package_exist is None:
                    if (
                        add_package(package, session, disable_recursive=True)
                        != DBOperationResult.success
                    ):
                        return DBOperationResult.model_not_created
                package_exist = session.query(Package).filter_by(name=package.name).first()
            elif isinstance(package, int):
                package_exist = session.query(Package).filter_by(id=package).first()
                if package_exist is None:
                    return DBOperationResult.model_not_created
                package_content.packages.append(package_exist)
    return add_db_model(package_content, session)


def add_u_package(
    u_package: U_Package, session: scoped_session = db.session
) -> DBOperationResult:
    if u_package.base_package is not None:
        if u_package.base_package.id is None:
            add_package(u_package.base_package, session)
        db_package = get_package_by_id(u_package.base_package.id, session)
        if db_package is None:
            return DBOperationResult.model_not_found
        u_package.base_package = db_package
    if u_package.user is not None:
        if u_package.user.id is None:
            add_user(u_package.user, session)
        db_user = get_user_by_id(u_package.user.id, session)
        if db_user is None:
            return DBOperationResult.model_not_found
        u_package.user = db_user
    return add_db_model(u_package, session)


def get_user(name: str, session: scoped_session = db.session) -> User | None:
    return session.query(User).filter_by(name=name).first()


def get_admin(name: str, session: scoped_session = db.session) -> Admin | None:
    return session.query(Admin).filter_by(name=name).first()


def get_user_by_id(id: int, session: scoped_session = db.session) -> User | None:
    return session.query(User).filter_by(id=id).first()


def get_admin_by_id(id: int, session: scoped_session = db.session) -> Admin | None:
    return session.query(Admin).filter_by(id=id).first()


def get_package_by_id(id: int, session: scoped_session = db.session) -> Package | None:
    return session.query(Package).filter_by(id=id).first()


def get_package_content_by_id(
    id: int, session: scoped_session = db.session
) -> PackageContent | None:
    return session.query(PackageContent).filter_by(id=id).first()


def get_u_package_by_id(id: int, session: scoped_session = db.session) -> U_Package | None:
    return session.query(U_Package).filter_by(id=id).first()


def get_u_session_by_id(id: int, session: scoped_session = db.session) -> U_Session | None:
    return session.query(U_Session).filter_by(id=id).first()


def try_login(user: User, ip_addr: str | None) -> loginError | bool:
    if ip_addr is None:
        return loginError.not_found_client_ip
    if user is not None:
        return user.open_session(ip_addr)
    return loginError.user_not_found


def filter_list(function: Callable[[Any], bool], input_list: List[Any]) -> List[Any]:
    return list(filter(function, input_list))


def _package_contents_validate(package_contents: List[PackageContent | None | int]) -> bool:
    if package_contents is None:
        return False
    for package_content in package_contents:
        if not _package_content_validate(package_content):
            return False
    return True


def _package_content_validate(package_content: PackageContent | None | int) -> bool:
    if package_content is None:
        return False
    elif isinstance(package_content, int):
        package_content = PackageContent.query.filter_by(id=package_content).first()
        if package_content is None:
            return False
    elif isinstance(package_content, PackageContent):
        package_content_exist = PackageContent.query.filter_by(
            name=package_content.name
        ).first()
        if package_content_exist is None:
            return package_content.validate(package_content.__json__()) is not None
    return True


def _package_id_check(package_id: int) -> bool:
    return package_id in [package.id for package in Package.query.all()]


def _user_id_check(user_id: int) -> bool:
    return user_id in [user.id for user in User.query.all()]


def validate_data_schema(cls, data):
    try:
        cls.validate(data)
    except SchemaError as e:
        raise e


def update_user(
    old_user: int | User, new_user: User, session: scoped_session = db.session
) -> DBOperationResult:
    """
    update user with k_id
    :param old_user: id of user to update or user object
    :param new_user: new user object
    :param session: db session
    :return: DBOperationResult
    ---
    only update name, password_hash, discord_id, k_ps
    ---
    """
    try:
        if isinstance(old_user, int):
            db_user = session.query(User).filter_by(k_id=old_user).first()
        else:
            db_user = old_user
        if db_user is None:
            return DBOperationResult.model_not_found
        if new_user.name is not None:
            if db_user.name != new_user.name:
                db_user.name = new_user.name
        if new_user.password_hash is not None:
            db_user.password_hash = new_user.password_hash
        if new_user.discord_id is not None:
            db_user.discord_id = new_user.discord_id
        if new_user.package is not None:
            if isinstance(new_user.package, int):
                db_package = session.query(Package).filter_by(id=new_user.package).first()
                if db_package is None:
                    raise SchemaError("package_not_found")
                db_user.package = db_package
            else:
                db_user.package = new_user.package
        del new_user
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while updating user to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_package_content(
    old_package_content: int | PackageContent,
    new_package_content: PackageContent,
    session: scoped_session = db.session,
) -> DBOperationResult:
    try:
        if isinstance(old_package_content, int):
            db_package_content = (
                session.query(PackageContent).filter_by(id=old_package_content).first()
            )
        else:
            db_package_content = old_package_content
        if db_package_content is None:
            return DBOperationResult.model_not_found
        if new_package_content.name is not None:
            db_package_content.name = new_package_content.name
        if new_package_content.content_value is not None:
            db_package_content.content_value = new_package_content.content_value
        if new_package_content.package_id is not None:
            db_package_content.package_id = new_package_content.package_id
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while updating package_content to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_package(
    old_package: int | Package, new_package: Package, session: scoped_session = db.session
):
    try:
        if isinstance(old_package, int):
            db_package = session.query(Package).filter_by(id=old_package).first()
        else:
            db_package = old_package
        if db_package is None:
            return DBOperationResult.model_not_found
        if new_package.name is not None:
            db_package.name = new_package.name
        if new_package.days is not None:
            db_package.days = new_package.days
        if new_package.detail is not None:
            db_package.detail = new_package.detail
        if new_package.package_contents is not None:
            for package_content in new_package.package_contents:
                if isinstance(package_content, int):
                    db_package.package_contents.append(
                        session.query(PackageContent).filter_by(id=package_content).first()
                    )
                else:
                    db_package.package_contents.append(package_content)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while updating package to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_u_package(
    old_u_package: int | U_Package,
    new_u_package: U_Package,
    session: scoped_session = db.session,
):
    try:
        if isinstance(old_u_package, int):
            db_u_package = session.query(U_Package).filter_by(id=old_u_package).first()
        else:
            db_u_package = old_u_package
        if db_u_package is None:
            return DBOperationResult.model_not_found
        if new_u_package.start_date is not None:
            db_u_package.start_date = new_u_package.start_date
        if new_u_package.end_date is not None:
            db_u_package.end_date = new_u_package.end_date
        if new_u_package.base_package_id is not None:
            db_u_package.base_package_id = new_u_package.base_package_id
        if new_u_package.user is not None:
            db_u_package.user_id = new_u_package.user.id
        elif new_u_package.user_id is not None:
            db_u_package.user_id = new_u_package.user_id

        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while updating u_package %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_u_session(
    old_u_session: int | U_Session,
    new_u_session: U_Session,
    session: scoped_session = db.session,
):
    try:
        if isinstance(old_u_session, int):
            db_u_session = session.query(U_Session).filter_by(id=old_u_session).first()
        else:
            db_u_session = old_u_session
        if db_u_session is None:
            return DBOperationResult.model_not_found
        if new_u_session.start_date is not None:
            db_u_session.start_date = new_u_session.start_date
        if new_u_session.end_date is not None:
            db_u_session.end_date = new_u_session.end_date
        if new_u_session.user_id is not None:
            db_u_session.user_id = new_u_session.user_id
        if new_u_session.ip is not None:
            db_u_session.ip = new_u_session.ip
        if new_u_session.access is not None:
            db_u_session.access = new_u_session.access
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while updating u_session to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def _delete_model(
    model: User | Admin | Package | PackageContent | U_Package | U_Session,
    session: scoped_session = db.session,
):
    try:
        session.delete(model)
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while deleting model from database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def delete_model(
    model: User | Admin | Package | PackageContent | U_Package | U_Session,
    session: scoped_session = db.session,
) -> DBOperationResult:
    DB_LOGGER.info("deleting model from database %s" % model)
    return _delete_model(model, session)


def get_all_admins(session: scoped_session = db.session) -> List[Admin]:
    return session.query(Admin).all()


def get_all_users(session: scoped_session = db.session) -> List[User]:
    return session.query(User).all()


def get_all_packages(session: scoped_session = db.session) -> List[Package]:
    return session.query(Package).all()


def get_all_package_contents(session: scoped_session = db.session) -> List[PackageContent]:
    return session.query(PackageContent).all()


def get_all_content_values():
    return pContentEnum.__members__.keys()


def get_all_u_packages(session: scoped_session = db.session) -> List[U_Package]:
    return session.query(U_Package).all()


def get_all_u_sessions(session: scoped_session = db.session) -> List[U_Session]:
    return session.query(U_Session).all()


def update_user_from_req_form(
    old_user: User,
    form_data: ImmutableMultiDict,
    session: scoped_session = db.session,
):
    try:
        db_user = old_user
        if db_user is None:
            return DBOperationResult.model_not_found
        form_user = User.from_req_form(form_data, org_user=db_user)
        return update_user(db_user, form_user, session)
    except Exception as e:
        DB_LOGGER.error("error accured while updating user to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_package_from_req_form(
    old_package: Package,
    form_data: ImmutableMultiDict,
    session: scoped_session = db.session,
):
    try:
        db_package = old_package
        if db_package is None:
            return DBOperationResult.model_not_found
        form_package = Package.from_req_form(form_data)
        return update_package(db_package, form_package, session=session)
    except Exception as e:
        DB_LOGGER.error("error accured while updating package to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_package_content_from_req_form(
    old_package_content: PackageContent,
    form_data: ImmutableMultiDict,
    session: scoped_session = db.session,
):
    try:
        db_package_content = old_package_content
        if db_package_content is None:
            return DBOperationResult.model_not_found
        form_package_content = PackageContent.from_req_form(form_data)
        return update_package_content(
            db_package_content, form_package_content, session=session
        )
    except Exception as e:
        DB_LOGGER.error("error accured while updating package_content to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_u_package_from_req_form(
    old_u_package: U_Package,
    form_data: ImmutableMultiDict,
    session: scoped_session = db.session,
):
    try:
        db_u_package = old_u_package
        if db_u_package is None:
            return DBOperationResult.model_not_found
        form_u_package = U_Package.from_req_form(form_data)
        return update_u_package(db_u_package, form_u_package, session=session)
    except Exception as e:
        DB_LOGGER.error("error accured while updating u_package to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error


def update_u_session_from_req_form(
    old_u_session: U_Session,
    form_data: ImmutableMultiDict,
    session: scoped_session = db.session,
):
    try:
        db_u_session = old_u_session
        if db_u_session is None:
            return DBOperationResult.model_not_found
        form_u_session = U_Session.from_req_form(form_data)
        return update_u_session(db_u_session, form_u_session, session=session)
    except Exception as e:
        DB_LOGGER.error("error accured while updating u_session to database %s" % e)
        session.rollback()
    return DBOperationResult.unknown_error

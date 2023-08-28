from __future__ import annotations
import enum
from datetime import datetime, timedelta
from logging import getLogger
from typing import Any, Callable, List

from .config.flask import USER_OLDEST_SESSION_TIMEOUT, USER_SESSION_TIMEOUT

from flask_sqlalchemy import SQLAlchemy
from schema import Or, Schema, And, Use, Optional, SchemaError
from sqlalchemy import DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import Mapped, declarative_base, mapped_column, relationship, scoped_session
from sqlalchemy.orm.decl_api import DeclarativeMeta

Base: DeclarativeMeta = declarative_base()
db = SQLAlchemy(model_class=Base)
DB_LOGGER = getLogger("sqlalchemy_db")

# DEVLOG -> serilize datetime as utc_timestamp


class pContentEnum(enum.StrEnum):
    # TODO : maybe change in future for more flexibility
    moe_gatherer = enum.auto()  # -> "moe_gatherer"
    moe_advantures = enum.auto()
    moe_camp = enum.auto()
    moe_arena = enum.auto()
    moe_raid = enum.auto()
    extra_user = enum.auto()
    discord = enum.auto()  # TODO: discord api kullanım hakkı


class loginError(enum.IntEnum):
    # sifre_veya_user_adi_yanlis = enum.auto()
    max_online_user = enum.auto()
    user_not_found = enum.auto()
    user_not_have_package = enum.auto()
    user_package_expired = enum.auto()
    not_found_client_ip = enum.auto()


class DBOperationResult(enum.Enum):
    success = True
    unknown_error = enum.auto()
    model_already_exists = enum.auto()
    model_not_found = enum.auto()
    model_not_created = enum.auto()
    model_not_updated = enum.auto()
    model_not_deleted = enum.auto()
    model_name_too_short = enum.auto()
    model_name_too_long = enum.auto()
    model_passhash_too_short = enum.auto()

    def __json__(self) -> dict[str, Any]:
        "serialize enum to json"
        return {"db_operation_result": self.name}


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
    content_value: Mapped[str] = mapped_column(Enum(*[e for e in pContentEnum]), nullable=False)
    package_id: Mapped[int | None] = mapped_column(ForeignKey("packages.id"), nullable=True)
    packages: Mapped[List[Package]] = relationship("Package", secondary=pcontent_packages_conn_table, back_populates="packagecontents")

    def __repr__(self):
        return f"<PackageContent ({self.id} {self.name} {self.content_value} {self.packages})>"

    def __json__(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "content_value": self.content_value,
        }

    @staticmethod
    def from_json(data: dict) -> PackageContent:
        PackageContent.validate(data=data)
        return PackageContent(
            name=data["name"],
            content_value=data["content_value"],
        )

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(int, Use(lambda x: x in [p_content.id for p_content in PackageContent.query.all()])),
                "name": And(str, len),
                "content_value": And(str, Use(pContentEnum)),
                Optional("packages"): And(list, Use(lambda x: [Package.from_json(package_data) for package_data in x])),
                Optional("package_id"): And(Or(int, None), Use(_package_id_check)),
            }
        )
        schema.validate(data)


class Package(Base):
    __tablename__ = "packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)

    days: Mapped[int] = mapped_column(nullable=False, default=30)  # 1,30,90,365 gibi
    detail: Mapped[str] = mapped_column(String(256), nullable=False, default="package_detail")

    packagecontents: Mapped[List[PackageContent]] = relationship(
        "PackageContent", back_populates="packages", secondary=pcontent_packages_conn_table
    )

    def __repr__(self):
        return f"<Package {self.id} {self.name} {self.days} {self.detail}>"

    def __json__(self) -> dict[str, Any]:
        if self.packagecontents is not None and len(self.packagecontents) > 0:
            return {
                "id": self.id,
                "name": self.name,
                "days": self.days,
                "detail": self.detail,
                "packagecontents": [package_content.__json__() for package_content in self.packagecontents],
            }
        return {
            "id": self.id,
            "name": self.name,
            "days": self.days,
            "detail": self.detail,
            "packagecontents": None,
        }

    @staticmethod
    def from_json(data: dict) -> Package:
        Package.validate(data=data)
        if "packagecontents" in data.keys():
            return Package(
                name=data["name"],
                days=data["days"],
                detail=data["detail"],
                packagecontents=data["packagecontents"],
            )
        return Package(
            name=data["name"],
            days=data["days"],
            detail=data["detail"],
        )

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(int, Use(lambda x: x in [package.id for package in Package.query.all()])),
                "name": And(str, len),
                "days": And(int, Use(lambda x: (1 >= x) and (x < 366))),  # 1,30,90,365 gibi
                "detail": And(str, len),
                Optional("package_contents"): And(
                    Or(list, int),
                    Or(
                        Use(_package_content_validate),
                        Or(Use(_package_content_id_check), Use(lambda x: [PackageContent.from_json(pc_data) for pc_data in x])),
                    ),
                ),
            }
        )
        schema.validate(data)


class U_Package(Base):
    __tablename__ = "user_packages"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    base_package_id: Mapped[int] = mapped_column(ForeignKey("packages.id"), nullable=False)
    base_package: Mapped[Package] = relationship("Package", uselist=False, backref="user_packages")

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {self.id} \
                    {self.base_package} {self.start_date} {self.end_date} {self.user}>"

    def __json__(self, user_incld=True) -> dict[str, Any]:
        return (
            {
                "id": self.id,
                "base_package": self.base_package.__json__(),
                "start_date": utc_timestamp(self.start_date),
                "end_date": utc_timestamp(self.end_date),
                "user": self.user.__json__(),
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
        if "end_date" in data.keys():
            return U_Package(
                base_package=data["base_package"],
                start_date=utc_timestamp(data["start_date"], return_type=datetime),
                end_date=utc_timestamp(data["end_data"], return_type=datetime),
                user=data["user"],
            )
        else:
            base_package = get_package_by_id(data["base_package"])
            if base_package is None:
                raise AttributeError("base_package not found")
            if base_package.days is None:
                raise AttributeError("base_package.days not found")
            base_package_days = int(base_package.days)
            return U_Package(
                base_package=get_package_by_id(data["base_package"]),
                start_date=utc_timestamp(data["start_date"], return_type=datetime),
                end_date=utc_timestamp(data["start_date"], return_type=datetime) + timedelta(days=base_package_days),  # type: ignore
                user=get_user_by_id(data["user"]),
            )

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(int, Use(lambda x: x in [u_package.id for u_package in U_Package.query.all()])),
                "base_package": And(int, Use(_package_id_check)),
                "start_date": And(int),
                Optional("end_date"): And(int, Use(lambda x: (x > data["start_date"] and x < utc_timestamp(datetime.utcnow())))),
                "user": And(int, Use(_user_id_check)),
            }
        )
        schema.validate(data)

    def is_expired(self) -> bool:
        return self.end_date < datetime.utcnow()


class U_Session(Base):
    __tablename__ = "user_sessions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    start_date: Mapped[datetime] = mapped_column(DateTime, nullable=False, default=datetime.utcnow)
    end_date: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    ip: Mapped[str] = mapped_column(String(256), nullable=False)
    access: Mapped[bool] = mapped_column(nullable=False, default=True)

    def __repr__(self) -> str:
        return f"<U_Session {self.id} {self.user_id} {self.start_date} {self.end_date} {self.ip} {self.access}>"

    def __json__(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "start_date": utc_timestamp(self.start_date),
            "end_date": utc_timestamp(self.end_date),
            "ip": self.ip,
            "accesible": self.acces,
        }

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(int, Use(lambda x: x in [u_session.id for u_session in U_Session.query.all()])),
                "user_id": And(int, Use(_user_id_check)),
                "start_date": And(int),
                "end_date": And(int, Use(lambda x: (x > data["start_date"]))),
                "ip": And(str, len),
                "accesible": And(bool),
            }
        )
        schema.validate(data)

    def extend_session(self) -> None:
        self.end_date = datetime.utcnow() + timedelta(minutes=USER_SESSION_TIMEOUT)
        self.acces = True
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

    package: Mapped[U_Package] = relationship("U_Package", cascade="all, delete", backref="user")
    sessions: Mapped[List[U_Session]] = relationship("U_Session", backref="user")

    def __repr__(self) -> str:
        return "<User (id:%s, name:%s, password_hash:%s, discord_id:%s)>" % (self.id, self.name, self.password_hash, self.discord_id)

    def __json__(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "package": self.package,
            "sessions": [session.__json__() for session in self.sessions] if self.sessions is not None else None,
            "discord_id": self.discord_id,
        }

    @staticmethod
    def from_json(data: dict) -> User:
        User.validate(data=data)
        return User(
            name=data["name"],
            password_hash=data["password_hash"],
        )

    @staticmethod
    def validate(data: dict) -> None:
        schema = Schema(
            {
                Optional("id"): And(int, Use(_user_id_check)),
                "name": And(str, len),
                "password_hash": And(str, len),
                Optional("discord_id"): And(str, len),
                Optional("package"): And(Or(int, None), Use(_package_id_check)),
            }
        )

        schema.validate(data)

    @staticmethod
    def validate_login_data(data: dict) -> None:
        schema = Schema(
            {
                "name": And(str, len),
                "password_hash": And(str, len),
            }
        )
        schema.validate(data)

    def open_session(self, inamedr: str) -> loginError | bool:
        self.sessions.sort(key=lambda x: x.end_date)
        self.u_accessible_sessions = list(filter(lambda x: x.access, self.sessions))
        u_package: U_Package = self.package
        if u_package is not None:
            if u_package.is_expired():
                db.session.delete(u_package)
                db.session.commit()
                return loginError.user_package_expired
            p_contents = u_package.base_package.packagecontents
            extra_user_quota = list(filter(lambda x: x.content_value == pContentEnum.extra_user, p_contents))
            max_sessions = 1 + len(extra_user_quota) if extra_user_quota is not None else 0
            same_ip_expired_session = self._eleminate_expired_accessible_sessions(inamedr)

            if len(self.u_accessible_sessions) >= max_sessions:
                return loginError.max_online_user
            if same_ip_expired_session is not None:
                same_ip_expired_session.oturumuzat()
                DB_LOGGER.info("user oturum uzatildi: id:%s, name:%s, ip:%s" % (self.id, self.name, inamedr))
                return True
            self._add_new_session(inamedr)
            db.session.commit()
            DB_LOGGER.info("user oturum acildi: id:%s, name:%s, ip:%s" % (self.id, self.name, inamedr))
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
            end_date=datetime.utcnow() + timedelta(minutes=USER_SESSION_TIMEOUT),
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
        same_ip_expired_sessions = filter_list(lambda x: x.k_oIp == inamedr, expired_sessions)
        other_ip_expired_sessions = filter_list(lambda x: x.k_oIp != inamedr, expired_sessions)
        self._disable_multiple_sessions_acess(other_ip_expired_sessions)

        if len(same_ip_expired_sessions) > 1:
            same_ip_expired_sessions.sort(key=lambda x: x.end_date)

            newest_same_ip_session = same_ip_expired_sessions[0]
            same_ip_expired_sessions.remove(newest_same_ip_session)
            self._disable_multiple_sessions_acess(same_ip_expired_sessions)
            if not (newest_same_ip_session.end_date + timedelta(minutes=USER_OLDEST_SESSION_TIMEOUT)) < datetime.utcnow():
                self._disable_session_access(newest_same_ip_session)
                return newest_same_ip_session
            return None
        return None

    def _disable_session_access(self, oturum: U_Session) -> None:
        oturum.accessible = False
        DB_LOGGER.info("user oturum kapatildi: id:%s, k_ad:%s" % (self.id, self.name))
        self.u_accessible_sessions.remove(oturum)
        self.sessions.append(oturum)

    def _disable_multiple_sessions_acess(self, oturumlar: List[U_Session]) -> None:
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
        return "<Admin (id:%s, name:%s, password_hash:%s)>" % (self.id, self.name, self.password_hash)

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
                "name": And(str, len),
                "password_hash": And(str, len),
            }
        )
        schema.validate(data)


# def check_password(sifre: str, hash: str) -> bool:
#     return sha256_hash(sifre) == hash


def utc_timestamp(dt: datetime | int, return_type: type | None = None) -> int | datetime:
    """
    toggle datetime to int timestamp
    toggle int timestampt to datetime
    :param: dt
    :param: return_type -> datetime | int | None (default None)

    note: i lose some presition but is it need to be that precise
    """
    if return_type is None:
        if isinstance(dt, datetime):
            return int(dt.timestamp())
        if isinstance(dt, int):
            return datetime.utcfromtimestamp(float(dt))
    else:
        for _ in range(2):
            new_dt = utc_timestamp(dt, return_type=None)
            if isinstance(new_dt, return_type):
                return new_dt
    raise RuntimeError("dt needs to be int or datetime.datetime object")


def add_db_model(
    model: U_Package | U_Session | User | Admin | Package | PackageContent, session: scoped_session = db.session
) -> DBOperationResult:
    try:
        if not isinstance(model, U_Package) or isinstance(model, U_Session):
            if len(model.name) < 3:
                return DBOperationResult.model_name_too_short
            if len(model.name) > 256:
                return DBOperationResult.model_name_too_long
        with session.begin_nested():
            session.add(model)
            session.commit()
            return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while adding model to database %s" % e)
        if "UNIQUE constraint failed" in str(e):
            DB_LOGGER.error("model already exists")
            return DBOperationResult.model_already_exists
    return DBOperationResult.unknown_error


def add_db_all_models(
    models: List[U_Package | U_Session | User | Admin | Package | PackageContent], session: scoped_session = db.session
) -> DBOperationResult:
    try:
        with session.begin_nested():
            session.add_all(models)
            session.commit()
            return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while adding model to database %s" % e)
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
    return add_db_model(user, session)


def add_admin(admin: Admin, session: scoped_session = db.session) -> DBOperationResult:
    if len(admin.password_hash) < 16:
        return DBOperationResult.model_passhash_too_short
    return add_db_model(admin, session)


def add_package(package: Package, session: scoped_session = db.session, disable_recursive=False) -> DBOperationResult:
    if hasattr(package, "packagecontents") and not disable_recursive:
        # TODO: maybe change this to add_db_all_models
        for package_content in package.packagecontents:
            if isinstance(package_content, PackageContent):
                package_content_exist = session.query(PackageContent).filter_by(name=package_content.name).first()
                if package_content_exist is None:
                    if add_package_content(package_content, session, disable_recursive=True) != DBOperationResult.success:
                        return DBOperationResult.model_not_created
            elif isinstance(package_content, int):
                package_content_exist = session.query(PackageContent).filter_by(id=package_content).first()
                if package_content_exist is None:
                    return DBOperationResult.model_not_created
    return add_db_model(package, session)


def add_package_content(
    package_content: PackageContent, session: scoped_session = db.session, disable_recursive=False
) -> DBOperationResult:
    if hasattr(package_content, "packages") and not disable_recursive:
        # TODO: maybe change this to add_db_all_models
        for package in package_content.packages:
            if isinstance(package, Package):
                package_exist = session.query(Package).filter_by(name=package.name).first()
                if package_exist is None:
                    if add_package(package, session, disable_recursive=True) != DBOperationResult.success:
                        return DBOperationResult.model_not_created
                package_exist = session.query(Package).filter_by(name=package.name).first()
            elif isinstance(package, int):
                package_exist = session.query(Package).filter_by(id=package).first()
                if package_exist is None:
                    return DBOperationResult.model_not_created
                package_content.packages.append(package_exist)
    return add_db_model(package_content, session)


def add_u_package(u_package: U_Package, session: scoped_session = db.session) -> DBOperationResult:
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


def update_user(u_id: str, new_user: User, session: scoped_session = db.session) -> DBOperationResult:
    """
    update user with k_id
    :param k_id: id of user to update
    :param new_user: new user object
    :param session: db session
    :return: DBOperationResult
    ---
    only update name, password_hash, discord_id, k_ps
    ---
    """
    try:
        db_user = session.query(User).filter_by(k_id=u_id).first()
        if db_user is None:
            return DBOperationResult.model_not_found
        if new_user.name is not None:
            db_user.name = new_user.name
        if new_user.password_hash is not None:
            db_user.password_hash = new_user.password_hash
        if new_user.discord_id is not None:
            db_user.discord_id = new_user.discord_id
        if new_user.k_ps is not None:
            db_user.k_ps = new_user.k_ps
        session.commit()
        return DBOperationResult.success
    except Exception as e:
        DB_LOGGER.error("error accured while updating user to database %s" % e)
    return DBOperationResult.unknown_error


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


def try_login(user: User, ip_addr: str | None) -> loginError | bool:
    if ip_addr is None:
        return loginError.not_found_client_ip
    if user is not None:
        return user.open_session(ip_addr)
    return loginError.user_not_found


def filter_list(function: Callable[[Any], bool], input_list: List[Any]) -> List[Any]:
    return list(filter(function, input_list))


def _package_content_id_check(package_content_id: int) -> bool:
    if package_content_id is None:
        return False
    return package_content_id in [package_content.id for package_content in PackageContent.query.all()]


def _package_content_validate(package_content: PackageContent) -> bool:
    if package_content is None:
        return False
    package_content_exist = PackageContent.query.filter_by(name=package_content.name).first()
    if package_content_exist is None:
        return package_content.validate(package_content.__json__()) is None
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

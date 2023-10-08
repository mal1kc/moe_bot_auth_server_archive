import logging

import click
from flask import Blueprint, current_app

from moe_bot_auth_server.database_ops import (
    Admin,
    DBOperationResult,
    Package,
    PackageContent,
    User,
    add_admin,
    add_package,
    add_package_content,
    db,
    pContentEnum,
)

cli_blueprint = Blueprint("cli", __name__)
LOGGER = logging.getLogger("cli")


@cli_blueprint.cli.command("initdb")
@click.option("--recreate", is_flag=True, help="delete old database if exists")
@click.option(
    "--init", help="initialize database, if not exists,defaults True", default=True
)
def initdb_command(recreate: bool = False, init: bool = True):
    """
    initialize database
    and delete old database if exists
    """
    from sqlalchemy import inspect

    LOGGER.info("veritabanı temel verisi oluşturuluyor")
    if ("admins" not in inspect(db.get_engine()).get_table_names()) and (not recreate):
        db.drop_all()

        ask_for_confirmation = input(
            "‼ eski veritabani tablolari bulundu‼ \neski veritabanı silinsin mi? (y/n) : "
        )
        if ask_for_confirmation == "y":
            LOGGER.info(" ✅ eski veritabanı silindi ✅ ")
            recreate = True
        else:
            LOGGER.info(" ❌ eski veritabanı silinmedi ❌ ")
            return

    if recreate:
        LOGGER.info("eski veritabani droplanıyor")
        db.drop_all()

    if init:
        LOGGER.info("veritabanı kontrol ediliyor")
        # inspect db is tables are correct
        tables = inspect(db.get_engine()).get_table_names()
        olmasi_gereken_tablolar = [
            "admins",
            "packages",
            "package_contents",
            "users",
            "user_packages",
            "user_sessions",
            "pcontent_packages_conn_table",
        ]
        if all([table in tables for table in olmasi_gereken_tablolar]):
            LOGGER.info(" ☑ veritabanı tablolari var ☑ , çıkılıyor")
            return
        LOGGER.info("veritabanı tabloları oluşturuluyor")

    db.create_all()
    LOGGER.info(" ✅ veritabanı tablolari oluşturuldu ✅ ")
    LOGGER.info("veritabanı içeriği oluşturuluyor")
    LOGGER.info("configden admin ekleniyor")
    # in config
    # ADMIN_USERNAME_1 = "mustafa"
    # ADMIN_PASSWORD_HASH_1 = "" -> make_password_hash("23ı13ıc1j3ucsu91")
    admin_infos: list[dict[str, str]] = current_app.config["ADMINS"]
    for conf_admin in admin_infos:
        if len(conf_admin["username"]) > 0 and len("password_hash") > 0:
            admin_ = Admin(
                name=conf_admin["username"],
                password_hash=conf_admin["password_hash"],
            )
            db_op_result = add_admin(admin_)
        if db_op_result != DBOperationResult.success:
            LOGGER.info(" ❌ admin eklenemedi ❌ ")
            LOGGER.info(" ❌ veritabanı oluşturulamadı ❌ ")
            LOGGER.info(" ❌ Hata: %s ❌ ", db_op_result)
            return
    LOGGER.info(" ☑ admin eklendi")
    db.session.commit()

    LOGGER.info("temel package icerikler ekleniyor")
    for package_content_deger in pContentEnum:
        p_icerik = PackageContent(
            name=package_content_deger.name,
            content_value=package_content_deger,
        )
        add_package_content(p_icerik)
    LOGGER.info(" ☑ temel package icerikler eklendi")
    LOGGER.info("temel packageler ekleniyor")
    db_op_result = add_package(
        Package(
            name="moe_gatherer",
            package_contents=[
                PackageContent.query.filter_by(name=pContentEnum.moe_gatherer).first(),
            ],
            days=60,
        )
    )
    if db_op_result != DBOperationResult.success:
        LOGGER.info(" ❌ package eklenemedi ❌ ")
        LOGGER.info(" ❌ veritabanı oluşturulamadı ❌ ")
        LOGGER.info(" ❌ Hata: %s ❌ ", db_op_result)
        return

    if (
        db_op_result := add_package(
            Package(
                name="moe_gatherer+eksra_user",
                package_contents=[
                    PackageContent.query.filter_by(name=pContentEnum.moe_gatherer).first(),
                    PackageContent.query.filter_by(name=pContentEnum.extra_user).first(),
                ],
                days=60,
            ),
        )
        != DBOperationResult.success
    ):
        LOGGER.info(" ❌ package eklenemedi ❌ ")
        LOGGER.info(" ❌ veritabanı oluşturulamadı ❌ ")
        LOGGER.info(" ❌ Hata: %s ❌ ", db_op_result)
        return

    LOGGER.info(" ☑ temel package eklendi")
    db.session.commit()
    db_packageler = [package.__json__() for package in Package.query.all()]
    db_package_contentleri = [
        package_content.__json__() for package_content in PackageContent.query.all()
    ]
    db_kullanicilar = [kullanici.__json__() for kullanici in User.query.all()]
    db_adminler = [admin.__json__() for admin in Admin.query.all()]
    LOGGER.info("veritabanı oluşturuldu")
    LOGGER.info("veritabanı içeriği : ")
    LOGGER.info("packageler -> {}".format(db_packageler))
    LOGGER.info("package İçerikleri -> {}".format(db_package_contentleri))
    LOGGER.info("kullanıcılar -> {}".format(db_kullanicilar))
    LOGGER.info("adminler -> {}".format(db_adminler))


@cli_blueprint.cli.command("resetdb")
def resetdb_command():
    """
    reset database to default
    """
    click.Context(cli_blueprint.cli).invoke(initdb_command, recreate=True)


@cli_blueprint.cli.command("inspectdb")
def inspect_db():
    """
    inspect database
    """
    from sqlalchemy import inspect

    LOGGER.info("veritabanı tabloları : ")
    LOGGER.info(inspect(db.get_engine()).get_table_names())
    LOGGER.info("veritabanı içeriği : ")
    db_packageler = [package.__json__() for package in Package.query.all()]
    db_package_contentleri = [
        package_content.__json__() for package_content in PackageContent.query.all()
    ]
    db_kullanicilar = [kullanici.__json__() for kullanici in User.query.all()]
    db_adminler = [admin.__json__() for admin in Admin.query.all()]
    LOGGER.info("packageler -> {}".format(db_packageler))
    LOGGER.info("package İçerikleri -> {}".format(db_package_contentleri))
    LOGGER.info("kullanıcılar -> {}".format(db_kullanicilar))
    LOGGER.info("adminler -> {}".format(db_adminler))

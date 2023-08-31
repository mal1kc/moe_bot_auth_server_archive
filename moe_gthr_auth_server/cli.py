import click

from flask import Blueprint


from moe_gthr_auth_server.database_ops import (
    db,
    add_admin,
    add_package,
    add_package_content,
    DBOperationResult,
    Admin,
    Package,
    PackageContent,
    User,
    pContentEnum,
)
from moe_gthr_auth_server.crpytion import make_password_hash

cli_blueprint = Blueprint("cli", __name__)


@cli_blueprint.cli.command("initdb")
@click.option("--recreate", is_flag=True, help="delete old database if exists")
def initdb_command(recreate: bool = False):
    """
    initialize database
    and delete old database if exists
    """
    from pprint import pprint
    from sqlalchemy import inspect

    print("veritabanı temel verisi oluşturuluyor")
    if ("admins" not in inspect(db.get_engine()).get_table_names()) and (not recreate):
        db.drop_all()

        ask_for_confirmation = input(
            "‼ eski veritabani tablolari bulundu‼ \neski veritabanı silinsin mi? (y/n) : "
        )
        if ask_for_confirmation == "y":
            print(" ✅ eski veritabanı silindi ✅ ")
            recreate = True
        else:
            print(" ❌ eski veritabanı silinmedi ❌ ")
            return

    if recreate:
        print("eski veritabani droplanıyor")
        db.drop_all()

    db.create_all()
    print(" ✅ veritabanı tablolari oluşturuldu ✅ ")
    print("veritabanı içeriği oluşturuluyor")
    print("admin ekleniyor")
    if (
        db_op_result := add_admin(
            Admin(name="mal1kc", password_hash=make_password_hash("deov04ın-!ıj0dı12klsa"))
        )
    ) != DBOperationResult.success:
        print(" ❌ admin eklenemedi ❌ ")
        print(" ❌ veritabanı oluşturulamadı ❌ ")
        print(" ❌ Hata: %s ❌ ", db_op_result)
        return
    print(" ☑ admin eklendi")
    db.session.commit()

    print("temel package icerikler ekleniyor")
    for package_content_deger in pContentEnum:
        p_icerik = PackageContent(
            name=package_content_deger,
            content_value=pContentEnum[package_content_deger],
        )
        add_package_content(p_icerik)
    print(" ☑ temel package icerikler eklendi")
    print("temel packageler ekleniyor")
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
        print(" ❌ package eklenemedi ❌ ")
        print(" ❌ veritabanı oluşturulamadı ❌ ")
        print(" ❌ Hata: %s ❌ ", db_op_result)
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
        print(" ❌ package eklenemedi ❌ ")
        print(" ❌ veritabanı oluşturulamadı ❌ ")
        print(" ❌ Hata: %s ❌ ", db_op_result)
        return

    print(" ☑ temel package eklendi")
    db.session.commit()
    db_packageler = [package.__json__() for package in Package.query.all()]
    db_package_contentleri = [
        package_content.__json__() for package_content in PackageContent.query.all()
    ]
    db_kullanicilar = [kullanici.__json__() for kullanici in User.query.all()]
    db_adminler = [admin.__json__() for admin in Admin.query.all()]
    print("veritabanı oluşturuldu")
    print("veritabanı içeriği : ")
    print("packageler ->")
    pprint(db_packageler)
    print("package İçerikleri ->")
    pprint(db_package_contentleri)
    print("kullanıcılar ->")
    pprint(db_kullanicilar)
    print("adminler ->")
    pprint(db_adminler)


@cli_blueprint.cli.command("resetdb")
def resetdb_command():
    """
    reset database to default
    """
    click.Context(cli_blueprint.cli).invoke(initdb_command, recreate=True)

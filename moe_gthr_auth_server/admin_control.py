import logging
import datetime
from flask import (
    Blueprint,
    render_template,
)

"""
One Page Admin Control Panel

- capabilities
    - model listing
    - model creation
    - model deletion
    - model update
    - uses internal API to perform actions with redirections
"""


# Blueprint
admin_control_blueprint = Blueprint("admin_control", __name__, template_folder="templates")

LOGGER = logging.getLogger("app")


@admin_control_blueprint.route("/admin_control/", defaults={"path": ""})
@admin_control_blueprint.route("/admin_control/<path:path>")
def admin(path):
    """
    Admin Control Panel
    """
    # return render_template("admin_control.html")
    #
    example_user = {
        "id": 1,
        "name": "example_user",
        "discord_id": "123456789",
        "package": {
            "start_date": datetime.datetime.now(),
            "end_date": datetime.datetime.now() + datetime.timedelta(days=30),
            "base_package": {
                "name": "base_package_1",
                "package_contents": [
                    {"name": "package_content_1", "content_value": 1},
                    {"name": "package_content_2", "content_value": 2},
                    {"name": "package_content_3", "content_value": 3},
                ],
            },
        },
        "sessions": [
            {
                "start_date": datetime.datetime.now(),
                "end_date": datetime.datetime.now() + datetime.timedelta(minutes=20),
                "ip_address": "127.0.0.1",
            },
            {
                "start_date": datetime.datetime.now() - datetime.timedelta(minutes=10),
                "end_date": datetime.datetime.now() + datetime.timedelta(minutes=10),
                "ip_address": "127.0.0.1",
            },
        ],
    }

    utc_now = datetime.datetime.utcnow()
    return render_template(
        "example.html",
        example_user=example_user,
        utc_now=utc_now,
        enumerate=enumerate,
    )

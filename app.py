from flask import Flask

from router_app import router_app
from valve_app import valve_app
from nat_app import nat_app
from acl_app import acl_app
from route_app import route_app
from vpn_app import vpn_app
from tunnel_app import tunnel_app
from bridge_app import bridge_app
from ovsnat_app import ovsnat_app
from stat_app import stat_app
from conn_app import conn_app
from cmd_app import cmd_app

app = Flask(__name__)
app.register_blueprint(router_app)
app.register_blueprint(valve_app)
app.register_blueprint(nat_app)
app.register_blueprint(acl_app)
app.register_blueprint(route_app)
app.register_blueprint(vpn_app)
app.register_blueprint(tunnel_app)
app.register_blueprint(bridge_app)
app.register_blueprint(ovsnat_app)
app.register_blueprint(stat_app)
app.register_blueprint(conn_app)
app.register_blueprint(cmd_app)

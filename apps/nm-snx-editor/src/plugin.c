/*
 * SNX VPN Editor Plugin for NetworkManager
 * 
 * This implements the NMVpnEditorPlugin interface, allowing GNOME Settings
 * to configure SNX VPN connections.
 */

#include <gtk/gtk.h>
#include <NetworkManager.h>
#include <string.h>
#include <stdlib.h>

#define SNX_TYPE_EDITOR_PLUGIN            (snx_editor_plugin_get_type())
#define SNX_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST((obj), SNX_TYPE_EDITOR_PLUGIN, SnxEditorPlugin))
#define SNX_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), SNX_TYPE_EDITOR_PLUGIN))

#define SNX_TYPE_EDITOR                   (snx_editor_get_type())
#define SNX_EDITOR(obj)                   (G_TYPE_CHECK_INSTANCE_CAST((obj), SNX_TYPE_EDITOR, SnxEditor))

/* Plugin object */
typedef struct {
    GObject parent;
} SnxEditorPlugin;

typedef struct {
    GObjectClass parent;
} SnxEditorPluginClass;

/* Editor object */
typedef struct {
    GObject parent;
    GtkWidget *widget;
    
    /* Entry widgets for VPN settings */
    GtkWidget *server_entry;
    GtkWidget *username_entry;
    GtkWidget *login_type_combo;
    GtkWidget *tunnel_type_combo;
    GtkWidget *cert_type_combo;
    GtkWidget *transport_type_combo;
    GtkWidget *search_domains_entry;
    GtkWidget *add_routes_entry;
    GtkWidget *ignore_routes_entry;
    GtkWidget *default_route_switch;
    GtkWidget *no_routing_switch;
    GtkWidget *no_dns_switch;
    GtkWidget *no_keychain_switch;
    GtkWidget *ignore_server_cert_switch;
    GtkWidget *mtu_spin;
    GtkWidget *ike_lifetime_spin;
    GtkWidget *ike_persist_switch;
    GtkWidget *no_keepalive_switch;
    GtkWidget *disable_ipv6_switch;
    GtkWidget *port_knock_switch;
    GtkWidget *set_routing_domains_switch;
    GtkWidget *cert_path_entry;
    GtkWidget *cert_id_entry;
    GtkWidget *ca_cert_entry;
    GtkWidget *dns_servers_entry;
    GtkWidget *ignore_search_domains_entry;
    GtkWidget *ignore_dns_servers_entry;
} SnxEditor;

typedef struct {
    GObjectClass parent;
} SnxEditorClass;

static void snx_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface);
static void snx_editor_interface_init(NMVpnEditorInterface *iface);

G_DEFINE_TYPE_WITH_CODE(SnxEditorPlugin, snx_editor_plugin, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN, snx_editor_plugin_interface_init))

G_DEFINE_TYPE_WITH_CODE(SnxEditor, snx_editor, G_TYPE_OBJECT,
    G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, snx_editor_interface_init))

/* Constants for VPN setting keys */
#define SNX_KEY_SERVER "server-name"
#define SNX_KEY_USERNAME "user-name"
#define SNX_KEY_LOGIN_TYPE "login-type"
#define SNX_KEY_TUNNEL_TYPE "tunnel-type"
#define SNX_KEY_CERT_TYPE "cert-type"
#define SNX_KEY_CERT_PATH "cert-path"
#define SNX_KEY_CERT_ID "cert-id"
#define SNX_KEY_CA_CERT "ca-cert"
#define SNX_KEY_TRANSPORT_TYPE "transport-type"
#define SNX_KEY_SEARCH_DOMAINS "search-domains"
#define SNX_KEY_IGNORE_SEARCH_DOMAINS "ignore-search-domains"
#define SNX_KEY_DNS_SERVERS "dns-servers"
#define SNX_KEY_IGNORE_DNS_SERVERS "ignore-dns-servers"
#define SNX_KEY_ADD_ROUTES "add-routes"
#define SNX_KEY_IGNORE_ROUTES "ignore-routes"
#define SNX_KEY_DEFAULT_ROUTE "default-route"
#define SNX_KEY_NO_ROUTING "no-routing"
#define SNX_KEY_NO_DNS "no-dns"
#define SNX_KEY_NO_KEYCHAIN "no-keychain"
#define SNX_KEY_IGNORE_SERVER_CERT "ignore-server-cert"
#define SNX_KEY_MTU "mtu"
#define SNX_KEY_IKE_LIFETIME "ike-lifetime"
#define SNX_KEY_IKE_PERSIST "ike-persist"
#define SNX_KEY_NO_KEEPALIVE "no-keepalive"
#define SNX_KEY_DISABLE_IPV6 "disable-ipv6"
#define SNX_KEY_PORT_KNOCK "port-knock"
#define SNX_KEY_SET_ROUTING_DOMAINS "set-routing-domains"

/* Default values (from TunnelParams) */
#define DEFAULT_MTU 1350
#define DEFAULT_IKE_LIFETIME 28800

/* Structure to hold config file values */
typedef struct {
    char *server_name;
    char *user_name;
    char *login_type;
    char *tunnel_type;
    char *cert_type;
    char *cert_path;
    char *cert_id;
    char *ca_cert;
    char *transport_type;
    char *search_domains;
    char *ignore_search_domains;
    char *dns_servers;
    char *ignore_dns_servers;
    char *add_routes;
    char *ignore_routes;
    gboolean default_route;
    gboolean no_routing;
    gboolean no_dns;
    gboolean no_keychain;
    gboolean ignore_server_cert;
    int mtu;
    int ike_lifetime;
    gboolean ike_persist;
    gboolean no_keepalive;
    gboolean disable_ipv6;
    gboolean port_knock;
    gboolean set_routing_domains;
    gboolean has_default_route;
    gboolean has_no_routing;
    gboolean has_no_dns;
    gboolean has_no_keychain;
    gboolean has_ignore_server_cert;
    gboolean has_mtu;
    gboolean has_ike_lifetime;
    gboolean has_ike_persist;
    gboolean has_no_keepalive;
    gboolean has_disable_ipv6;
    gboolean has_port_knock;
    gboolean has_set_routing_domains;
} SnxConfigDefaults;

static void
snx_config_defaults_free(SnxConfigDefaults *cfg)
{
    if (!cfg) return;
    g_free(cfg->server_name);
    g_free(cfg->user_name);
    g_free(cfg->login_type);
    g_free(cfg->tunnel_type);
    g_free(cfg->cert_type);
    g_free(cfg->cert_path);
    g_free(cfg->cert_id);
    g_free(cfg->ca_cert);
    g_free(cfg->transport_type);
    g_free(cfg->search_domains);
    g_free(cfg->ignore_search_domains);
    g_free(cfg->dns_servers);
    g_free(cfg->ignore_dns_servers);
    g_free(cfg->add_routes);
    g_free(cfg->ignore_routes);
    g_free(cfg);
}

static gboolean
parse_bool(const char *value)
{
    if (!value) return FALSE;
    return (g_ascii_strcasecmp(value, "true") == 0 ||
            g_ascii_strcasecmp(value, "1") == 0 ||
            g_ascii_strcasecmp(value, "yes") == 0);
}

static SnxConfigDefaults *
load_config_defaults(void)
{
    SnxConfigDefaults *cfg = g_new0(SnxConfigDefaults, 1);
    
    /* Set defaults from TunnelParams */
    cfg->mtu = DEFAULT_MTU;
    cfg->ike_lifetime = DEFAULT_IKE_LIFETIME;
    cfg->no_keychain = TRUE;  /* default is true in TunnelParams */
    cfg->has_no_keychain = TRUE;
    
    /* Try to read from config file */
    const char *home = g_get_home_dir();
    if (!home) return cfg;
    
    char *config_path = g_build_filename(home, ".config", "snx-rs", "snx-rs.conf", NULL);
    char *contents = NULL;
    gsize length = 0;
    
    if (!g_file_get_contents(config_path, &contents, &length, NULL)) {
        g_free(config_path);
        return cfg;
    }
    g_free(config_path);
    
    /* Parse config file line by line */
    char **lines = g_strsplit(contents, "\n", -1);
    g_free(contents);
    
    for (int i = 0; lines[i] != NULL; i++) {
        char *line = g_strstrip(lines[i]);
        if (line[0] == '#' || line[0] == '\0') continue;
        
        char *eq = strchr(line, '=');
        if (!eq) continue;
        
        *eq = '\0';
        char *key = g_strstrip(line);
        char *value = g_strstrip(eq + 1);
        
        if (g_strcmp0(key, "server-name") == 0) {
            cfg->server_name = g_strdup(value);
        } else if (g_strcmp0(key, "user-name") == 0) {
            cfg->user_name = g_strdup(value);
        } else if (g_strcmp0(key, "login-type") == 0) {
            cfg->login_type = g_strdup(value);
        } else if (g_strcmp0(key, "tunnel-type") == 0) {
            cfg->tunnel_type = g_strdup(value);
        } else if (g_strcmp0(key, "cert-type") == 0) {
            cfg->cert_type = g_strdup(value);
        } else if (g_strcmp0(key, "cert-path") == 0) {
            cfg->cert_path = g_strdup(value);
        } else if (g_strcmp0(key, "cert-id") == 0) {
            cfg->cert_id = g_strdup(value);
        } else if (g_strcmp0(key, "ca-cert") == 0) {
            cfg->ca_cert = g_strdup(value);
        } else if (g_strcmp0(key, "transport-type") == 0) {
            cfg->transport_type = g_strdup(value);
        } else if (g_strcmp0(key, "search-domains") == 0) {
            cfg->search_domains = g_strdup(value);
        } else if (g_strcmp0(key, "ignore-search-domains") == 0) {
            cfg->ignore_search_domains = g_strdup(value);
        } else if (g_strcmp0(key, "dns-servers") == 0) {
            cfg->dns_servers = g_strdup(value);
        } else if (g_strcmp0(key, "ignore-dns-servers") == 0) {
            cfg->ignore_dns_servers = g_strdup(value);
        } else if (g_strcmp0(key, "add-routes") == 0) {
            cfg->add_routes = g_strdup(value);
        } else if (g_strcmp0(key, "ignore-routes") == 0) {
            cfg->ignore_routes = g_strdup(value);
        } else if (g_strcmp0(key, "default-route") == 0) {
            cfg->default_route = parse_bool(value);
            cfg->has_default_route = TRUE;
        } else if (g_strcmp0(key, "no-routing") == 0) {
            cfg->no_routing = parse_bool(value);
            cfg->has_no_routing = TRUE;
        } else if (g_strcmp0(key, "no-dns") == 0) {
            cfg->no_dns = parse_bool(value);
            cfg->has_no_dns = TRUE;
        } else if (g_strcmp0(key, "no-keychain") == 0) {
            cfg->no_keychain = parse_bool(value);
            cfg->has_no_keychain = TRUE;
        } else if (g_strcmp0(key, "ignore-server-cert") == 0) {
            cfg->ignore_server_cert = parse_bool(value);
            cfg->has_ignore_server_cert = TRUE;
        } else if (g_strcmp0(key, "mtu") == 0) {
            cfg->mtu = atoi(value);
            cfg->has_mtu = TRUE;
        } else if (g_strcmp0(key, "ike-lifetime") == 0) {
            cfg->ike_lifetime = atoi(value);
            cfg->has_ike_lifetime = TRUE;
        } else if (g_strcmp0(key, "ike-persist") == 0) {
            cfg->ike_persist = parse_bool(value);
            cfg->has_ike_persist = TRUE;
        } else if (g_strcmp0(key, "no-keepalive") == 0) {
            cfg->no_keepalive = parse_bool(value);
            cfg->has_no_keepalive = TRUE;
        } else if (g_strcmp0(key, "disable-ipv6") == 0) {
            cfg->disable_ipv6 = parse_bool(value);
            cfg->has_disable_ipv6 = TRUE;
        } else if (g_strcmp0(key, "port-knock") == 0) {
            cfg->port_knock = parse_bool(value);
            cfg->has_port_knock = TRUE;
        } else if (g_strcmp0(key, "set-routing-domains") == 0) {
            cfg->set_routing_domains = parse_bool(value);
            cfg->has_set_routing_domains = TRUE;
        }
    }
    
    g_strfreev(lines);
    return cfg;
}

/* Properties for the plugin */
enum {
    PROP_0,
    PROP_NAME,
    PROP_DESCRIPTION,
    PROP_SERVICE,
    LAST_PROP
};

static void
get_property(GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
    (void)object;
    switch (prop_id) {
    case PROP_NAME:
        g_value_set_string(value, "Check Point SNX");
        break;
    case PROP_DESCRIPTION:
        g_value_set_string(value, "Check Point SNX VPN client using snx-rs");
        break;
    case PROP_SERVICE:
        g_value_set_string(value, "org.freedesktop.NetworkManager.snx");
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
        break;
    }
}

/*
 * SnxEditorPlugin implementation
 */
static void
snx_editor_plugin_init(SnxEditorPlugin *plugin)
{
    (void)plugin;
}

static void
snx_editor_plugin_class_init(SnxEditorPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    
    object_class->get_property = get_property;
    
    g_object_class_override_property(object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
    g_object_class_override_property(object_class, PROP_DESCRIPTION, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
    g_object_class_override_property(object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static NMVpnEditorPluginCapability
get_capabilities(NMVpnEditorPlugin *plugin)
{
    (void)plugin;
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

/*
 * SnxEditor implementation
 */
static void
snx_editor_init(SnxEditor *editor)
{
    editor->widget = NULL;
}

static void
snx_editor_dispose(GObject *object)
{
    SnxEditor *editor = SNX_EDITOR(object);
    
    g_clear_object(&editor->widget);
    
    G_OBJECT_CLASS(snx_editor_parent_class)->dispose(object);
}

static void
snx_editor_class_init(SnxEditorClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);
    object_class->dispose = snx_editor_dispose;
}

/* Callback to emit "changed" signal when any widget is modified */
static void
on_widget_changed(GtkWidget *widget, gpointer user_data)
{
    (void)widget;
    SnxEditor *editor = SNX_EDITOR(user_data);
    g_signal_emit_by_name(editor, "changed");
}

/* Callback for switch notify::active */
static void
on_switch_changed(GObject *gobject, GParamSpec *pspec, gpointer user_data)
{
    (void)gobject;
    (void)pspec;
    SnxEditor *editor = SNX_EDITOR(user_data);
    g_signal_emit_by_name(editor, "changed");
}

/* Helper: add a labeled entry row */
static GtkWidget *
create_entry_row(GtkWidget *list, const char *label_text, const char *value, GtkWidget **out_entry, SnxEditor *editor)
{
    GtkWidget *row = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *label = gtk_label_new(label_text);
    GtkWidget *entry = gtk_entry_new();
    
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_widget_set_hexpand(label, FALSE);
    gtk_widget_set_size_request(label, 180, -1);
    
    gtk_widget_set_hexpand(entry, TRUE);
    if (value && *value)
        gtk_editable_set_text(GTK_EDITABLE(entry), value);
    
    /* Connect changed signal */
    if (editor)
        g_signal_connect(entry, "changed", G_CALLBACK(on_widget_changed), editor);
    
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), entry);
    
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
    
    if (out_entry) *out_entry = entry;
    return row;
}

/* Helper: add a labeled switch row */
static GtkWidget *
create_switch_row(GtkWidget *list, const char *label_text, gboolean value, GtkWidget **out_switch, SnxEditor *editor)
{
    GtkWidget *row = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *label = gtk_label_new(label_text);
    GtkWidget *switch_widget = gtk_switch_new();
    
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_widget_set_hexpand(label, TRUE);
    
    gtk_switch_set_active(GTK_SWITCH(switch_widget), value);
    gtk_widget_set_valign(switch_widget, GTK_ALIGN_CENTER);
    
    /* Connect notify::active signal for switches */
    if (editor)
        g_signal_connect(switch_widget, "notify::active", G_CALLBACK(on_switch_changed), editor);
    
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), switch_widget);
    
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
    
    if (out_switch) *out_switch = switch_widget;
    return row;
}

/* Helper: add a labeled combo box row with predefined options */
static GtkWidget *
create_combo_row(GtkWidget *list, const char *label_text, const char *value,
                 const char **options, const char **option_ids, int n_options,
                 gboolean has_entry, GtkWidget **out_combo, SnxEditor *editor)
{
    GtkWidget *row = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *label = gtk_label_new(label_text);
    GtkWidget *combo = gtk_combo_box_text_new_with_entry();
    
    if (!has_entry) {
        combo = gtk_combo_box_text_new();
    }
    
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_widget_set_hexpand(label, FALSE);
    gtk_widget_set_size_request(label, 180, -1);
    
    gtk_widget_set_hexpand(combo, TRUE);
    
    /* Add options */
    for (int i = 0; i < n_options; i++) {
        gtk_combo_box_text_append(GTK_COMBO_BOX_TEXT(combo), option_ids[i], options[i]);
    }
    
    /* Set active value */
    if (value && *value) {
        if (has_entry) {
            /* For combo with entry, first try to set by ID, then set text directly */
            if (!gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), value)) {
                GtkWidget *entry = gtk_combo_box_get_child(GTK_COMBO_BOX(combo));
                gtk_editable_set_text(GTK_EDITABLE(entry), value);
            }
        } else {
            gtk_combo_box_set_active_id(GTK_COMBO_BOX(combo), value);
        }
    } else if (n_options > 0) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);
    }
    
    /* Connect changed signal */
    if (editor) {
        g_signal_connect(combo, "changed", G_CALLBACK(on_widget_changed), editor);
        /* Also connect to the entry inside if it has one */
        if (has_entry) {
            GtkWidget *entry = gtk_combo_box_get_child(GTK_COMBO_BOX(combo));
            if (entry)
                g_signal_connect(entry, "changed", G_CALLBACK(on_widget_changed), editor);
        }
    }
    
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), combo);
    
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
    
    if (out_combo) *out_combo = combo;
    return row;
}

/* Helper: add a labeled spin button row */
static GtkWidget *
create_spin_row(GtkWidget *list, const char *label_text, int value, int min, int max, GtkWidget **out_spin, SnxEditor *editor)
{
    GtkWidget *row = gtk_list_box_row_new();
    gtk_list_box_row_set_activatable(GTK_LIST_BOX_ROW(row), FALSE);
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *label = gtk_label_new(label_text);
    GtkWidget *spin = gtk_spin_button_new_with_range(min, max, 1);
    
    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_widget_set_hexpand(label, FALSE);
    gtk_widget_set_size_request(label, 180, -1);
    
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(spin), value);
    gtk_widget_set_valign(spin, GTK_ALIGN_CENTER);
    gtk_widget_set_hexpand(spin, TRUE);
    
    /* Connect value-changed signal */
    if (editor)
        g_signal_connect(spin, "value-changed", G_CALLBACK(on_widget_changed), editor);
    
    gtk_box_append(GTK_BOX(box), label);
    gtk_box_append(GTK_BOX(box), spin);
    
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);
    
    gtk_list_box_row_set_child(GTK_LIST_BOX_ROW(row), box);
    gtk_list_box_append(GTK_LIST_BOX(list), row);
    
    if (out_spin) *out_spin = spin;
    return row;
}

/* Helper: get string value with fallback */
static const char *
get_string_value(const char *nm_value, const char *conf_value, const char *default_value)
{
    if (nm_value && *nm_value) return nm_value;
    if (conf_value && *conf_value) return conf_value;
    return default_value;
}

/* Helper: get bool value with fallback */
static gboolean
get_bool_value(const char *nm_value, gboolean has_nm, gboolean conf_value, gboolean has_conf, gboolean default_value)
{
    if (has_nm && nm_value) return parse_bool(nm_value);
    if (has_conf) return conf_value;
    return default_value;
}

/* Helper: get int value with fallback */
static int
get_int_value(const char *nm_value, int conf_value, gboolean has_conf, int default_value)
{
    if (nm_value && *nm_value) return atoi(nm_value);
    if (has_conf) return conf_value;
    return default_value;
}

/* Build the editor widget */
static void
build_editor_widget(SnxEditor *editor, NMConnection *connection)
{
    NMSettingVpn *s_vpn = NULL;
    SnxConfigDefaults *cfg = load_config_defaults();
    
    /* Values from NM connection (if any) */
    const char *nm_server = NULL, *nm_username = NULL, *nm_login_type = NULL;
    const char *nm_tunnel_type = NULL, *nm_cert_type = NULL, *nm_transport_type = NULL;
    const char *nm_search_domains = NULL, *nm_add_routes = NULL, *nm_ignore_routes = NULL;
    const char *nm_cert_path = NULL, *nm_cert_id = NULL, *nm_ca_cert = NULL;
    const char *nm_dns_servers = NULL, *nm_ignore_search_domains = NULL, *nm_ignore_dns_servers = NULL;
    const char *nm_default_route = NULL, *nm_no_routing = NULL, *nm_no_dns = NULL;
    const char *nm_no_keychain = NULL, *nm_ignore_server_cert = NULL;
    const char *nm_mtu = NULL, *nm_ike_lifetime = NULL;
    const char *nm_ike_persist = NULL, *nm_no_keepalive = NULL;
    const char *nm_disable_ipv6 = NULL, *nm_port_knock = NULL, *nm_set_routing_domains = NULL;
    gboolean has_nm_values = FALSE;
    
    if (connection) {
        s_vpn = nm_connection_get_setting_vpn(connection);
        if (s_vpn) {
            nm_server = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_SERVER);
            /* Use the built-in user-name property, with fallback to data item */
            nm_username = nm_setting_vpn_get_user_name(s_vpn);
            if (!nm_username || !*nm_username) {
                nm_username = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_USERNAME);
            }
            nm_login_type = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_LOGIN_TYPE);
            nm_tunnel_type = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_TUNNEL_TYPE);
            nm_cert_type = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_CERT_TYPE);
            nm_cert_path = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_CERT_PATH);
            nm_cert_id = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_CERT_ID);
            nm_ca_cert = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_CA_CERT);
            nm_transport_type = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_TRANSPORT_TYPE);
            nm_search_domains = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_SEARCH_DOMAINS);
            nm_ignore_search_domains = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_IGNORE_SEARCH_DOMAINS);
            nm_dns_servers = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_DNS_SERVERS);
            nm_ignore_dns_servers = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_IGNORE_DNS_SERVERS);
            nm_add_routes = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_ADD_ROUTES);
            nm_ignore_routes = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_IGNORE_ROUTES);
            nm_default_route = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_DEFAULT_ROUTE);
            nm_no_routing = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_NO_ROUTING);
            nm_no_dns = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_NO_DNS);
            nm_no_keychain = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_NO_KEYCHAIN);
            nm_ignore_server_cert = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_IGNORE_SERVER_CERT);
            nm_mtu = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_MTU);
            nm_ike_lifetime = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_IKE_LIFETIME);
            nm_ike_persist = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_IKE_PERSIST);
            nm_no_keepalive = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_NO_KEEPALIVE);
            nm_disable_ipv6 = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_DISABLE_IPV6);
            nm_port_knock = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_PORT_KNOCK);
            nm_set_routing_domains = nm_setting_vpn_get_data_item(s_vpn, SNX_KEY_SET_ROUTING_DOMAINS);
            has_nm_values = (nm_server != NULL);
        }
    }
    
    /* Compute final values
     * For NEW connections (no server set): use .conf as defaults for easy migration
     * For EXISTING connections: only use NM values, don't pollute with .conf values
     * This prevents settings from one VPN "leaking" into another
     */
    gboolean is_new_connection = !has_nm_values;
    
    const char *server, *username, *login_type, *tunnel_type, *cert_type;
    const char *cert_path, *cert_id, *ca_cert, *transport_type;
    const char *search_domains, *ignore_search_domains, *dns_servers, *ignore_dns_servers;
    const char *add_routes, *ignore_routes;
    gboolean default_route, no_routing, no_dns, no_keychain, ignore_server_cert;
    gboolean ike_persist, no_keepalive, disable_ipv6, port_knock, set_routing_domains;
    int mtu, ike_lifetime;
    
    if (is_new_connection) {
        /* NEW connection: use .conf as defaults for migration from standalone snx-rs */
        server = get_string_value(nm_server, cfg->server_name, "");
        username = get_string_value(nm_username, cfg->user_name, "");
        login_type = get_string_value(nm_login_type, cfg->login_type, "");
        tunnel_type = get_string_value(nm_tunnel_type, cfg->tunnel_type, "ipsec");
        cert_type = get_string_value(nm_cert_type, cfg->cert_type, "none");
        cert_path = get_string_value(nm_cert_path, cfg->cert_path, "");
        cert_id = get_string_value(nm_cert_id, cfg->cert_id, "");
        ca_cert = get_string_value(nm_ca_cert, cfg->ca_cert, "");
        transport_type = get_string_value(nm_transport_type, cfg->transport_type, "auto");
        search_domains = get_string_value(nm_search_domains, cfg->search_domains, "");
        ignore_search_domains = get_string_value(nm_ignore_search_domains, cfg->ignore_search_domains, "");
        dns_servers = get_string_value(nm_dns_servers, cfg->dns_servers, "");
        ignore_dns_servers = get_string_value(nm_ignore_dns_servers, cfg->ignore_dns_servers, "");
        add_routes = get_string_value(nm_add_routes, cfg->add_routes, "");
        ignore_routes = get_string_value(nm_ignore_routes, cfg->ignore_routes, "");
        
        default_route = get_bool_value(nm_default_route, has_nm_values, cfg->default_route, cfg->has_default_route, FALSE);
        no_routing = get_bool_value(nm_no_routing, has_nm_values, cfg->no_routing, cfg->has_no_routing, FALSE);
        no_dns = get_bool_value(nm_no_dns, has_nm_values, cfg->no_dns, cfg->has_no_dns, FALSE);
        no_keychain = get_bool_value(nm_no_keychain, has_nm_values, cfg->no_keychain, cfg->has_no_keychain, TRUE);
        ignore_server_cert = get_bool_value(nm_ignore_server_cert, has_nm_values, cfg->ignore_server_cert, cfg->has_ignore_server_cert, FALSE);
        ike_persist = get_bool_value(nm_ike_persist, has_nm_values, cfg->ike_persist, cfg->has_ike_persist, FALSE);
        no_keepalive = get_bool_value(nm_no_keepalive, has_nm_values, cfg->no_keepalive, cfg->has_no_keepalive, FALSE);
        disable_ipv6 = get_bool_value(nm_disable_ipv6, has_nm_values, cfg->disable_ipv6, cfg->has_disable_ipv6, FALSE);
        port_knock = get_bool_value(nm_port_knock, has_nm_values, cfg->port_knock, cfg->has_port_knock, FALSE);
        set_routing_domains = get_bool_value(nm_set_routing_domains, has_nm_values, cfg->set_routing_domains, cfg->has_set_routing_domains, FALSE);
        
        mtu = get_int_value(nm_mtu, cfg->mtu, cfg->has_mtu, DEFAULT_MTU);
        ike_lifetime = get_int_value(nm_ike_lifetime, cfg->ike_lifetime, cfg->has_ike_lifetime, DEFAULT_IKE_LIFETIME);
    } else {
        /* EXISTING connection: only use NM values, no .conf fallback */
        server = nm_server ? nm_server : "";
        username = nm_username ? nm_username : "";
        login_type = nm_login_type ? nm_login_type : "";
        tunnel_type = nm_tunnel_type ? nm_tunnel_type : "ipsec";
        cert_type = nm_cert_type ? nm_cert_type : "none";
        cert_path = nm_cert_path ? nm_cert_path : "";
        cert_id = nm_cert_id ? nm_cert_id : "";
        ca_cert = nm_ca_cert ? nm_ca_cert : "";
        transport_type = nm_transport_type ? nm_transport_type : "auto";
        search_domains = nm_search_domains ? nm_search_domains : "";
        ignore_search_domains = nm_ignore_search_domains ? nm_ignore_search_domains : "";
        dns_servers = nm_dns_servers ? nm_dns_servers : "";
        ignore_dns_servers = nm_ignore_dns_servers ? nm_ignore_dns_servers : "";
        add_routes = nm_add_routes ? nm_add_routes : "";
        ignore_routes = nm_ignore_routes ? nm_ignore_routes : "";
        
        default_route = nm_default_route ? parse_bool(nm_default_route) : FALSE;
        no_routing = nm_no_routing ? parse_bool(nm_no_routing) : FALSE;
        no_dns = nm_no_dns ? parse_bool(nm_no_dns) : FALSE;
        no_keychain = nm_no_keychain ? parse_bool(nm_no_keychain) : TRUE;
        ignore_server_cert = nm_ignore_server_cert ? parse_bool(nm_ignore_server_cert) : FALSE;
        ike_persist = nm_ike_persist ? parse_bool(nm_ike_persist) : FALSE;
        no_keepalive = nm_no_keepalive ? parse_bool(nm_no_keepalive) : FALSE;
        disable_ipv6 = nm_disable_ipv6 ? parse_bool(nm_disable_ipv6) : FALSE;
        port_knock = nm_port_knock ? parse_bool(nm_port_knock) : FALSE;
        set_routing_domains = nm_set_routing_domains ? parse_bool(nm_set_routing_domains) : FALSE;
        
        mtu = nm_mtu ? atoi(nm_mtu) : DEFAULT_MTU;
        ike_lifetime = nm_ike_lifetime ? atoi(nm_ike_lifetime) : DEFAULT_IKE_LIFETIME;
    }
    
    /* Main container - no scroll, GNOME Settings provides its own */
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 18);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    
    /* Helper macro for creating sections */
    #define CREATE_SECTION(title_text, list_var) \
        GtkWidget *title_##list_var = gtk_label_new(title_text); \
        gtk_widget_add_css_class(title_##list_var, "heading"); \
        gtk_widget_set_halign(title_##list_var, GTK_ALIGN_START); \
        gtk_widget_set_margin_bottom(title_##list_var, 6); \
        gtk_box_append(GTK_BOX(box), title_##list_var); \
        GtkWidget *list_var = gtk_list_box_new(); \
        gtk_list_box_set_selection_mode(GTK_LIST_BOX(list_var), GTK_SELECTION_NONE); \
        gtk_widget_add_css_class(list_var, "boxed-list"); \
        gtk_widget_set_margin_bottom(list_var, 6);
    
    /* === Server section === */
    CREATE_SECTION("Server", server_list);
    create_entry_row(server_list, "Gateway", server, &editor->server_entry, editor);
    gtk_box_append(GTK_BOX(box), server_list);
    
    /* === Authentication section === */
    CREATE_SECTION("Authentication", auth_list);
    create_entry_row(auth_list, "Username", username, &editor->username_entry, editor);
    
    /* Login type - combo with entry for custom values */
    static const char *login_type_options[] = {
        "Username + Password",
        "Username + Password + MFA",
        "MFA (RADIUS)",
        "Mobile Access"
    };
    static const char *login_type_ids[] = {
        "vpn_Username_Password",
        "vpn_Username_Password_MFA",
        "vpn_MFA-RADIUS",
        "ma"
    };
    create_combo_row(auth_list, "Login Type", login_type,
                     login_type_options, login_type_ids, 4, TRUE, &editor->login_type_combo, editor);
    
    /* Cert type dropdown */
    static const char *cert_type_options[] = { "None", "PKCS#12", "PKCS#8", "PKCS#11" };
    static const char *cert_type_ids[] = { "none", "pkcs12", "pkcs8", "pkcs11" };
    create_combo_row(auth_list, "Certificate Type", cert_type,
                     cert_type_options, cert_type_ids, 4, FALSE, &editor->cert_type_combo, editor);
    
    create_entry_row(auth_list, "Certificate Path", cert_path, &editor->cert_path_entry, editor);
    create_entry_row(auth_list, "Certificate ID (PKCS#11)", cert_id, &editor->cert_id_entry, editor);
    gtk_box_append(GTK_BOX(box), auth_list);
    
    /* === Tunnel section === */
    CREATE_SECTION("Tunnel", tunnel_list);
    
    /* Tunnel type dropdown */
    static const char *tunnel_type_options[] = { "IPSec", "SSL" };
    static const char *tunnel_type_ids[] = { "ipsec", "ssl" };
    create_combo_row(tunnel_list, "Tunnel Type", tunnel_type,
                     tunnel_type_options, tunnel_type_ids, 2, FALSE, &editor->tunnel_type_combo, editor);
    
    /* Transport type dropdown */
    static const char *transport_type_options[] = { "Auto-detect", "Kernel", "UDP", "TCP Transport" };
    static const char *transport_type_ids[] = { "auto", "kernel", "udp", "tcpt" };
    create_combo_row(tunnel_list, "Transport Type", transport_type,
                     transport_type_options, transport_type_ids, 4, FALSE, &editor->transport_type_combo, editor);
    
    create_spin_row(tunnel_list, "MTU", mtu, 576, 9000, &editor->mtu_spin, editor);
    create_switch_row(tunnel_list, "Persist IKE Session", ike_persist, &editor->ike_persist_switch, editor);
    create_switch_row(tunnel_list, "Disable Keepalive", no_keepalive, &editor->no_keepalive_switch, editor);
    gtk_box_append(GTK_BOX(box), tunnel_list);
    
    /* === Routing section === */
    CREATE_SECTION("Routing", route_list);
    create_switch_row(route_list, "Use as default route", default_route, &editor->default_route_switch, editor);
    create_switch_row(route_list, "Disable all routing", no_routing, &editor->no_routing_switch, editor);
    create_entry_row(route_list, "Additional routes", add_routes, &editor->add_routes_entry, editor);
    create_entry_row(route_list, "Ignore routes", ignore_routes, &editor->ignore_routes_entry, editor);
    gtk_box_append(GTK_BOX(box), route_list);
    
    /* === DNS section === */
    CREATE_SECTION("DNS", dns_list);
    create_switch_row(dns_list, "Do not configure DNS", no_dns, &editor->no_dns_switch, editor);
    create_entry_row(dns_list, "DNS Servers", dns_servers, &editor->dns_servers_entry, editor);
    create_entry_row(dns_list, "Search domains", search_domains, &editor->search_domains_entry, editor);
    create_entry_row(dns_list, "Ignore search domains", ignore_search_domains, &editor->ignore_search_domains_entry, editor);
    create_entry_row(dns_list, "Ignore DNS servers", ignore_dns_servers, &editor->ignore_dns_servers_entry, editor);
    gtk_box_append(GTK_BOX(box), dns_list);
    
    /* === Security section === */
    CREATE_SECTION("Security", sec_list);
    create_switch_row(sec_list, "Do not use keychain", no_keychain, &editor->no_keychain_switch, editor);
    create_switch_row(sec_list, "Ignore server certificate errors", ignore_server_cert, &editor->ignore_server_cert_switch, editor);
    create_entry_row(sec_list, "CA Certificates", ca_cert, &editor->ca_cert_entry, editor);
    gtk_box_append(GTK_BOX(box), sec_list);
    
    /* === Advanced section === */
    CREATE_SECTION("Advanced", adv_list);
    create_spin_row(adv_list, "IKE Lifetime (seconds)", ike_lifetime, 300, 86400, &editor->ike_lifetime_spin, editor);
    create_switch_row(adv_list, "Disable IPv6", disable_ipv6, &editor->disable_ipv6_switch, editor);
    create_switch_row(adv_list, "Port Knock", port_knock, &editor->port_knock_switch, editor);
    create_switch_row(adv_list, "Set Routing Domains", set_routing_domains, &editor->set_routing_domains_switch, editor);
    gtk_box_append(GTK_BOX(box), adv_list);
    
    #undef CREATE_SECTION
    
    /* No ScrolledWindow - GNOME Settings provides its own scroll */
    editor->widget = g_object_ref(box);
    
    snx_config_defaults_free(cfg);
}

/* Helper: get combo box value (handles both with and without entry) */
static const char *
get_combo_value(GtkWidget *combo)
{
    const char *id = gtk_combo_box_get_active_id(GTK_COMBO_BOX(combo));
    if (id && *id) return id;
    
    /* For combo with entry, get the text directly */
    if (GTK_IS_COMBO_BOX_TEXT(combo)) {
        GtkWidget *entry = gtk_combo_box_get_child(GTK_COMBO_BOX(combo));
        if (entry && GTK_IS_EDITABLE(entry)) {
            return gtk_editable_get_text(GTK_EDITABLE(entry));
        }
    }
    return "";
}

static GObject *
snx_editor_get_widget(NMVpnEditor *iface)
{
    SnxEditor *editor = SNX_EDITOR(iface);
    return G_OBJECT(editor->widget);
}

static gboolean
snx_editor_update_connection(NMVpnEditor *iface, NMConnection *connection, GError **error)
{
    (void)error;
    SnxEditor *editor = SNX_EDITOR(iface);
    NMSettingVpn *s_vpn;
    const char *text;
    
    s_vpn = nm_connection_get_setting_vpn(connection);
    if (!s_vpn) {
        s_vpn = (NMSettingVpn *) nm_setting_vpn_new();
        g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE,
                     "org.freedesktop.NetworkManager.snx", NULL);
        nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    }
    
    /* Server */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->server_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_SERVER, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_SERVER);
    
    /* Username - use the NMSettingVpn's built-in user-name property */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->username_entry));
    if (text && *text) {
        g_object_set(G_OBJECT(s_vpn), NM_SETTING_VPN_USER_NAME, text, NULL);
    } else {
        g_object_set(G_OBJECT(s_vpn), NM_SETTING_VPN_USER_NAME, NULL, NULL);
    }
    
    /* Login type (combo with entry) */
    text = get_combo_value(editor->login_type_combo);
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_LOGIN_TYPE, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_LOGIN_TYPE);
    
    /* Tunnel type */
    text = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->tunnel_type_combo));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_TUNNEL_TYPE, text);
    
    /* Cert type */
    text = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->cert_type_combo));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_CERT_TYPE, text);
    
    /* Cert path */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->cert_path_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_CERT_PATH, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_CERT_PATH);
    
    /* Cert ID */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->cert_id_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_CERT_ID, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_CERT_ID);
    
    /* CA Cert */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->ca_cert_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_CA_CERT, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_CA_CERT);
    
    /* Transport type */
    text = gtk_combo_box_get_active_id(GTK_COMBO_BOX(editor->transport_type_combo));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_TRANSPORT_TYPE, text);
    
    /* Search domains */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->search_domains_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_SEARCH_DOMAINS, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_SEARCH_DOMAINS);
    
    /* Ignore search domains */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->ignore_search_domains_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_IGNORE_SEARCH_DOMAINS, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_IGNORE_SEARCH_DOMAINS);
    
    /* DNS servers */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->dns_servers_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_DNS_SERVERS, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_DNS_SERVERS);
    
    /* Ignore DNS servers */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->ignore_dns_servers_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_IGNORE_DNS_SERVERS, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_IGNORE_DNS_SERVERS);
    
    /* Add routes */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->add_routes_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_ADD_ROUTES, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_ADD_ROUTES);
    
    /* Ignore routes */
    text = gtk_editable_get_text(GTK_EDITABLE(editor->ignore_routes_entry));
    if (text && *text)
        nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_IGNORE_ROUTES, text);
    else
        nm_setting_vpn_remove_data_item(s_vpn, SNX_KEY_IGNORE_ROUTES);
    
    /* Boolean switches */
    gboolean val;
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->default_route_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_DEFAULT_ROUTE, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->no_routing_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_NO_ROUTING, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->no_dns_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_NO_DNS, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->no_keychain_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_NO_KEYCHAIN, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->ignore_server_cert_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_IGNORE_SERVER_CERT, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->ike_persist_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_IKE_PERSIST, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->no_keepalive_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_NO_KEEPALIVE, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->disable_ipv6_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_DISABLE_IPV6, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->port_knock_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_PORT_KNOCK, val ? "true" : "false");
    
    val = gtk_switch_get_active(GTK_SWITCH(editor->set_routing_domains_switch));
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_SET_ROUTING_DOMAINS, val ? "true" : "false");
    
    /* Integer values */
    char buf[32];
    
    int mtu = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(editor->mtu_spin));
    snprintf(buf, sizeof(buf), "%d", mtu);
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_MTU, buf);
    
    int ike_lifetime = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(editor->ike_lifetime_spin));
    snprintf(buf, sizeof(buf), "%d", ike_lifetime);
    nm_setting_vpn_add_data_item(s_vpn, SNX_KEY_IKE_LIFETIME, buf);
    
    return TRUE;
}

static void
snx_editor_interface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget = snx_editor_get_widget;
    iface->update_connection = snx_editor_update_connection;
}

static NMVpnEditor *
get_editor(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    (void)plugin;
    (void)error;
    SnxEditor *editor;
    
    editor = g_object_new(SNX_TYPE_EDITOR, NULL);
    build_editor_widget(editor, connection);
    
    return NM_VPN_EDITOR(editor);
}

static void
snx_editor_plugin_interface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor = get_editor;
    iface->get_capabilities = get_capabilities;
    /* import/export not implemented */
}

/* Factory function - the only exported symbol */
G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    (void)error;
    return g_object_new(SNX_TYPE_EDITOR_PLUGIN, NULL);
}

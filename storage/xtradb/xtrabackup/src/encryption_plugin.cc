#include <mysqld.h>
#include <mysql.h>
#include <xtrabackup.h>

#include <sql_plugin.h>
#include <vector>
#include <common.h>


extern struct st_maria_plugin *mysql_optional_plugins[];
extern struct st_maria_plugin *mysql_mandatory_plugins[];

extern char *xb_plugin_load;
extern char *xb_plugin_dir;

static char *plugin_name;
static char *plugin_library;

static int plugin_argc;
#define MAX_PLUGIN_VARS 1024
static char *plugin_argv[MAX_PLUGIN_VARS];

string all_params;

void encryption_plugin_read_vars(MYSQL *mysql)
{
  MYSQL_RES *result;
  MYSQL_ROW row;

  if (mysql_query(mysql, 
    "SELECT plugin_name, plugin_library, @@plugin_dir"
    " FROM information_schema.plugins WHERE plugin_type='ENCRYPTION'"
    " AND plugin_status='ACTIVE'"))

    return;

  result = mysql_store_result(mysql);
  if (!result)
    return;

  row = mysql_fetch_row(result);
  if (!row)
  {
    mysql_free_result(result);
    return;
  }

  plugin_name = strdup(row[0]);
  plugin_library = strdup(row[1]);
  xb_plugin_dir = strdup(row[2]);
#ifdef _WIN32
  /* Damn, we get a sysvar that we cannot set in my.ini without mmessing up with slash conversion. */
  for (char *p = xb_plugin_dir; *p; p++)
    if (*p == '\\') *p = '/';
#endif
  all_params += string("plugin_dir=\"") + xb_plugin_dir + "\"\n";

  asprintf(&xb_plugin_load, "%s=%s", plugin_name, plugin_library);
  all_params += string("plugin_load=") + xb_plugin_load + "\n";
  mysql_free_result(result);

  result = 0;

  char query[1024];
  snprintf(query, 1024, "SHOW variables like '%s_%%'",plugin_name);

  if (mysql_query(mysql, query))
    return;
  result = mysql_store_result(mysql);
  if (!result)
    return;

  plugin_argv[plugin_argc++]=strdup("xtrabackup");

  while ((row = mysql_fetch_row(result)))
  {
    asprintf(&plugin_argv[plugin_argc],"--loose-%s=%s", row[0], row[1]);
    all_params += (plugin_argv[plugin_argc] + 2);
    plugin_argc++;
    if (plugin_argc == MAX_PLUGIN_VARS)
      break;
    
  }

  mysql_free_result(result);
}


extern int sys_var_init();

const char *encryption_plugin_cnf_parameters()
{
  return all_params.c_str();

}

void encryption_plugin_init(int argc, char **argv)
{
  if (!argv)
  {
    argc = plugin_argc;
    argv = plugin_argv;
  }
  else
  {
    memcpy(plugin_argv + 1, argv, argc * sizeof(char*));
    plugin_argv[0] = "xtrabackup";
    argc++;
    argv = plugin_argv;
  }

  if (!xb_plugin_load)
    return;
  sys_var_init();

  if (xb_plugin_dir)
    strncpy(opt_plugin_dir, xb_plugin_dir, FN_REFLEN);

  opt_plugin_load_list_ptr->push_back(new i_string(xb_plugin_load));

  /* Patch optional and mandatory plugins, we only need to load the one in xb_plugin_load. */
  mysql_optional_plugins[0] = mysql_mandatory_plugins[0] = 0;
  mysql_rwlock_init(key_rwlock_LOCK_system_variables_hash, &LOCK_system_variables_hash);
  plugin_mutex_init();
  files_charset_info = &my_charset_utf8_general_ci;

  plugin_init(&argc, argv, PLUGIN_INIT_SKIP_PLUGIN_TABLE);
}
